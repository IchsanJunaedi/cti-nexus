import asyncio
import importlib.util
import re
from datetime import datetime, timedelta
from pathlib import Path
from bson import ObjectId
from app.database import get_database
from app.config import PIR_COLLECTION, PIR_NOTES_COLLECTION, COLLECTION_NAME

_SCRIPT_PATH = Path(__file__).parent.parent.parent / "scripts" / "export_pir_docx.py"


def _load_build_docx():
    spec = importlib.util.spec_from_file_location("export_pir_docx", _SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_docx


def _client_filter(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


def _pir_col():
    return get_database()[PIR_COLLECTION]


def _art_col():
    return get_database()[COLLECTION_NAME]


def _notes_col():
    return get_database()[PIR_NOTES_COLLECTION]


def _build_query(criteria: dict) -> dict:
    q: dict = {}
    if criteria.get("threat_actors"):
        q["threat_actors"] = {"$in": criteria["threat_actors"]}
    if criteria.get("industries"):
        q["impacted_industries"] = {"$in": criteria["industries"]}
    if criteria.get("countries"):
        q["mentioned_countries"] = {"$in": criteria["countries"]}
    if criteria.get("news_types"):
        q["news_type"] = {"$in": criteria["news_types"]}
    if criteria.get("keywords"):
        pattern = "|".join(re.escape(k) for k in criteria["keywords"])
        regex = {"$regex": pattern, "$options": "i"}
        q["$or"] = [
            {"title": regex},
            {"description": regex},
            {"body": regex},
            {"content": regex},
        ]
    if criteria.get("ttps"):
        q["ttps.id"] = {"$in": criteria["ttps"]}
    return q


def _apply_date_range(q: dict, start_date: str | None, end_date: str | None) -> dict:
    if start_date or end_date:
        date_filter: dict = {}
        if start_date:
            date_filter["$gte"] = start_date
        if end_date:
            date_filter["$lte"] = end_date
        q["posted_on"] = date_filter
    return q


async def _compute_coverage(criteria: dict, start_date: str | None = None, end_date: str | None = None) -> tuple[int, str | None, int]:
    """Returns (total, last_match_date, recent_14d_count)."""
    col = _art_col()
    q = _build_query(criteria)
    _apply_date_range(q, start_date, end_date)
    cutoff = (datetime.utcnow() - timedelta(days=14)).strftime("%Y-%m-%d")
    # recent query respects end_date but uses max(cutoff, start_date) as lower bound
    recent_start = max(cutoff, start_date) if start_date else cutoff
    recent_end = end_date
    q_recent = {**q}
    _apply_date_range(q_recent, recent_start, recent_end)

    total, last, recent = await asyncio.gather(
        col.count_documents(q),
        col.find_one(q, {"posted_on": 1}, sort=[("posted_on", -1)]),
        col.count_documents(q_recent) if q else asyncio.coroutine(lambda: 0)(),
    )
    return total, (last["posted_on"] if last else None), recent


def _to_out(doc: dict, total: int = 0, last_match: str | None = None, recent: int = 0) -> dict:
    return {
        "id": str(doc["_id"]),
        "title": doc.get("title", ""),
        "description": doc.get("description", ""),
        "priority": doc.get("priority", "P2"),
        "owner": doc.get("owner", ""),
        "status": doc.get("status", "active"),
        "criteria": doc.get("criteria", {}),
        "start_date": doc.get("start_date"),
        "end_date": doc.get("end_date"),
        "coverage_count": total,
        "recent_coverage": recent,
        "is_gap": total > 0 and recent == 0,
        "last_match": last_match,
        "created_at": doc.get("created_at", ""),
        "updated_at": doc.get("updated_at", ""),
    }


async def list_pirs(client_id: str = "default") -> list[dict]:
    col = _pir_col()
    docs = await col.find(_client_filter(client_id)).sort("priority", 1).to_list(500)
    tasks = [_compute_coverage(d.get("criteria", {}), d.get("start_date"), d.get("end_date")) for d in docs]
    coverages = await asyncio.gather(*tasks)
    return [_to_out(d, *cov) for d, cov in zip(docs, coverages)]


async def get_pir_articles(pir_id: str, page: int = 1, page_size: int = 15) -> tuple[list[dict], int] | None:
    doc = await _pir_col().find_one({"_id": ObjectId(pir_id)})
    if not doc:
        return None
    col = _art_col()
    q = _build_query(doc.get("criteria", {}))
    _apply_date_range(q, doc.get("start_date"), doc.get("end_date"))
    proj = {"_id": 1, "title": 1, "url": 1, "posted_on": 1, "source": 1,
            "news_type": 1, "threat_actors": 1, "impacted_industries": 1, "mentioned_countries": 1}
    skip = (page - 1) * page_size
    cursor = col.find(q, proj).sort("posted_on", -1).skip(skip).limit(page_size)
    articles, total = await asyncio.gather(cursor.to_list(page_size), col.count_documents(q))
    for a in articles:
        a["_id"] = str(a["_id"])
    urls = [a.get("url") for a in articles if a.get("url")]
    noted_urls: set[str] = set()
    if urls:
        noted = await _notes_col().find(
            {"pir_id": pir_id, "url": {"$in": urls}}, {"url": 1}
        ).to_list(page_size)
        noted_urls = {n["url"] for n in noted}
    for a in articles:
        a["has_note"] = a.get("url", "") in noted_urls
    return articles, total


async def get_pir_options() -> dict:
    col = _art_col()
    ttp_pipeline = [
        {"$match": {"ttps": {"$exists": True, "$ne": []}}},
        {"$unwind": "$ttps"},
        {"$group": {"_id": {"id": "$ttps.id", "name": "$ttps.name"}}},
        {"$sort": {"_id.id": 1}},
        {"$limit": 500},
    ]
    tas, industries, countries, news_types, ttps_raw = await asyncio.gather(
        col.distinct("threat_actors"),
        col.distinct("impacted_industries"),
        col.distinct("mentioned_countries"),
        col.distinct("news_type"),
        col.aggregate(ttp_pipeline).to_list(500),
    )
    return {
        "threat_actors": sorted([t for t in tas if t]),
        "industries":    sorted([i for i in industries if i]),
        "countries":     sorted([c for c in countries if c]),
        "news_types":    sorted([n for n in news_types if n]),
        "ttps": [{"id": t["_id"]["id"], "name": t["_id"]["name"]} for t in ttps_raw],
    }


async def get_pir_note(pir_id: str, url: str) -> dict | None:
    doc = await _notes_col().find_one({"pir_id": pir_id, "url": url})
    if not doc:
        return None
    return {"pir_id": doc["pir_id"], "url": doc["url"],
            "note": doc.get("note", ""), "analyst": doc.get("analyst", ""),
            "updated_at": doc.get("updated_at", "")}


async def save_pir_note(pir_id: str, url: str, note: str, analyst: str) -> dict:
    now = datetime.utcnow().isoformat()
    doc = {"pir_id": pir_id, "url": url, "note": note, "analyst": analyst, "updated_at": now}
    await _notes_col().update_one(
        {"pir_id": pir_id, "url": url},
        {"$set": doc},
        upsert=True,
    )
    return doc


async def get_pir_export(pir_id: str) -> dict | None:
    pir = await _pir_col().find_one({"_id": ObjectId(pir_id)})
    if not pir:
        return None
    pir_out = _to_out(pir)
    col = _art_col()
    q = _build_query(pir.get("criteria", {}))
    _apply_date_range(q, pir.get("start_date"), pir.get("end_date"))
    proj = {"_id": 1, "title": 1, "url": 1, "posted_on": 1, "source": 1,
            "news_type": 1, "threat_actors": 1, "impacted_industries": 1, "mentioned_countries": 1}
    articles_raw, notes_raw = await asyncio.gather(
        col.find(q, proj).sort("posted_on", -1).to_list(10000),
        _notes_col().find({"pir_id": pir_id}).to_list(10000),
    )
    notes_by_url = {
        n["url"]: {"note": n.get("note", ""), "analyst": n.get("analyst", ""), "updated_at": n.get("updated_at", "")}
        for n in notes_raw
    }
    articles_out = []
    for a in articles_raw:
        a["_id"] = str(a["_id"])
        a["analyst_note"] = notes_by_url.get(a.get("url", ""), {})
        articles_out.append(a)
    return {
        "pir": pir_out,
        "exported_at": datetime.utcnow().isoformat(),
        "total_articles": len(articles_out),
        "articles": articles_out,
    }


_alerted_urls: set[str] = set()
_alerted_date: str = ""


async def check_new_articles_vs_pirs(since: datetime) -> list[dict]:
    """Returns [{pir, articles}] for new articles matching active PIRs."""
    global _alerted_urls, _alerted_date

    today = datetime.utcnow().strftime("%Y-%m-%d")
    if today != _alerted_date:
        _alerted_urls = set()
        _alerted_date = today

    pir_col = _pir_col()
    art_col = _art_col()
    active_pirs = await pir_col.find({"status": "active"}).to_list(500)
    if not active_pirs:
        return []

    since_str = since.strftime("%Y-%m-%d")
    results = []
    for pir in active_pirs:
        end_date = pir.get("end_date")
        start_date = pir.get("start_date")
        # skip PIR if today is outside its active window
        if end_date and today > end_date:
            continue
        if start_date and today < start_date:
            continue

        q = _build_query(pir.get("criteria", {}))
        if not q:
            continue
        # scan only articles since last check, but respect PIR date bounds
        effective_start = max(since_str, start_date) if start_date else since_str
        effective_end = end_date
        _apply_date_range(q, effective_start, effective_end)
        proj = {"title": 1, "url": 1, "source": 1, "posted_on": 1, "news_type": 1}
        matched = await art_col.find(q, proj).sort("posted_on", -1).limit(5).to_list(5)
        new_articles = [a for a in matched if a.get("url") not in _alerted_urls]
        if new_articles:
            for a in new_articles:
                _alerted_urls.add(a.get("url", ""))
            results.append({"pir": pir, "articles": new_articles})

    return results


async def create_pir(data: dict, client_id: str = "default") -> dict:
    col = _pir_col()
    now = datetime.utcnow().isoformat()
    doc = {
        "title": data["title"],
        "description": data.get("description", ""),
        "priority": data.get("priority", "P2"),
        "owner": data.get("owner", ""),
        "status": "active",
        "criteria": data.get("criteria", {}),
        "start_date": data.get("start_date"),
        "end_date": data.get("end_date"),
        "client_id": client_id,
        "created_at": now,
        "updated_at": now,
    }
    res = await col.insert_one(doc)
    doc["_id"] = res.inserted_id
    total, last, recent = await _compute_coverage(doc["criteria"], doc.get("start_date"), doc.get("end_date"))
    return _to_out(doc, total, last, recent)


async def update_pir(pir_id: str, data: dict) -> dict | None:
    col = _pir_col()
    now = datetime.utcnow().isoformat()
    fields: dict = {"updated_at": now}
    for key in ("title", "description", "priority", "owner", "status", "criteria", "start_date", "end_date"):
        if key in data:
            fields[key] = data[key]
    res = await col.find_one_and_update(
        {"_id": ObjectId(pir_id)},
        {"$set": fields},
        return_document=True,
    )
    if not res:
        return None
    total, last, recent = await _compute_coverage(res.get("criteria", {}), res.get("start_date"), res.get("end_date"))
    return _to_out(res, total, last, recent)


async def delete_pir(pir_id: str) -> bool:
    res = await _pir_col().delete_one({"_id": ObjectId(pir_id)})
    return res.deleted_count > 0


async def export_pir_to_docx_bytes(pir_id: str) -> tuple[bytes, str] | None:
    """Returns (docx_bytes, filename) or None if PIR not found.
    Loads build_docx fresh from scripts/export_pir_docx.py on each call."""
    data = await get_pir_export(pir_id)
    if not data:
        return None
    if not _SCRIPT_PATH.exists():
        raise RuntimeError(f"Export script not found: {_SCRIPT_PATH}")
    build_docx = _load_build_docx()
    docx_bytes = build_docx(data)
    safe_title = re.sub(r"[^a-zA-Z0-9]", "_", data["pir"].get("title", "PIR"))[:40]
    filename   = f"PIR_{safe_title}_{datetime.utcnow().strftime('%Y%m%d')}.docx"
    return docx_bytes, filename
