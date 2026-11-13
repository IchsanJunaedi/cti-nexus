import asyncio
import re
from datetime import datetime
from app.database import get_database
from app.config import COLLECTION_NAME


async def _active_tech_names(client_id: str) -> list[str] | None:
    """Return active tech stack names for client. None means no restriction (empty stack)."""
    from app.services.techstack_service import list_techstack
    items, _ = await list_techstack(page=1, page_size=10000, client_id=client_id)
    names = [item["name"] for item in items if item.get("name")]
    return names if names else None

CVE_COLLECTION      = "cve_tracker"
FP_COLLECTION       = "cve_false_positives"
ARTICLES_COLLECTION = COLLECTION_NAME


def _collection():
    return get_database()[CVE_COLLECTION]

def _fp_collection():
    return get_database()[FP_COLLECTION]


def _client_filter(client_id: str) -> dict:
    return {"client_id": client_id}

def _articles_collection():
    return get_database()[ARTICLES_COLLECTION]


async def get_article_mentions(cve_ids: list[str]) -> dict[str, list[dict]]:
    """Return {cve_id: [{"title": ..., "url": ...}]} for each CVE found in article titles."""
    if not cve_ids:
        return {}
    col = _articles_collection()
    pattern = "|".join(re.escape(cid) for cid in cve_ids)
    docs = await col.find(
        {"title": {"$regex": pattern, "$options": "i"}},
        {"title": 1, "url": 1, "_id": 0},
    ).to_list(length=2000)

    result: dict[str, list[dict]] = {cid: [] for cid in cve_ids}
    for doc in docs:
        title = doc.get("title", "")
        for cid in cve_ids:
            if cid.upper() in title.upper():
                result[cid].append({"title": title, "url": doc.get("url", "")})
    return result


async def upsert_newsletter_mention(cve_id: str, article: dict) -> None:
    """Append article reference to cve_tracker.newsletter_mentions, deduped by url."""
    col = _collection()
    entry = {
        "title":    article.get("title", ""),
        "url":      article.get("url", ""),
        "source":   article.get("source", ""),
        "date":     article.get("posted_on", ""),
        "added_at": datetime.utcnow().isoformat(),
    }
    # Filter excludes doc when url already present → push only runs once per url
    await col.update_one(
        {"cve_id": cve_id, "newsletter_mentions": {"$not": {"$elemMatch": {"url": entry["url"]}}}},
        {"$push": {"newsletter_mentions": entry}},
    )


async def get_fp_cve_ids(client_id: str = "default") -> list[str]:
    col = _fp_collection()
    docs = await col.find({**_client_filter(client_id)}, {"cve_id": 1, "_id": 0}).to_list(length=10000)
    return [d["cve_id"] for d in docs]


async def get_tp_cve_ids(client_id: str = "default") -> list[str]:
    """CVE IDs tracked for this client, minus false positives."""
    col = _collection()
    fp_ids, docs = await asyncio.gather(
        get_fp_cve_ids(client_id),
        col.find({**_client_filter(client_id)}, {"cve_id": 1, "_id": 0}).to_list(length=10000),
    )
    fp_set = set(fp_ids)
    return sorted({d["cve_id"] for d in docs if d.get("cve_id") and d["cve_id"] not in fp_set})


async def mark_false_positive(cve_id: str, client_id: str = "default") -> None:
    col = _fp_collection()
    await col.update_one(
        {"cve_id": cve_id, **_client_filter(client_id)},
        {"$setOnInsert": {"cve_id": cve_id, "client_id": client_id, "marked_at": datetime.utcnow().isoformat()}},
        upsert=True,
    )


async def unmark_false_positive(cve_id: str, client_id: str = "default") -> None:
    col = _fp_collection()
    await col.delete_one({"cve_id": cve_id, **_client_filter(client_id)})


async def bulk_mark_false_positive(cve_ids: list[str], client_id: str = "default") -> int:
    """Mark multiple CVEs as false positive. Returns count inserted."""
    if not cve_ids:
        return 0
    from pymongo import UpdateOne
    col = _fp_collection()
    now = datetime.utcnow().isoformat()
    ops = [
        UpdateOne(
            {"cve_id": cid, **_client_filter(client_id)},
            {"$setOnInsert": {"cve_id": cid, "client_id": client_id, "marked_at": now}},
            upsert=True,
        )
        for cid in cve_ids
    ]
    result = await col.bulk_write(ops)
    return result.upserted_count


def apply_extra_filters(
    query: dict,
    kev_filter: str | None = None,
    score_filter: str | None = None,
    updated_filter: str | None = None,
) -> None:
    """KEV / unscored / updated-since-detected filters. Uses $and so it never clobbers other keys (e.g. cve_score buckets in stats)."""
    clauses = []
    if kev_filter == "kev":
        clauses.append({"cisa_kev": True})
    elif kev_filter == "not_kev":
        clauses.append({"cisa_kev": {"$ne": True}})
    if score_filter == "unscored":
        clauses.append({"cve_score": {"$in": [0, None]}})   # None also matches missing field
    elif score_filter == "scored":
        clauses.append({"cve_score": {"$gt": 0}})
    if updated_filter == "updated":
        clauses.append({"updated_since_detected": True})
    if clauses:
        query.setdefault("$and", []).extend(clauses)


_SORT_FIELD_MAP = {
    "tech":      "tech",
    "severity":  "cve_score",   # sort by numeric score, not severity string
    "published": "published",
    "epss":      "epss_score",
}

async def get_cves(
    page: int = 1,
    page_size: int = 20,
    tech: list[str] | None = None,
    severity: list[str] | None = None,
    search: str | None = None,
    date_start: str | None = None,
    date_end: str | None = None,
    include_fp: bool = False,
    sort_by: str = "published",
    sort_dir: str = "desc",
    ack_filter: str | None = None,
    draft_filter: str | None = None,
    client_id: str = "default",
    cve_ids: list[str] | None = None,
    kev_filter: str | None = None,
    score_filter: str | None = None,
    updated_filter: str | None = None,
) -> tuple[list[dict], int]:
    from app.services.cve_ticket_service import get_acked_cve_ids, get_drafted_cve_ids
    col = _collection()
    query: dict = {**_client_filter(client_id)}

    if cve_ids:
        query["cve_id"] = {"$in": cve_ids}

    fp_ids      = await get_fp_cve_ids(client_id)
    fp_ids_set  = set(fp_ids)

    if not include_fp and fp_ids:
        query["cve_id"] = {"$nin": fp_ids} if "cve_id" not in query else {**query["cve_id"], "$nin": fp_ids}

    if ack_filter in ("acked", "unacked"):
        acked_ids = await get_acked_cve_ids(client_id)
        if ack_filter == "acked":
            existing = query.get("cve_id", {})
            nin = existing.get("$nin", []) if isinstance(existing, dict) else []
            query["cve_id"] = {"$in": [i for i in acked_ids if i not in set(nin)]}
        else:
            acked_set = set(acked_ids)
            existing = query.get("cve_id", {})
            nin = list(existing.get("$nin", []) if isinstance(existing, dict) else [])
            query["cve_id"] = {"$nin": nin + [i for i in acked_set if i not in set(nin)]}

    if draft_filter in ("drafted", "undrafted"):
        drafted_ids = await get_drafted_cve_ids(client_id)
        if draft_filter == "drafted":
            existing = query.get("cve_id", {})
            nin = existing.get("$nin", []) if isinstance(existing, dict) else []
            query["cve_id"] = {"$in": [i for i in drafted_ids if i not in set(nin)]}
        else:
            drafted_set = set(drafted_ids)
            existing = query.get("cve_id", {})
            nin = list(existing.get("$nin", []) if isinstance(existing, dict) else [])
            query["cve_id"] = {"$nin": nin + [i for i in drafted_set if i not in set(nin)]}

    if tech:
        query["tech"] = {"$in": tech}
    else:
        active_techs = await _active_tech_names(client_id)
        if active_techs:
            query["tech"] = {"$in": active_techs}

    if severity:
        query["cve_severity"] = {"$in": [s.upper() for s in severity]}

    apply_extra_filters(query, kev_filter, score_filter, updated_filter)

    if search:
        query["$or"] = [
            {"cve_id":  {"$regex": search, "$options": "i"}},
            {"summary": {"$regex": search, "$options": "i"}},
            {"tech":    {"$regex": search, "$options": "i"}},
        ]

    if date_start or date_end:
        date_filter: dict = {}
        if date_start:
            date_filter["$gte"] = date_start
        if date_end:
            date_filter["$lte"] = date_end
        query["published"] = date_filter

    mongo_field = _SORT_FIELD_MAP.get(sort_by, "published")
    mongo_dir   = -1 if sort_dir == "desc" else 1
    skip   = (page - 1) * page_size
    cursor = col.find(query).sort(mongo_field, mongo_dir).skip(skip).limit(page_size)
    cves, total = await asyncio.gather(
        cursor.to_list(length=page_size),
        col.count_documents(query),
    )

    for c in cves:
        c["false_positive"] = c.get("cve_id", "") in fp_ids_set

    # Enrich with article mentions (only for true positives)
    tp_ids = [c["cve_id"] for c in cves if not c.get("false_positive")]
    mentions_map = await get_article_mentions(tp_ids) if tp_ids else {}

    from app.services.techstack_service import get_tech_risk_context
    from app.models.techstack import EXPOSURE_MULTIPLIER, HOSTING_MULTIPLIER
    risk_ctx = await get_tech_risk_context(client_id)
    KEV_MULTIPLIER = 1.5  # CISA KEV = confirmed active exploitation, matches pkg_vuln_service kev_mult
    POC_MULTIPLIER = 1.2  # CVSS Exploit Code Maturity (E:P) — public PoC lowers attack cost

    for c in cves:
        c_id = c.get("cve_id", "")
        c["news_mentions"] = mentions_map.get(c_id, [])
        c["news_mentions_count"] = len(c["news_mentions"])
        tech_name = (c.get("tech") or "").lower()
        ctx          = risk_ctx.get(tech_name, {})
        exposure     = ctx.get("exposure", "internal")
        hosting      = ctx.get("hosting_type", "on_prem")
        c["tech_exposure"]  = exposure
        c["hosting_type"]   = hosting
        raw          = float(c.get("cve_score") or 0)
        epss         = float(c.get("epss_score") or 0)
        epss_mult    = 1.3 if epss >= 0.5 else (1.15 if epss >= 0.1 else 1.0)
        exposure_mult = EXPOSURE_MULTIPLIER.get(exposure, 1.0)
        hosting_mult  = HOSTING_MULTIPLIER.get(hosting, 1.0)
        kev_mult     = KEV_MULTIPLIER if c.get("cisa_kev") else 1.0
        poc_mult     = POC_MULTIPLIER if c.get("poc_available") else 1.0
        c["epss_multiplier"]    = epss_mult
        c["hosting_multiplier"] = hosting_mult
        c["kev_multiplier"]     = kev_mult
        c["poc_multiplier"]     = poc_mult
        c["adjusted_risk_score"] = round(
            min(10.0, raw * exposure_mult * epss_mult * hosting_mult * kev_mult * poc_mult), 1
        ) if raw else 0.0

    return cves, total


async def get_cve_stats(
    include_fp: bool = False,
    client_id: str = "default",
    search: str | None = None,
    severity: list[str] | None = None,
    tech: list[str] | None = None,
    date_start: str | None = None,
    date_end: str | None = None,
    ack_filter: str | None = None,
    draft_filter: str | None = None,
    kev_filter: str | None = None,
    score_filter: str | None = None,
    updated_filter: str | None = None,
) -> dict:
    from app.services.cve_ticket_service import get_acked_cve_ids, get_drafted_cve_ids
    col = _collection()
    cf = _client_filter(client_id)
    base: dict = {**cf}

    if not include_fp:
        fp_ids = await get_fp_cve_ids(client_id)
        if fp_ids:
            base["cve_id"] = {"$nin": fp_ids}

    if ack_filter in ("acked", "unacked"):
        acked_ids = await get_acked_cve_ids(client_id)
        acked_set = set(acked_ids)
        if ack_filter == "acked":
            existing = base.get("cve_id", {})
            nin = existing.get("$nin", []) if isinstance(existing, dict) else []
            base["cve_id"] = {"$in": [i for i in acked_ids if i not in set(nin)]}
        else:
            existing = base.get("cve_id", {})
            nin = list(existing.get("$nin", []) if isinstance(existing, dict) else [])
            base["cve_id"] = {"$nin": nin + [i for i in acked_set if i not in set(nin)]}

    if draft_filter in ("drafted", "undrafted"):
        drafted_ids = await get_drafted_cve_ids(client_id)
        drafted_set = set(drafted_ids)
        if draft_filter == "drafted":
            existing = base.get("cve_id", {})
            nin = existing.get("$nin", []) if isinstance(existing, dict) else []
            base["cve_id"] = {"$in": [i for i in drafted_ids if i not in set(nin)]}
        else:
            existing = base.get("cve_id", {})
            nin = list(existing.get("$nin", []) if isinstance(existing, dict) else [])
            base["cve_id"] = {"$nin": nin + [i for i in drafted_set if i not in set(nin)]}

    if tech:
        base["tech"] = {"$in": tech}
    else:
        active_techs = await _active_tech_names(client_id)
        if active_techs:
            base["tech"] = {"$in": active_techs}

    apply_extra_filters(base, kev_filter, score_filter, updated_filter)

    if search:
        base["$or"] = [
            {"cve_id":  {"$regex": search, "$options": "i"}},
            {"summary": {"$regex": search, "$options": "i"}},
            {"tech":    {"$regex": search, "$options": "i"}},
        ]

    if date_start or date_end:
        date_filter: dict = {}
        if date_start:
            date_filter["$gte"] = date_start
        if date_end:
            date_filter["$lte"] = date_end
        base["published"] = date_filter

    # severity filter not applied to base so all severity buckets remain meaningful
    # (filtering by severity would make non-selected buckets always 0)
    sev_base = {**base}
    if severity:
        sev_base["cve_severity"] = {"$in": [s.upper() for s in severity]}

    total, critical, high, medium, low = await asyncio.gather(
        col.count_documents({**sev_base}),
        col.count_documents({"cve_score": {"$gte": 9.0},               **base}),
        col.count_documents({"cve_score": {"$gte": 7.0, "$lt": 9.0},  **base}),
        col.count_documents({"cve_score": {"$gte": 4.0, "$lt": 7.0},  **base}),
        col.count_documents({"cve_score": {"$gt":  0,   "$lt": 4.0},  **base}),
    )
    return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low}


async def purge_orphaned_cves(client_id: str = "default", dry_run: bool = True) -> dict:
    """Delete CVEs whose tech is not in the active tech stack for this client.
    dry_run=True (default): returns what WOULD be deleted without touching DB.
    """
    from app.services.techstack_service import list_techstack
    items, _ = await list_techstack(page=1, page_size=10000, client_id=client_id)
    active_names = {item["name"] for item in items if item.get("name")}

    col = _collection()
    cf  = _client_filter(client_id)

    if active_names:
        orphan_filter = {"tech": {"$nin": list(active_names)}, **cf}
    else:
        # No active tech stacks → all CVEs are orphaned
        orphan_filter = {**cf}

    orphan_docs = await col.find(orphan_filter, {"cve_id": 1, "tech": 1, "_id": 0}).to_list(length=10000)
    cve_ids     = [d["cve_id"] for d in orphan_docs if d.get("cve_id")]
    by_tech: dict[str, int] = {}
    for d in orphan_docs:
        t = d.get("tech") or "(no tech)"
        by_tech[t] = by_tech.get(t, 0) + 1

    if dry_run or not cve_ids:
        return {"dry_run": True, "would_delete": len(cve_ids), "by_tech": by_tech, "cve_ids": cve_ids}

    db = get_database()
    await col.delete_many(orphan_filter)
    await asyncio.gather(
        db[FP_COLLECTION].delete_many({"cve_id": {"$in": cve_ids}, **cf}),
        db["cve_tickets"].delete_many({"cve_id": {"$in": cve_ids}, **cf}),
    )
    return {"dry_run": False, "deleted": len(cve_ids), "by_tech": by_tech, "cve_ids": cve_ids}


async def get_newsletter_cve_summary(client_id: str = "default", cve_ids: list[str] | None = None) -> list[dict]:
    """Trimmed, client-scoped CVE details for newsletter's 'Outstanding TP CVEs' section.
    Manual selection only — cve_ids is the analyst-picked list; empty/None returns no CVEs."""
    if not cve_ids:
        return []
    cves, _ = await get_cves(
        page=1, page_size=len(cve_ids), sort_by="severity", sort_dir="desc",
        include_fp=False, client_id=client_id, cve_ids=cve_ids,
    )
    return [
        {
            "cve_id":             c.get("cve_id", ""),
            "tech":               c.get("tech", ""),
            "cve_severity":       c.get("cve_severity", ""),
            "adjusted_risk_score": c.get("adjusted_risk_score", 0.0),
            "epss_score":         c.get("epss_score", 0.0),
            "cisa_kev":           bool(c.get("cisa_kev")),
            "published":          c.get("published", ""),
        }
        for c in cves
    ]


async def get_tech_list(client_id: str = "default") -> list[str]:
    col = _collection()
    return sorted([t for t in await col.distinct("tech", _client_filter(client_id)) if t])
