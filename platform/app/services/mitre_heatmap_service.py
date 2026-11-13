import asyncio
from datetime import date, timedelta
from app.database import get_database
from app.config import COLLECTION_NAME


def _col():
    return get_database()[COLLECTION_NAME]


async def get_heatmap(view: str, days: int, top_rows: int = 15, top_ttps: int = 20) -> dict:
    """
    view: 'ta' | 'industry'
    Returns: {rows, ttps: [{id, name}], matrix: [[int]], max_val}
    """
    col = _col()
    cutoff = (date.today() - timedelta(days=days)).isoformat()
    row_field = "threat_actors" if view == "ta" else "impacted_industries"

    top_rows_pipeline = [
        {"$match": {"posted_on": {"$gte": cutoff}, row_field: {"$exists": True, "$ne": []}}},
        {"$unwind": f"${row_field}"},
        {"$group": {"_id": f"${row_field}", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": top_rows},
    ]
    top_ttps_pipeline = [
        {"$match": {"posted_on": {"$gte": cutoff}, "ttps": {"$exists": True, "$ne": []}}},
        {"$unwind": "$ttps"},
        {"$group": {"_id": {"id": "$ttps.id", "name": "$ttps.name"}, "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": top_ttps},
    ]

    top_rows_res, top_ttps_res = await asyncio.gather(
        col.aggregate(top_rows_pipeline).to_list(top_rows),
        col.aggregate(top_ttps_pipeline).to_list(top_ttps),
    )

    row_names = [r["_id"] for r in top_rows_res]
    ttp_list = [{"id": t["_id"]["id"], "name": t["_id"]["name"]} for t in top_ttps_res]
    ttp_ids = [t["id"] for t in ttp_list]

    if not row_names or not ttp_ids:
        return {"rows": [], "ttps": [], "matrix": [], "max_val": 0}

    co_pipeline = [
        {"$match": {
            "posted_on": {"$gte": cutoff},
            row_field: {"$in": row_names},
            "ttps": {"$exists": True, "$ne": []},
        }},
        {"$unwind": f"${row_field}"},
        {"$match": {row_field: {"$in": row_names}}},
        {"$unwind": "$ttps"},
        {"$match": {"ttps.id": {"$in": ttp_ids}}},
        {"$group": {
            "_id": {"row": f"${row_field}", "ttp": "$ttps.id"},
            "count": {"$sum": 1},
        }},
    ]
    co_res = await col.aggregate(co_pipeline).to_list(10000)

    co_map = {(r["_id"]["row"], r["_id"]["ttp"]): r["count"] for r in co_res}

    matrix = []
    for row in row_names:
        matrix.append([co_map.get((row, tid), 0) for tid in ttp_ids])

    max_val = max((max(row) for row in matrix if row), default=0)

    return {"rows": row_names, "ttps": ttp_list, "matrix": matrix, "max_val": max_val}


async def get_navigator_layer(view: str, days: int) -> dict:
    """Export MITRE ATT&CK Navigator layer JSON (v4.5) from observed TTP frequencies."""
    col = _col()
    cutoff = (date.today() - timedelta(days=days)).isoformat()
    row_field = "threat_actors" if view == "ta" else "impacted_industries"

    pipeline = [
        {"$match": {"posted_on": {"$gte": cutoff}, "ttps": {"$exists": True, "$ne": []}}},
        {"$unwind": "$ttps"},
        {"$group": {"_id": "$ttps.id", "name": {"$first": "$ttps.name"}, "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    raw = await col.aggregate(pipeline).to_list(500)

    if not raw:
        max_count = 1
    else:
        max_count = max(r["count"] for r in raw) or 1

    techniques = []
    for r in raw:
        tid = r["_id"] or ""
        if not tid.startswith("T"):
            continue
        score = round((r["count"] / max_count) * 100)
        techniques.append({
            "techniqueID": tid,
            "score": score,
            "comment": f"Observed {r['count']} time(s) in last {days} days",
            "enabled": True,
            "showSubtechniques": False,
        })

    label = f"CTI Platform — {'Threat Actor' if view == 'ta' else 'Industry'} View ({days}d)"
    return {
        "name": label,
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Generated from scraped articles over the last {days} days.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
    }


async def get_ttp_articles(
    ttp_id: str, row: str, view: str, days: int,
    page: int = 1, page_size: int = 20,
) -> tuple[list[dict], int]:
    col = _col()
    cutoff = (date.today() - timedelta(days=days)).isoformat()
    row_field = "threat_actors" if view == "ta" else "impacted_industries"

    query = {
        "posted_on": {"$gte": cutoff},
        row_field: row,
        "ttps.id": ttp_id,
    }

    skip = (page - 1) * page_size
    projection = {"_id": 1, "title": 1, "url": 1, "posted_on": 1, "source": 1, "news_type": 1}
    cursor = col.find(query, projection).sort("posted_on", -1).skip(skip).limit(page_size)

    docs, total = await asyncio.gather(cursor.to_list(length=page_size), col.count_documents(query))

    for doc in docs:
        doc["_id"] = str(doc["_id"])

    return docs, total
