import asyncio
from datetime import datetime, timedelta
from app.database import get_database

_EXCLUDED_SCRIPTS = {'NEW RANSOMWARE VICTIM', 'NEW RANSOMWARE VICTIM (INDONESIA)'}


def _col():
    return get_database()["scraper_runs"]


async def get_scraper_articles(script: str, days: int = 7) -> dict:
    col = _col()
    cutoff = datetime.utcnow() - timedelta(days=days)
    cursor = col.find(
        {"script": script, "run_at": {"$gte": cutoff}},
        {"_id": 0, "title": 1, "url": 1, "accepted": 1, "run_at": 1},
    ).sort("run_at", -1).limit(200)
    docs = await cursor.to_list(200)
    accepted = []
    rejected = []
    for d in docs:
        item = {
            "title": d.get("title", ""),
            "url": d.get("url", ""),
            "run_at": d["run_at"].isoformat() if d.get("run_at") else None,
        }
        (accepted if d.get("accepted") else rejected).append(item)
    return {"script": script, "accepted": accepted, "rejected": rejected}


async def get_health_summary(days: int = 7) -> dict:
    col = _col()
    cutoff = datetime.utcnow() - timedelta(days=days)

    total_pipeline = [
        {"$match": {"run_at": {"$gte": cutoff}, "script": {"$nin": list(_EXCLUDED_SCRIPTS)}}},
        {"$group": {
            "_id": "$accepted",
            "count": {"$sum": 1},
        }},
    ]
    per_script_pipeline = [
        {"$match": {"run_at": {"$gte": cutoff}, "script": {"$nin": list(_EXCLUDED_SCRIPTS)}}},
        {"$group": {
            "_id": "$script",
            "total":    {"$sum": 1},
            "accepted": {"$sum": {"$cond": ["$accepted", 1, 0]}},
            "rejected": {"$sum": {"$cond": ["$accepted", 0, 1]}},
            "last_run": {"$max": "$run_at"},
        }},
        {"$sort": {"total": -1}},
        {"$limit": 50},
    ]
    daily_pipeline = [
        {"$match": {"run_at": {"$gte": cutoff}, "accepted": True, "script": {"$nin": list(_EXCLUDED_SCRIPTS)}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$run_at"}},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id": 1}},
    ]

    totals_raw, per_script_raw, daily_raw = await asyncio.gather(
        col.aggregate(total_pipeline).to_list(10),
        col.aggregate(per_script_pipeline).to_list(50),
        col.aggregate(daily_pipeline).to_list(400),
    )

    totals = {r["_id"]: r["count"] for r in totals_raw}
    total_accepted = totals.get(True, 0)
    total_rejected = totals.get(False, 0)

    per_script = [
        {
            "script": r["_id"],
            "total": r["total"],
            "accepted": r["accepted"],
            "rejected": r["rejected"],
            "accept_rate": round(r["accepted"] / r["total"] * 100, 1) if r["total"] else 0,
            "last_run": r["last_run"].isoformat() if r.get("last_run") else None,
        }
        for r in per_script_raw
    ]

    daily = [{"date": r["_id"], "count": r["count"]} for r in daily_raw]

    return {
        "total_accepted": total_accepted,
        "total_rejected": total_rejected,
        "total_processed": total_accepted + total_rejected,
        "accept_rate": round(total_accepted / (total_accepted + total_rejected) * 100, 1)
                       if (total_accepted + total_rejected) else 0,
        "per_script": per_script,
        "daily_accepted": daily,
    }
