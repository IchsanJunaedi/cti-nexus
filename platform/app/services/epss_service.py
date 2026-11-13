import asyncio
from datetime import datetime, timezone

import httpx

from app.database import get_database
from app.services.cve_service import CVE_COLLECTION, get_fp_cve_ids

_EPSS_URL = "https://api.first.org/data/v1/epss"
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
}
_TIMEOUT = 30
_BATCH_SIZE = 100


def _col():
    return get_database()[CVE_COLLECTION]


async def fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch EPSS scores for a list of CVE IDs. Returns {cve_id_upper: {epss, percentile, date}}."""
    if not cve_ids:
        return {}

    results: dict[str, dict] = {}
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        for i in range(0, len(cve_ids), _BATCH_SIZE):
            batch = cve_ids[i : i + _BATCH_SIZE]
            params = {"cve": ",".join(batch), "limit": _BATCH_SIZE}
            resp = await client.get(_EPSS_URL, params=params, headers=_HEADERS)
            resp.raise_for_status()
            data = resp.json()
            for entry in data.get("data", []):
                cve_id = entry.get("cve", "").strip().upper()
                if cve_id:
                    results[cve_id] = {
                        "epss":        float(entry.get("epss", 0)),
                        "percentile":  float(entry.get("percentile", 0)),
                        "date":        entry.get("date", ""),
                    }
    return results


async def save_epss_scores(scores: dict[str, dict]) -> None:
    """Bulk-update cve_tracker documents with EPSS scores."""
    if not scores:
        return
    col = _col()
    now = datetime.now(timezone.utc).isoformat()
    tasks = [
        col.update_many(
            {"cve_id": cve_id},
            {"$set": {
                "epss_score":      data["epss"],
                "epss_percentile": data["percentile"],
                "epss_date":       data["date"],
                "epss_checked_at": now,
            }},
        )
        for cve_id, data in scores.items()
    ]
    await asyncio.gather(*tasks)


async def lookup_all_true_positives() -> dict:
    """Fetch EPSS scores for all true-positive CVEs in DB and persist results."""
    col    = _col()
    fp_ids = await get_fp_cve_ids()
    query  = {"cve_id": {"$nin": fp_ids}} if fp_ids else {}
    docs   = await col.find(query, {"cve_id": 1, "_id": 0}).to_list(length=10000)
    tp_ids = [d["cve_id"].upper() for d in docs if d.get("cve_id")]

    scores = await fetch_epss_scores(tp_ids)
    await save_epss_scores(scores)

    return {
        "checked":  len(tp_ids),
        "scored":   len(scores),
        "no_data":  len(tp_ids) - len(scores),
    }
