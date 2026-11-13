"""Read/query layer for the full CISA KEV catalog, ingested by ScraperNewsRevamp's
cisaKevIngestion.py into cisa_kev_catalog. Independent of per-client cve_tracker rows."""
import asyncio
from datetime import datetime, timedelta, timezone
from app.database import get_database

_CATALOG_COL = "cisa_kev_catalog"


def _col():
    return get_database()[_CATALOG_COL]


async def ensure_indexes() -> None:
    col = _col()
    await col.create_index("cve_id", unique=True, background=True)
    await col.create_index("date_added", background=True)
    await col.create_index("matched_tracker", background=True)


async def list_kev_entries(
    search: str | None = None,
    matched: bool | None = None,
    ransomware_only: bool = False,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "date_added",
    sort_dir: str = "desc",
) -> tuple[list[dict], int]:
    col = _col()
    query: dict = {}
    if search:
        query["$or"] = [
            {"cve_id":             {"$regex": search, "$options": "i"}},
            {"vendor_project":     {"$regex": search, "$options": "i"}},
            {"product":            {"$regex": search, "$options": "i"}},
            {"vulnerability_name": {"$regex": search, "$options": "i"}},
        ]
    if matched is not None:
        query["matched_tracker"] = matched
    if ransomware_only:
        query["known_ransomware_use"] = "Known"

    valid_sorts = {"cve_id", "date_added", "due_date", "vendor_project", "product"}
    if sort_by not in valid_sorts:
        sort_by = "date_added"
    direction = 1 if sort_dir == "asc" else -1
    skip = (page - 1) * page_size

    cursor = col.find(query).sort(sort_by, direction).skip(skip).limit(page_size)
    items, total = await asyncio.gather(cursor.to_list(page_size), col.count_documents(query))
    return items, total


async def get_kev_stats() -> dict:
    col = _col()
    week_out = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%d")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    total, matched, ransomware_known, due_soon = await asyncio.gather(
        col.count_documents({}),
        col.count_documents({"matched_tracker": True}),
        col.count_documents({"known_ransomware_use": "Known"}),
        col.count_documents({
            "matched_tracker": False,
            "due_date": {"$gte": today, "$lte": week_out, "$ne": ""},
        }),
    )
    return {
        "total": total,
        "matched": matched,
        "unmatched": total - matched,
        "ransomware_known": ransomware_known,
        "due_soon": due_soon,
    }
