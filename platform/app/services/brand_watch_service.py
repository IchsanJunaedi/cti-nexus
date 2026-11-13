"""Brand watch — user-managed watchlist of domains for favicon/Shodan monitoring.

Scanning itself (favicon fetch + Shodan http.favicon.hash search) runs
out-of-process in ScraperNewsRevamp/faviconWatchScanner.py, which polls
`monitored_brands` and writes findings to `brand_favicon_matches`. This
service only owns the watchlist CRUD and read access to match results.
"""
import asyncio
import re
from datetime import date, datetime, timezone
from bson import ObjectId
from app.database import get_database

_BRAND_COL = "monitored_brands"
_MATCH_COL = "brand_favicon_matches"

_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", re.I)


def _brand_col():
    return get_database()[_BRAND_COL]


def _match_col():
    return get_database()[_MATCH_COL]


def _client_filter(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


async def ensure_indexes() -> None:
    db = get_database()
    await db[_BRAND_COL].create_index(
        [("name", 1), ("client_id", 1)], unique=True, background=True,
    )
    await db[_MATCH_COL].create_index(
        [("base_name", 1), ("ip_str", 1), ("port", 1), ("client_id", 1)],
        unique=True, background=True,
    )
    await db[_MATCH_COL].create_index([("base_name", 1), ("client_id", 1)], background=True)
    await db[_MATCH_COL].create_index([("newly_seen", 1), ("client_id", 1)], background=True)
    await db[_MATCH_COL].create_index([("is_own_domain", 1), ("client_id", 1)], background=True)
    await db[_MATCH_COL].create_index([("acknowledged", 1), ("client_id", 1)], background=True)


# ── Watchlist management ────────────────────────────────────────────────────

async def list_domains(
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "name",
    sort_dir: str = "asc",
    client_id: str = "default",
) -> tuple[list[dict], int]:
    col = _brand_col()
    query: dict = {**_client_filter(client_id)}
    if search:
        query["name"] = {"$regex": search, "$options": "i"}
    valid_sorts = {"name", "added_date", "last_scan", "match_count",
                   "new_match_count", "suspicious_count"}
    if sort_by not in valid_sorts:
        sort_by = "name"
    direction = 1 if sort_dir == "asc" else -1
    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, direction).skip(skip).limit(page_size)
    items, total = await asyncio.gather(cursor.to_list(page_size), col.count_documents(query))
    return items, total


async def add_domain(name: str, client_id: str = "default") -> dict:
    name = name.strip().lower()
    name = re.sub(r"^https?://", "", name).split("/")[0]
    if not name or not _NAME_RE.match(name):
        return {"success": False, "reason": "invalid domain name — use a full domain (e.g. \"example.com\")"}
    col = _brand_col()
    cf = _client_filter(client_id)
    existing = await col.find_one(
        {"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}, **cf}
    )
    if existing:
        return {"success": False, "reason": "duplicate"}
    await col.insert_one({
        "name": name,
        "client_id": client_id,
        "added_date": str(date.today()),
        "last_scan": None,
        "favicon_hash": None,
        "match_count": 0,
        "new_match_count": 0,
        "suspicious_count": 0,
    })
    return {"success": True, "name": name}


async def delete_domain(domain_id: str, client_id: str = "default") -> dict:
    col = _brand_col()
    mcol = _match_col()
    try:
        oid = ObjectId(domain_id)
    except Exception:
        return {"success": False, "reason": "invalid id"}
    doc = await col.find_one({"_id": oid, **_client_filter(client_id)})
    if not doc:
        return {"success": False, "reason": "not found"}
    await asyncio.gather(
        col.delete_one({"_id": oid}),
        mcol.delete_many({"base_name": doc["name"], **_client_filter(client_id)}),
    )
    return {"success": True, "deleted": doc["name"]}


async def get_domain_by_id(domain_id: str, client_id: str = "default") -> dict | None:
    try:
        oid = ObjectId(domain_id)
    except Exception:
        return None
    return await _brand_col().find_one({"_id": oid, **_client_filter(client_id)})


# ── Match result queries ─────────────────────────────────────────────────────

async def list_results(
    base_name: str | None = None,
    newly_seen_only: bool = False,
    suspicious_only: bool = False,
    acknowledged: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "ip_str",
    sort_dir: str = "asc",
    client_id: str = "default",
) -> tuple[list[dict], int]:
    col = _match_col()
    query: dict = {**_client_filter(client_id)}
    if base_name:
        query["base_name"] = base_name
    if newly_seen_only:
        query["newly_seen"] = True
    if suspicious_only:
        query["is_own_domain"] = False
    if acknowledged == "true":
        query["acknowledged"] = True
    elif acknowledged == "false":
        query["acknowledged"] = {"$ne": True}
    if search:
        query["$or"] = [
            {"ip_str": {"$regex": search, "$options": "i"}},
            {"hostnames": {"$regex": search, "$options": "i"}},
            {"org": {"$regex": search, "$options": "i"}},
        ]
    valid_sorts = {"ip_str", "port", "org", "first_seen", "last_seen"}
    if sort_by not in valid_sorts:
        sort_by = "ip_str"
    direction = 1 if sort_dir == "asc" else -1
    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, direction).skip(skip).limit(page_size)
    items, total = await asyncio.gather(cursor.to_list(page_size), col.count_documents(query))
    return items, total


async def acknowledge_result(result_id: str, username: str, client_id: str = "default") -> dict:
    col = _match_col()
    try:
        oid = ObjectId(result_id)
    except Exception:
        return {"success": False, "reason": "invalid id"}
    doc = await col.find_one({"_id": oid, **_client_filter(client_id)})
    if not doc:
        return {"success": False, "reason": "not found"}
    now     = datetime.now(timezone.utc).isoformat()
    toggled = not doc.get("acknowledged", False)
    update: dict = {"acknowledged": toggled}
    if toggled:
        update["ack_by"]   = username
        update["ack_date"] = now
    else:
        update["ack_by"]   = None
        update["ack_date"] = None
    await col.update_one({"_id": oid}, {"$set": update})
    return {"success": True, "acknowledged": toggled}


async def get_stats(client_id: str = "default") -> dict:
    brand_col = _brand_col()
    match_col = _match_col()
    cf = _client_filter(client_id)
    brands, matches, new_matches, suspicious, unacked = await asyncio.gather(
        brand_col.count_documents(cf),
        match_col.count_documents(cf),
        match_col.count_documents({"newly_seen": True, **cf}),
        match_col.count_documents({"is_own_domain": False, **cf}),
        match_col.count_documents({"acknowledged": {"$ne": True}, **cf}),
    )
    return {
        "brands": brands,
        "total_matches": matches,
        "new_matches": new_matches,
        "suspicious": suspicious,
        "unacknowledged": unacked,
    }
