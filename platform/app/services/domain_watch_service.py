"""Domain watch — user-managed watchlist of base domains.

Scanning itself (TLD sweep via tldsweep) runs out-of-process in
ScraperNewsRevamp/tldsweepScanner.py, which polls `monitored_domains` and
writes findings to `domain_scan_results`. This service only owns the
watchlist CRUD and read access to scan results.
"""
import asyncio
import re
from datetime import date, datetime, timezone
from bson import ObjectId
from app.database import get_database

_DOMAIN_COL = "monitored_domains"
_RESULT_COL = "domain_scan_results"

_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def _domain_col():
    return get_database()[_DOMAIN_COL]


def _result_col():
    return get_database()[_RESULT_COL]


def _client_filter(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


async def ensure_indexes() -> None:
    db = get_database()
    await db[_DOMAIN_COL].create_index(
        [("name", 1), ("client_id", 1)], unique=True, background=True,
    )
    await db[_RESULT_COL].create_index(
        [("base_name", 1), ("tld", 1), ("client_id", 1)], unique=True, background=True,
    )
    await db[_RESULT_COL].create_index([("base_name", 1), ("client_id", 1)], background=True)
    await db[_RESULT_COL].create_index([("newly_registered", 1), ("client_id", 1)], background=True)
    await db[_RESULT_COL].create_index([("registered", 1), ("client_id", 1)], background=True)
    await db[_RESULT_COL].create_index([("acknowledged", 1), ("client_id", 1)], background=True)


# ── Watchlist management ────────────────────────────────────────────────────

async def list_domains(
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "name",
    sort_dir: str = "asc",
    client_id: str = "default",
) -> tuple[list[dict], int]:
    col = _domain_col()
    query: dict = {**_client_filter(client_id)}
    if search:
        query["name"] = {"$regex": search, "$options": "i"}
    valid_sorts = {"name", "added_date", "last_scan", "registered_count",
                   "alive_count", "newly_registered_count", "risk_count"}
    if sort_by not in valid_sorts:
        sort_by = "name"
    direction = 1 if sort_dir == "asc" else -1
    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, direction).skip(skip).limit(page_size)
    items, total = await asyncio.gather(cursor.to_list(page_size), col.count_documents(query))
    return items, total


async def add_domain(name: str, client_id: str = "default") -> dict:
    name = name.strip().lower()
    # strip a scheme/path if pasted as a URL, and drop a trailing TLD if given
    name = re.sub(r"^https?://", "", name).split("/")[0]
    name = name.split(".")[0] if "." in name else name
    if not name or not _NAME_RE.match(name):
        return {"success": False, "reason": "invalid domain name — use the base name without TLD (e.g. \"example\")"}
    col = _domain_col()
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
        "tld_count": 0,
        "registered_count": 0,
        "alive_count": 0,
        "newly_registered_count": 0,
        "risk_count": 0,
    })
    return {"success": True, "name": name}


async def delete_domain(domain_id: str, client_id: str = "default") -> dict:
    col = _domain_col()
    rcol = _result_col()
    try:
        oid = ObjectId(domain_id)
    except Exception:
        return {"success": False, "reason": "invalid id"}
    doc = await col.find_one({"_id": oid, **_client_filter(client_id)})
    if not doc:
        return {"success": False, "reason": "not found"}
    await asyncio.gather(
        col.delete_one({"_id": oid}),
        rcol.delete_many({"base_name": doc["name"], **_client_filter(client_id)}),
    )
    return {"success": True, "deleted": doc["name"]}


async def get_domain_by_id(domain_id: str, client_id: str = "default") -> dict | None:
    try:
        oid = ObjectId(domain_id)
    except Exception:
        return None
    return await _domain_col().find_one({"_id": oid, **_client_filter(client_id)})


# ── Scan result queries ─────────────────────────────────────────────────────

async def list_results(
    base_name: str | None = None,
    registered_only: bool = False,
    alive_only: bool = False,
    newly_registered_only: bool = False,
    parked_only: bool = False,
    exclude_parked: bool = False,
    acknowledged: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "domain",
    sort_dir: str = "asc",
    client_id: str = "default",
) -> tuple[list[dict], int]:
    col = _result_col()
    query: dict = {**_client_filter(client_id)}
    if base_name:
        query["base_name"] = base_name
    if registered_only:
        query["registered"] = True
    if alive_only:
        query["alive"] = True
    if newly_registered_only:
        query["newly_registered"] = True
    if parked_only:
        query["parked"] = True
    elif exclude_parked:
        query["parked"] = {"$ne": True}
    if acknowledged == "true":
        query["acknowledged"] = True
    elif acknowledged == "false":
        query["acknowledged"] = {"$ne": True}
    if search:
        query["domain"] = {"$regex": search, "$options": "i"}
    valid_sorts = {"domain", "tld", "timestamp", "registered", "alive", "newly_registered"}
    if sort_by not in valid_sorts:
        sort_by = "domain"
    direction = 1 if sort_dir == "asc" else -1
    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, direction).skip(skip).limit(page_size)
    items, total = await asyncio.gather(cursor.to_list(page_size), col.count_documents(query))
    return items, total


async def acknowledge_result(result_id: str, username: str, client_id: str = "default") -> dict:
    col = _result_col()
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
    dom_col = _domain_col()
    res_col = _result_col()
    cf = _client_filter(client_id)
    domains, findings, registered, alive, newly, at_risk, unacked, parked = await asyncio.gather(
        dom_col.count_documents(cf),
        res_col.count_documents(cf),
        res_col.count_documents({"registered": True, **cf}),
        res_col.count_documents({"alive": True, **cf}),
        res_col.count_documents({"newly_registered": True, **cf}),
        res_col.count_documents({"risk_indicators": {"$exists": True, "$ne": []}, **cf}),
        res_col.count_documents({
            "$or": [{"registered": True}, {"alive": True}],
            "acknowledged": {"$ne": True}, **cf,
        }),
        res_col.count_documents({"parked": True, **cf}),
    )
    return {
        "domains": domains,
        "total_findings": findings,
        "registered": registered,
        "alive": alive,
        "newly_registered": newly,
        "at_risk": at_risk,
        "unacknowledged": unacked,
        "parked": parked,
    }
