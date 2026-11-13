import re
import time
from bson import ObjectId
from datetime import datetime, timezone

from app.database import get_database
from app.config import IOC_ALLOWLIST_COLLECTION, IOC_COLLECTION

_VALID_TYPES = {"domain", "ip"}

_RE_EXTRACT_DOMAIN = re.compile(r'^(?:https?://)?([^/:?\s]+)')

_allowlist_cache: dict | None = None
_allowlist_cache_ts: float = 0.0
_CACHE_TTL = 300.0


def _col():
    return get_database()[IOC_ALLOWLIST_COLLECTION]


def _ioc_col():
    return get_database()[IOC_COLLECTION]


def _extract_url_domain(url: str) -> str:
    m = _RE_EXTRACT_DOMAIN.match(url.lower().strip())
    return m.group(1) if m else ""


def _extract_email_domain(email: str) -> str:
    parts = re.split(r'[@\[\(]at[\)\]]', email.lower())
    if len(parts) == 2:
        return parts[1].strip().lstrip('[').rstrip(']').strip()
    if '@' in email:
        return email.split('@', 1)[1].lower()
    return ""


async def get_allowlist_sets(force: bool = False) -> dict:
    global _allowlist_cache, _allowlist_cache_ts
    now = time.monotonic()
    if not force and _allowlist_cache is not None and (now - _allowlist_cache_ts) < _CACHE_TTL:
        return _allowlist_cache

    docs = await _col().find({}).to_list(2000)
    domains: set[str] = set()
    ips: set[str] = set()
    for d in docs:
        if d.get("type") == "domain":
            domains.add(d["value"].lower())
        elif d.get("type") == "ip":
            ips.add(d["value"])

    _allowlist_cache = {"domains": domains, "ips": ips}
    _allowlist_cache_ts = now
    return _allowlist_cache


async def list_allowlist() -> list[dict]:
    docs = await _col().find({}).sort("added_at", -1).to_list(2000)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


async def add_allowlist_entry(entry_type: str, value: str, user: str) -> dict:
    if entry_type not in _VALID_TYPES:
        raise ValueError(f"type must be one of {_VALID_TYPES}")
    value = value.lower().strip()

    existing = await _col().find_one({"type": entry_type, "value": value})
    if existing:
        existing["_id"] = str(existing["_id"])
        existing["deleted_iocs"] = 0
        return existing

    doc = {
        "type": entry_type,
        "value": value,
        "added_by": user,
        "added_at": datetime.now(timezone.utc).isoformat(),
    }
    result = await _col().insert_one(doc)
    doc["_id"] = str(result.inserted_id)

    # invalidate cache
    global _allowlist_cache
    _allowlist_cache = None

    deleted = await _sweep_delete_matching(entry_type, value)
    doc["deleted_iocs"] = deleted
    return doc


async def _sweep_delete_matching(entry_type: str, value: str) -> int:
    if entry_type == "domain":
        to_delete = []

        cursor = _ioc_col().find({"type": "domain"}, {"_id": 1, "value": 1})
        async for doc in cursor:
            domain = doc.get("value", "").lower().strip()
            if domain == value or domain.endswith("." + value):
                to_delete.append(doc["_id"])

        cursor = _ioc_col().find(
            {"type": {"$in": ["url", "url_with_path"]}},
            {"_id": 1, "value": 1},
        )
        async for doc in cursor:
            domain = _extract_url_domain(doc.get("value", ""))
            if domain == value or domain.endswith("." + value):
                to_delete.append(doc["_id"])

        cursor = _ioc_col().find({"type": "email"}, {"_id": 1, "value": 1})
        async for doc in cursor:
            domain = _extract_email_domain(doc.get("value", ""))
            if domain == value:
                to_delete.append(doc["_id"])
    elif entry_type == "ip":
        result = await _ioc_col().delete_many({"type": "ip", "value": value})
        return result.deleted_count
    else:
        return 0

    if not to_delete:
        return 0
    result = await _ioc_col().delete_many({"_id": {"$in": to_delete}})
    return result.deleted_count


async def remove_allowlist_entry(entry_id: str) -> bool:
    try:
        oid = ObjectId(entry_id)
    except Exception:
        return False
    result = await _col().delete_one({"_id": oid})
    if result.deleted_count:
        global _allowlist_cache
        _allowlist_cache = None
    return result.deleted_count > 0
