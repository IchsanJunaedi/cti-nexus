"""In-app notification feed — generic, producer-agnostic.

Any service can call `create_notification()`. The UI shows unread items in a
modal after login and in a header bell. Read state is tracked per user.
"""
from datetime import datetime, timezone
from typing import Any

from app.database import get_database

_COLL = "notifications"
_MAX_LIST = 100

_indexed = False


def _col():
    return get_database()[_COLL]


async def _ensure_indexes() -> None:
    global _indexed
    if _indexed:
        return
    col = _col()
    await col.create_index([("dedupe_key", 1)], unique=True, sparse=True)
    await col.create_index([("created_at", -1)])
    _indexed = True


async def create_notification(
    *,
    type: str,
    title: str,
    body: str = "",
    severity: str = "info",
    data: dict[str, Any] | None = None,
    action: dict[str, str] | None = None,
    popup: bool = True,
    dedupe_key: str | None = None,
) -> bool:
    """Insert a notification. Returns False if dedupe_key already exists.

    popup  -- show in the post-login modal (otherwise bell only)
    action -- optional UI link, e.g. {"label": "Open ATT&CK DB", "tab": "intelligence"}
    """
    await _ensure_indexes()
    doc: dict[str, Any] = {
        "type": type,
        "title": title,
        "body": body,
        "severity": severity,
        "data": data or {},
        "action": action,
        "popup": popup,
        "read_by": [],
        "created_at": datetime.now(timezone.utc),
    }
    if dedupe_key:
        doc["dedupe_key"] = dedupe_key
    from pymongo.errors import DuplicateKeyError
    try:
        await _col().insert_one(doc)
    except DuplicateKeyError:
        return False
    return True


def _serialize(d: dict, username: str) -> dict:
    return {
        "id": str(d["_id"]),
        "type": d.get("type", ""),
        "title": d.get("title", ""),
        "body": d.get("body", ""),
        "severity": d.get("severity", "info"),
        "data": d.get("data", {}),
        "action": d.get("action"),
        "popup": d.get("popup", True),
        "created_at": d["created_at"].isoformat(),
        "read": username in d.get("read_by", []),
    }


async def list_notifications(username: str, unread_only: bool = False) -> list[dict]:
    filt: dict = {"read_by": {"$ne": username}} if unread_only else {}
    docs = await _col().find(filt).sort("created_at", -1).to_list(length=_MAX_LIST)
    return [_serialize(d, username) for d in docs]


async def mark_read(username: str, notif_id: str) -> bool:
    from bson import ObjectId
    from bson.errors import InvalidId
    try:
        oid = ObjectId(notif_id)
    except InvalidId:
        return False
    res = await _col().update_one({"_id": oid}, {"$addToSet": {"read_by": username}})
    return res.matched_count > 0


async def mark_all_read(username: str) -> int:
    res = await _col().update_many(
        {"read_by": {"$ne": username}}, {"$addToSet": {"read_by": username}}
    )
    return res.modified_count
