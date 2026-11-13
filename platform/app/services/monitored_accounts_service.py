from datetime import datetime, timezone
from app.database import get_database
from app.config import MONITORED_ACCOUNTS_COLLECTION


def _col():
    return get_database()[MONITORED_ACCOUNTS_COLLECTION]


async def list_accounts() -> list[dict]:
    col = _col()
    await col.create_index("username", unique=True)
    docs = await col.find({}).sort("username", 1).to_list(1000)
    for d in docs:
        d["_id"] = str(d["_id"])
        if isinstance(d.get("added_at"), datetime):
            d["added_at"] = d["added_at"].isoformat()
    return docs


async def add_account(username: str, display_name: str = "", notes: str = "") -> dict:
    col = _col()
    await col.create_index("username", unique=True)
    username = username.lstrip("@").strip().lower()
    existing = await col.find_one({"username": username})
    if existing:
        raise ValueError(f"@{username} already monitored")
    doc = {
        "username": username,
        "display_name": display_name.strip(),
        "notes": notes.strip(),
        "active": True,
        "added_at": datetime.now(timezone.utc),
    }
    await col.insert_one(doc)
    doc["_id"] = str(doc["_id"])
    if isinstance(doc.get("added_at"), datetime):
        doc["added_at"] = doc["added_at"].isoformat()
    return doc


async def remove_account(username: str) -> bool:
    col = _col()
    username = username.lstrip("@").strip().lower()
    result = await col.delete_one({"username": username})
    return result.deleted_count > 0


async def toggle_account(username: str, active: bool) -> bool:
    col = _col()
    username = username.lstrip("@").strip().lower()
    result = await col.update_one({"username": username}, {"$set": {"active": active}})
    return result.modified_count > 0
