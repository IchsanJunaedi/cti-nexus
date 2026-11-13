from datetime import datetime
from app.database import get_database
from app.config import AUDIT_COLLECTION


def _col():
    return get_database()[AUDIT_COLLECTION]


async def write_audit(
    user: str,
    action: str,
    target_id: str = "",
    detail: dict | None = None,
    ip: str = "",
) -> None:
    await _col().insert_one({
        "user":      user,
        "action":    action,
        "target_id": target_id,
        "detail":    detail or {},
        "ip":        ip,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def get_audit_log(
    page: int = 1,
    page_size: int = 50,
    user: str | None = None,
    action: str | None = None,
) -> tuple[list[dict], int]:
    col = _col()
    query: dict = {}
    if user:
        query["user"] = {"$regex": user, "$options": "i"}
    if action:
        query["action"] = {"$regex": action, "$options": "i"}
    skip   = (page - 1) * page_size
    cursor = col.find(query, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(page_size)
    import asyncio
    docs, total = await asyncio.gather(
        cursor.to_list(length=page_size),
        col.count_documents(query),
    )
    return docs, total
