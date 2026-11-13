import asyncio
from datetime import datetime, timezone
from bson import ObjectId

from app.ta_database import get_ta_database
from app.config import RFI_COLLECTION


def _col():
    return get_ta_database()[RFI_COLLECTION]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _serialize(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    return doc


def _client_filter(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


async def list_rfis(
    status: str | None = None,
    page: int = 1,
    page_size: int = 20,
    client_id: str = "default",
) -> tuple[list[dict], int]:
    col = _col()
    query: dict = {**_client_filter(client_id)}
    if status:
        query["status"] = status

    skip = (page - 1) * page_size
    cursor = col.find(query).sort("created_at", -1).skip(skip).limit(page_size)
    docs, total = await asyncio.gather(
        cursor.to_list(length=page_size),
        col.count_documents(query),
    )
    return [_serialize(d) for d in docs], total


async def get_rfi(rfi_id: str, client_id: str = "default") -> dict | None:
    col = _col()
    doc = await col.find_one({"_id": ObjectId(rfi_id), **_client_filter(client_id)})
    return _serialize(doc) if doc else None


async def create_rfi(data: dict, client_id: str = "default") -> dict:
    col = _col()
    now = _now()
    doc = {**data, "client_id": client_id, "created_at": now, "updated_at": now}
    doc.setdefault("status", "open")
    doc.setdefault("response", "")
    result = await col.insert_one(doc)
    doc["id"] = str(result.inserted_id)
    doc.pop("_id", None)
    return doc


async def update_rfi(rfi_id: str, updates: dict) -> dict | None:
    col = _col()
    updates["updated_at"] = _now()
    result = await col.find_one_and_update(
        {"_id": ObjectId(rfi_id)},
        {"$set": updates},
        return_document=True,
    )
    return _serialize(result) if result else None


async def delete_rfi(rfi_id: str) -> bool:
    col = _col()
    result = await col.delete_one({"_id": ObjectId(rfi_id)})
    return result.deleted_count > 0
