from datetime import datetime, timezone
from bson import ObjectId
from app.database import get_database
from app.config import DIAGRAMS_COLLECTION


def _col():
    return get_database()[DIAGRAMS_COLLECTION]


def _client_filter(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def ensure_indexes() -> None:
    col = _col()
    await col.create_index([("client_id", 1), ("owner", 1)], background=True)
    await col.create_index([("client_id", 1), ("updated_at", -1)], background=True)


async def list_diagrams(client_id: str, username: str, privileged: bool) -> list[dict]:
    q = _client_filter(client_id)
    if not privileged:
        q["owner"] = username
    return await _col().find(q).sort("updated_at", -1).to_list(500)


async def get_diagram(diagram_id: str, client_id: str) -> dict | None:
    q = {"_id": ObjectId(diagram_id), **_client_filter(client_id)}
    return await _col().find_one(q)


async def create_diagram(data: dict, client_id: str, owner: str) -> dict:
    now = _now()
    doc = {
        "name": data.get("name", "Untitled"),
        "doc": data.get("doc") or {"nodes": [], "edges": [], "zones": []},
        "view": data.get("view") or {"x": 0, "y": 0, "k": 1},
        "client_id": client_id,
        "owner": owner,
        "created_at": now,
        "updated_at": now,
    }
    result = await _col().insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


async def save_diagram(diagram_id: str, client_id: str, patch: dict) -> dict | None:
    set_patch = {k: v for k, v in patch.items() if v is not None}
    set_patch["updated_at"] = _now()
    return await _col().find_one_and_update(
        {"_id": ObjectId(diagram_id), **_client_filter(client_id)},
        {"$set": set_patch},
        return_document=True,
    )


async def delete_diagram(diagram_id: str, client_id: str, username: str, privileged: bool) -> bool:
    q = {"_id": ObjectId(diagram_id), **_client_filter(client_id)}
    if not privileged:
        q["owner"] = username
    res = await _col().delete_one(q)
    return res.deleted_count > 0
