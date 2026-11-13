import uuid
from datetime import datetime, timezone
from bson import ObjectId
from app.database import get_database
from app.config import SCENARIOS_COLLECTION


def _col():
    return get_database()[SCENARIOS_COLLECTION]


def _client_filter(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def ensure_indexes() -> None:
    col = _col()
    await col.create_index([("client_id", 1), ("diagram_id", 1)], background=True)
    await col.create_index([("client_id", 1), ("owner", 1)], background=True)
    await col.create_index("diagram_id", background=True)


async def list_scenarios(client_id: str, diagram_id: str | None = None) -> list[dict]:
    q = _client_filter(client_id)
    if diagram_id:
        q["diagram_id"] = diagram_id
    docs = await _col().find(q).sort("updated_at", -1).to_list(500)
    for d in docs:
        d["step_count"] = len(d.get("steps", []))
    return docs


async def get_scenario(scenario_id: str, client_id: str) -> dict | None:
    q = {"_id": ObjectId(scenario_id), **_client_filter(client_id)}
    return await _col().find_one(q)


async def create_scenario(data: dict, client_id: str, owner: str) -> dict:
    now = _now()
    steps = [
        {
            "id": uuid.uuid4().hex,
            "order": i,
            "note": s.get("note", ""),
            "node_ids": s.get("node_ids", []),
            "edge_ids": s.get("edge_ids", []),
            "created_at": now,
        }
        for i, s in enumerate(data.get("steps", []))
    ]
    doc = {
        "name": data["name"],
        "description": data.get("description", ""),
        "diagram_id": data["diagram_id"],
        "client_id": client_id,
        "owner": owner,
        "steps": steps,
        "version": 1,
        "created_at": now,
        "updated_at": now,
    }
    result = await _col().insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


async def update_scenario(scenario_id: str, client_id: str, patch: dict) -> dict | None:
    patch["updated_at"] = _now()
    return await _col().find_one_and_update(
        {"_id": ObjectId(scenario_id), **_client_filter(client_id)},
        {"$set": patch, "$inc": {"version": 1}},
        return_document=True,
    )


async def replace_steps(scenario_id: str, client_id: str, steps_in: list[dict]) -> dict | None:
    now = _now()
    steps = [
        {
            "id": s.get("id") or uuid.uuid4().hex,
            "order": i,
            "note": s.get("note", ""),
            "node_ids": s.get("node_ids", []),
            "edge_ids": s.get("edge_ids", []),
            "created_at": s.get("created_at") or now,
        }
        for i, s in enumerate(steps_in)
    ]
    return await _col().find_one_and_update(
        {"_id": ObjectId(scenario_id), **_client_filter(client_id)},
        {"$set": {"steps": steps, "updated_at": now}, "$inc": {"version": 1}},
        return_document=True,
    )


async def delete_scenario(scenario_id: str, client_id: str, username: str, privileged: bool) -> bool:
    q = {"_id": ObjectId(scenario_id), **_client_filter(client_id)}
    if not privileged:
        q["owner"] = username
    res = await _col().delete_one(q)
    return res.deleted_count > 0
