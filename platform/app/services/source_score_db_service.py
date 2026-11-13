import asyncio
from datetime import date
from bson import ObjectId
from app.database import get_ta_database
from app.config import SOURCE_SCORES_COLLECTION

# Admiralty system:
#   Reliability  A–F  (source trustworthiness)
#   Credibility  1–6  (information accuracy, corroboration)
#   Combined code e.g. "B2"

RELIABILITY_LABELS = {
    "A": "Completely reliable",
    "B": "Usually reliable",
    "C": "Fairly reliable",
    "D": "Not usually reliable",
    "E": "Unreliable",
    "F": "Cannot be judged",
}

CREDIBILITY_LABELS = {
    "1": "Confirmed by other sources",
    "2": "Probably true",
    "3": "Possibly true",
    "4": "Doubtful",
    "5": "Improbable",
    "6": "Cannot be judged",
}

_SORT_FIELDS = {"source_name", "analyst_name", "reliability_grade", "credibility_code", "added_date", "last_updated"}

DEFAULT_TEMPLATE_CLIENT_ID = "default"  # shared baseline rating library, copied into new clients on request


def _col():
    return get_ta_database()[SOURCE_SCORES_COLLECTION]


def _serialize(doc: dict) -> dict:
    doc["_id"] = str(doc["_id"])
    return doc


async def list_entries(
    client_id: str,
    search: str | None = None,
    grade: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "source_name",
    sort_dir: str = "asc",
) -> tuple[list[dict], int]:
    col = _col()
    query: dict = {"client_id": client_id}
    if search:
        query["$or"] = [
            {"source_name": {"$regex": search, "$options": "i"}},
            {"analyst_name": {"$regex": search, "$options": "i"}},
            {"notes": {"$regex": search, "$options": "i"}},
        ]
    if grade:
        query["reliability_grade"] = grade.upper()

    if sort_by not in _SORT_FIELDS:
        sort_by = "source_name"
    mongo_dir = 1 if sort_dir == "asc" else -1

    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, mongo_dir).skip(skip).limit(page_size)
    docs, total = await asyncio.gather(
        cursor.to_list(length=page_size),
        col.count_documents(query),
    )
    return [_serialize(d) for d in docs], total


async def add_entry(
    client_id: str,
    source_name: str,
    analyst_name: str,
    reliability_grade: str,
    credibility_code: str,
    notes: str,
) -> dict:
    col = _col()
    # Case-insensitive duplicate check on source name, scoped to this client
    if await col.find_one({"client_id": client_id, "source_name": {"$regex": f"^{source_name}$", "$options": "i"}}):
        return {"success": False, "reason": "duplicate"}

    today = str(date.today())
    doc = {
        "client_id":         client_id,
        "source_name":       source_name,
        "analyst_name":      analyst_name,
        "reliability_grade": reliability_grade.upper(),
        "credibility_code":  credibility_code,
        "admiralty_code":    f"{reliability_grade.upper()}{credibility_code}",
        "notes":             notes,
        "added_date":        today,
        "last_updated":      today,
    }
    result = await col.insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    return {"success": True, "entry": doc}


async def update_entry(
    entry_id: str,
    client_id: str,
    reliability_grade: str,
    credibility_code: str,
    notes: str,
) -> dict:
    col = _col()
    update = {
        "$set": {
            "reliability_grade": reliability_grade.upper(),
            "credibility_code":  credibility_code,
            "admiralty_code":    f"{reliability_grade.upper()}{credibility_code}",
            "notes":             notes,
            "last_updated":      str(date.today()),
        }
    }
    result = await col.update_one({"_id": ObjectId(entry_id), "client_id": client_id}, update)
    return {"success": result.matched_count > 0}


async def delete_entry(entry_id: str, client_id: str) -> dict:
    col = _col()
    result = await col.delete_one({"_id": ObjectId(entry_id), "client_id": client_id})
    return {"success": result.deleted_count > 0}


async def get_stats(client_id: str) -> dict:
    col = _col()
    query = {"client_id": client_id}
    total_task = col.count_documents(query)
    by_grade_task = col.aggregate([
        {"$match":  query},
        {"$group": {"_id": "$reliability_grade", "count": {"$sum": 1}}},
        {"$sort":  {"_id": 1}},
    ]).to_list(10)

    total, by_grade = await asyncio.gather(total_task, by_grade_task)
    return {
        "total": total,
        "by_grade": [{"grade": r["_id"], "count": r["count"]} for r in by_grade],
    }


async def import_default_entries(client_id: str, analyst_name: str) -> dict:
    """Copy DEFAULT_TEMPLATE_CLIENT_ID entries into client_id, skipping sources already graded there."""
    col = _col()
    existing_docs = await col.find({"client_id": client_id}, {"source_name": 1, "_id": 0}).to_list(None)
    existing = {d["source_name"].lower() for d in existing_docs}

    template_docs = await col.find({"client_id": DEFAULT_TEMPLATE_CLIENT_ID}).to_list(None)
    today = str(date.today())
    new_docs = []
    for d in template_docs:
        if d["source_name"].lower() in existing:
            continue
        new_docs.append({
            "client_id":         client_id,
            "source_name":       d["source_name"],
            "analyst_name":      analyst_name,
            "reliability_grade": d["reliability_grade"],
            "credibility_code":  d["credibility_code"],
            "admiralty_code":    d["admiralty_code"],
            "notes":             d["notes"],
            "added_date":        today,
            "last_updated":      today,
        })

    if new_docs:
        await col.insert_many(new_docs)
    return {"success": True, "imported": len(new_docs), "skipped": len(template_docs) - len(new_docs)}
