import asyncio
import re
from datetime import date
from bson import ObjectId
from app.database import get_ta_database
from app.database import get_database
from app.config import TA_GROUPS_COLLECTION, TA_WHITELIST_COLLECTION, TA_WATCHLIST_COLLECTION, COLLECTION_NAME as NEWS_COLLECTION

# Generic filler tokens stripped when clustering near-duplicate actor names
# (e.g. "Everest", "Everest Group", "Everest Ransomware Group" all normalize to "everest").
# Real distinguishing tokens (e.g. "Sudan" in "Anonymous Sudan") are never in this set,
# so unrelated actors never collide.
_GENERIC_NAME_TOKENS = {
    "ransomware", "group", "gang", "team", "the", "cybercrime", "criminal",
    "collective", "organization", "org", "actor", "apt",
}


def normalize_actor_core(name: str) -> str:
    tokens = re.findall(r"[a-z0-9]+", str(name).lower())
    core = [t for t in tokens if t not in _GENERIC_NAME_TOKENS]
    return " ".join(core) if core else " ".join(tokens)


def _groups():
    return get_ta_database()[TA_GROUPS_COLLECTION]


def _whitelist():
    return get_ta_database()[TA_WHITELIST_COLLECTION]


def _ta_watchlist():
    return get_ta_database()[TA_WATCHLIST_COLLECTION]


_SORT_FIELDS = {"name", "added_date", "source"}


async def list_groups(
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "name",
    sort_dir: str = "asc",
) -> tuple[list[dict], int]:
    col = _groups()
    query: dict = {}
    if search:
        query["name"] = {"$regex": search, "$options": "i"}

    if sort_by not in _SORT_FIELDS:
        sort_by = "name"
    mongo_dir = 1 if sort_dir == "asc" else -1

    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, mongo_dir).skip(skip).limit(page_size)
    groups, total = await asyncio.gather(
        cursor.to_list(length=page_size),
        col.count_documents(query),
    )
    return groups, total


async def add_group(name: str) -> dict:
    # Check whitelist (stored as lowercase)
    wl = _whitelist()
    if await wl.find_one({"name": name.lower()}):
        return {"success": False, "reason": "whitelisted"}

    # Check for exact duplicate (case-insensitive)
    col = _groups()
    if await col.find_one({"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}}):
        return {"success": False, "reason": "duplicate"}

    # Check for near-duplicate (e.g. "Everest" vs "Everest Ransomware Group") —
    # fold into the existing group's aliases instead of creating a second entry.
    core = normalize_actor_core(name)
    if core:
        async for existing in col.find({}, {"name": 1, "aliases": 1}):
            variants = [existing["name"]] + existing.get("aliases", [])
            if any(normalize_actor_core(v) == core for v in variants):
                await col.update_one(
                    {"_id": existing["_id"]},
                    {"$addToSet": {"aliases": name}},
                )
                return {"success": True, "reason": "merged_as_alias", "canonical": existing["name"]}

    doc = {"name": name, "added_date": str(date.today()), "source": "manual", "aliases": []}
    await col.insert_one(doc)
    return {"success": True}


async def merge_group(source_id: str, target_id: str) -> dict:
    """Merge source group into target: target keeps canonical name, source name+aliases
    fold into target.aliases, source doc is deleted, and existing news article
    threat_actors arrays are rewritten so historical stats stay consistent."""
    col = _groups()
    if source_id == target_id:
        return {"success": False, "reason": "same_group"}

    source = await col.find_one({"_id": ObjectId(source_id)})
    target = await col.find_one({"_id": ObjectId(target_id)})
    if not source or not target:
        return {"success": False, "reason": "not_found"}

    folded_names = [source["name"]] + source.get("aliases", [])
    new_aliases = list(dict.fromkeys(target.get("aliases", []) + folded_names))
    new_aliases = [a for a in new_aliases if a.lower() != target["name"].lower()]

    await col.update_one({"_id": target["_id"]}, {"$set": {"aliases": new_aliases}})
    await col.delete_one({"_id": source["_id"]})

    news_col = get_database()[NEWS_COLLECTION]
    updated = 0
    for old_name in folded_names:
        if old_name.lower() == target["name"].lower():
            continue
        result = await news_col.update_many(
            {"threat_actors": {"$regex": f"^{re.escape(old_name)}$", "$options": "i"}},
            {"$addToSet": {"threat_actors": target["name"]}},
        )
        updated += result.modified_count
        await news_col.update_many(
            {},
            {"$pull": {"threat_actors": {"$regex": f"^{re.escape(old_name)}$", "$options": "i"}}},
        )

    return {"success": True, "canonical": target["name"], "aliases_merged": folded_names, "articles_updated": updated}


async def list_aliases(
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[dict], int]:
    """Flatten groups.aliases into one row per alias, paired with its canonical group —
    lets an analyst check whether a newly-seen actor name is already tracked under
    a different canonical name before adding it as a fresh entry."""
    col = _groups()

    match_stage: dict = {"aliases.0": {"$exists": True}}
    pipeline: list[dict] = [
        {"$match": match_stage},
        {"$unwind": "$aliases"},
        {"$project": {
            "_id": 0,
            "alias": "$aliases",
            "canonical_id": {"$toString": "$_id"},
            "canonical_name": "$name",
        }},
    ]
    if search:
        pipeline.append({"$match": {"$or": [
            {"alias": {"$regex": search, "$options": "i"}},
            {"canonical_name": {"$regex": search, "$options": "i"}},
        ]}})
    pipeline.append({"$sort": {"alias": 1}})

    count_pipeline = pipeline + [{"$count": "total"}]
    skip = (page - 1) * page_size
    page_pipeline = pipeline + [{"$skip": skip}, {"$limit": page_size}]

    items_task = col.aggregate(page_pipeline).to_list(page_size)
    count_task = col.aggregate(count_pipeline).to_list(1)
    items, count_result = await asyncio.gather(items_task, count_task)
    total = count_result[0]["total"] if count_result else 0
    return items, total


async def get_ta_stats() -> dict:
    col = _groups()
    wl  = _whitelist()

    total_task    = col.count_documents({})
    wl_task       = wl.count_documents({})
    by_source_task = col.aggregate([
        {"$group": {"_id": {"$ifNull": ["$source", "unknown"]}, "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
    ]).to_list(20)
    all_names_task = col.distinct("name")

    total, wl_total, by_source, all_names = await asyncio.gather(
        total_task, wl_task, by_source_task, all_names_task,
    )

    manual_count = next((r["count"] for r in by_source if r["_id"] == "manual"), 0)

    # Cross-reference: which tracked groups appear in news articles?
    news_col = get_database()[NEWS_COLLECTION]
    group_names_lower = {n.lower() for n in all_names if n}

    top_news_actors = await news_col.aggregate([
        {"$unwind": "$threat_actors"},
        {"$match":  {"threat_actors": {"$ne": ""}}},
        {"$group":  {"_id": "$threat_actors", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  500},
    ]).to_list(500)

    in_news = [
        {"name": r["_id"], "count": r["count"]}
        for r in top_news_actors
        if r["_id"] and r["_id"].lower() in group_names_lower
    ]

    return {
        "total_groups":     total,
        "total_whitelisted": wl_total,
        "manual_count":     manual_count,
        "in_news_count":    len(in_news),
        "by_source":        [{"name": r["_id"], "count": r["count"]} for r in by_source],
        "top_in_news":      in_news[:10],
    }


async def list_whitelist(
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "name",
    sort_dir: str = "asc",
) -> tuple[list[dict], int]:
    col = _whitelist()
    query: dict = {}
    if search:
        query["name"] = {"$regex": search, "$options": "i"}

    if sort_by not in {"name", "added_date"}:
        sort_by = "name"
    mongo_dir = 1 if sort_dir == "asc" else -1

    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, mongo_dir).skip(skip).limit(page_size)
    items, total = await asyncio.gather(
        cursor.to_list(length=page_size),
        col.count_documents(query),
    )
    return items, total


async def remove_from_whitelist(name: str) -> dict:
    wl = _whitelist()
    result = await wl.delete_one({"name": name.lower()})
    return {"success": result.deleted_count > 0}


async def list_ta_watchlist(
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "name",
    sort_dir: str = "asc",
    client_id: str = "default",
) -> tuple[list[dict], int]:
    col = _ta_watchlist()
    query: dict = {"client_id": client_id}
    if search:
        query["name"] = {"$regex": search, "$options": "i"}
    if sort_by not in {"name", "added_date"}:
        sort_by = "name"
    mongo_dir = 1 if sort_dir == "asc" else -1
    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, mongo_dir).skip(skip).limit(page_size)
    items, total = await asyncio.gather(cursor.to_list(length=page_size), col.count_documents(query))
    return items, total


async def get_watchlist_names(client_id: str = "default") -> list[str]:
    col = _ta_watchlist()
    docs = await col.find({"client_id": client_id}, {"name": 1, "_id": 0}).to_list(10000)
    return [d["name"] for d in docs]


async def add_to_ta_watchlist(name: str, client_id: str = "default") -> dict:
    col = _ta_watchlist()
    if await col.find_one({"name": {"$regex": f"^{name}$", "$options": "i"}, "client_id": client_id}):
        return {"success": False, "reason": "already_watched"}
    await col.insert_one({"name": name, "added_date": str(date.today()), "client_id": client_id})
    return {"success": True}


async def remove_from_ta_watchlist(name: str, client_id: str = "default") -> dict:
    col = _ta_watchlist()
    result = await col.delete_one({"name": {"$regex": f"^{name}$", "$options": "i"}, "client_id": client_id})
    return {"success": result.deleted_count > 0}


async def delete_group(group_id: str, group_name: str) -> dict:
    # Add to whitelist (lowercase, upsert so no duplicates)
    wl = _whitelist()
    await wl.update_one(
        {"name": group_name.lower()},
        {"$setOnInsert": {"name": group_name.lower(), "added_date": str(date.today())}},
        upsert=True,
    )

    # Delete from groups collection
    col = _groups()
    await col.delete_one({"_id": ObjectId(group_id)})
    return {"success": True}
