import asyncio
import re
import time
from collections import defaultdict
from app.database import get_database
from app.config import COLLECTION_NAME
from app.country_groups import normalize_country


def _collection():
    return get_database()[COLLECTION_NAME]


async def get_articles(
    page: int = 1,
    page_size: int = 20,
    posted_on_start: str | None = None,
    posted_on_end: str | None = None,
    industries: list[str] | None = None,
    countries: list[str] | None = None,
    sources: list[str] | None = None,
    news_types: list[str] | None = None,
    regions: list[str] | None = None,
    threat_actors: list[str] | None = None,
    search: str | None = None,
    victim_countries: list[str] | None = None,
    actor_countries: list[str] | None = None,
    title_keywords: list[str] | None = None,
    cve_ids: list[str] | None = None,
) -> tuple[list[dict], int]:
    col = _collection()
    query: dict = {}

    if posted_on_start or posted_on_end:
        date_filter = {}
        if posted_on_start:
            date_filter["$gte"] = posted_on_start
        if posted_on_end:
            date_filter["$lte"] = posted_on_end
        query["posted_on"] = date_filter

    if industries:
        query["impacted_industries"] = {"$in": industries}

    if countries:
        query["mentioned_countries"] = {"$in": countries}

    if victim_countries:
        query["victim_countries"] = {"$in": victim_countries}

    if actor_countries:
        query["actor_countries"] = {"$in": actor_countries}

    if sources:
        query["source"] = {"$in": sources}

    if news_types:
        query["news_type"] = {"$in": news_types}

    if threat_actors:
        query["threat_actors"] = {"$in": [re.compile(f"^{re.escape(t)}$", re.IGNORECASE) for t in threat_actors]}

    keyword_or = [{"title": {"$regex": re.escape(kw), "$options": "i"}} for kw in title_keywords] if title_keywords else []
    if cve_ids:
        keyword_or.append({"iocs.cves": {"$in": cve_ids}})
    keyword_or = keyword_or or None
    search_or  = [{"title": {"$regex": search, "$options": "i"}}, {"source": {"$regex": search, "$options": "i"}}] if search else None

    if keyword_or and search_or:
        query["$and"] = [{"$or": keyword_or}, {"$or": search_or}]
    elif keyword_or:
        query["$or"] = keyword_or
    elif search_or:
        query["$or"] = search_or

    if regions:
        # `region` field only exists on articles saved after the nlp.py region-tag fix.
        # Older docs never had news_type clobbered by a category label at save time
        # (fix wasn't needed yet for them), so news_type still holds the true region —
        # fall back to it when region is absent.
        region_clause = {"$or": [
            {"region": {"$in": regions}},
            {"region": {"$exists": False}, "news_type": {"$in": regions}},
        ]}
        if "$or" in query:
            query["$and"] = query.get("$and", []) + [{"$or": query.pop("$or")}, region_clause]
        elif "$and" in query:
            query["$and"].append(region_clause)
        else:
            query.update(region_clause)

    skip = (page - 1) * page_size

    cursor = col.find(query).sort("posted_on", -1).skip(skip).limit(page_size)
    count_task = col.count_documents(query)

    articles, total = await asyncio.gather(cursor.to_list(length=page_size), count_task)
    return articles, total


async def get_filter_options() -> dict:
    col = _collection()

    industries_task    = col.distinct("impacted_industries")
    countries_task     = col.distinct("mentioned_countries")
    sources_task       = col.distinct("source")
    news_types_task    = col.distinct("news_type")
    threat_actors_task = col.distinct("threat_actors")
    date_range_task    = col.aggregate([
        {"$group": {
            "_id": None,
            "min_date": {"$min": "$posted_on"},
            "max_date": {"$max": "$posted_on"},
        }}
    ]).to_list(length=1)

    industries, countries, sources, news_types, threat_actors, date_agg = await asyncio.gather(
        industries_task, countries_task, sources_task, news_types_task, threat_actors_task, date_range_task
    )

    industries    = sorted([i for i in industries    if i])
    countries     = sorted([c for c in countries     if c])
    sources       = sorted([s for s in sources       if s])
    news_types    = sorted([n for n in news_types    if n])
    threat_actors = sorted([t for t in threat_actors if t])

    date_range = {"min": "", "max": ""}
    if date_agg:
        date_range = {
            "min": date_agg[0].get("min_date", ""),
            "max": date_agg[0].get("max_date", ""),
        }

    return {
        "industries":    industries,
        "countries":     countries,
        "sources":       sources,
        "news_types":    news_types,
        "threat_actors": threat_actors,
        "date_range":    date_range,
    }


# ── Dashboard TTL cache ────────────────────────────────────
_dashboard_cache: dict[str, tuple[dict, float]] = {}
_CACHE_TTL = 900  # 15 minutes


async def get_dashboard_stats(
    posted_on_start: str | None = None,
    posted_on_end: str | None = None,
) -> dict:
    cache_key = f"{posted_on_start or ''}|{posted_on_end or ''}"
    now = time.monotonic()
    if cache_key in _dashboard_cache:
        cached_data, cached_at = _dashboard_cache[cache_key]
        if now - cached_at < _CACHE_TTL:
            return cached_data

    result = await _fetch_dashboard_stats(posted_on_start, posted_on_end)
    _dashboard_cache[cache_key] = (result, now)
    return result


async def _fetch_dashboard_stats(
    posted_on_start: str | None = None,
    posted_on_end: str | None = None,
) -> dict:
    col = _collection()

    # Build base date match (applied to every pipeline)
    date_filter: dict = {}
    if posted_on_start:
        date_filter["$gte"] = posted_on_start
    if posted_on_end:
        date_filter["$lte"] = posted_on_end
    base_match: dict = {"posted_on": date_filter} if date_filter else {}

    def prepend_match(pipeline: list) -> list:
        return ([{"$match": base_match}] + pipeline) if base_match else pipeline

    total_task         = col.count_documents(base_match)
    all_sources_task   = col.distinct("source",             base_match)
    all_countries_task = col.distinct("mentioned_countries", base_match)
    all_actors_task    = col.distinct("threat_actors",       base_match)

    top_countries_task  = col.aggregate(prepend_match([
        {"$unwind": "$mentioned_countries"},
        {"$match":  {"mentioned_countries": {"$ne": ""}}},
        {"$group":  {"_id": "$mentioned_countries", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  50},
    ])).to_list(length=50)

    top_sources_task    = col.aggregate(prepend_match([
        {"$match": {"source": {"$ne": ""}}},
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
        {"$limit": 10},
    ])).to_list(length=10)

    top_actors_task     = col.aggregate(prepend_match([
        {"$unwind": "$threat_actors"},
        {"$match":  {"threat_actors": {"$ne": ""}}},
        {"$group":  {"_id": "$threat_actors", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  10},
    ])).to_list(length=10)

    top_industries_task = col.aggregate(prepend_match([
        {"$unwind": "$impacted_industries"},
        {"$match":  {"impacted_industries": {"$ne": ""}}},
        {"$group":  {"_id": "$impacted_industries", "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  10},
    ])).to_list(length=10)

    top_ttps_task       = col.aggregate(prepend_match([
        {"$unwind": "$ttps"},
        {"$group":  {"_id": {"id": "$ttps.id", "name": "$ttps.name"}, "count": {"$sum": 1}}},
        {"$sort":   {"count": -1}},
        {"$limit":  10},
    ])).to_list(length=10)

    by_type_task        = col.aggregate(prepend_match([
        {"$match": {"news_type": {"$ne": ""}}},
        {"$group": {"_id": "$news_type", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
    ])).to_list(length=20)

    timeline_task       = col.aggregate(prepend_match([
        {"$match": {"posted_on": {"$ne": ""}}},
        {"$group": {"_id": "$posted_on", "count": {"$sum": 1}}},
        {"$sort":  {"_id": 1}},
    ])).to_list(length=365)

    (total, all_sources, all_countries, all_actors,
     raw_countries, top_sources, top_actors, top_industries,
     top_ttps, by_type, timeline) = await asyncio.gather(
        total_task, all_sources_task, all_countries_task, all_actors_task,
        top_countries_task, top_sources_task, top_actors_task, top_industries_task,
        top_ttps_task, by_type_task, timeline_task,
    )

    # Normalize + re-aggregate country counts
    country_counts: dict = defaultdict(int)
    for r in raw_countries:
        if r["_id"]:
            country_counts[normalize_country(r["_id"])] += r["count"]
    top_countries = sorted(
        [{"name": k, "count": v} for k, v in country_counts.items()],
        key=lambda x: x["count"], reverse=True
    )[:10]

    return {
        "total_articles":      total,
        "total_sources":       len([s for s in all_sources  if s]),
        "total_countries":     len(set(normalize_country(c) for c in all_countries if c)),
        "total_threat_actors": len([a for a in all_actors if a]),
        "top_countries":       top_countries,
        "top_sources":         [{"name": r["_id"], "count": r["count"]} for r in top_sources  if r["_id"]],
        "top_threat_actors":   [{"name": r["_id"], "count": r["count"]} for r in top_actors   if r["_id"]],
        "top_industries":      [{"name": r["_id"], "count": r["count"]} for r in top_industries if r["_id"]],
        "top_ttps":            [{"name": f"{r['_id']['id']} — {r['_id']['name']}", "count": r["count"]} for r in top_ttps],
        "by_news_type":        [{"name": r["_id"], "count": r["count"]} for r in by_type      if r["_id"]],
        "timeline":            [{"date": r["_id"],  "count": r["count"]} for r in timeline],
    }
