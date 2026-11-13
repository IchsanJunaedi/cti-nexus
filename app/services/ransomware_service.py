import asyncio
import re
from datetime import date, timedelta
from bson import ObjectId
from bson.errors import InvalidId
from app.database import get_database
from app.config import COLLECTION_NAME, TWEETS_COLLECTION
from app.services.dls_service import get_dls_group

COLLECTION = "ransomware_victims"

_NAME_SUFFIXES = re.compile(
    r"\b(corp(oration)?|inc|ltd|llc|co|company|group|plc|holdings?)\b\.?", re.I
)


def _col():
    return get_database()[COLLECTION]


def _articles_col():
    return get_database()[COLLECTION_NAME]


def _tweets_col():
    return get_database()[TWEETS_COLLECTION]


def _normalize_name(name: str) -> str:
    """Fold victim/group names for dedup: lowercase, strip legal suffixes/punctuation."""
    if not name:
        return ""
    n = name.lower()
    n = _NAME_SUFFIXES.sub("", n)
    n = re.sub(r"[^a-z0-9]+", "", n)
    return n


async def get_victims(
    page: int = 1,
    page_size: int = 50,
    group: str | None = None,
    country: str | None = None,
    industry: str | None = None,
    date_start: str | None = None,
    date_end: str | None = None,
    search: str | None = None,
) -> tuple[list[dict], int]:
    col = _col()
    query: dict = {}

    if group:
        query["group_name"] = {"$regex": group, "$options": "i"}
    if country:
        query["country"] = {"$regex": country, "$options": "i"}
    if industry:
        query["industry"] = {"$regex": industry, "$options": "i"}
    if search:
        query["victim"] = {"$regex": re.escape(search), "$options": "i"}
    if date_start or date_end:
        date_filter: dict = {}
        if date_start:
            date_filter["$gte"] = date_start
        if date_end:
            date_filter["$lte"] = date_end
        query["published"] = date_filter

    skip = (page - 1) * page_size
    cursor = col.find(query, {"offset_key": 0}).sort("published", -1).skip(skip).limit(page_size)
    docs, total = await asyncio.gather(cursor.to_list(length=page_size), col.count_documents(query))
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs, total


async def get_activity(
    page: int = 1,
    page_size: int = 50,
    group: str | None = None,
    country: str | None = None,
    industry: str | None = None,
    date_start: str | None = None,
    date_end: str | None = None,
    search: str | None = None,
    include_claimed: bool = True,
) -> tuple[list[dict], int]:
    """
    Ransomware Activity feed: verified victims (ransomware.live) merged with
    unverified claims (X/Twitter), deduped on normalized group+victim name.
    A claim already covered by a verified record is dropped; verified always wins.
    """
    col = _col()

    verified_query: dict = {}
    if group:
        verified_query["group_name"] = {"$regex": group, "$options": "i"}
    if country:
        verified_query["country"] = {"$regex": country, "$options": "i"}
    if industry:
        verified_query["industry"] = {"$regex": industry, "$options": "i"}
    if search:
        verified_query["victim"] = {"$regex": re.escape(search), "$options": "i"}
    if date_start or date_end:
        date_filter: dict = {}
        if date_start:
            date_filter["$gte"] = date_start
        if date_end:
            date_filter["$lte"] = date_end
        verified_query["published"] = date_filter

    verified_cursor = col.find(verified_query, {"offset_key": 0}).sort("published", -1)
    verified_docs, known_groups = await asyncio.gather(
        verified_cursor.to_list(length=1000),
        col.distinct("group_name"),
    )

    known_group_norms = {_normalize_name(g): g for g in known_groups if g}

    rows: list[dict] = []
    verified_keys: set[str] = set()

    for d in verified_docs:
        d["id"] = str(d.pop("_id"))
        d["source"] = "verified"
        key = f"{_normalize_name(d.get('group_name'))}|{_normalize_name(d.get('victim'))}"
        verified_keys.add(key)
        rows.append(d)

    if include_claimed:
        tcol = _tweets_col()
        tweet_query: dict = {
            "confirmed_incident": True,
            "victim_name": {"$nin": [None, ""]},
            "mentioned_group.0": {"$exists": True},
        }
        if search:
            tweet_query["victim_name"] = {"$regex": re.escape(search), "$options": "i"}
        if date_start or date_end:
            date_filter = {}
            if date_start:
                date_filter["$gte"] = date_start
            if date_end:
                date_filter["$lte"] = date_end
            tweet_query["posted_on"] = date_filter

        tweet_cursor = tcol.find(
            tweet_query,
            {"tweet_id": 1, "url": 1, "posted_on": 1, "mentioned_group": 1,
             "victim_name": 1, "victim_countries": 1, "industries_impacted": 1,
             "incident_confidence": 1},
        ).sort("posted_on", -1).limit(500)

        claimed_seen: dict[str, dict] = {}
        async for t in tweet_cursor:
            # only groups we recognize as ransomware actors (cross-ref verified feed)
            matched_group = None
            for mg in t.get("mentioned_group", []):
                norm = _normalize_name(mg)
                if norm in known_group_norms:
                    matched_group = known_group_norms[norm]
                    break
            if not matched_group:
                continue
            if group and group.lower() not in matched_group.lower():
                continue

            victim_name = t.get("victim_name", "")
            key = f"{_normalize_name(matched_group)}|{_normalize_name(victim_name)}"
            if key in verified_keys:
                continue  # official record already covers this claim

            victim_countries = t.get("victim_countries") or []
            industries = t.get("industries_impacted") or []
            row_country = victim_countries[0] if victim_countries else None
            row_industry = industries[0] if industries else None

            if country and (not row_country or country.lower() not in row_country.lower()):
                continue
            if industry and (not row_industry or industry.lower() not in row_industry.lower()):
                continue

            # tweets are sorted newest-first; keep the EARLIEST claim per victim
            # (that's the point — the first sighting, not the latest retweet of it)
            claimed_seen[key] = {
                "id": f"tweet:{t.get('tweet_id')}",
                "source": "claimed",
                "group_name": matched_group,
                "victim": victim_name,
                "country": row_country,
                "industry": row_industry,
                "published": t.get("posted_on"),
                "discovered": t.get("posted_on"),
                "post_url": t.get("url", ""),
                "screenshot": None,
                "confidence": t.get("incident_confidence"),
            }

        rows.extend(claimed_seen.values())

    rows.sort(key=lambda r: r.get("published") or "", reverse=True)

    total = len(rows)
    start = (page - 1) * page_size
    return rows[start:start + page_size], total


async def update_victim(victim_id: str, country: str | None = None, industry: str | None = None) -> bool:
    """Analyst manual enrichment — fill in country/industry when the source feed left them blank."""
    try:
        oid = ObjectId(victim_id)
    except InvalidId:
        return False

    fields: dict = {}
    if country is not None:
        fields["country"] = country.strip()
    if industry is not None:
        fields["industry"] = industry.strip()
    if not fields:
        return False

    result = await _col().update_one({"_id": oid}, {"$set": fields})
    return result.matched_count > 0


async def get_related_articles(
    page: int = 1,
    page_size: int = 20,
    search: str | None = None,
    date_start: str | None = None,
    date_end: str | None = None,
    industry: str | None = None,
    threat_actor: str | None = None,
    country: list[str] | None = None,
) -> tuple[list[dict], int]:
    """Return articles mentioning known ransomware groups from ransomware_victims."""
    vcol = _col()
    acol = _articles_col()

    # Get all distinct group names from victims collection
    group_names: list[str] = await vcol.distinct("group_name")
    group_names = [g for g in group_names if g]

    if not group_names:
        return [], 0

    # Primary: threat_actors array contains any known group (exact, case-insensitive $in)
    # Secondary: title regex matches any of top 40 groups (limit regex alternation size)
    top_groups = group_names[:40]
    pattern = "|".join(re.escape(g) for g in top_groups)

    query: dict = {"$or": [
        {"threat_actors": {"$in": group_names}},
        {"title": {"$regex": pattern, "$options": "i"}},
    ]}

    if search:
        query["title"] = {"$regex": re.escape(search), "$options": "i"}
    if date_start or date_end:
        date_filter: dict = {}
        if date_start:
            date_filter["$gte"] = date_start
        if date_end:
            date_filter["$lte"] = date_end
        query["posted_on"] = date_filter
    if industry:
        query["impacted_industries"] = {"$regex": re.escape(industry), "$options": "i"}
    if threat_actor:
        query["threat_actors"] = {"$regex": f"^{re.escape(threat_actor)}$", "$options": "i"}
    if country:
        query["mentioned_countries"] = {"$in": country}

    skip = (page - 1) * page_size
    cursor = acol.find(query, {"_id": 0}).sort("posted_on", -1).skip(skip).limit(page_size)
    docs, total = await asyncio.gather(cursor.to_list(length=page_size), acol.count_documents(query))
    return docs, total


async def get_group_treemap(days: int) -> dict:
    """
    Per-group victim counts for [cutoff, today) vs prior equal-length window,
    for a size(count)+color(% change) treemap.
    """
    col = _col()
    today = date.today()
    cutoff = (today - timedelta(days=days)).isoformat()
    prev_cutoff = (today - timedelta(days=days * 2)).isoformat()

    cur_pipeline = [
        {"$match": {"published": {"$gte": cutoff}, "group_name": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$group_name", "count": {"$sum": 1}}},
    ]
    prev_pipeline = [
        {"$match": {"published": {"$gte": prev_cutoff, "$lt": cutoff}, "group_name": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$group_name", "count": {"$sum": 1}}},
    ]
    cur_res, prev_res = await asyncio.gather(
        col.aggregate(cur_pipeline).to_list(500),
        col.aggregate(prev_pipeline).to_list(500),
    )

    prev_map = {r["_id"]: r["count"] for r in prev_res}

    groups = []
    for r in cur_res:
        name = r["_id"]
        cur = r["count"]
        prev = prev_map.get(name, 0)
        if prev == 0:
            pct = None  # renders as "NEW"
        else:
            pct = round(((cur - prev) / prev) * 100, 1)
        groups.append({"group": name, "cur": cur, "prev": prev, "pct": pct})

    groups.sort(key=lambda g: -g["cur"])
    return {"days": days, "groups": groups}


async def get_group_detail(group_name: str) -> dict:
    """Top country, top industry, and all-time victim volume for one ransomware group."""
    col = _col()

    country_pipeline = [
        {"$match": {"group_name": group_name, "country": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$country", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 1},
    ]
    industry_pipeline = [
        {"$match": {"group_name": group_name, "industry": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$industry", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 1},
    ]
    top_countries_pipeline = [
        {"$match": {"group_name": group_name, "country": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$country", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]
    top_industries_pipeline = [
        {"$match": {"group_name": group_name, "industry": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$industry", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]
    monthly_trend_pipeline = [
        {"$match": {"group_name": group_name, "published": {"$nin": [None, ""]}}},
        {"$group": {"_id": {"$substrCP": ["$published", 0, 7]}, "count": {"$sum": 1}}},
        {"$sort": {"_id": -1}},
        {"$limit": 12},
    ]

    (
        top_country_res, top_industry_res, top_countries_res, top_industries_res,
        monthly_res, total_volume, recent_docs, dls,
    ) = await asyncio.gather(
        col.aggregate(country_pipeline).to_list(1),
        col.aggregate(industry_pipeline).to_list(1),
        col.aggregate(top_countries_pipeline).to_list(5),
        col.aggregate(top_industries_pipeline).to_list(5),
        col.aggregate(monthly_trend_pipeline).to_list(12),
        col.count_documents({"group_name": group_name}),
        col.find({"group_name": group_name}, {"offset_key": 0})
           .sort("published", -1).limit(10).to_list(length=10),
        get_dls_group(group_name),
    )

    monthly_trend = sorted(
        [{"month": r["_id"], "count": r["count"]} for r in monthly_res if r["_id"]],
        key=lambda r: r["month"],
    )
    for d in recent_docs:
        d["id"] = str(d.pop("_id"))

    return {
        "group": group_name,
        "top_country": top_country_res[0]["_id"] if top_country_res else None,
        "top_industry": top_industry_res[0]["_id"] if top_industry_res else None,
        "top_countries": [{"name": r["_id"], "count": r["count"]} for r in top_countries_res],
        "top_industries": [{"name": r["_id"], "count": r["count"]} for r in top_industries_res],
        "monthly_trend": monthly_trend,
        "total_volume": total_volume,
        "recent_victims": recent_docs,
        "dls": dls,
    }


async def get_victim_filter_options() -> dict:
    col = _col()
    groups, countries, industries = await asyncio.gather(
        col.distinct("group_name"),
        col.distinct("country"),
        col.distinct("industry"),
    )
    return {
        "groups":     sorted(g for g in groups if g),
        "countries":  sorted(c for c in countries if c),
        "industries": sorted(i for i in industries if i),
    }
