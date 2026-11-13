import asyncio
from app.database import get_database
from app.config import TWEETS_COLLECTION


def _col():
    return get_database()[TWEETS_COLLECTION]


async def get_tweets(
    page: int = 1,
    page_size: int = 20,
    search: str | None = None,
    author: str | None = None,
    lang: str | None = None,
    posted_on_start: str | None = None,
    posted_on_end: str | None = None,
    apac_only: bool = False,
    ot_only: bool = False,
    confirmed_only: bool = False,
    countries: list[str] | None = None,
) -> tuple[list[dict], int]:
    col = _col()
    query: dict = {}

    if search:
        query["text"] = {"$regex": search, "$options": "i"}
    if author:
        query["author_username"] = {"$regex": author, "$options": "i"}
    if lang:
        query["lang"] = lang
    if apac_only:
        query["apac_indicator"] = True
    if ot_only:
        query["ot_status"] = True
    if confirmed_only:
        query["confirmed_incident"] = True
    if countries:
        query["mentioned_apac_country"] = {"$in": countries}

    date_filter: dict = {}
    if posted_on_start:
        date_filter["$gte"] = posted_on_start
    if posted_on_end:
        date_filter["$lte"] = posted_on_end
    if date_filter:
        query["posted_on"] = date_filter

    skip = (page - 1) * page_size
    cursor = col.find(query).sort("posted_on", -1).skip(skip).limit(page_size)
    docs, total = await asyncio.gather(
        cursor.to_list(page_size),
        col.count_documents(query),
    )
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs, total


async def get_tweet_stats(
    search: str | None = None,
    author: str | None = None,
    lang: str | None = None,
    posted_on_start: str | None = None,
    posted_on_end: str | None = None,
    apac_only: bool = False,
    ot_only: bool = False,
    confirmed_only: bool = False,
) -> dict:
    col = _col()
    query: dict = {}

    if search:
        query["text"] = {"$regex": search, "$options": "i"}
    if author:
        query["author_username"] = {"$regex": author, "$options": "i"}
    if lang:
        query["lang"] = lang
    if apac_only:
        query["apac_indicator"] = True
    if ot_only:
        query["ot_status"] = True
    if confirmed_only:
        query["confirmed_incident"] = True

    date_filter: dict = {}
    if posted_on_start:
        date_filter["$gte"] = posted_on_start
    if posted_on_end:
        date_filter["$lte"] = posted_on_end
    if date_filter:
        query["posted_on"] = date_filter

    match_stage = [{"$match": query}] if query else []
    pipeline = match_stage + [
        {"$group": {"_id": "$author_username", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    top_authors_raw, total = await asyncio.gather(
        col.aggregate(pipeline).to_list(10),
        col.count_documents(query),
    )
    return {
        "total": total,
        "top_authors": [{"author": r["_id"], "count": r["count"]} for r in top_authors_raw],
    }
