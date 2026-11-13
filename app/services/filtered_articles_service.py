import asyncio
from bson import ObjectId
from app.database import get_database
from app.config import COLLECTION_NAME

_RANSOMWARE_TITLES = [
    "NEW RANSOMWARE VICTIM (INDONESIA)",
    "NEW RANSOMWARE VICTIM",
]


def _scraper_runs():
    return get_database()["scraper_runs"]


def _news_col():
    return get_database()[COLLECTION_NAME]


async def get_filtered_articles(
    page: int = 1,
    page_size: int = 20,
    search: str | None = None,
) -> tuple[list[dict], int]:
    col = _scraper_runs()
    query: dict = {
        "accepted": False,
        "title": {"$nin": _RANSOMWARE_TITLES},
    }
    if search:
        regex = {"$regex": search, "$options": "i"}
        query["$or"] = [{"title": regex}, {"script": regex}]

    skip = (page - 1) * page_size
    cursor = col.find(query).sort("run_at", -1).skip(skip).limit(page_size)
    articles, total = await asyncio.gather(
        cursor.to_list(length=page_size),
        col.count_documents(query),
    )
    return articles, total


async def restore_filtered_article(article_id: str) -> bool:
    try:
        oid = ObjectId(article_id)
    except Exception:
        return False

    run = await _scraper_runs().find_one({"_id": oid})
    if not run:
        return False

    ts = run.get("run_at")
    posted_on = ts.strftime("%Y-%m-%d") if ts else ""
    year = ts.year if ts else 0
    month = ts.strftime("%B").lower() if ts else ""
    week = f"W{(ts.day - 1) // 7 + 1}" if ts else ""

    doc = {
        "title": run.get("title", ""),
        "url": run.get("url", ""),
        "source": run.get("script", ""),
        "posted_on": posted_on,
        "year": year,
        "month": month,
        "week": week,
        "news_type": "Manually Restored",
        "impacted_industries": [],
        "mentioned_countries": [],
        "victim_countries": [],
        "actor_countries": [],
        "threat_actors": [],
        "ttps": [],
        "manually_restored": True,
    }

    existing = await _news_col().find_one({"url": doc["url"]})
    if existing:
        return True

    await _news_col().insert_one(doc)
    return True
