import httpx
from fastapi import APIRouter, Query, Depends
from app.auth import require_auth
from app.config import TWITTER_API_KEY
from app.models.tweet import TweetListResponse, TweetOut
from app.services.tweet_service import get_tweets, get_tweet_stats

router = APIRouter(prefix="/api/tweets", tags=["tweets"], dependencies=[Depends(require_auth)])


@router.get("/balance")
async def twitter_api_balance():
    if not TWITTER_API_KEY:
        return {"error": "TWITTER_API_KEY not configured"}
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            "https://api.twitterapi.io/oapi/my/info",
            headers={"X-API-Key": TWITTER_API_KEY},
        )
        resp.raise_for_status()
        return resp.json()


@router.get("/stats")
async def tweet_stats(
    search: str | None = None,
    author: str | None = None,
    lang: str | None = None,
    posted_on_start: str | None = None,
    posted_on_end: str | None = None,
    apac_only: bool = Query(False),
    ot_only: bool = Query(False),
    confirmed_only: bool = Query(False),
):
    return await get_tweet_stats(
        search=search,
        author=author,
        lang=lang,
        posted_on_start=posted_on_start,
        posted_on_end=posted_on_end,
        apac_only=apac_only,
        ot_only=ot_only,
        confirmed_only=confirmed_only,
    )


@router.get("", response_model=TweetListResponse)
async def list_tweets(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = None,
    author: str | None = None,
    lang: str | None = None,
    posted_on_start: str | None = None,
    posted_on_end: str | None = None,
    apac_only: bool = Query(False),
    ot_only: bool = Query(False),
    confirmed_only: bool = Query(False),
    country: list[str] = Query(default=[]),
):
    docs, total = await get_tweets(
        page=page,
        page_size=page_size,
        search=search,
        author=author,
        lang=lang,
        posted_on_start=posted_on_start,
        posted_on_end=posted_on_end,
        apac_only=apac_only,
        ot_only=ot_only,
        confirmed_only=confirmed_only,
        countries=country or None,
    )
    tweets = [TweetOut.from_mongo(d) for d in docs]
    return TweetListResponse(tweets=tweets, total=total, page=page, page_size=page_size)
