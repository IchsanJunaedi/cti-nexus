from fastapi import APIRouter, Query, Depends
from app.auth import require_auth
from app.services.scraper_health_service import get_health_summary, get_scraper_articles

router = APIRouter(prefix="/api/scraper", tags=["scraper-health"], dependencies=[Depends(require_auth)])


@router.get("/health")
async def scraper_health(days: int = Query(7, ge=1, le=90)):
    return await get_health_summary(days=days)


@router.get("/articles")
async def scraper_articles(script: str, days: int = Query(7, ge=1, le=90)):
    return await get_scraper_articles(script=script, days=days)
