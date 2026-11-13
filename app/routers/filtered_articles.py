from fastapi import APIRouter, Depends, HTTPException, Query
from app.auth import require_auth
from app.services.filtered_articles_service import get_filtered_articles, restore_filtered_article

router = APIRouter(prefix="/api/filtered-articles", tags=["filtered-articles"])


@router.get("")
async def list_filtered(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = None,
):
    articles, total = await get_filtered_articles(page=page, page_size=page_size, search=search)
    items = [
        {
            "id": str(a["_id"]),
            "title": a.get("title", ""),
            "url": a.get("url", ""),
            "posted_on": None,
            "script_name": a.get("script", ""),
            "created_at": a["run_at"].isoformat() if a.get("run_at") else None,
            "completed_at": None,
        }
        for a in articles
    ]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.post("/{article_id}/restore")
async def restore_article(article_id: str, user: dict = Depends(require_auth)):
    ok = await restore_filtered_article(article_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Article not found or already restored")
    return {"success": True}
