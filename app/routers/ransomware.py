from fastapi import APIRouter, Query, Depends, Request, HTTPException
from pydantic import BaseModel
from app.auth import require_auth
from app.services.ransomware_service import (
    get_victims, get_victim_filter_options, get_related_articles,
    get_group_treemap, get_group_detail, update_victim, get_activity,
)
from app.services.dls_service import get_dls_group, get_dls_stats
from app.services.audit_service import write_audit

router = APIRouter(prefix="/api/ransomware", tags=["ransomware"], dependencies=[Depends(require_auth)])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


class VictimUpdate(BaseModel):
    country: str | None = None
    industry: str | None = None


@router.get("/victims")
async def list_victims(
    page:       int = Query(1, ge=1),
    page_size:  int = Query(50, ge=1, le=200),
    group:      str | None = None,
    country:    str | None = None,
    industry:   str | None = None,
    date_start: str | None = None,
    date_end:   str | None = None,
    search:     str | None = None,
):
    victims, total = await get_victims(
        page=page,
        page_size=page_size,
        group=group,
        country=country,
        industry=industry,
        date_start=date_start,
        date_end=date_end,
        search=search,
    )
    return {"victims": victims, "total": total, "page": page, "page_size": page_size}


@router.get("/activity")
async def list_activity(
    page:            int = Query(1, ge=1),
    page_size:       int = Query(50, ge=1, le=200),
    group:           str | None = None,
    country:         str | None = None,
    industry:        str | None = None,
    date_start:      str | None = None,
    date_end:        str | None = None,
    search:          str | None = None,
    include_claimed: bool = True,
):
    rows, total = await get_activity(
        page=page,
        page_size=page_size,
        group=group,
        country=country,
        industry=industry,
        date_start=date_start,
        date_end=date_end,
        search=search,
        include_claimed=include_claimed,
    )
    return {"activity": rows, "total": total, "page": page, "page_size": page_size}


@router.get("/victims/filters")
async def victim_filters():
    return await get_victim_filter_options()


@router.get("/related-articles")
async def related_articles(
    page:         int = Query(1, ge=1),
    page_size:    int = Query(20, ge=1, le=100),
    search:       str | None = None,
    date_start:   str | None = None,
    date_end:     str | None = None,
    industry:     str | None = None,
    threat_actor: str | None = None,
    country:      list[str] | None = Query(None),
):
    articles, total = await get_related_articles(
        page=page,
        page_size=page_size,
        search=search,
        date_start=date_start,
        date_end=date_end,
        industry=industry,
        threat_actor=threat_actor,
        country=country,
    )
    return {"articles": articles, "total": total, "page": page, "page_size": page_size}


@router.get("/treemap")
async def ransomware_treemap(days: int = Query(7, ge=1, le=365)):
    return await get_group_treemap(days=days)


@router.get("/group-detail")
async def ransomware_group_detail(group: str = Query(...)):
    return await get_group_detail(group_name=group)


@router.get("/dls")
async def ransomware_dls(group: str = Query(...)):
    return {"dls": await get_dls_group(group)}


@router.get("/dls/stats")
async def ransomware_dls_stats():
    return await get_dls_stats()


@router.patch("/victims/{victim_id}")
async def patch_victim(
    victim_id: str, body: VictimUpdate, request: Request,
    user: dict = Depends(require_auth),
):
    ok = await update_victim(victim_id, country=body.country, industry=body.industry)
    if not ok:
        raise HTTPException(status_code=404, detail="Victim not found or no fields to update")
    await write_audit(
        user["username"], "edit_ransomware_victim", target_id=victim_id,
        detail={"country": body.country, "industry": body.industry}, ip=_ip(request),
    )
    return {"success": True}
