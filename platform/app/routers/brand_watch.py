from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from app.models.brand_watch import (
    MonitoredBrand, MonitoredBrandAdd, MonitoredBrandListResponse,
    BrandFaviconMatch, BrandFaviconMatchListResponse, BrandWatchStats,
)
from app.services.brand_watch_service import (
    list_domains, add_domain, delete_domain, get_domain_by_id,
    list_results, get_stats, acknowledge_result,
)
from app.services.audit_service import write_audit
from app.auth import require_auth, effective_client_id

router = APIRouter(prefix="/api/brandwatch", tags=["brandwatch"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


# ── Watchlist ────────────────────────────────────────────────────────────────

@router.get("/domains", response_model=MonitoredBrandListResponse)
async def get_domains(
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("name"),
    sort_dir: str = Query("asc"),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    items, total = await list_domains(
        search=search, page=page, page_size=page_size,
        sort_by=sort_by, sort_dir=sort_dir, client_id=cid,
    )
    return MonitoredBrandListResponse(
        items=[MonitoredBrand.from_mongo(i) for i in items],
        total=total, page=page, page_size=page_size,
    )


@router.post("/domains")
async def post_domain(
    body: MonitoredBrandAdd, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await add_domain(body.name, client_id=cid)
    if not result.get("success"):
        raise HTTPException(status_code=409, detail=result.get("reason", "error"))
    await write_audit(user["username"], "add_monitored_brand",
                      target_id=result.get("name", body.name), ip=_ip(request))
    return result


@router.delete("/domains/{domain_id}")
async def remove_domain(
    domain_id: str, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await delete_domain(domain_id, client_id=cid)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("reason", "not found"))
    await write_audit(user["username"], "delete_monitored_brand",
                      target_id=domain_id, ip=_ip(request))
    return result


# ── Match results ────────────────────────────────────────────────────────────

@router.get("/results", response_model=BrandFaviconMatchListResponse)
async def get_results(
    base_name: str | None = None,
    newly_seen_only: bool = Query(False),
    suspicious_only: bool = Query(False),
    acknowledged: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("ip_str"),
    sort_dir: str = Query("asc"),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    items, total = await list_results(
        base_name=base_name, newly_seen_only=newly_seen_only,
        suspicious_only=suspicious_only, acknowledged=acknowledged, search=search,
        page=page, page_size=page_size, sort_by=sort_by, sort_dir=sort_dir,
        client_id=cid,
    )
    return BrandFaviconMatchListResponse(
        items=[BrandFaviconMatch.from_mongo(i) for i in items],
        total=total, page=page, page_size=page_size,
    )


@router.get("/domains/{domain_id}/results", response_model=BrandFaviconMatchListResponse)
async def get_domain_results(
    domain_id: str,
    acknowledged: str | None = None,
    suspicious_only: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(500, ge=1, le=1000),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    doc = await get_domain_by_id(domain_id, cid)
    if not doc:
        raise HTTPException(status_code=404, detail="Domain not found")
    items, total = await list_results(
        base_name=doc["name"], acknowledged=acknowledged, suspicious_only=suspicious_only,
        page=page, page_size=page_size, sort_by="first_seen", sort_dir="desc", client_id=cid,
    )
    return BrandFaviconMatchListResponse(
        items=[BrandFaviconMatch.from_mongo(i) for i in items],
        total=total, page=page, page_size=page_size,
    )


@router.post("/results/{result_id}/ack")
async def ack_result(
    result_id: str, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await acknowledge_result(result_id, user["username"], client_id=cid)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("reason", "not found"))
    await write_audit(user["username"], "ack_brand_favicon_match",
                      target_id=result_id, ip=_ip(request))
    return result


@router.get("/stats", response_model=BrandWatchStats)
async def get_brand_watch_stats(
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    return BrandWatchStats(**await get_stats(cid))
