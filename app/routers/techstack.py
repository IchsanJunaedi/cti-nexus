import asyncio
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from app.models.techstack import TechStack, TechStackAdd, TechStackExposureUpdate, TechStackHostingUpdate, TechStackVendorUpdate, TechStackListResponse
from app.services.techstack_service import list_techstack, add_techstack, delete_techstack, update_techstack_exposure, update_techstack_hosting, update_techstack_vendor, backfill_all_cves_for_client, backfill_nvd_for_tech, get_tech_by_id
from app.services.audit_service import write_audit
from app.auth import require_auth, effective_client_id

router = APIRouter(prefix="/api/techstack", tags=["techstack"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


@router.get("", response_model=TechStackListResponse)
async def get_techstack(
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("name"),
    sort_dir: str = Query("asc"),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    items, total = await list_techstack(
        search=search, page=page, page_size=page_size,
        sort_by=sort_by, sort_dir=sort_dir, client_id=cid,
    )
    return TechStackListResponse(
        items=[TechStack.from_mongo(i) for i in items],
        total=total, page=page, page_size=page_size,
    )


@router.post("")
async def post_techstack(
    body: TechStackAdd, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await add_techstack(body.name, client_id=cid, exposure=body.exposure, hosting_type=body.hosting_type, vendor=body.vendor)
    if result.get("reason") == "index_conflict":
        raise HTTPException(status_code=409, detail=result["hint"])
    await write_audit(user["username"], "add_techstack", target_id=body.name, ip=_ip(request))
    return result


@router.post("/backfill-cves")
async def backfill_cves(
    request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    """Copy all existing CVEs for this client's tech stack from other clients. Run after fix_cve_tracker_index.py."""
    cid = effective_client_id(user, x_client_id)
    result = await backfill_all_cves_for_client(client_id=cid)
    await write_audit(user["username"], "backfill_cves", detail=result, ip=_ip(request))
    return result


@router.patch("/{tech_id}/exposure")
async def patch_exposure(
    tech_id: str, body: TechStackExposureUpdate, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await update_techstack_exposure(tech_id, body.exposure, client_id=cid)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail="Tech not found or invalid exposure value")
    await write_audit(user["username"], "update_techstack_exposure", target_id=tech_id,
                      detail={"exposure": body.exposure}, ip=_ip(request))
    return result


@router.patch("/{tech_id}/hosting")
async def patch_hosting(
    tech_id: str, body: TechStackHostingUpdate, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await update_techstack_hosting(tech_id, body.hosting_type, client_id=cid)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail="Tech not found or invalid hosting type")
    await write_audit(user["username"], "update_techstack_hosting", target_id=tech_id,
                      detail={"hosting_type": body.hosting_type}, ip=_ip(request))
    return result


@router.patch("/{tech_id}/vendor")
async def patch_vendor(
    tech_id: str, body: TechStackVendorUpdate, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await update_techstack_vendor(tech_id, body.vendor, client_id=cid)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail="Tech not found")
    await write_audit(user["username"], "update_techstack_vendor", target_id=tech_id,
                      detail={"vendor": body.vendor}, ip=_ip(request))
    return result


@router.post("/{tech_id}/backfill-historical")
async def backfill_historical(
    tech_id: str, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    """Trigger 180-day NVD historical backfill for a specific tech. Returns immediately; runs in background."""
    cid = effective_client_id(user, x_client_id)
    doc = await get_tech_by_id(tech_id, cid)
    if not doc:
        raise HTTPException(status_code=404, detail="Tech not found")
    tech_name = doc.get("name", "")
    asyncio.create_task(backfill_nvd_for_tech(tech_name, cid))
    await write_audit(user["username"], "backfill_historical", target_id=tech_name, ip=_ip(request))
    return {"started": True, "tech": tech_name, "days": 180}


@router.delete("/{tech_id}")
async def remove_techstack(
    tech_id: str, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await delete_techstack(tech_id, client_id=cid)
    await write_audit(user["username"], "delete_techstack", target_id=tech_id, ip=_ip(request))
    return result
