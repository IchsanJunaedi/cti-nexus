from fastapi import APIRouter, Depends, HTTPException, Query, Request, Header

from app.auth import require_auth, effective_client_id
from app.models.rfi import RFICreate, RFIUpdate
from app.services.audit_service import write_audit
from app.services.rfi_service import (
    create_rfi, delete_rfi, get_rfi, list_rfis, update_rfi,
)

router = APIRouter(prefix="/api/rfi", tags=["rfi"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


@router.get("")
async def get_rfis(
    status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    rfis, total = await list_rfis(status=status, page=page, page_size=page_size, client_id=cid)
    return {"rfis": rfis, "total": total, "page": page, "page_size": page_size}


@router.get("/{rfi_id}")
async def get_rfi_by_id(
    rfi_id: str,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    rfi = await get_rfi(rfi_id, client_id=cid)
    if not rfi:
        raise HTTPException(status_code=404, detail="RFI not found")
    return rfi


@router.post("")
async def post_rfi(
    body: RFICreate,
    request: Request,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await create_rfi(body.model_dump(), client_id=cid)
    await write_audit(user["username"], "create_rfi", detail={"question": body.question[:80]}, ip=_ip(request))
    return result


@router.put("/{rfi_id}")
async def put_rfi(rfi_id: str, body: RFIUpdate, request: Request, user: dict = Depends(require_auth)):
    result = await update_rfi(rfi_id, body.model_dump(exclude_none=True))
    if not result:
        raise HTTPException(status_code=404, detail="RFI not found")
    await write_audit(user["username"], "update_rfi", target_id=rfi_id, ip=_ip(request))
    return result


@router.delete("/{rfi_id}")
async def remove_rfi(rfi_id: str, request: Request, user: dict = Depends(require_auth)):
    ok = await delete_rfi(rfi_id)
    if not ok:
        raise HTTPException(status_code=404, detail="RFI not found")
    await write_audit(user["username"], "delete_rfi", target_id=rfi_id, ip=_ip(request))
    return {"deleted": True}
