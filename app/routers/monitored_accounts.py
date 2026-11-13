from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from app.auth import require_auth, require_permission
from app.services.audit_service import write_audit
from app.services.monitored_accounts_service import (
    list_accounts, add_account, remove_account, toggle_account,
)

router = APIRouter(prefix="/api/monitored-accounts", tags=["monitored-accounts"], dependencies=[Depends(require_auth)])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


class AddAccountRequest(BaseModel):
    username: str
    display_name: str = ""
    notes: str = ""


class ToggleRequest(BaseModel):
    active: bool


@router.get("")
async def get_accounts():
    return await list_accounts()


@router.post("")
async def post_account(body: AddAccountRequest, request: Request, admin: dict = Depends(require_permission("manage_tweets"))):
    if not body.username.strip():
        raise HTTPException(status_code=400, detail="username required")
    try:
        result = await add_account(body.username, body.display_name, body.notes)
        await write_audit(admin["username"], "add_monitored_account", target_id=body.username, ip=_ip(request))
        return result
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.delete("/{username}")
async def delete_account(username: str, request: Request, admin: dict = Depends(require_permission("manage_tweets"))):
    deleted = await remove_account(username)
    if not deleted:
        raise HTTPException(status_code=404, detail="account not found")
    await write_audit(admin["username"], "delete_monitored_account", target_id=username, ip=_ip(request))
    return {"ok": True}


@router.patch("/{username}/toggle")
async def patch_toggle(username: str, body: ToggleRequest, request: Request, admin: dict = Depends(require_permission("manage_tweets"))):
    ok = await toggle_account(username, body.active)
    if not ok:
        raise HTTPException(status_code=404, detail="account not found")
    await write_audit(admin["username"], "toggle_monitored_account", target_id=username,
                      detail={"active": body.active}, ip=_ip(request))
    return {"ok": True}
