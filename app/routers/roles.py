from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from app.services.role_service import (
    ALL_PERMISSIONS, list_roles, get_role, create_role, update_role, delete_role, role_exists,
)
from app.services.audit_service import write_audit
from app.auth import require_auth, require_admin, require_superadmin

router = APIRouter(prefix="/api/roles", tags=["roles"])


class RoleCreate(BaseModel):
    name:         str        = Field(..., min_length=2, max_length=40, pattern=r"^[a-z0-9_-]+$")
    display_name: str        = Field(..., min_length=1, max_length=60)
    permissions:  list[str]  = Field(default_factory=list)


class RoleUpdate(BaseModel):
    display_name: str        = Field(..., min_length=1, max_length=60)
    permissions:  list[str]  = Field(default_factory=list)


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


@router.get("/permissions")
async def get_all_permissions(_user: dict = Depends(require_auth)):
    return [{"key": k, "description": v} for k, v in ALL_PERMISSIONS.items()]


@router.get("")
async def get_roles(_user: dict = Depends(require_auth)):
    return await list_roles()


@router.post("")
async def add_role(body: RoleCreate, request: Request, admin: dict = Depends(require_superadmin)):
    unknown = [p for p in body.permissions if p not in ALL_PERMISSIONS]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown permissions: {unknown}")
    if await role_exists(body.name):
        raise HTTPException(status_code=409, detail=f"Role '{body.name}' already exists")
    doc = await create_role(body.name, body.display_name, body.permissions, admin["username"])
    await write_audit(admin["username"], "create_role", target_id=body.name,
                      detail={"permissions": body.permissions}, ip=_ip(request))
    return doc


@router.put("/{name}")
async def edit_role(name: str, body: RoleUpdate, request: Request, admin: dict = Depends(require_admin)):
    unknown = [p for p in body.permissions if p not in ALL_PERMISSIONS]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown permissions: {unknown}")
    if admin["role"] != "superadmin":
        # admin may not grant permissions their own role lacks (no self-escalation)
        own = set((await get_role(admin["role"]) or {}).get("permissions", []))
        current = set((await get_role(name) or {}).get("permissions", []))
        escalate = [p for p in body.permissions if p not in own and p not in current]
        if escalate:
            raise HTTPException(status_code=403, detail=f"Cannot grant permissions you lack: {escalate}")
    try:
        doc = await update_role(name, body.display_name, body.permissions)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not doc:
        raise HTTPException(status_code=404, detail="Role not found")
    await write_audit(admin["username"], "update_role", target_id=name,
                      detail={"permissions": body.permissions}, ip=_ip(request))
    return doc


@router.delete("/{name}")
async def remove_role(name: str, request: Request, admin: dict = Depends(require_superadmin)):
    role = await get_role(name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.get("is_system"):
        raise HTTPException(status_code=400, detail="Cannot delete system role")
    try:
        ok = await delete_role(name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="Role not found")
    await write_audit(admin["username"], "delete_role", target_id=name, ip=_ip(request))
    return {"ok": True}
