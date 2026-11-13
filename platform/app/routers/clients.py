from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from app.auth import require_auth, require_permission
from app.services.role_service import role_has_permission
from app.services.client_service import list_clients, create_client, delete_client, get_client, update_client
from app.services.audit_service import write_audit

router = APIRouter(prefix="/api/clients", tags=["clients"])


def _ip(r: Request) -> str:
    return r.client.host if r.client else ""


class ClientCreate(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")
    name:      str = Field(..., min_length=1, max_length=128)
    countries: list[str] = Field(default_factory=list)
    sectors:   list[str] = Field(default_factory=list)
    recipients:        list[str] = Field(default_factory=list)
    newsletter_css:    str = ""
    newsletter_intro:  str = ""
    newsletter_footer: str = ""


class ClientUpdate(BaseModel):
    name:      str = Field(..., min_length=1, max_length=128)
    countries: list[str] = Field(default_factory=list)
    sectors:   list[str] = Field(default_factory=list)
    recipients:        list[str] = Field(default_factory=list)
    newsletter_css:    str = ""
    newsletter_intro:  str = ""
    newsletter_footer: str = ""


@router.get("")
async def get_clients(user: dict = Depends(require_auth)):
    clients = await list_clients()
    # full list for superadmin / user managers; everyone else sees only their assigned clients
    if user["role"] == "superadmin" or await role_has_permission(user["role"], "manage_users"):
        return clients
    allowed = set(user.get("client_ids", []))
    return [c for c in clients if c.get("client_id") in allowed]


@router.post("", status_code=201)
async def post_client(body: ClientCreate, request: Request, sa: dict = Depends(require_permission("manage_clients"))):
    existing = await get_client(body.client_id)
    if existing:
        raise HTTPException(status_code=409, detail="client_id already exists")
    result = await create_client(
        body.client_id, body.name, body.countries, body.sectors,
        body.recipients, body.newsletter_css, body.newsletter_intro, body.newsletter_footer,
    )
    await write_audit(sa["username"], "create_client", target_id=body.client_id,
                      detail={"name": body.name, "countries": body.countries, "sectors": body.sectors,
                              "recipients": body.recipients}, ip=_ip(request))
    return result


@router.put("/{client_id}")
async def edit_client(client_id: str, body: ClientUpdate, request: Request, sa: dict = Depends(require_permission("manage_clients"))):
    updated = await update_client(
        client_id, body.name, body.countries, body.sectors,
        body.recipients, body.newsletter_css, body.newsletter_intro, body.newsletter_footer,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Client not found")
    await write_audit(sa["username"], "update_client", target_id=client_id,
                      detail={"name": body.name, "countries": body.countries, "sectors": body.sectors,
                              "recipients": body.recipients}, ip=_ip(request))
    return updated


@router.delete("/{client_id}")
async def remove_client(client_id: str, request: Request, sa: dict = Depends(require_permission("manage_clients"))):
    if client_id == "default":
        raise HTTPException(status_code=400, detail="Cannot delete the default client")
    ok = await delete_client(client_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Client not found")
    await write_audit(sa["username"], "delete_client", target_id=client_id, ip=_ip(request))
    return {"deleted": True}
