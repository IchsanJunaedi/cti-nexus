from fastapi import APIRouter, Depends, HTTPException, Header, Request
from app.models.diagram import DiagramCreate, DiagramUpdate, DiagramOut, DiagramListOut
from app.services.diagram_service import (
    list_diagrams, get_diagram, create_diagram, save_diagram, delete_diagram,
)
from app.services.audit_service import write_audit
from app.auth import require_auth, effective_client_id

router = APIRouter(prefix="/api/diagrams", tags=["diagrams"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _privileged(user: dict) -> bool:
    return user["role"] in ("admin", "superadmin")


@router.get("")
async def get_diagrams(
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    docs = await list_diagrams(cid, user["username"], _privileged(user))
    return [DiagramListOut.from_mongo(d) for d in docs]


@router.get("/{diagram_id}")
async def get_diagram_ep(
    diagram_id: str,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    doc = await get_diagram(diagram_id, cid)
    if not doc:
        raise HTTPException(status_code=404, detail="Diagram not found")
    return DiagramOut.from_mongo(doc)


@router.post("")
async def post_diagram(
    body: DiagramCreate,
    request: Request,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    doc = await create_diagram(body.model_dump(), cid, user["username"])
    await write_audit(
        user["username"], "create_diagram", target_id=str(doc["_id"]),
        detail={"name": body.name}, ip=_ip(request),
    )
    return DiagramOut.from_mongo(doc)


@router.put("/{diagram_id}")
async def put_diagram(
    diagram_id: str,
    body: DiagramUpdate,
    request: Request,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    doc = await save_diagram(diagram_id, cid, body.model_dump(exclude_none=True))
    if not doc:
        raise HTTPException(status_code=404, detail="Diagram not found")
    await write_audit(user["username"], "update_diagram", target_id=diagram_id, ip=_ip(request))
    return DiagramOut.from_mongo(doc)


@router.delete("/{diagram_id}")
async def remove_diagram(
    diagram_id: str,
    request: Request,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    ok = await delete_diagram(diagram_id, cid, user["username"], _privileged(user))
    if not ok:
        raise HTTPException(status_code=404, detail="Diagram not found")
    await write_audit(user["username"], "delete_diagram", target_id=diagram_id, ip=_ip(request))
    return {"deleted": True}
