from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from app.services.exec_dashboard_service import get_exec_dashboard
from app.services.exec_dashboard_v2_service import get_exec_dashboard_v2
from app.services.exec_brief_service import generate_exec_brief
from app.services.audit_service import write_audit
from app.auth import require_auth, effective_client_id


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""

router = APIRouter(prefix="/api/exec", tags=["exec-dashboard"])


@router.get("/dashboard")
async def exec_dashboard(
    days: int = Query(90, ge=7, le=365),
    incident_only: bool = True,
):
    return await get_exec_dashboard(days=days, incident_only=incident_only)


@router.get("/dashboard-v2")
async def exec_dashboard_v2(
    days: int = Query(90, ge=7, le=365),
    incident_only: bool = True,
    confirmed_only: bool = False,
    role: str | None = Query(None, description="Role preview — admin only"),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    effective_role = user.get("role", "analyst")
    if role is not None:
        if user["role"] not in ("admin", "superadmin"):
            raise HTTPException(status_code=403, detail="Role preview is admin-only")
        await write_audit(user["username"], "exec_dashboard_role_preview",
                          detail={"preview_role": role}, ip="")
        effective_role = role
    return await get_exec_dashboard_v2(
        days=days, incident_only=incident_only, confirmed_only=confirmed_only,
        client_id=cid, role=effective_role,
    )


@router.post("/brief")
async def exec_brief(
    request: Request,
    days: int = Query(90),
    incident_only: bool = True,
    confirmed_only: bool = False,
    user: dict = Depends(require_auth),
):
    text = await generate_exec_brief(days, incident_only, confirmed_only)
    await write_audit(user["username"], "generate_exec_brief",
                      detail={"days": days, "incident_only": incident_only, "confirmed_only": confirmed_only},
                      ip=_ip(request))
    return {"brief": text, "generated_at": datetime.now(timezone.utc).isoformat()}
