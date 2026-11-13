from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request
from app.models.scenario import (
    ScenarioCreate, ScenarioUpdate, ScenarioStepsReplace, ScenarioOut, ScenarioListOut,
)
from app.services.scenario_service import (
    list_scenarios, get_scenario, create_scenario, update_scenario,
    replace_steps, delete_scenario,
)
from app.services.audit_service import write_audit
from app.auth import require_auth, effective_client_id

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _privileged(user: dict) -> bool:
    return user["role"] in ("admin", "superadmin")


@router.get("")
async def get_scenarios(
    diagram_id: str | None = Query(None),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    docs = await list_scenarios(cid, diagram_id=diagram_id)
    return [ScenarioListOut.from_mongo(d) for d in docs]


@router.get("/{scenario_id}")
async def get_scenario_ep(
    scenario_id: str,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    doc = await get_scenario(scenario_id, cid)
    if not doc:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return ScenarioOut.from_mongo(doc)


@router.post("")
async def post_scenario(
    body: ScenarioCreate,
    request: Request,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    doc = await create_scenario(body.model_dump(), cid, user["username"])
    await write_audit(
        user["username"], "create_scenario", target_id=str(doc["_id"]),
        detail={"name": body.name, "diagram_id": body.diagram_id}, ip=_ip(request),
    )
    return ScenarioOut.from_mongo(doc)


@router.put("/{scenario_id}")
async def put_scenario(
    scenario_id: str,
    body: ScenarioUpdate,
    request: Request,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    doc = await update_scenario(scenario_id, cid, body.model_dump(exclude_none=True))
    if not doc:
        raise HTTPException(status_code=404, detail="Scenario not found")
    await write_audit(user["username"], "update_scenario", target_id=scenario_id, ip=_ip(request))
    return ScenarioOut.from_mongo(doc)


@router.put("/{scenario_id}/steps")
async def put_scenario_steps(
    scenario_id: str,
    body: ScenarioStepsReplace,
    request: Request,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    doc = await replace_steps(scenario_id, cid, body.steps)
    if not doc:
        raise HTTPException(status_code=404, detail="Scenario not found")
    await write_audit(
        user["username"], "update_scenario_steps", target_id=scenario_id,
        detail={"step_count": len(body.steps)}, ip=_ip(request),
    )
    return ScenarioOut.from_mongo(doc)


@router.delete("/{scenario_id}")
async def remove_scenario(
    scenario_id: str,
    request: Request,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    ok = await delete_scenario(scenario_id, cid, user["username"], _privileged(user))
    if not ok:
        raise HTTPException(status_code=404, detail="Scenario not found")
    await write_audit(user["username"], "delete_scenario", target_id=scenario_id, ip=_ip(request))
    return {"deleted": True}
