from fastapi import APIRouter, Query, HTTPException, BackgroundTasks, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from app.services import attack_sync_service as svc
from app.auth import require_auth, require_permission
from app.services.audit_service import write_audit

router = APIRouter(prefix="/api/attack", tags=["attack"], dependencies=[Depends(require_auth)])


class SyncRequest(BaseModel):
    domains: list[str] | None = None  # None = all


@router.get("/status")
async def attack_status():
    return await svc.get_sync_status()


@router.post("/sync")
async def attack_sync(body: SyncRequest, request: Request, background_tasks: BackgroundTasks, admin: dict = Depends(require_permission("manage_intel"))):
    domains = body.domains if body.domains else list(svc._DOMAINS.keys())
    invalid = [d for d in domains if d not in svc._DOMAINS]
    if invalid:
        raise HTTPException(400, f"Unknown domains: {invalid}")

    async def _run():
        for key in domains:
            try:
                await svc.sync_domain(key)
            except Exception as e:
                print(f"[ATT&CK sync] {key} failed: {e}")

    background_tasks.add_task(_run)
    ip = request.client.host if request.client else ""
    await write_audit(admin["username"], "attack_sync", detail={"domains": domains}, ip=ip)
    return {"status": "started", "domains": domains}


@router.get("/sync/{domain_key}")
async def attack_sync_single(domain_key: str, request: Request, background_tasks: BackgroundTasks, admin: dict = Depends(require_permission("manage_intel"))):
    if domain_key not in svc._DOMAINS:
        raise HTTPException(404, f"Unknown domain: {domain_key}")

    async def _run():
        try:
            await svc.sync_domain(domain_key)
        except Exception as e:
            print(f"[ATT&CK sync] {domain_key} failed: {e}")

    background_tasks.add_task(_run)
    ip = request.client.host if request.client else ""
    await write_audit(admin["username"], "attack_sync", detail={"domains": [domain_key]}, ip=ip)
    return {"status": "started", "domain": domain_key}


@router.get("/techniques")
async def list_techniques(
    domain: str | None = Query(None),
    tactic: str | None = Query(None),
    search: str | None = Query(None),
    is_subtechnique: bool | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    docs, total = await svc.get_techniques(
        domain=domain, tactic=tactic, search=search,
        is_subtechnique=is_subtechnique, page=page, page_size=page_size,
    )
    return {"techniques": docs, "total": total, "page": page, "page_size": page_size}


@router.get("/tactics/distinct")
async def distinct_tactics(domain: str | None = Query(None)):
    filt = {"domains": domain} if domain else {}
    from app.database import get_database
    col = get_database()["attack_techniques"]
    values = await col.distinct("tactics", filt)
    return sorted([v for v in values if v])


@router.get("/techniques/{attack_id}")
async def get_technique(attack_id: str):
    doc = await svc.get_technique(attack_id)
    if not doc:
        raise HTTPException(404, "Technique not found")
    return doc


@router.get("/tactics")
async def list_tactics(domain: str | None = Query(None)):
    return await svc.get_tactics(domain=domain)


@router.get("/mitigations")
async def list_mitigations(
    domain: str | None = Query(None),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    docs, total = await svc.get_mitigations(domain=domain, search=search, page=page, page_size=page_size)
    return {"mitigations": docs, "total": total, "page": page, "page_size": page_size}


@router.get("/groups")
async def list_groups(
    domain: str | None = Query(None),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    docs, total = await svc.get_groups(domain=domain, search=search, page=page, page_size=page_size)
    return {"groups": docs, "total": total, "page": page, "page_size": page_size}


@router.get("/groups/{group_id}")
async def get_group(group_id: str):
    doc = await svc.get_group(group_id)
    if not doc:
        raise HTTPException(404, "Group not found")
    return doc


@router.get("/software")
async def list_software(
    domain: str | None = Query(None),
    sw_type: str | None = Query(None, alias="type"),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    docs, total = await svc.get_software(domain=domain, sw_type=sw_type, search=search, page=page, page_size=page_size)
    return {"software": docs, "total": total, "page": page, "page_size": page_size}


@router.get("/software/{software_id}")
async def get_software_item(software_id: str):
    doc = await svc.get_software_item(software_id)
    if not doc:
        raise HTTPException(404, "Software not found")
    return doc


@router.get("/navigator-layer")
async def attack_navigator_layer(
    domain: str | None = Query(None),
    tactic: str | None = Query(None),
    search: str | None = Query(None),
    is_subtechnique: bool | None = Query(None),
    group_id: str | None = Query(None),
):
    layer = await svc.get_navigator_layer(
        domain=domain, tactic=tactic, search=search,
        is_subtechnique=is_subtechnique, group_id=group_id,
    )
    return JSONResponse(content=layer)
