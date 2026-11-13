import asyncio
from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile
from app.models.pkg_vuln import (
    MonitoredPackage, MonitoredPackageAdd, MonitoredPackageEdit,
    MonitoredPackageListResponse,
    PackageVuln, PackageVulnListResponse, LockfileImportResult,
)
from app.services.pkg_vuln_service import (
    list_packages, add_package, update_package, delete_package, get_package_by_id,
    list_vulns, acknowledge_vuln, get_stats,
    scan_package, scan_all_packages, import_lockfile,
    resolve_package_deps, get_package_deps,
)
from app.services.audit_service import write_audit
from app.auth import require_auth, effective_client_id

router = APIRouter(prefix="/api/pkgvuln", tags=["pkgvuln"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


# ── Packages ──────────────────────────────────────────────────────────────────

@router.get("/packages", response_model=MonitoredPackageListResponse)
async def get_packages(
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("name"),
    sort_dir: str = Query("asc"),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    items, total = await list_packages(
        search=search, page=page, page_size=page_size,
        sort_by=sort_by, sort_dir=sort_dir, client_id=cid,
    )
    return MonitoredPackageListResponse(
        items=[MonitoredPackage.from_mongo(i) for i in items],
        total=total, page=page, page_size=page_size,
    )


@router.post("/packages")
async def post_package(
    body: MonitoredPackageAdd, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await add_package(body.name, body.ecosystem, version=body.version, client_id=cid)
    if not result.get("success"):
        raise HTTPException(status_code=409, detail=result.get("reason", "error"))
    ver_str = f"@{body.version}" if body.version else ""
    await write_audit(user["username"], "add_monitored_package",
                      target_id=f"{body.name}{ver_str}/{body.ecosystem}", ip=_ip(request))
    return result


@router.patch("/packages/{pkg_id}")
async def patch_package(
    pkg_id: str, body: MonitoredPackageEdit, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await update_package(pkg_id, version=body.version, ecosystem=body.ecosystem, client_id=cid)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("reason", "not found"))
    await write_audit(user["username"], "edit_monitored_package",
                      target_id=pkg_id, ip=_ip(request))
    return result


@router.delete("/packages/{pkg_id}")
async def remove_package(
    pkg_id: str, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await delete_package(pkg_id, client_id=cid)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("reason", "not found"))
    await write_audit(user["username"], "delete_monitored_package",
                      target_id=pkg_id, ip=_ip(request))
    return result


@router.post("/packages/{pkg_id}/resolve-deps")
async def resolve_deps(
    pkg_id: str, request: Request,
    scan_transitive: bool = Query(False),
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    doc = await get_package_by_id(pkg_id, cid)
    if not doc:
        raise HTTPException(status_code=404, detail="Package not found")
    asyncio.create_task(resolve_package_deps(pkg_id, cid, scan_transitive))
    await write_audit(user["username"], "resolve_package_deps",
                      target_id=f"{doc['name']}/{doc['ecosystem']}", ip=_ip(request))
    return {"started": True, "package": doc["name"], "ecosystem": doc["ecosystem"]}


@router.get("/packages/{pkg_id}/deps")
async def get_deps(
    pkg_id: str,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await get_package_deps(pkg_id, cid)
    if not result:
        raise HTTPException(status_code=404, detail="No dependency graph found — resolve first")
    result["_id"] = str(result["_id"])
    return result


@router.post("/packages/{pkg_id}/scan")
async def scan_one_package(
    pkg_id: str, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    doc = await get_package_by_id(pkg_id, cid)
    if not doc:
        raise HTTPException(status_code=404, detail="Package not found")
    asyncio.create_task(scan_package(doc["name"], doc["ecosystem"], doc.get("version"), cid))
    await write_audit(user["username"], "scan_package",
                      target_id=f"{doc['name']}/{doc['ecosystem']}", ip=_ip(request))
    return {"started": True, "package": doc["name"], "ecosystem": doc["ecosystem"],
            "version": doc.get("version")}


@router.post("/scan")
async def scan_all(
    request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    asyncio.create_task(scan_all_packages(cid))
    await write_audit(user["username"], "scan_all_packages", ip=_ip(request))
    return {"started": True}


@router.post("/import-lockfile", response_model=LockfileImportResult)
async def import_lockfile_endpoint(
    request: Request,
    file: UploadFile = File(...),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    """Upload a lockfile (requirements.txt, package-lock.json, go.mod, pom.xml, poetry.lock).
    Parses packages with pinned versions and adds them to monitoring."""
    cid = effective_client_id(user, x_client_id)
    content_bytes = await file.read()
    try:
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as UTF-8")
    if len(content) > 2_000_000:
        raise HTTPException(status_code=413, detail="File too large (max 2 MB)")
    result = await import_lockfile(file.filename or "unknown", content, client_id=cid)
    await write_audit(user["username"], "import_lockfile",
                      target_id=file.filename or "unknown",
                      detail={"parsed": result["parsed"], "added": result["added"]},
                      ip=_ip(request))
    return LockfileImportResult(**result)


# ── Vulnerabilities ────────────────────────────────────────────────────────────

@router.get("/vulns", response_model=PackageVulnListResponse)
async def get_vulns(
    package_name: str | None = None,
    ecosystem: str | None = None,
    severity: str | None = None,
    kev_only: bool = Query(False),
    acknowledged: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("adjusted_score"),
    sort_dir: str = Query("desc"),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    items, total = await list_vulns(
        package_name=package_name, ecosystem=ecosystem, severity=severity,
        kev_only=kev_only, acknowledged=acknowledged, search=search,
        page=page, page_size=page_size, sort_by=sort_by, sort_dir=sort_dir,
        client_id=cid,
    )
    return PackageVulnListResponse(
        items=[PackageVuln.from_mongo(i) for i in items],
        total=total, page=page, page_size=page_size,
    )


@router.patch("/vulns/{vuln_id}/ack")
async def ack_vuln(
    vuln_id: str, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await acknowledge_vuln(vuln_id, user["username"], client_id=cid)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("reason", "not found"))
    return result


# ── Stats ──────────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_pkg_stats(
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    return await get_stats(cid)
