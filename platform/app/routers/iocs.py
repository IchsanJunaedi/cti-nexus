import csv
import io
import json
from datetime import date

from fastapi import APIRouter, Depends, Query, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from typing import Literal
from app.services.ioc_service import (
    get_iocs, get_ioc_detail, get_ioc_stats, tag_ioc, get_ioc_ta_links,
    tag_ioc_threat_actors, untag_ioc_threat_actor, submit_feedback,
    delete_ioc, bulk_delete_iocs, get_related_iocs,
    set_ioc_tlp, set_ioc_kill_chain, add_ioc_techniques, remove_ioc_technique,
)
from app.services.ioc_allowlist_service import (
    list_allowlist, add_allowlist_entry, remove_allowlist_entry,
)
from app.services.fp_analytics_service import get_fp_analytics
from app.services.audit_service import write_audit
from app.auth import require_auth, require_permission, effective_client_id
from app.config import IOC_FEED_TOKEN


def _worst_enrichment_verdict(doc: dict) -> str:
    enrichment = doc.get("enrichment") or {}
    providers = enrichment.get("providers") or []
    order = {"malicious": 4, "suspicious": 3, "clean": 1, "unknown": 0}
    worst = ""
    for p in providers:
        v = (p.get("verdict") or "unknown").lower()
        if not worst or order.get(v, 0) > order.get(worst, 0):
            worst = v
    return worst


def _csv_rows(docs: list[dict]):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "type", "value", "confidence_score", "actionability_label",
        "recommended_action", "first_seen", "last_seen", "seen_count",
        "threat_actors", "enrichment_verdict",
    ])
    yield buf.getvalue()
    for doc in docs:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            doc.get("type", ""),
            doc.get("value", ""),
            doc.get("confidence_score", ""),
            doc.get("actionability_label", ""),
            doc.get("recommended_action", ""),
            doc.get("first_seen", ""),
            doc.get("last_seen", ""),
            doc.get("seen_count", ""),
            ";".join(doc.get("threat_actors") or []),
            _worst_enrichment_verdict(doc),
        ])
        yield buf.getvalue()


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


class TagBody(BaseModel):
    tags: list[str]


class ThreatActorBody(BaseModel):
    threat_actors: list[str]


class FeedbackBody(BaseModel):
    verdict: Literal["tp", "fp"]
    note: str | None = None


class AllowlistBody(BaseModel):
    type: Literal["domain", "ip"]
    value: str


class TLPBody(BaseModel):
    tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]


class KillChainBody(BaseModel):
    phase: Literal[
        "reconnaissance", "weaponization", "delivery", "exploitation",
        "installation", "command-and-control", "actions-on-objectives",
    ]


class TechniquesBody(BaseModel):
    techniques: list[str]


@router.get("")
async def list_iocs(
    ioc_type: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: str | None = None,
    actionability: str | None = None,
    enrichment_verdict: str | None = None,
    user: dict = Depends(require_auth),
):
    docs, total = await get_iocs(
        ioc_type=ioc_type, search=search, page=page, page_size=page_size,
        sort_by=sort_by, actionability=actionability, enrichment_verdict=enrichment_verdict,
    )
    return {"iocs": docs, "total": total, "page": page, "page_size": page_size}


@router.get("/stats")
async def ioc_stats(user: dict = Depends(require_auth)):
    return await get_ioc_stats()


@router.get("/allowlist")
async def ioc_allowlist_list(user: dict = Depends(require_auth)):
    return {"entries": await list_allowlist()}


@router.post("/allowlist")
async def ioc_allowlist_add(
    body: AllowlistBody,
    request: Request,
    user: dict = Depends(require_permission("manage_ioc")),
):
    try:
        entry = await add_allowlist_entry(body.type, body.value, user["username"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    await write_audit(
        user["username"], "add_ioc_allowlist",
        target_id=f"{body.type}:{body.value}",
        detail={"deleted_iocs": entry.get("deleted_iocs", 0)},
        ip=_ip(request),
    )
    return entry


@router.delete("/allowlist/{entry_id}")
async def ioc_allowlist_remove(
    entry_id: str,
    request: Request,
    user: dict = Depends(require_permission("manage_ioc")),
):
    ok = await remove_allowlist_entry(entry_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Allowlist entry not found")
    await write_audit(user["username"], "remove_ioc_allowlist", target_id=entry_id, ip=_ip(request))
    return {"ok": True}


@router.post("/{ioc_type}/{value:path}/threat-actors")
async def add_ioc_threat_actors(
    ioc_type: str,
    value: str,
    body: ThreatActorBody,
    request: Request,
    user: dict = Depends(require_auth),
):
    ok = await tag_ioc_threat_actors(ioc_type, value, body.threat_actors)
    if not ok:
        raise HTTPException(status_code=404, detail="IOC not found")
    await write_audit(user["username"], "tag_ioc_ta", target_id=f"{ioc_type}/{value}",
                      detail={"threat_actors": body.threat_actors}, ip=_ip(request))
    return {"ok": True}


@router.delete("/{ioc_type}/{value:path}/threat-actors/{actor}")
async def remove_ioc_threat_actor(
    ioc_type: str,
    value: str,
    actor: str,
    request: Request,
    user: dict = Depends(require_auth),
):
    ok = await untag_ioc_threat_actor(ioc_type, value, actor)
    if not ok:
        raise HTTPException(status_code=404, detail="IOC not found")
    await write_audit(user["username"], "untag_ioc_ta", target_id=f"{ioc_type}/{value}",
                      detail={"actor": actor}, ip=_ip(request))
    return {"ok": True}


@router.post("/{ioc_type}/{value:path}/tlp")
async def set_ioc_tlp_route(
    ioc_type: str,
    value: str,
    body: TLPBody,
    request: Request,
    user: dict = Depends(require_auth),
):
    try:
        ok = await set_ioc_tlp(ioc_type, value, body.tlp)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="IOC not found")
    await write_audit(user["username"], "set_ioc_tlp", target_id=f"{ioc_type}/{value}",
                      detail={"tlp": body.tlp}, ip=_ip(request))
    return {"ok": True}


@router.post("/{ioc_type}/{value:path}/kill-chain")
async def set_ioc_kill_chain_route(
    ioc_type: str,
    value: str,
    body: KillChainBody,
    request: Request,
    user: dict = Depends(require_auth),
):
    try:
        ok = await set_ioc_kill_chain(ioc_type, value, body.phase)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="IOC not found")
    await write_audit(user["username"], "set_ioc_kill_chain", target_id=f"{ioc_type}/{value}",
                      detail={"phase": body.phase}, ip=_ip(request))
    return {"ok": True}


@router.post("/{ioc_type}/{value:path}/techniques")
async def add_ioc_techniques_route(
    ioc_type: str,
    value: str,
    body: TechniquesBody,
    request: Request,
    user: dict = Depends(require_auth),
):
    ok = await add_ioc_techniques(ioc_type, value, body.techniques)
    if not ok:
        raise HTTPException(status_code=404, detail="IOC not found")
    await write_audit(user["username"], "add_ioc_techniques", target_id=f"{ioc_type}/{value}",
                      detail={"techniques": body.techniques}, ip=_ip(request))
    return {"ok": True}


@router.delete("/{ioc_type}/{value:path}/techniques/{technique}")
async def remove_ioc_technique_route(
    ioc_type: str,
    value: str,
    technique: str,
    request: Request,
    user: dict = Depends(require_auth),
):
    ok = await remove_ioc_technique(ioc_type, value, technique)
    if not ok:
        raise HTTPException(status_code=404, detail="IOC not found")
    await write_audit(user["username"], "remove_ioc_technique", target_id=f"{ioc_type}/{value}",
                      detail={"technique": technique}, ip=_ip(request))
    return {"ok": True}


@router.delete("/{ioc_id}")
async def delete_ioc_by_id(
    ioc_id: str,
    request: Request,
    user: dict = Depends(require_permission("manage_ioc")),
):
    ok = await delete_ioc(ioc_id)
    if not ok:
        raise HTTPException(status_code=404, detail="IOC not found")
    await write_audit(user["username"], "delete_ioc", target_id=ioc_id, ip=_ip(request))
    return {"ok": True}


@router.post("/bulk-delete")
async def bulk_delete(
    body: dict,
    request: Request,
    user: dict = Depends(require_permission("manage_ioc")),
):
    ioc_ids: list[str] = body.get("ids", [])
    if not ioc_ids:
        raise HTTPException(status_code=400, detail="ids required")
    count = await bulk_delete_iocs(ioc_ids)
    await write_audit(user["username"], "bulk_delete_iocs", detail={"count": count}, ip=_ip(request))
    return {"deleted": count}


@router.get("/fp-analytics")
async def ioc_fp_analytics(
    force: bool = Query(False),
    user: dict = Depends(require_auth),
):
    return await get_fp_analytics(force=force)


@router.post("/fp-analytics/apply-suggestions")
async def apply_fp_suggestions(
    request: Request,
    user: dict = Depends(require_permission("manage_ioc")),
):
    analytics = await get_fp_analytics()
    suggestions = analytics.get("suggested_allowlist", [])
    added = 0
    skipped = 0
    for s in suggestions:
        al_type = s.get("allowlist_type")
        value = s.get("value", "")
        if not al_type or not value:
            continue
        if al_type == "domain" and "@" in value:
            value = value.split("@")[-1]
        try:
            await add_allowlist_entry(al_type, value, user["username"])
            added += 1
        except Exception:
            skipped += 1
    await write_audit(
        user["username"], "apply_fp_suggestions",
        detail={"added": added, "skipped": skipped},
        ip=_ip(request),
    )
    return {"added": added, "skipped": skipped}


@router.post("/{ioc_id}/feedback")
async def ioc_feedback(
    ioc_id: str,
    body: FeedbackBody,
    request: Request,
    x_client_id: str | None = None,
    user: dict = Depends(require_auth),
):
    client_id = effective_client_id(user, x_client_id)
    doc = await submit_feedback(
        ioc_id=ioc_id,
        user_id=user["username"],
        client_id=client_id,
        verdict=body.verdict,
        note=body.note,
    )
    if doc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    return doc


@router.get("/ta-links/{ioc_type}/{value:path}")
async def ioc_ta_links(
    ioc_type: str,
    value: str,
    user: dict = Depends(require_auth),
):
    result = await get_ioc_ta_links(ioc_type, value)
    if result is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    return result


@router.get("/related/{ioc_type}/{value:path}")
async def ioc_related(
    ioc_type: str,
    value: str,
    user: dict = Depends(require_auth),
):
    result = await get_related_iocs(ioc_type, value)
    if result is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    return result


@router.get("/export.csv")
async def export_iocs_csv(
    ioc_type: str | None = None,
    search: str | None = None,
    actionability: str | None = None,
    enrichment_verdict: str | None = None,
    user: dict = Depends(require_auth),
):
    docs, _ = await get_iocs(
        ioc_type=ioc_type,
        search=search,
        actionability=actionability,
        enrichment_verdict=enrichment_verdict,
        page=1,
        page_size=10000,
    )
    fname = f"iocs-{date.today().isoformat()}.csv"
    return StreamingResponse(
        _csv_rows(docs),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/feed")
async def ioc_feed(
    request: Request,
    format: str = Query("plain", pattern="^(plain|csv|stix)$"),
    actionability: str = Query("block_now"),
    token: str | None = Query(None),
):
    header_token = request.headers.get("X-Feed-Token")
    provided = token or header_token or ""
    if not IOC_FEED_TOKEN or provided != IOC_FEED_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if format == "stix":
        from app.services.stix_service import build_ioc_stix_bundle
        bundle = await build_ioc_stix_bundle(actionability=actionability, limit=10000)
        fname = f"iocs-feed-{date.today().isoformat()}.json"
        return JSONResponse(
            content=bundle,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    docs, _ = await get_iocs(actionability=actionability, page=1, page_size=10000)

    if format == "plain":
        content = "\n".join(doc.get("value", "") for doc in docs)
        return StreamingResponse(iter([content]), media_type="text/plain")

    fname = f"iocs-feed-{date.today().isoformat()}.csv"
    return StreamingResponse(
        _csv_rows(docs),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/{ioc_type}/{value:path}")
async def ioc_detail(
    ioc_type: str,
    value: str,
    user: dict = Depends(require_auth),
):
    doc = await get_ioc_detail(ioc_type, value)
    if not doc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return doc


@router.post("/{ioc_type}/{value:path}/tags")
async def add_ioc_tags(
    ioc_type: str,
    value: str,
    body: TagBody,
    request: Request,
    user: dict = Depends(require_auth),
):
    ok = await tag_ioc(ioc_type, value, body.tags)
    if not ok:
        raise HTTPException(status_code=404, detail="IOC not found")
    await write_audit(user["username"], "tag_ioc", target_id=f"{ioc_type}/{value}",
                      detail={"tags": body.tags}, ip=_ip(request))
    return {"ok": True}
