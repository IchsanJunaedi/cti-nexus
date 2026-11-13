import io
from fastapi import APIRouter, Body, Depends, HTTPException, Header, Query, Request
from fastapi.responses import StreamingResponse
from app.services.cve_priority_service import prioritize_campaign_cves
from app.models.cve_tracker import AcknowledgeRequest, CveOut, CveListResponse, CveStats, CveTicket
from app.services.cve_service import (
    get_cves, get_cve_stats, get_tech_list, get_tp_cve_ids,
    mark_false_positive, unmark_false_positive, bulk_mark_false_positive,
    purge_orphaned_cves,
)
from app.services.cve_ticket_service import get_ticket, upsert_ticket, acknowledge_cve, bulk_acknowledge_cves, get_next_ticket_id, get_ack_statuses
from app.services.cve_email_service import draft_email_for_cves, get_cve_email_recipients
from app.services.exploit_db_service import lookup_and_save_single, lookup_all_true_positives
from app.services.cisa_kev_service import lookup_all_true_positives as cisa_lookup_all
from app.services.mermaid_service import (
    build_cve_mindmap_by_id as build_cve_report_by_cve_id,
    get_or_generate, get_cached_mindmap, get_display_syntax,
)
from app.services.epss_service import lookup_all_true_positives as epss_lookup_all
from app.services.audit_service import write_audit
from app.services.cve_export_service import export_cves_to_excel
from app.auth import require_auth, effective_client_id

router = APIRouter(prefix="/api/cve", tags=["cve"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


@router.get("", response_model=CveListResponse)
async def list_cves(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    tech: list[str] | None = Query(None),
    severity: list[str] | None = Query(None),
    search: str | None = None,
    date_start: str | None = None,
    date_end: str | None = None,
    include_fp: bool = False,
    sort_by: str = Query("published", pattern="^(tech|severity|published|epss)$"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
    ack_filter: str | None = Query(None, pattern="^(acked|unacked)$"),
    draft_filter: str | None = Query(None, pattern="^(drafted|undrafted)$"),
    kev_filter: str | None = Query(None, pattern="^(kev|not_kev)$"),
    score_filter: str | None = Query(None, pattern="^(unscored|scored)$"),
    updated_filter: str | None = Query(None, pattern="^updated$"),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    cves, total = await get_cves(
        page=page, page_size=page_size, tech=tech, severity=severity,
        search=search, date_start=date_start, date_end=date_end,
        include_fp=include_fp, sort_by=sort_by, sort_dir=sort_dir,
        ack_filter=ack_filter, draft_filter=draft_filter, client_id=cid,
        kev_filter=kev_filter, score_filter=score_filter, updated_filter=updated_filter,
    )
    return CveListResponse(
        cves=[CveOut.from_mongo(c) for c in cves],
        total=total, page=page, page_size=page_size,
    )


@router.get("/tp-ids")
async def list_tp_cve_ids(
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    """Lightweight list of this client's tracked true-positive CVE IDs, for client-side tagging (e.g. News Room badges)."""
    cid = effective_client_id(user, x_client_id)
    return {"cve_ids": await get_tp_cve_ids(cid)}


@router.get("/stats", response_model=CveStats)
async def cve_stats(
    include_fp: bool = False,
    search:     str | None = Query(None),
    severity:   list[str] | None = Query(None),
    tech:       list[str] | None = Query(None),
    date_start: str | None = Query(None),
    date_end:   str | None = Query(None),
    ack_filter: str | None = Query(None, pattern="^(acked|unacked)$"),
    draft_filter: str | None = Query(None, pattern="^(drafted|undrafted)$"),
    kev_filter: str | None = Query(None, pattern="^(kev|not_kev)$"),
    score_filter: str | None = Query(None, pattern="^(unscored|scored)$"),
    updated_filter: str | None = Query(None, pattern="^updated$"),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    return await get_cve_stats(
        include_fp=include_fp, client_id=cid,
        search=search, severity=severity, tech=tech,
        date_start=date_start, date_end=date_end, ack_filter=ack_filter, draft_filter=draft_filter,
        kev_filter=kev_filter, score_filter=score_filter, updated_filter=updated_filter,
    )


@router.get("/export")
async def export_cves(
    date_start: str | None = Query(None, description="Start date YYYY-MM-DD"),
    date_end:   str | None = Query(None, description="End date YYYY-MM-DD"),
    search:     str | None = Query(None),
    severity:   list[str] | None = Query(None),
    tech:       list[str] | None = Query(None),
    include_fp: bool = Query(False),
    ack_filter: str | None = Query(None, pattern="^(acked|unacked)$"),
    draft_filter: str | None = Query(None, pattern="^(drafted|undrafted)$"),
    kev_filter: str | None = Query(None, pattern="^(kev|not_kev)$"),
    score_filter: str | None = Query(None, pattern="^(unscored|scored)$"),
    updated_filter: str | None = Query(None, pattern="^updated$"),
    request: Request = None,
    user: dict = Depends(require_auth),
):
    """Export filtered CVEs as an Excel file, respecting all active filter params."""
    try:
        data = await export_cves_to_excel(
            date_start=date_start, date_end=date_end,
            search=search, severity=severity, tech=tech,
            include_fp=include_fp, ack_filter=ack_filter, draft_filter=draft_filter,
            kev_filter=kev_filter, score_filter=score_filter, updated_filter=updated_filter,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=f"Template not found: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    from datetime import date
    filename = f"CVE_Tracker_Export_{date.today().strftime('%Y%m%d')}.xlsx"
    if date_start or date_end:
        filename = f"CVE_Tracker_{date_start or 'start'}_{date_end or 'end'}.xlsx"

    await write_audit(
        user["username"], "export_cve_excel",
        detail={"date_start": date_start, "date_end": date_end, "search": search,
                "severity": severity, "tech": tech, "ack_filter": ack_filter, "draft_filter": draft_filter,
                "kev_filter": kev_filter, "score_filter": score_filter, "updated_filter": updated_filter},
        ip=_ip(request) if request else "",
    )
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/tech-list")
async def tech_list(
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    return await get_tech_list(client_id=cid)


@router.get("/next-ticket-id")
async def next_ticket_id(
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    return {"ticket_id": await get_next_ticket_id(cid)}


@router.get("/ack-statuses")
async def ack_statuses(
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    return await get_ack_statuses(client_id=cid)


@router.get("/email-recipients")
async def cve_email_recipients(
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    """Recipients for CVE notification emails — same list used for the client newsletter."""
    cid = effective_client_id(user, x_client_id)
    return {"client_id": cid, "recipients": await get_cve_email_recipients(cid)}


@router.post("/draft-email")
async def create_draft_email(
    request: Request,
    body: dict = Body(...),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cve_ids = body.get("cve_ids", [])
    if not cve_ids:
        raise HTTPException(status_code=400, detail="cve_ids required")
    mode = body.get("mode", "send")
    if mode not in ("send", "eml"):
        raise HTTPException(status_code=400, detail="mode must be 'send' or 'eml'")
    lang = body.get("lang", "en")
    if lang not in ("en", "id"):
        raise HTTPException(status_code=400, detail="lang must be 'en' or 'id'")
    recipients = body.get("recipients")  # optional override (e.g. user unchecked some addresses)
    custom_instruction = body.get("custom_instruction")  # optional free-text LLM edit request
    cid = effective_client_id(user, x_client_id)
    ticket_id = body.get("ticket_id") or await get_next_ticket_id(cid)
    try:
        result = await draft_email_for_cves(
            cve_ids, ticket_id, client_id=cid, mode=mode, lang=lang, recipients=recipients,
            custom_instruction=custom_instruction,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    await write_audit(
        user["username"], "draft_email",
        detail={"cve_ids": cve_ids, "mode": mode, "lang": lang}, ip=_ip(request),
    )

    if mode == "eml":
        filename = f"{ticket_id or 'cve-notification'}.eml"
        return StreamingResponse(
            io.BytesIO(result["eml_bytes"]),
            media_type="message/rfc822",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    return result


@router.post("/{cve_id}/false-positive")
async def set_false_positive(
    cve_id: str, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    await mark_false_positive(cve_id, client_id=cid)
    await write_audit(user["username"], "mark_false_positive", target_id=cve_id, ip=_ip(request))
    return {"ok": True}


@router.delete("/{cve_id}/false-positive")
async def remove_false_positive(
    cve_id: str, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    await unmark_false_positive(cve_id, client_id=cid)
    await write_audit(user["username"], "unmark_false_positive", target_id=cve_id, ip=_ip(request))
    return {"ok": True}


@router.get("/{cve_id}/ticket")
async def get_cve_ticket(
    cve_id: str,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    return await get_ticket(cve_id, client_id=cid) or {}


@router.put("/{cve_id}/ticket")
async def update_cve_ticket(
    cve_id: str, ticket: CveTicket, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    await upsert_ticket(cve_id, ticket.model_dump(exclude={"cve_id"}), client_id=cid)
    await write_audit(user["username"], "update_ticket", target_id=cve_id, ip=_ip(request))
    return {"ok": True}


@router.post("/purge-orphaned")
async def purge_orphaned(
    request: Request, body: dict = Body(default={}),
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    """Delete CVEs whose tech is not in the active tech stack for this client.
    Pass {"dry_run": false} to actually delete. Default is dry_run=true (preview only).
    """
    dry_run = body.get("dry_run", True)
    cid = effective_client_id(user, x_client_id)
    result = await purge_orphaned_cves(client_id=cid, dry_run=dry_run)
    if not dry_run:
        await write_audit(user["username"], "purge_orphaned_cves",
                          detail={"deleted": result.get("deleted", 0), "by_tech": result.get("by_tech")},
                          ip=_ip(request))
    return result


@router.post("/bulk-acknowledge")
async def bulk_acknowledge(
    request: Request, body: dict = Body(...),
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cve_ids = body.get("cve_ids", [])
    analyst_name = (body.get("analyst_name") or "").strip()
    if not cve_ids:
        raise HTTPException(status_code=400, detail="cve_ids required")
    if not analyst_name:
        raise HTTPException(status_code=400, detail="analyst_name required")
    if len(cve_ids) > 100:
        raise HTTPException(status_code=400, detail="max 100 CVEs per bulk operation")
    cid = effective_client_id(user, x_client_id)
    acknowledged = await bulk_acknowledge_cves(cve_ids, analyst_name, client_id=cid)
    await write_audit(user["username"], "bulk_acknowledge_cve",
                      detail={"cve_ids": cve_ids, "analyst_name": analyst_name, "acknowledged": acknowledged},
                      ip=_ip(request))
    return {"ok": True, "acknowledged": acknowledged}


@router.post("/bulk-false-positive")
async def set_bulk_false_positive(
    request: Request, body: dict = Body(...),
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cve_ids = body.get("cve_ids", [])
    if not cve_ids:
        raise HTTPException(status_code=400, detail="cve_ids required")
    if len(cve_ids) > 100:
        raise HTTPException(status_code=400, detail="max 100 CVEs per bulk operation")
    cid = effective_client_id(user, x_client_id)
    await bulk_mark_false_positive(cve_ids, client_id=cid)
    await write_audit(user["username"], "bulk_mark_false_positive",
                      detail={"cve_ids": cve_ids, "count": len(cve_ids)}, ip=_ip(request))
    return {"ok": True, "marked": len(cve_ids)}


@router.post("/cisa-lookup")
async def cisa_kev_lookup(request: Request, user: dict = Depends(require_auth)):
    """Cross-reference all TP CVEs against CISA Known Exploited Vulnerabilities catalog."""
    try:
        summary = await cisa_lookup_all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    await write_audit(user["username"], "cisa_kev_lookup", ip=_ip(request),
                      detail={"checked": summary["checked"], "matched": summary["matched"]})
    return summary


@router.post("/epss-lookup")
async def epss_lookup(request: Request, user: dict = Depends(require_auth)):
    """Fetch EPSS scores from FIRST.org for all true positive CVEs and persist results."""
    try:
        summary = await epss_lookup_all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    await write_audit(user["username"], "epss_lookup", ip=_ip(request),
                      detail={"checked": summary["checked"], "scored": summary["scored"]})
    return summary


@router.post("/exploit-lookup")
async def bulk_exploit_lookup(request: Request, user: dict = Depends(require_auth)):
    """Run exploit-db lookup for all true positive CVEs and save results."""
    try:
        summary = await lookup_all_true_positives()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    await write_audit(user["username"], "exploit_db_bulk_lookup", ip=_ip(request),
                      detail={"checked": summary["checked"], "with_exploits": summary["with_exploits"]})
    return summary


@router.post("/{cve_id}/exploit-lookup")
async def single_exploit_lookup(cve_id: str, request: Request, user: dict = Depends(require_auth)):
    """Run exploit-db lookup for a single CVE and save results."""
    result = await lookup_and_save_single(cve_id)
    if result["error"]:
        raise HTTPException(status_code=500, detail=result["error"])
    await write_audit(user["username"], "exploit_db_lookup", target_id=cve_id, ip=_ip(request))
    return result


@router.post("/{cve_id}/acknowledge")
async def acknowledge(
    cve_id: str,
    body: AcknowledgeRequest,
    request: Request,
    user: dict = Depends(require_auth),
):
    if not body.analyst_name.strip():
        raise HTTPException(status_code=400, detail="analyst_name required")
    cid = effective_client_id(user, request.headers.get("x-client-id"))
    await acknowledge_cve(cve_id, body.analyst_name, client_id=cid)
    await write_audit(user["username"], "acknowledge_cve", target_id=cve_id,
                      detail={"analyst_name": body.analyst_name}, ip=_ip(request))
    return {"ok": True}


@router.get("/{cve_id}/mindmap")
async def get_cve_mindmap(cve_id: str, regenerate: bool = False, _user=Depends(require_auth)):
    if regenerate:
        result = await build_cve_report_by_cve_id(cve_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        from app.services.mermaid_service import save_mindmap
        title, syntax = result
        doc = await save_mindmap("cve", cve_id, title, syntax)
    else:
        doc = await get_or_generate("cve", cve_id, lambda: build_cve_report_by_cve_id(cve_id))
        if doc is None:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return {
        "cve_id": cve_id,
        "title": doc.get("title", ""),
        "mermaid_syntax": doc.get("mermaid_syntax", ""),
        "custom_syntax": doc.get("custom_syntax") or None,
        "display_syntax": get_display_syntax(doc),
        "generated_at": doc.get("generated_at", ""),
    }


@router.get("/prioritize")
async def prioritize_cves(
    cves: str = Query(..., description="Comma-separated CVE IDs"),
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    """Ad-hoc CVE prioritization outside campaign context."""
    from app.auth import effective_client_id
    cid = effective_client_id(user, x_client_id)
    cve_list = [c.strip() for c in cves.split(",") if c.strip()]
    if not cve_list:
        raise HTTPException(status_code=400, detail="cves query param required")
    if len(cve_list) > 100:
        raise HTTPException(status_code=400, detail="Max 100 CVEs per request")
    result = await prioritize_campaign_cves(cve_list, {}, client_id=cid)
    return {"cves": result, "total": len(result)}
