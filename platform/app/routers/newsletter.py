import asyncio
import json
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from app.auth import require_auth
from app.services.audit_service import write_audit


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""
from app.services.newsletter_service import (
    build_newsletter_context,
    delete_newsletter,
    fetch_articles_by_ids,
    get_all_paywall_hints,
    get_newsletter_doc,
    get_newsletter_html,
    list_newsletters,
    render_newsletter_html,
    save_newsletter,
)
from app.services.client_service import get_client
from app.services.role_service import role_has_permission
from app.config import (
    EMAIL_METHOD, CVE_EMAIL_SENDER, CVE_EMAIL_CC,
    AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID,
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_USE_TLS,
)

router = APIRouter(prefix="/api/newsletter", tags=["newsletter"])


async def _allowed_client_ids(user: dict) -> list[str] | None:
    """None = unrestricted (superadmin / user managers), else the user's assigned client ids."""
    if user["role"] == "superadmin" or await role_has_permission(user["role"], "manage_users"):
        return None
    return list(user.get("client_ids", []))


async def _require_client_access(user: dict, client_id: str) -> None:
    allowed = await _allowed_client_ids(user)
    if allowed is not None and client_id not in allowed:
        raise HTTPException(status_code=403, detail="Not assigned to this client")


def _require_recipients(to_addrs: list[str] | None) -> None:
    """Auto-send must never fall back to the sender mailbox: refuse if the client has no recipients."""
    if EMAIL_METHOD == "graph_send" and not to_addrs:
        raise HTTPException(status_code=400, detail="This client has no recipients configured; add recipients before sending")


def _validate_section(ids: list, max_count: int, name: str) -> None:
    if len(ids) > max_count:
        raise HTTPException(status_code=400, detail=f"{name}: max {max_count} articles")


async def _resolve_sections(body: dict) -> tuple[dict, list, list, list, list]:
    highlight_id = body.get("highlight")
    apac_ids = body.get("apac", [])
    global_ids = body.get("global_news", [])
    indonesia_ids = body.get("indonesia", [])

    if not highlight_id:
        raise HTTPException(status_code=400, detail="highlight article id required")
    _validate_section(apac_ids, 5, "apac")
    _validate_section(global_ids, 5, "global_news")
    _validate_section(indonesia_ids, 5, "indonesia")

    all_ids = [highlight_id] + apac_ids + global_ids + indonesia_ids
    articles = await fetch_articles_by_ids(all_ids)

    if highlight_id not in articles:
        raise HTTPException(status_code=404, detail=f"Highlight article {highlight_id} not found; re-pick it")

    missing: list[str] = []

    def _keep(ids: list) -> list:
        kept = []
        for aid in ids:
            if aid in articles:
                kept.append(articles[aid])
            else:
                missing.append(aid)
        return kept

    return (
        articles[highlight_id],
        _keep(apac_ids),
        _keep(global_ids),
        _keep(indonesia_ids),
        missing,
    )


def _send_newsletter_email(html_content: str, subject: str, to_addrs: list[str] | None = None) -> str:
    to_addrs = to_addrs or [CVE_EMAIL_SENDER]
    if EMAIL_METHOD == "smtp":
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from datetime import datetime

        cc_addrs = [a.strip() for a in CVE_EMAIL_CC.split(",") if a.strip()]
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = CVE_EMAIL_SENDER
        msg["To"] = ", ".join(to_addrs)
        if cc_addrs:
            msg["Cc"] = ", ".join(cc_addrs)
        msg.attach(MIMEText(html_content, "html", "utf-8"))
        recipients = to_addrs + cc_addrs

        if SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.ehlo(); s.starttls(); s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(CVE_EMAIL_SENDER, recipients, msg.as_string())
        else:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as s:
                s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(CVE_EMAIL_SENDER, recipients, msg.as_string())

        return f"smtp-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    # Microsoft Graph: draft (EMAIL_METHOD=graph) or send immediately (EMAIL_METHOD=graph_send)
    import msal
    import requests as http_requests

    authority = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
    app = msal.ConfidentialClientApplication(
        AZURE_CLIENT_ID, authority=authority, client_credential=AZURE_CLIENT_SECRET
    )
    resp = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    token = resp.get("access_token")
    if not token:
        raise RuntimeError("Failed to acquire Azure access token")

    to_list = [{"emailAddress": {"address": a}} for a in to_addrs]
    cc_list = [
        {"emailAddress": {"address": a.strip()}}
        for a in CVE_EMAIL_CC.split(",") if a.strip()
    ]
    payload = {
        "subject": subject,
        "body": {"contentType": "html", "content": html_content},
        "toRecipients": to_list,
        "ccRecipients": cc_list,
    }
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    if EMAIL_METHOD == "graph_send":
        from datetime import datetime
        r = http_requests.post(
            f"https://graph.microsoft.com/v1.0/users/{CVE_EMAIL_SENDER}/sendMail",
            headers=headers,
            data=json.dumps({"message": payload, "saveToSentItems": True}),
        )
        if r.status_code != 202:
            raise RuntimeError(f"Graph API error {r.status_code}: {r.text[:200]}")
        return f"graph-sent-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    r = http_requests.post(
        f"https://graph.microsoft.com/v1.0/users/{CVE_EMAIL_SENDER}/messages",
        headers=headers,
        data=json.dumps(payload),
    )
    if r.status_code != 201:
        raise RuntimeError(f"Graph API error {r.status_code}: {r.text[:200]}")
    return r.json()["id"]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/source-hints")
async def source_hints():
    return await get_all_paywall_hints()


@router.get("/history")
async def newsletter_history(
    page: int = 1,
    page_size: int = 20,
    client_id: str | None = None,
    user: dict = Depends(require_auth),
):
    allowed = await _allowed_client_ids(user)
    if allowed is not None:
        if client_id and client_id not in allowed:
            raise HTTPException(status_code=403, detail="Not assigned to this client")
        if not client_id:
            docs, total = await list_newsletters(page, page_size, client_ids=allowed)
            return {"newsletters": docs, "total": total, "page": page, "page_size": page_size}
    docs, total = await list_newsletters(page, page_size, client_id)
    return {"newsletters": docs, "total": total, "page": page, "page_size": page_size}


@router.get("/{newsletter_id}/html")
async def get_saved_html(newsletter_id: str, user: dict = Depends(require_auth)):
    doc = await get_newsletter_doc(newsletter_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Newsletter not found")
    await _require_client_access(user, doc.get("client_id", "default"))
    html = doc["html"]
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html)


@router.delete("/{newsletter_id}")
async def delete_saved_newsletter(newsletter_id: str, request: Request, user: dict = Depends(require_auth)):
    doc = await get_newsletter_doc(newsletter_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Newsletter not found")
    await _require_client_access(user, doc.get("client_id", "default"))
    is_admin = user["role"] in ("admin", "superadmin")
    if not is_admin and doc.get("created_by") != user["username"]:
        raise HTTPException(status_code=403, detail="Only the creator or an admin can delete this newsletter")
    if not await delete_newsletter(newsletter_id):
        raise HTTPException(status_code=404, detail="Newsletter not found")
    await write_audit(user["username"], "delete_newsletter", target_id=newsletter_id,
                      detail={"week": doc.get("week"), "year": doc.get("year"),
                              "client_id": doc.get("client_id", "default")},
                      ip=_ip(request))
    return {"success": True}


@router.post("/{newsletter_id}/resend")
async def resend_newsletter(newsletter_id: str, request: Request, user: dict = Depends(require_auth)):
    doc = await get_newsletter_doc(newsletter_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Newsletter not found")
    await _require_client_access(user, doc.get("client_id", "default"))
    html = doc["html"]
    client_name = doc.get("client_name", "")
    client = await get_client(doc.get("client_id", "default"))
    to_addrs = (client or {}).get("recipients") or None
    _require_recipients(to_addrs)
    subject_prefix = f"[CTI Newsletter] {client_name} — " if client_name else "[CTI Newsletter] "
    subject = f"{subject_prefix}Threat Intelligence Digest — Week {doc['week']}, {doc['year']}"
    try:
        email_id = await asyncio.get_event_loop().run_in_executor(
            None, _send_newsletter_email, html, subject, to_addrs
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    await write_audit(user["username"], "resend_newsletter", target_id=newsletter_id,
                      detail={"week": doc["week"], "year": doc["year"], "method": EMAIL_METHOD},
                      ip=_ip(request))
    return {"email_id": email_id, "method": EMAIL_METHOD, "recipients": to_addrs or [], "subject": subject}


@router.post("/preview")
async def preview_newsletter(
    body: dict = Body(...),
    user: dict = Depends(require_auth),
):
    await _require_client_access(user, body.get("client_id", "default"))
    highlight, apac, global_news, indonesia, missing_ids = await _resolve_sections(body)
    try:
        context = await build_newsletter_context(
            highlight, apac, global_news, indonesia,
            custom_css=body.get("custom_css", ""),
            custom_intro=body.get("custom_intro", ""),
            custom_footer=body.get("custom_footer", ""),
            notes=body.get("notes", {}),
            include_clusters=bool(body.get("include_clusters", False)),
            cluster_days=int(body.get("cluster_days", 7)),
            client_id=body.get("client_id", "default"),
            cve_ids=body.get("cve_ids", []),
        )
        html = render_newsletter_html(context)
        newsletter_id = await save_newsletter(context, html, user["username"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {
        "html": html,
        "week": context["week"],
        "year": context["year"],
        "newsletter_id": newsletter_id,
        "missing_ids": missing_ids,
    }


@router.post("/draft-email")
async def draft_email(
    request: Request,
    body: dict = Body(...),
    user: dict = Depends(require_auth),
):
    client_id = body.get("client_id", "default")
    await _require_client_access(user, client_id)
    to_addrs = ((await get_client(client_id)) or {}).get("recipients") or None
    _require_recipients(to_addrs)
    highlight, apac, global_news, indonesia, _missing = await _resolve_sections(body)
    try:
        context = await build_newsletter_context(
            highlight, apac, global_news, indonesia,
            custom_css=body.get("custom_css", ""),
            custom_intro=body.get("custom_intro", ""),
            custom_footer=body.get("custom_footer", ""),
            notes=body.get("notes", {}),
            include_clusters=bool(body.get("include_clusters", False)),
            cluster_days=int(body.get("cluster_days", 7)),
            client_id=client_id,
            cve_ids=body.get("cve_ids", []),
        )
        html = render_newsletter_html(context)
        newsletter_id = await save_newsletter(context, html, user["username"])
        client_name = context.get("client_name", "")
        subject_prefix = f"[CTI Newsletter] {client_name} — " if client_name else "[CTI Newsletter] "
        subject = f"{subject_prefix}Threat Intelligence Digest — Week {context['week']}, {context['year']}"
        email_id = await asyncio.get_event_loop().run_in_executor(
            None, _send_newsletter_email, html, subject, to_addrs
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    await write_audit(user["username"], "draft_newsletter_email", target_id=newsletter_id,
                      detail={"week": context["week"], "year": context["year"], "method": EMAIL_METHOD},
                      ip=_ip(request))
    return {
        "email_id": email_id,
        "method": EMAIL_METHOD,
        "recipients": to_addrs or [],
        "subject": subject,
        "week": context["week"],
        "year": context["year"],
        "newsletter_id": newsletter_id,
    }
