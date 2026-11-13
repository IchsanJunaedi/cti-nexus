import asyncio
import json
import re
import smtplib
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import msal
import requests as http_requests
from jinja2 import Environment, FileSystemLoader
from app.config import (
    AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID,
    CVE_EMAIL_SENDER, CVE_EMAIL_SENDER_NAME, CVE_EMAIL_CC,
    EMAIL_METHOD, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_USE_TLS,
    LLM_PROVIDER, LLM_API_KEY, LLM_MODEL,
)
from app.services.llm_client import get_llm_client, store_param
from app.database import get_database
from app.services.cve_ticket_service import get_next_ticket_id, mark_drafted, get_tickets_map
from app.services.client_service import get_client
from app.services.techstack_service import get_tech_vendor_map

_TEMPLATE_DIR   = Path(__file__).parent.parent.parent / "scripts"
_TEMPLATE_FILES = {
    "en": "cve_notification_email_en.html",
    "id": "cve_notification_email_id.html",
}

_TZ_UTC7 = timezone(timedelta(hours=7))

_LANG_NAMES = {"en": "English", "id": "Bahasa Indonesia"}

_SLA_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 60, "LOW": 90}
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ── LLM helpers (adapted from cveValidator.py) ────────────────────────────────

def _llm_cve_validator(cve_data: dict, lang: str = "en") -> dict:
    prompt = f"""You are a Cyber Threat Intelligence manager with 7+ years of expertise.

Analyze the CVE data and return ONLY a valid JSON object with these fields. No markdown, no code blocks.
Write all free-text field values in {_LANG_NAMES.get(lang, "English")}.

{{
  "product_name": "The possible impacted product name",
  "summary": "Max 50 words describing what attackers can do or what data is exposed",
  "executive_summary": "2-3 sentences for non-technical leadership",
  "risk_context": "1-2 paragraphs (narrative prose, no lists) describing risks if NOT patched. Cover: business impact, compliance violations, exploitation likelihood.",
  "primary_remediation_action": [
    {{"version_branch": "affected version branch", "fixed_version": "safe version to upgrade to"}}
  ],
  "affected_version": "version X or below is affected based on 'affected' key",
  "alternative_remediation_action": [
    "5-7 compensating controls if patching delayed, each max 30 words"
  ],
  "attack_complexity": "Low or High from cvss_vector AC:",
  "impact": "The impact if CVE exploited",
  "recommended_timeline": "CRITICAL (24-48h) / HIGH (7 days) / MEDIUM (30 days) / LOW (90 days)",
  "analysis_timestamp": "ISO 8601 timestamp"
}}

CRITICAL: Return ONLY the JSON object. Start with {{ and end with }}."""

    client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user",   "content": str(cve_data)},
        ],
        temperature=0,
        n=1,
        **store_param(LLM_PROVIDER),
    )
    return json.loads(completion.choices[0].message.content)


def _dedup_mitigation(mitigation_list: list, lang: str = "en") -> dict:
    prompt = f"""You are a Cyber Threat Intelligence manager with 7+ years of expertise.
Write all list items in {_LANG_NAMES.get(lang, "English")}.

Return ONLY a valid JSON object:
{{
  "alternative_remediation_action": [
    "Provide EXACTLY 7 unique, non-overlapping compensating controls if patching is delayed",
    "Each item must be 20-30 words and actionable",
    "NO DUPLICATES - each control must address a different security layer"
  ]
}}

CRITICAL: Return ONLY the JSON object. Start with {{ and end with }}."""

    client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user",   "content": str(mitigation_list)},
        ],
        temperature=0,
        n=1,
        **store_param(LLM_PROVIDER),
    )
    return json.loads(completion.choices[0].message.content)


def _dedup_risk_context(risk_str: str, lang: str = "en") -> str:
    prompt = f"""You are a Cyber Threat Intelligence analyst writing impact assessments.
Write the statement in {_LANG_NAMES.get(lang, "English")}.

Generate a concise HTML impact statement (max 100 words) covering:
1. Direct technical impact
2. Business consequences (data breach, financial loss, operational disruption)
3. Exploitation likelihood based on attack complexity
4. Time-sensitive risk factors

Wrap important phrases in <strong> tags. Return only the HTML fragment, no surrounding tags."""

    client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user",   "content": risk_str},
        ],
        temperature=0,
        n=1,
        **store_param(LLM_PROVIDER),
    )
    return completion.choices[0].message.content


def _apply_custom_edit(html_content: str, instruction: str, lang: str = "en") -> str:
    prompt = f"""You are an HTML editor for a cybersecurity notification email.
Apply the user's requested edit to the HTML below. Rules:
- Return ONLY the full modified HTML document, no markdown fences, no commentary.
- Keep all existing inline CSS, structure, and Jinja-rendered values intact unless the instruction says to change them.
- Do not remove tracking/classification footer text unless explicitly asked.
- Keep the response in {_LANG_NAMES.get(lang, "English")} unless told otherwise."""

    client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user",   "content": f"INSTRUCTION:\n{instruction}\n\nHTML:\n{html_content}"},
        ],
        temperature=0,
        n=1,
        **store_param(LLM_PROVIDER),
    )
    edited = completion.choices[0].message.content.strip()
    edited = re.sub(r"^```(?:html)?\s*|\s*```$", "", edited.strip())
    return edited or html_content


# ── Email rendering ───────────────────────────────────────────────────────────

def _render_email(context: dict, lang: str = "en") -> str:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)))
    template_file = _TEMPLATE_FILES.get(lang, _TEMPLATE_FILES["en"])
    return env.get_template(template_file).render(**context)


def _highest_severity(cves: list[dict]) -> str:
    for sev in _SEV_ORDER:
        if any(c["severity"].upper() == sev for c in cves):
            return sev
    return "LOW"


# ── Microsoft Graph draft creation ───────────────────────────────────────────

def _get_access_token() -> str | None:
    authority = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
    app = msal.ConfidentialClientApplication(
        AZURE_CLIENT_ID,
        authority=authority,
        client_credential=AZURE_CLIENT_SECRET,
    )
    resp = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    return resp.get("access_token")


def _create_graph_draft(html_content: str, subject: str, cc_addrs: list[str]) -> str:
    token = _get_access_token()
    if not token:
        raise RuntimeError("Failed to acquire Azure access token")

    cc_list = [
        {"emailAddress": {"address": addr.strip()}}
        for addr in cc_addrs
        if addr.strip()
    ]

    payload = {
        "subject": subject,
        "body": {"contentType": "html", "content": html_content},
        "ccRecipients": cc_list,
    }

    resp = http_requests.post(
        f"https://graph.microsoft.com/v1.0/users/{CVE_EMAIL_SENDER}/messages",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        data=json.dumps(payload),
    )

    if resp.status_code != 201:
        raise RuntimeError(f"Graph API error {resp.status_code}: {resp.text[:200]}")

    return resp.json()["id"]


def _send_smtp(html_content: str, subject: str, cc_addrs: list[str]) -> str:
    if not SMTP_USER or not SMTP_PASS:
        raise RuntimeError("SMTP_USER and SMTP_PASS env vars not set")

    cc_addrs = [a.strip() for a in cc_addrs if a.strip()]

    from_addr = formataddr((CVE_EMAIL_SENDER_NAME, CVE_EMAIL_SENDER)) if CVE_EMAIL_SENDER_NAME else CVE_EMAIL_SENDER

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = CVE_EMAIL_SENDER
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    recipients = [CVE_EMAIL_SENDER] + cc_addrs

    if SMTP_USE_TLS:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(CVE_EMAIL_SENDER, recipients, msg.as_string())
    else:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(CVE_EMAIL_SENDER, recipients, msg.as_string())

    return f"smtp-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"


def _dispatch_email(html_content: str, subject: str, cc_addrs: list[str]) -> str:
    if EMAIL_METHOD == "smtp":
        return _send_smtp(html_content, subject, cc_addrs)
    return _create_graph_draft(html_content, subject, cc_addrs)


def _build_eml_bytes(html_content: str, subject: str, to_addrs: list[str]) -> bytes:
    to_addrs = [a.strip() for a in to_addrs if a.strip()]
    from_addr = formataddr((CVE_EMAIL_SENDER_NAME, CVE_EMAIL_SENDER)) if CVE_EMAIL_SENDER_NAME else (CVE_EMAIL_SENDER or "soc@localhost")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"]    = from_addr
    if to_addrs:
        msg["To"] = ", ".join(to_addrs)
    msg.set_content("This email requires an HTML-capable client to view.")
    msg.add_alternative(html_content, subtype="html")
    return msg.as_bytes()


# ── Recipients (shared with newsletter) ───────────────────────────────────────

async def get_cve_email_recipients(client_id: str | None) -> list[str]:
    """CVE notification recipients = same client.recipients list used for the newsletter."""
    addrs = None
    if client_id:
        client = await get_client(client_id)
        addrs = client.get("recipients") if client else None
    if not addrs:
        addrs = [a.strip() for a in CVE_EMAIL_CC.split(",") if a.strip()]
    return addrs


# ── Main entry point (called from router) ────────────────────────────────────

async def draft_email_for_cves(
    cve_ids: list[str],
    ticket_id: str,
    client_id: str | None = None,
    mode: str = "send",
    lang: str = "en",
    recipients: list[str] | None = None,
    custom_instruction: str | None = None,
) -> dict[str, Any]:
    col   = get_database()["cve_tracker"]
    query = {"cve_id": {"$in": cve_ids}}
    if client_id:
        query["client_id"] = client_id
    docs  = await col.find(query, {"_id": 0}).to_list(None)
    if not docs:
        raise ValueError("No CVE documents found for provided IDs")

    cc_addrs = recipients if recipients else await get_cve_email_recipients(client_id)

    # Per-CVE tracking ID: reuse the CVE's existing ticket if it already has one
    # (from a prior acknowledge or draft) — only CVEs with no ticket yet fall back
    # to `ticket_id` (freshly minted by the router). Prevents the email showing a
    # different tracking number than what's saved against the CVE.
    existing_tickets = await get_tickets_map(cve_ids, client_id or "default")
    cve_tracking_map = {cid: existing_tickets.get(cid, ticket_id) for cid in cve_ids}

    # Group CVEs by tech (product) — CVEs from different products of the same vendor
    # (e.g. FortiOS + FortiWeb, both Fortinet) go in one email as separate product sections,
    # keeping remediation/fix versions scoped per product so they're never mixed up.
    vendor_map   = await get_tech_vendor_map(client_id or "default")
    product_order: list[str] = []
    products: dict[str, dict] = {}

    accumulated: dict[str, Any] = {
        "mitigations":         [],
        "vendor_advisory_url": [],
        "risk_parts":          [],
    }

    for doc in docs:
        tech_raw     = doc.get("tech", "Unknown Product")
        product_name = tech_raw.replace("%20", " ").title()
        if product_name not in products:
            product_order.append(product_name)
            products[product_name] = {"product_name": product_name, "cves": [], "remediation_fixes": []}

        cve_data = await asyncio.get_event_loop().run_in_executor(None, _llm_cve_validator, doc, lang)

        products[product_name]["cves"].append({
            "id":              doc.get("cve_id", ""),
            "severity":        doc.get("cve_severity", "MEDIUM"),
            "impact":          cve_data.get("summary", "").replace("\xa0", " "),
            "cvss_score":      doc.get("cve_score", 0),
            "published":       doc.get("published", ""),
            "link":            doc.get("link", ""),
            "exploit_available": bool(doc.get("poc_available") or doc.get("exploit_db_hits")),
            "exploited_in_wild": bool(doc.get("cisa_kev") or doc.get("active_exploitation")),
            "tracking_id":     cve_tracking_map.get(doc.get("cve_id", ""), ticket_id),
        })

        # Collect remediation fixes scoped to this product (list of {version_branch, fixed_version})
        for fix in cve_data.get("primary_remediation_action", []):
            if isinstance(fix, dict) and fix not in products[product_name]["remediation_fixes"]:
                products[product_name]["remediation_fixes"].append(fix)

        for alt in cve_data.get("alternative_remediation_action", []):
            if alt not in accumulated["mitigations"]:
                accumulated["mitigations"].append(alt)

        for ref in doc.get("reference", []):
            tags = ", ".join(ref.get("tags", []))
            entry = ref["url"] + (f" ({tags})" if tags else "")
            if entry not in accumulated["vendor_advisory_url"]:
                accumulated["vendor_advisory_url"].append(entry)

        risk = cve_data.get("risk_context", "")
        if risk and risk not in accumulated["risk_parts"]:
            accumulated["risk_parts"].append(risk)

    product_groups = [products[name] for name in product_order]
    vendors_involved = {vendor_map.get(name.lower(), "") for name in product_order}
    vendors_involved.discard("")
    vendor_name = next(iter(vendors_involved)) if len(vendors_involved) == 1 else None

    all_cves = [c for grp in product_groups for c in grp["cves"]]
    display_name = vendor_name if (vendor_name and len(product_groups) > 1) else product_groups[0]["product_name"]
    cve_tracking_ids = [{"cve_id": c["id"], "tracking_id": c["tracking_id"]} for c in all_cves]

    # Dedup mitigations via LLM
    deduped_mit = await asyncio.get_event_loop().run_in_executor(
        None, _dedup_mitigation, accumulated["mitigations"], lang
    )
    mitigations = deduped_mit.get("alternative_remediation_action", accumulated["mitigations"])

    # Dedup risk context via LLM
    risk_html = await asyncio.get_event_loop().run_in_executor(
        None, _dedup_risk_context, " || ".join(accumulated["risk_parts"]), lang
    )

    today            = datetime.now(_TZ_UTC7)
    highest_sev      = _highest_severity(all_cves)
    remediation_days = _SLA_DAYS.get(highest_sev, 90)

    context = {
        "cve_count":           len(all_cves),
        "product_name":        display_name,
        "vendor_name":         vendor_name,
        "product_groups":      product_groups,
        "due_date":            (today + timedelta(days=remediation_days)).strftime("%B %d, %Y"),
        "plan_date":           (today + timedelta(days=3)).strftime("%B %d, %Y"),
        "email_date":          today.strftime("%B %d, %Y"),
        "highest_severity":    highest_sev,
        "remediation_days":    remediation_days,
        "risk_context":        risk_html,
        "mitigations":         mitigations,
        "vendor_advisory_url": accumulated["vendor_advisory_url"],
        "timeline_actions": [
            {"description": "CTI Team Detect CVE",          "owner": "CTI Team",      "due_date": today.strftime("%b %d, %Y"),                             "critical": False},
            {"description": "Acknowledge Receipt",           "owner": "Product Owner", "due_date": (today + timedelta(days=1)).strftime("%b %d, %Y"),       "critical": False},
            {"description": "Submit Remediation Plan",       "owner": "Product Owner", "due_date": "",                                                      "critical": False},
            {"description": "Complete Patching/Remediation", "owner": "Product Owner", "due_date": "",                                                      "critical": True},
            {"description": "Verification",                  "owner": "CTI Team",      "due_date": "Maximum Day + 3 After Complete Patching",               "critical": False},
        ],
        "cve_tracking_ids": cve_tracking_ids,
        "classification":   "Internal - Confidential",
    }

    html_content = _render_email(context, lang)
    if custom_instruction and custom_instruction.strip():
        html_content = await asyncio.get_event_loop().run_in_executor(
            None, _apply_custom_edit, html_content, custom_instruction, lang
        )
    if len(product_groups) > 1:
        subject = f"[ACTION REQUIRED] {len(all_cves)} CVE(s) across {display_name} products ({', '.join(product_order)})"
    else:
        subject = f"[ACTION REQUIRED] {len(all_cves)} CVE(s) in {display_name}"

    drafted_tracking_map = {c["id"]: c["tracking_id"] for c in all_cves}

    if mode == "eml":
        eml_bytes = _build_eml_bytes(html_content, subject, cc_addrs)
        await mark_drafted(drafted_tracking_map, mode, lang, client_id or "default")
        return {
            "mode":       "eml",
            "eml_bytes":  eml_bytes,
            "subject":    subject,
            "cve_count":  len(all_cves),
            "client_id":  client_id,
            "recipients": cc_addrs,
        }

    email_id = await asyncio.get_event_loop().run_in_executor(
        None, _dispatch_email, html_content, subject, cc_addrs
    )
    await mark_drafted(drafted_tracking_map, mode, lang, client_id or "default")

    return {
        "mode":       "send",
        "email_id":   email_id,
        "method":     EMAIL_METHOD,
        "subject":    subject,
        "cve_count":  len(all_cves),
        "client_id":  client_id,
        "recipients": cc_addrs,
    }
