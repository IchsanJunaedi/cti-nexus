"""
Shared IOC document schema builder for ScraperNewsRevamp.

Ports confidence scoring, actionability scoring, and benign auto-suppress logic
from ScraperNewsWeb/app/services/confidence_service.py and fp_analytics_service.py
as synchronous functions (Revamp uses pymongo, not async motor).

Deviations from Web:
  - compute_ioc_actionability: campaign_score fixed at 0 — Revamp has no cluster DB.
    Actionability scores will be slightly conservative for IOCs linked to active campaigns.
  - auto_suppress_check: omits source FP-rate check — no fp_analytics DB in Revamp.
    Static heuristics (private IP, CDN domain, benign email provider) are fully ported.
"""

import ipaddress
from datetime import datetime, timezone


# ── Confidence scoring ─────────────────────────────────────────────────────────

_IOC_HALF_LIFE: dict[str, float] = {
    "ip": 30.0,
    "domain": 60.0,
    "url": 30.0,
    "url_with_path": 30.0,
    "email": 30.0,
    "sha256": 90.0,
    "sha1": 90.0,
    "md5": 90.0,
    "cve": 90.0,
}


def compute_ioc_confidence(ioc_doc: dict, now: datetime) -> int:
    last_seen_str = ioc_doc.get("last_seen", "")
    try:
        last_seen = datetime.strptime(last_seen_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        last_seen = now

    age_days = max((now - last_seen).total_seconds() / 86400, 0)
    base = 50
    recency_bonus = 30 if age_days <= 7 else 0

    sources = ioc_doc.get("sources") or ioc_doc.get("source_article_ids") or []
    source_bonus = min(len(sources) * 10, 30)

    tp = ioc_doc.get("tp_count", 0)
    fp = ioc_doc.get("fp_count", 0)
    verdict_bonus = 20 * tp / (tp + fp + 1)

    raw = base + recency_bonus + source_bonus + verdict_bonus

    ioc_type = ioc_doc.get("type", "ip")
    half_life = _IOC_HALF_LIFE.get(ioc_type, 30.0)
    decayed = raw * (0.5 ** (age_days / half_life))

    return max(0, min(100, int(round(decayed))))


# ── Actionability scoring ──────────────────────────────────────────────────────

_ACTIONABILITY_LABELS = [
    (75, "block_now"),
    (50, "investigate"),
    (25, "monitor"),
    (0,  "archive"),
]

_BLOCK_HASH_TYPES = {"sha256", "sha1", "md5"}
_BLOCK_NET_TYPES  = {"ip", "domain"}


def _recommended_action(label: str, ioc_type: str) -> str:
    if label == "block_now":
        if ioc_type in _BLOCK_HASH_TYPES:
            return "Add to EDR blocklist"
        return "Add to firewall blocklist immediately"
    if label == "investigate":
        return "Verify in environment, check for matches in last 30 days"
    if label == "monitor":
        return "Add to watchlist, no immediate action"
    return "Low priority, aging indicator"


def compute_ioc_actionability(ioc: dict, now: datetime) -> dict:
    last_seen_str = ioc.get("last_seen", "")
    try:
        last_seen = datetime.strptime(last_seen_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        last_seen = now
    age_days = max((now - last_seen).total_seconds() / 86400, 0)

    if age_days <= 1:
        recency = 100
    elif age_days <= 3:
        recency = 80
    elif age_days <= 7:
        recency = 60
    elif age_days <= 30:
        recency = 30
    else:
        recency = 0

    seen_count = ioc.get("seen_count", 1)
    if seen_count >= 5:
        corroboration = 100
    elif seen_count >= 3:
        corroboration = 70
    elif seen_count >= 2:
        corroboration = 40
    else:
        corroboration = 10

    confidence = ioc.get("confidence_score", 50) or 50

    # campaign_score = 0 — no cluster DB in Revamp
    score = round(
        recency         * 0.40
        + 0             * 0.25
        + confidence    * 0.20
        + corroboration * 0.15
    )
    score = max(0, min(100, score))

    label = "archive"
    for threshold, lbl in _ACTIONABILITY_LABELS:
        if score >= threshold:
            label = lbl
            break

    return {
        "actionability_score": score,
        "actionability_label": label,
        "recommended_action":  _recommended_action(label, ioc.get("type", "")),
    }


# ── Auto-suppress (static benign heuristics) ──────────────────────────────────

_BENIGN_DOMAINS: frozenset[str] = frozenset({
    "amazonaws.com", "cloudflare.com", "google.com", "microsoft.com", "akamai.net",
    "fastly.net", "cloudfront.net", "azureedge.net", "googleusercontent.com",
    "googleapis.com", "gstatic.com", "github.com", "githubusercontent.com",
    "windows.net", "azure.com", "office.com", "sharepoint.com",
    "yahoo.com", "outlook.com", "gmail.com", "hotmail.com", "live.com",
})

_BENIGN_EMAIL_PROVIDERS: frozenset[str] = frozenset({
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "protonmail.com", "mail.com", "aol.com",
})

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _matches_benign_domain(value: str) -> tuple[bool, str]:
    v = value.lower().strip()
    for d in _BENIGN_DOMAINS:
        if v == d or v.endswith("." + d):
            return True, f"matches known CDN/cloud domain {d}"
    return False, ""


def _is_private_ip(value: str) -> tuple[bool, str]:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False, ""
    for net in _PRIVATE_NETWORKS:
        if addr in net:
            return True, f"IP in private/reserved range {net}"
    return False, ""


def _matches_benign_email_domain(value: str) -> tuple[bool, str]:
    domain = value.lower().split("@")[-1] if "@" in value else ""
    if domain in _BENIGN_EMAIL_PROVIDERS:
        return True, f"common email provider domain {domain}"
    return False, ""


def _is_benign_url(value: str) -> tuple[bool, str]:
    lower = value.lower()
    for d in _BENIGN_DOMAINS:
        if (f"://{d}/" in lower or f"://{d}" == lower
                or lower.startswith(f"https://{d}")
                or lower.startswith(f"http://{d}")):
            return True, f"URL from known benign domain {d}"
    return False, ""


def auto_suppress_check(ioc_type: str, value: str) -> dict:
    """Sync port of fp_analytics_service.auto_suppress_check.
    Source FP-rate check omitted — no fp_analytics infrastructure in Revamp."""
    should_suppress = False
    reason = ""
    confidence = 0.0

    if ioc_type == "domain":
        match, msg = _matches_benign_domain(value)
        if match:
            should_suppress, reason, confidence = True, msg, 0.95
    elif ioc_type == "ip":
        match, msg = _is_private_ip(value)
        if match:
            should_suppress, reason, confidence = True, msg, 0.99
    elif ioc_type in ("url", "url_with_path"):
        match, msg = _is_benign_url(value)
        if match:
            should_suppress, reason, confidence = True, msg, 0.95
    elif ioc_type == "email":
        match, msg = _matches_benign_email_domain(value)
        if match:
            should_suppress, reason, confidence = True, msg, 0.90

    return {"should_suppress": should_suppress, "reason": reason, "confidence": confidence}


# ── Document builder ───────────────────────────────────────────────────────────

def enrich_new_ioc(doc: dict) -> dict:
    """
    Attach all scoring/suppression fields to a new IOC document in-place.
    Call before insert_one so every writer produces the full schema matching
    ScraperNewsWeb/app/services/ioc_service.py upsert_ioc().

    Mutates and returns doc.
    """
    now = datetime.now(timezone.utc)
    ioc_type = doc.get("type", "")
    value = doc.get("value", "")

    doc.setdefault("tp_count", 0)
    doc.setdefault("fp_count", 0)
    doc.setdefault("feedback_log", [])
    doc.setdefault("tags", [])
    doc.setdefault("threat_actors", [])

    suppress = auto_suppress_check(ioc_type, value)
    doc["auto_suppressed"] = suppress["should_suppress"] and suppress["confidence"] > 0.8
    doc["suppression_reason"] = suppress["reason"] if doc["auto_suppressed"] else ""

    score = compute_ioc_confidence(doc, now)
    doc["confidence_score"] = score
    doc["confidence_decayed_at"] = now

    act = compute_ioc_actionability(doc, now)
    doc.update(act)

    return doc
