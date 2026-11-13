import ipaddress
import time
from datetime import datetime, timedelta, timezone
from app.database import get_database
from app.config import IOC_COLLECTION

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

_fp_analytics_cache: dict | None = None
_fp_analytics_cache_ts: float = 0.0
_FP_CACHE_TTL = 300.0


def _col():
    return get_database()[IOC_COLLECTION]


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
        if f"://{d}/" in lower or f"://{d}" == lower or lower.startswith(f"https://{d}") or lower.startswith(f"http://{d}"):
            return True, f"URL from known benign domain {d}"
    return False, ""


def invalidate_fp_cache() -> None:
    global _fp_analytics_cache
    _fp_analytics_cache = None


async def get_fp_source_rates() -> dict[str, dict]:
    """Return {source_name: {total_iocs, fp_count, fp_rate}} from cached analytics."""
    analytics = await get_fp_analytics()
    return analytics.get("fp_by_source", {})


async def get_fp_analytics(force: bool = False) -> dict:
    global _fp_analytics_cache, _fp_analytics_cache_ts
    now_mono = time.monotonic()
    if (
        not force
        and _fp_analytics_cache is not None
        and (now_mono - _fp_analytics_cache_ts) < _FP_CACHE_TTL
    ):
        return _fp_analytics_cache

    col = _col()
    now = datetime.now(timezone.utc)
    cutoff_30d = (now - timedelta(days=30)).isoformat()

    fp_by_source: dict[str, dict] = {}
    fp_by_type: dict[str, dict] = {}
    fp_by_pattern: dict[str, dict] = {}
    fp_by_day: dict[str, dict] = {}
    suggested_map: dict[str, dict] = {}

    async for doc in col.find(
        {"feedback_log": {"$exists": True, "$ne": []}},
        {"type": 1, "value": 1, "sources": 1, "feedback_log": 1, "tp_count": 1, "fp_count": 1},
    ):
        tp = doc.get("tp_count", 0)
        fp = doc.get("fp_count", 0)
        ioc_type = doc.get("type", "unknown")
        value = doc.get("value", "")

        for source in doc.get("sources", []):
            sname = source.get("source_name", "unknown")
            if sname not in fp_by_source:
                fp_by_source[sname] = {"total_iocs": 0, "fp_count": 0, "fp_rate": 0.0}
            fp_by_source[sname]["total_iocs"] += 1
            fp_by_source[sname]["fp_count"] += fp
            break  # count IOC once per primary source

        if ioc_type not in fp_by_type:
            fp_by_type[ioc_type] = {"total_iocs": 0, "fp_count": 0, "fp_rate": 0.0}
        fp_by_type[ioc_type]["total_iocs"] += 1
        fp_by_type[ioc_type]["fp_count"] += fp

        if fp >= 3 and tp == 0:
            key = f"{ioc_type}:{value}"
            al_type = "domain" if ioc_type in ("url", "url_with_path", "email", "domain") else (
                "ip" if ioc_type == "ip" else None
            )
            if al_type:
                suggested_map[key] = {
                    "ioc_type": ioc_type,
                    "value": value,
                    "allowlist_type": al_type,
                    "fp_count": fp,
                }

        for fb in doc.get("feedback_log", []):
            if fb.get("verdict") != "fp":
                continue
            ts = fb.get("ts", "")
            if ts < cutoff_30d:
                continue
            day = ts[:10]
            if day not in fp_by_day:
                fp_by_day[day] = {"fp_count": 0, "total_count": 0}
            fp_by_day[day]["fp_count"] += 1

        for fb in doc.get("feedback_log", []):
            ts = fb.get("ts", "")
            if ts < cutoff_30d:
                continue
            day = ts[:10]
            if day not in fp_by_day:
                fp_by_day[day] = {"fp_count": 0, "total_count": 0}
            fp_by_day[day]["total_count"] += 1

    for sname, d in fp_by_source.items():
        total = d["total_iocs"]
        d["fp_rate"] = round(d["fp_count"] / total, 3) if total else 0.0

    for itype, d in fp_by_type.items():
        total = d["total_iocs"]
        d["fp_rate"] = round(d["fp_count"] / total, 3) if total else 0.0

    fp_trend = [
        {"date": day, "fp_count": v["fp_count"], "total_count": v["total_count"],
         "fp_rate": round(v["fp_count"] / v["total_count"], 3) if v["total_count"] else 0.0}
        for day, v in sorted(fp_by_day.items())
    ]

    result = {
        "fp_by_source": fp_by_source,
        "fp_by_type": fp_by_type,
        "suggested_allowlist": list(suggested_map.values()),
        "fp_trend": fp_trend,
    }

    _fp_analytics_cache = result
    _fp_analytics_cache_ts = now_mono
    return result


async def auto_suppress_check(ioc_type: str, value: str, source_name: str | None = None) -> dict:
    should_suppress = False
    reason = ""
    confidence = 0.0

    if ioc_type == "domain":
        match, msg = _matches_benign_domain(value)
        if match:
            should_suppress = True
            reason = msg
            confidence = 0.95

    elif ioc_type == "ip":
        match, msg = _is_private_ip(value)
        if match:
            should_suppress = True
            reason = msg
            confidence = 0.99

    elif ioc_type in ("url", "url_with_path"):
        match, msg = _is_benign_url(value)
        if match:
            should_suppress = True
            reason = msg
            confidence = 0.95

    elif ioc_type == "email":
        match, msg = _matches_benign_email_domain(value)
        if match:
            should_suppress = True
            reason = msg
            confidence = 0.90

    if not should_suppress and source_name:
        source_rates = await get_fp_source_rates()
        sr = source_rates.get(source_name)
        if sr and sr["total_iocs"] >= 10 and sr["fp_rate"] > 0.5:
            should_suppress = True
            reason = f"source '{source_name}' has {sr['fp_rate']*100:.0f}% FP rate ({sr['fp_count']}/{sr['total_iocs']} IOCs)"
            confidence = min(0.5 + sr["fp_rate"] * 0.4, 0.90)

    return {"should_suppress": should_suppress, "reason": reason, "confidence": confidence}
