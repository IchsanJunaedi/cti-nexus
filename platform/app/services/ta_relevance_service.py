"""Non-LLM, per-client relevance scoring for threat actor profiles.

Joins a TA profile's targeting_profile + exploited_vulnerabilities against the
active client's configured sectors/countries/techstack to produce a deterministic
relevance score with a breakdown of exactly what matched.
"""
import asyncio
from app.database import get_ta_database
from app.config import TA_PROFILES_COLLECTION
from app.services.client_service import get_client
from app.services.techstack_service import get_tech_risk_context
from app.services.ta_profile_service import get_ta_profile

SECTOR_TAXONOMY = [
    "gov", "bfsi", "healthcare", "energy", "telco",
    "manufacturing", "retail", "education", "defense", "technology",
]

_EXPOSURE_WEIGHT = {"public": 40, "both": 30, "internal": 20}
_CISA_KEV_BONUS = 10
_CVE_SCORE_CAP = 60

_SECTOR_WEIGHT = 15
_SECTOR_SCORE_CAP = 30

_GEO_WEIGHT = 10
_GEO_SCORE_CAP = 20

_LABEL_THRESHOLDS = [(70, "critical"), (45, "high"), (20, "medium")]


def _label_for_score(score: int) -> str:
    for threshold, label in _LABEL_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


def _score_profile(profile: dict, client_sectors: set[str], client_countries: set[str], risk_ctx: dict[str, dict]) -> dict:
    targeting = profile.get("targeting_profile") or {}
    actor_sectors = {s.lower() for s in (targeting.get("targeted_sectors") or []) if s} | \
                    {s.lower() for s in (targeting.get("targeted_organization_types") or []) if s}
    actor_geos = {g.lower() for g in (targeting.get("targeted_geographies") or []) if g}

    sector_matches = sorted(client_sectors & actor_sectors)
    geo_matches = sorted(client_countries & actor_geos)

    capability = profile.get("capability_assessment") or {}
    exploited = capability.get("exploited_vulnerabilities") or []
    article_cves = profile.get("_article_cves") or []

    cve_matches: list[dict] = []
    seen: set[str] = set()
    for entry in list(exploited) + list(article_cves):
        cve_id = (entry.get("cve_id") or "").upper()
        if not cve_id or cve_id in seen:
            continue
        tech_raw = (entry.get("_tech") or entry.get("product") or "").strip().lower()
        if not tech_raw:
            continue
        ctx = risk_ctx.get(tech_raw)
        matched_name = tech_raw
        if ctx is None:
            for name_lower, c in risk_ctx.items():
                if name_lower and (name_lower in tech_raw or tech_raw in name_lower):
                    ctx = c
                    matched_name = name_lower
                    break
        if ctx is None:
            continue
        seen.add(cve_id)
        cve_matches.append({
            "cve_id": cve_id,
            "tech": matched_name,
            "exposure": ctx["exposure"],
            "severity": entry.get("_cve_severity"),
            "cisa_kev": bool(entry.get("_cisa_kev")),
        })

    cve_score = 0
    for m in cve_matches:
        weight = _EXPOSURE_WEIGHT.get(m["exposure"], _EXPOSURE_WEIGHT["internal"])
        if m["cisa_kev"]:
            weight += _CISA_KEV_BONUS
        cve_score += weight
    cve_score = min(cve_score, _CVE_SCORE_CAP)

    sector_score = min(len(sector_matches) * _SECTOR_WEIGHT, _SECTOR_SCORE_CAP)
    geo_score = min(len(geo_matches) * _GEO_WEIGHT, _GEO_SCORE_CAP)

    score = min(cve_score + sector_score + geo_score, 100)
    return {
        "score": score,
        "label": _label_for_score(score),
        "breakdown": {
            "sectors": sector_matches,
            "geographies": geo_matches,
            "cves": cve_matches,
        },
    }


async def _fetch_profiles_batch(actor_names: list[str]) -> dict[str, dict]:
    """Return {actor_name_lower: raw profile doc} for the given names (case-insensitive)."""
    if not actor_names:
        return {}
    col = get_ta_database()[TA_PROFILES_COLLECTION]
    patterns = [{"_actor_name": {"$regex": f"^{n}$", "$options": "i"}} for n in actor_names]
    docs = await col.find({"$or": patterns}, {"_id": 0}).to_list(length=len(actor_names))
    return {(d.get("_actor_name") or "").lower(): d for d in docs}


async def compute_actor_relevance(actor_name: str, client_id: str, profile: dict | None = None) -> dict:
    """Compute relevance for one actor. Pass an already-fetched (enriched) profile to avoid a second DB hit."""
    if profile is None:
        profile = await get_ta_profile(actor_name)
    if not profile:
        return {"score": 0, "label": "low", "breakdown": {"sectors": [], "geographies": [], "cves": []}}

    risk_ctx, client = await asyncio.gather(
        get_tech_risk_context(client_id),
        get_client(client_id),
    )
    client = client or {}
    client_sectors = {s.lower() for s in (client.get("sectors") or []) if s}
    client_countries = {c.lower() for c in (client.get("countries") or []) if c}

    return _score_profile(profile, client_sectors, client_countries, risk_ctx)


async def compute_relevance_for_watchlist(items: list[dict], client_id: str) -> list[dict]:
    """Attach relevance_score / relevance_label / relevance_breakdown to each item in place. Returns items."""
    names = [item["name"] for item in items if item.get("name")]
    if not names:
        return items

    profiles, risk_ctx, client = await asyncio.gather(
        _fetch_profiles_batch(names),
        get_tech_risk_context(client_id),
        get_client(client_id),
    )
    client = client or {}
    client_sectors = {s.lower() for s in (client.get("sectors") or []) if s}
    client_countries = {c.lower() for c in (client.get("countries") or []) if c}

    for item in items:
        profile = profiles.get((item.get("name") or "").lower())
        if not profile:
            item["relevance_score"] = None
            item["relevance_label"] = None
            item["relevance_breakdown"] = None
            continue
        rel = _score_profile(profile, client_sectors, client_countries, risk_ctx)
        item["relevance_score"] = rel["score"]
        item["relevance_label"] = rel["label"]
        item["relevance_breakdown"] = rel["breakdown"]

    return items
