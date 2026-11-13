"""
campaign_scoring_service.py — Compute 0-100 threat severity score for campaign clusters.

Factors:
  TA sophistication  (30%) — highest sophistication among dominant TAs
  IOC confidence     (20%) — average confidence_score of campaign IOCs
  CVE criticality    (20%) — max CVSS from cve_tracker, bonus for CISA KEV / active exploitation
  Campaign velocity  (15%) — articles-per-day, normalised
  Source quality     (15%) — average source reliability grade of member articles
"""

import asyncio
from datetime import datetime

from app.database import get_database, get_ta_database
from app.config import TA_PROFILES_COLLECTION, SOURCE_SCORES_COLLECTION

_SOPHISTICATION_SCORES = {
    "nation-state": 100,
    "high":         75,
    "medium":       50,
    "low":          25,
}

_RELIABILITY_SCORES = {"A": 100, "B": 80, "C": 60, "D": 40, "E": 20, "F": 10}


async def _ta_sophistication_factor(dominant_tas: list[str]) -> float:
    if not dominant_tas or not TA_PROFILES_COLLECTION:
        return 50.0
    col = get_ta_database()[TA_PROFILES_COLLECTION]
    pattern = "|".join(ta.replace("(", "\\(").replace(")", "\\)") for ta in dominant_tas)
    cursor = col.find(
        {"_actor_name": {"$regex": pattern, "$options": "i"}},
        {"capability_assessment.sophistication_level": 1, "_id": 0},
    )
    docs = await cursor.to_list(length=len(dominant_tas) + 5)
    best = 0
    for doc in docs:
        level = (doc.get("capability_assessment") or {}).get("sophistication_level", "")
        score = _SOPHISTICATION_SCORES.get((level or "").lower(), 0)
        if score > best:
            best = score
    return float(best) if best else 50.0


async def _ioc_confidence_factor(iocs: list[dict]) -> float:
    if not iocs:
        return 50.0
    ioc_ids = [ioc.get("id") for ioc in iocs if ioc.get("id")]
    if not ioc_ids:
        return 50.0
    from bson import ObjectId
    valid_oids = []
    for oid in ioc_ids:
        try:
            valid_oids.append(ObjectId(oid))
        except Exception:
            pass
    if not valid_oids:
        return 50.0
    col = get_database()["iocs"]
    cursor = col.find({"_id": {"$in": valid_oids}}, {"confidence_score": 1, "_id": 0})
    docs = await cursor.to_list(length=len(valid_oids))
    scores = [d["confidence_score"] for d in docs if d.get("confidence_score") is not None]
    return float(sum(scores) / len(scores)) if scores else 50.0


async def _cve_criticality_factor(cve_ids: list[str]) -> float:
    if not cve_ids:
        return 0.0
    cve_ids_upper = [c.upper() for c in cve_ids]
    col = get_database()["cve_tracker"]
    cursor = col.find(
        {"cve_id": {"$in": cve_ids_upper}},
        {"cve_score": 1, "cisa_kev": 1, "active_exploitation": 1, "poc_available": 1, "_id": 0},
    )
    docs = await cursor.to_list(length=len(cve_ids_upper))
    if not docs:
        return 0.0

    max_cvss = max((d.get("cve_score") or 0.0) for d in docs)
    base = (max_cvss / 10.0) * 80.0

    bonus = 0.0
    for d in docs:
        if d.get("cisa_kev"):
            bonus = max(bonus, 15.0)
        if d.get("active_exploitation"):
            bonus = max(bonus, 20.0)
        if d.get("poc_available"):
            bonus = max(bonus, 5.0)

    return min(100.0, base + bonus)


def _velocity_factor(velocity_articles_per_day: float) -> float:
    apd = velocity_articles_per_day or 0.0
    if apd >= 5.0:
        return 100.0
    if apd >= 3.0:
        return 80.0
    if apd >= 1.0:
        return 60.0
    if apd >= 0.3:
        return 40.0
    return 20.0


async def _source_quality_factor(member_article_ids: list[str], articles_raw: list[dict] | None) -> float:
    if articles_raw:
        grades = [(a.get("source_reliability") or "").upper() for a in articles_raw]
        scores = [_RELIABILITY_SCORES[g] for g in grades if g in _RELIABILITY_SCORES]
        if scores:
            return float(sum(scores) / len(scores))

    if not member_article_ids:
        return 50.0

    from bson import ObjectId
    from app.config import COLLECTION_NAME
    valid_oids = []
    for aid in member_article_ids:
        try:
            valid_oids.append(ObjectId(aid))
        except Exception:
            pass
    if not valid_oids:
        return 50.0

    col = get_database()[COLLECTION_NAME]
    cursor = col.find({"_id": {"$in": valid_oids}}, {"source_reliability": 1, "_id": 0})
    docs = await cursor.to_list(length=len(valid_oids))
    scores = []
    for d in docs:
        g = (d.get("source_reliability") or "").upper()
        if g in _RELIABILITY_SCORES:
            scores.append(_RELIABILITY_SCORES[g])
    return float(sum(scores) / len(scores)) if scores else 50.0


async def compute_campaign_severity(campaign: dict, articles_raw: list[dict] | None = None) -> dict:
    ta_f, ioc_f, cve_f, src_f = await asyncio.gather(
        _ta_sophistication_factor(campaign.get("dominant_tas", [])),
        _ioc_confidence_factor(campaign.get("iocs", [])),
        _cve_criticality_factor(campaign.get("cve_ids", [])),
        _source_quality_factor(campaign.get("member_article_ids", []), articles_raw),
    )

    vel_f = _velocity_factor(campaign.get("velocity_articles_per_day", 0.0))

    severity_score = round(
        ta_f  * 0.30
        + ioc_f * 0.20
        + cve_f * 0.20
        + vel_f * 0.15
        + src_f * 0.15
    )
    severity_score = max(0, min(100, severity_score))

    if severity_score >= 80:
        label = "critical"
    elif severity_score >= 60:
        label = "high"
    elif severity_score >= 40:
        label = "medium"
    else:
        label = "low"

    breakdown = {
        "ta_sophistication":  round(ta_f * 0.30, 1),
        "ioc_confidence":     round(ioc_f * 0.20, 1),
        "cve_criticality":    round(cve_f * 0.20, 1),
        "campaign_velocity":  round(vel_f * 0.15, 1),
        "source_quality":     round(src_f * 0.15, 1),
        "raw": {
            "ta_sophistication": round(ta_f, 1),
            "ioc_confidence":    round(ioc_f, 1),
            "cve_criticality":   round(cve_f, 1),
            "campaign_velocity": round(vel_f, 1),
            "source_quality":    round(src_f, 1),
        },
    }

    return {
        "severity_score":     severity_score,
        "severity_label":     label,
        "severity_breakdown": breakdown,
    }
