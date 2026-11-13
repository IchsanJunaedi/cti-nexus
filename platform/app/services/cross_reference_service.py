"""Cross-reference service: links CVEs, PIRs, and Threat Actor profiles."""
import asyncio
import re
from app.database import get_database
from app.database import get_ta_database
from app.config import PIR_COLLECTION, COLLECTION_NAME, TA_PROFILES_COLLECTION

CVE_COLLECTION = "cve_tracker"
FP_COLLECTION = "cve_false_positives"


def _news_db():
    return get_database()


def _ta_db():
    return get_ta_database()


async def get_cve_crossrefs(cve_id: str) -> dict:
    """
    For a CVE, find:
    - Active PIRs whose TA criteria overlap with articles mentioning this CVE
    - TA profiles for threat actors mentioned in articles about this CVE
    - News articles mentioning this CVE
    """
    db = _news_db()
    ta_db = _ta_db()

    cve_doc, fp_ids_raw = await asyncio.gather(
        db[CVE_COLLECTION].find_one({"cve_id": {"$regex": f"^{re.escape(cve_id)}$", "$options": "i"}}),
        db[FP_COLLECTION].distinct("cve_id"),
    )
    if not cve_doc:
        return {"error": "CVE not found"}

    fp_set = set(fp_ids_raw)
    if cve_id.upper() in fp_set:
        return {"error": "CVE is a false positive"}

    cve_tas = cve_doc.get("threat_actors", [])
    cve_tech = cve_doc.get("tech", "")

    # Articles mentioning this CVE (by title regex)
    articles_raw = await db[COLLECTION_NAME].find(
        {"title": {"$regex": re.escape(cve_id), "$options": "i"}},
        {"_id": 1, "title": 1, "url": 1, "posted_on": 1, "source": 1, "threat_actors": 1},
    ).sort("posted_on", -1).limit(20).to_list(20)
    for a in articles_raw:
        a["_id"] = str(a["_id"])

    # Aggregate threat actors seen in those articles
    article_tas: set[str] = set(cve_tas)
    for a in articles_raw:
        for ta in a.get("threat_actors", []):
            article_tas.add(ta)

    # Active PIRs that have overlapping TA criteria with this CVE's actors
    all_pirs = await db[PIR_COLLECTION].find({"status": "active"}).to_list(500)
    matched_pirs = []
    for pir in all_pirs:
        criteria = pir.get("criteria", {})
        pir_tas = set(criteria.get("threat_actors", []))
        pir_ttps = set(criteria.get("ttps", []))
        cve_ttps = {t.get("id") for t in cve_doc.get("ttps", []) if t.get("id")}

        ta_overlap = pir_tas & article_tas
        ttp_overlap = pir_ttps & cve_ttps

        if ta_overlap or ttp_overlap:
            matched_pirs.append({
                "id": str(pir["_id"]),
                "title": pir.get("title", ""),
                "priority": pir.get("priority", "P2"),
                "owner": pir.get("owner", ""),
                "ta_overlap": sorted(ta_overlap),
                "ttp_overlap": sorted(ttp_overlap),
            })

    # TA profiles for actors seen in CVE context
    ta_profiles = []
    if article_tas:
        profile_docs = await ta_db[TA_PROFILES_COLLECTION].find(
            {"_actor_name": {"$in": list(article_tas)}},
            {"_actor_name": 1, "identity.primary_name": 1, "identity.actor_type": 1,
             "motivation.primary_motivation": 1, "organizational_relevance.monitoring_priority": 1,
             "profile_metadata.analyst_confidence": 1, "_generated_at": 1},
        ).to_list(20)
        for p in ta_profiles:
            p["_id"] = str(p.get("_id", ""))
        ta_profiles = [
            {
                "actor_name": p.get("_actor_name", ""),
                "primary_name": p.get("identity", {}).get("primary_name", ""),
                "actor_type": p.get("identity", {}).get("actor_type", ""),
                "motivation": p.get("motivation", {}).get("primary_motivation", ""),
                "monitoring_priority": p.get("organizational_relevance", {}).get("monitoring_priority", ""),
                "confidence": p.get("profile_metadata", {}).get("analyst_confidence", ""),
                "generated_at": p.get("_generated_at", ""),
            }
            for p in profile_docs
        ]

    return {
        "cve_id": cve_id,
        "cve_severity": cve_doc.get("cve_severity", ""),
        "cve_score": cve_doc.get("cve_score"),
        "tech": cve_tech,
        "cisa_kev": cve_doc.get("cisa_kev", False),
        "poc_available": cve_doc.get("poc_available", False),
        "matched_pirs": matched_pirs,
        "ta_profiles": ta_profiles,
        "news_articles": articles_raw,
        "all_context_actors": sorted(article_tas),
    }


async def get_pir_crossrefs(pir_id: str) -> dict:
    """
    For a PIR, find:
    - CVEs whose threat actors overlap with PIR TA criteria
    - CVEs matching PIR TTP criteria
    - TA profiles for PIR-tracked actors
    """
    from bson import ObjectId
    db = _news_db()
    ta_db = _ta_db()

    pir = await db[PIR_COLLECTION].find_one({"_id": ObjectId(pir_id)})
    if not pir:
        return {"error": "PIR not found"}

    criteria = pir.get("criteria", {})
    pir_tas = criteria.get("threat_actors", [])
    pir_ttps = set(criteria.get("ttps", []))
    pir_industries = criteria.get("industries", [])

    fp_ids_raw = await db[FP_COLLECTION].distinct("cve_id")
    fp_set = set(fp_ids_raw)

    # CVEs matching PIR actors or TTPs
    cve_query: dict = {"cve_id": {"$nin": list(fp_set)}}
    cve_conditions = []
    if pir_tas:
        cve_conditions.append({"threat_actors": {"$in": pir_tas}})
    if pir_ttps:
        cve_conditions.append({"ttps.id": {"$in": list(pir_ttps)}})
    if pir_industries:
        cve_conditions.append({"tech": {"$in": pir_industries}})
    if cve_conditions:
        cve_query["$or"] = cve_conditions

    matched_cves_raw = await db[CVE_COLLECTION].find(
        cve_query,
        {"cve_id": 1, "cve_severity": 1, "cve_score": 1, "tech": 1,
         "cisa_kev": 1, "poc_available": 1, "threat_actors": 1, "ttps": 1},
    ).sort("cve_score", -1).limit(50).to_list(50)

    matched_cves = []
    for c in matched_cves_raw:
        c_ta_set = set(c.get("threat_actors", []))
        c_ttp_set = {t.get("id") for t in c.get("ttps", []) if t.get("id")}
        matched_cves.append({
            "cve_id": c["cve_id"],
            "severity": c.get("cve_severity", ""),
            "score": c.get("cve_score"),
            "tech": c.get("tech", ""),
            "cisa_kev": c.get("cisa_kev", False),
            "poc_available": c.get("poc_available", False),
            "ta_overlap": sorted(set(pir_tas) & c_ta_set),
            "ttp_overlap": sorted(pir_ttps & c_ttp_set),
        })

    # TA profiles
    ta_profiles = []
    if pir_tas:
        profile_docs = await ta_db[TA_PROFILES_COLLECTION].find(
            {"_actor_name": {"$in": pir_tas}},
            {"_actor_name": 1, "identity": 1, "motivation.primary_motivation": 1,
             "organizational_relevance.monitoring_priority": 1,
             "profile_metadata.analyst_confidence": 1, "_generated_at": 1},
        ).to_list(20)
        ta_profiles = [
            {
                "actor_name": p.get("_actor_name", ""),
                "primary_name": p.get("identity", {}).get("primary_name", ""),
                "actor_type": p.get("identity", {}).get("actor_type", ""),
                "motivation": p.get("motivation", {}).get("primary_motivation", ""),
                "monitoring_priority": p.get("organizational_relevance", {}).get("monitoring_priority", ""),
                "confidence": p.get("profile_metadata", {}).get("analyst_confidence", ""),
                "has_profile": True,
                "generated_at": p.get("_generated_at", ""),
            }
            for p in profile_docs
        ]
        profiled_names = {p["actor_name"] for p in ta_profiles}
        for ta in pir_tas:
            if ta not in profiled_names:
                ta_profiles.append({"actor_name": ta, "has_profile": False})

    return {
        "pir_id": pir_id,
        "pir_title": pir.get("title", ""),
        "pir_priority": pir.get("priority", "P2"),
        "matched_cves": matched_cves,
        "ta_profiles": ta_profiles,
        "pir_actors": pir_tas,
        "pir_ttps": list(pir_ttps),
    }


async def get_ta_crossrefs(actor_name: str) -> dict:
    """
    For a TA, find:
    - CVEs attributed to this actor
    - Active PIRs tracking this actor
    - Recent news articles
    """
    db = _news_db()
    ta_db = _ta_db()

    fp_ids_raw = await db[FP_COLLECTION].distinct("cve_id")
    fp_set = set(fp_ids_raw)

    pattern = re.compile(f"^{re.escape(actor_name)}$", re.IGNORECASE)
    cves_raw, pirs_raw, articles_raw, profile_doc = await asyncio.gather(
        db[CVE_COLLECTION].find(
            {"threat_actors": pattern, "cve_id": {"$nin": list(fp_set)}},
            {"cve_id": 1, "cve_severity": 1, "cve_score": 1, "tech": 1,
             "cisa_kev": 1, "poc_available": 1},
        ).sort("cve_score", -1).limit(30).to_list(30),
        db[PIR_COLLECTION].find(
            {"status": "active", "criteria.threat_actors": actor_name},
            {"title": 1, "priority": 1, "owner": 1},
        ).to_list(20),
        db[COLLECTION_NAME].find(
            {"threat_actors": pattern},
            {"_id": 0, "title": 1, "url": 1, "posted_on": 1, "source": 1},
        ).sort("posted_on", -1).limit(20).to_list(20),
        ta_db[TA_PROFILES_COLLECTION].find_one(
            {"_actor_name": {"$regex": f"^{re.escape(actor_name)}$", "$options": "i"}},
            {"_id": 0, "identity": 1, "motivation": 1, "targeting_profile": 1,
             "organizational_relevance": 1, "profile_metadata": 1, "_generated_at": 1},
        ),
    )

    return {
        "actor_name": actor_name,
        "has_profile": profile_doc is not None,
        "profile_summary": profile_doc,
        "matched_cves": [
            {
                "cve_id": c["cve_id"],
                "severity": c.get("cve_severity", ""),
                "score": c.get("cve_score"),
                "tech": c.get("tech", ""),
                "cisa_kev": c.get("cisa_kev", False),
                "poc_available": c.get("poc_available", False),
            }
            for c in cves_raw
        ],
        "active_pirs": [
            {"id": str(p["_id"]), "title": p.get("title", ""), "priority": p.get("priority", "P2"), "owner": p.get("owner", "")}
            for p in pirs_raw
        ],
        "recent_articles": articles_raw,
    }
