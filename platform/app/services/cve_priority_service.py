from app.database import get_database, get_ta_database
from app.config import TECHSTACK_COLLECTION


def _priority_label(score: float) -> str:
    if score >= 80:
        return "critical_patch"
    if score >= 60:
        return "high_priority"
    if score >= 40:
        return "medium"
    return "low"


def _patch_urgency(label: str, in_tech_stack: bool) -> str:
    if label == "critical_patch" and in_tech_stack:
        return "immediate"
    if label == "critical_patch":
        return "24h"
    if label == "high_priority":
        return "7d"
    if label == "medium":
        return "30d"
    return "monitor"


async def _fetch_tech_stack_names(client_id: str = "default") -> set[str]:
    try:
        col = get_ta_database()[TECHSTACK_COLLECTION]
        cf = {"client_id": client_id} if client_id != "default" else {
            "$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]
        }
        cursor = col.find(cf, {"name": 1, "_id": 0})
        docs = await cursor.to_list(length=10000)
        return {d["name"].lower() for d in docs if d.get("name")}
    except Exception:
        return set()


async def prioritize_campaign_cves(
    cve_ids: list[str],
    campaign_context: dict,
    client_id: str = "default",
) -> list[dict]:
    if not cve_ids:
        return []

    cve_col = get_database()["cve_tracker"]
    cursor = cve_col.find(
        {"cve_id": {"$in": cve_ids}},
        {"_id": 0, "cve_id": 1, "cve_score": 1, "cve_severity": 1,
         "cisa_kev": 1, "poc_available": 1, "active_exploitation": 1, "tech": 1},
    )
    tracker_docs = await cursor.to_list(length=len(cve_ids))
    tracker_map = {(d.get("cve_id") or "").upper(): d for d in tracker_docs}

    tech_stack = await _fetch_tech_stack_names(client_id)

    results: list[dict] = []
    for cve_id in cve_ids:
        doc = tracker_map.get(cve_id.upper())
        if doc is None:
            results.append({
                "cve_id":            cve_id,
                "cvss_score":        None,
                "severity":          None,
                "cisa_kev":          False,
                "poc_available":     False,
                "actively_exploited": False,
                "in_tech_stack":     False,
                "priority_score":    20,
                "priority_label":    "low",
                "patch_urgency":     "monitor",
            })
            continue

        cvss = float(doc.get("cve_score") or 0)
        cisa_kev = bool(doc.get("cisa_kev"))
        actively_exploited = bool(doc.get("active_exploitation"))
        poc_available = bool(doc.get("poc_available"))
        tech_name = (doc.get("tech") or "").lower()
        in_tech_stack = bool(tech_name and any(t in tech_name or tech_name in t for t in tech_stack))

        score = (
            cvss * 10 * 0.30
            + (100 if cisa_kev else 0) * 0.20
            + (100 if actively_exploited else 0) * 0.20
            + (100 if poc_available else 0) * 0.10
            + (100 if in_tech_stack else 0) * 0.20
        )
        score = round(min(score, 100), 1)

        label = _priority_label(score)
        results.append({
            "cve_id":            cve_id,
            "cvss_score":        cvss if cvss > 0 else None,
            "severity":          doc.get("cve_severity"),
            "cisa_kev":          cisa_kev,
            "poc_available":     poc_available,
            "actively_exploited": actively_exploited,
            "in_tech_stack":     in_tech_stack,
            "priority_score":    score,
            "priority_label":    label,
            "patch_urgency":     _patch_urgency(label, in_tech_stack),
        })

    results.sort(key=lambda x: x["priority_score"], reverse=True)
    return results
