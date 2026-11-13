import asyncio
from datetime import date, timedelta
from app.database import get_database
from app.config import COLLECTION_NAME


def _col():
    return get_database()[COLLECTION_NAME]

def _cve_col():
    return get_database()["cve_tracker"]

def _fp_col():
    return get_database()["cve_false_positives"]


async def _get_fp_ids() -> list[str]:
    docs = await _fp_col().find({}, {"cve_id": 1, "_id": 0}).to_list(length=10000)
    return [d["cve_id"] for d in docs]


NON_INCIDENT_TYPES = {"Vendor Report Article", "Unrelated Tech Stack Article", "Security Technology & Best Practices"}


async def get_exec_dashboard(days: int = 90, incident_only: bool = True, confirmed_only: bool = False) -> dict:
    col      = _col()
    cutoff   = (date.today() - timedelta(days=days)).isoformat()
    prev_cut = (date.today() - timedelta(days=days * 2)).isoformat()

    base_filter: dict = {"posted_on": {"$gte": cutoff}}
    prev_base: dict   = {"posted_on": {"$gte": prev_cut, "$lt": cutoff}}
    if incident_only:
        type_excl = {"news_type": {"$nin": list(NON_INCIDENT_TYPES)}}
        base_filter  = {**base_filter,  **type_excl}
        prev_base    = {**prev_base,    **type_excl}
    if confirmed_only:
        conf_excl = {"confirmed_incident": True}
        base_filter  = {**base_filter,  **conf_excl}
        prev_base    = {**prev_base,    **conf_excl}

    match      = {"$match": base_filter}
    prev_filt  = prev_base

    sector_trend_pipeline = [
        match,
        {"$unwind": "$impacted_industries"},
        {"$group": {
            "_id": {"sector": "$impacted_industries", "month": {"$substr": ["$posted_on", 0, 7]}},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id.month": 1}},
    ]
    country_trend_pipeline = [
        match,
        {"$unwind": "$mentioned_countries"},
        {"$group": {
            "_id": {"country": "$mentioned_countries", "month": {"$substr": ["$posted_on", 0, 7]}},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id.month": 1}},
    ]
    ta_pipeline = [
        match,
        {"$unwind": "$threat_actors"},
        {"$group": {"_id": "$threat_actors", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    unique_ta_pipeline = [
        match,
        {"$unwind": "$threat_actors"},
        {"$group": {"_id": "$threat_actors"}},
        {"$count": "count"},
    ]
    news_type_pipeline = [
        match,
        {"$group": {"_id": "$news_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    # Period-over-period pipelines
    prev_unique_ta_pipeline = [
        {"$match": prev_filt},
        {"$unwind": "$threat_actors"},
        {"$group": {"_id": "$threat_actors"}},
        {"$count": "count"},
    ]
    prev_sector_pipeline = [
        {"$match": prev_filt},
        {"$unwind": "$impacted_industries"},
        {"$group": {"_id": "$impacted_industries"}},
        {"$count": "count"},
    ]

    (
        sector_trend_raw, country_trend_raw, ta_raw,
        unique_ta_raw, news_type_raw,
        prev_unique_ta_raw, prev_sector_raw,
        total, prev_total,
        fp_ids,
    ) = await asyncio.gather(
        col.aggregate(sector_trend_pipeline).to_list(5000),
        col.aggregate(country_trend_pipeline).to_list(5000),
        col.aggregate(ta_pipeline).to_list(10),
        col.aggregate(unique_ta_pipeline).to_list(1),
        col.aggregate(news_type_pipeline).to_list(50),
        col.aggregate(prev_unique_ta_pipeline).to_list(1),
        col.aggregate(prev_sector_pipeline).to_list(1),
        col.count_documents(base_filter),
        col.count_documents(prev_base),
        _get_fp_ids(),
    )

    # ── Months ──
    months_set = set()
    for r in sector_trend_raw:
        months_set.add(r["_id"]["month"])
    months = sorted(months_set)

    # ── Sector trend: top 8 ──
    sector_map: dict[str, dict[str, int]] = {}
    for r in sector_trend_raw:
        s, m = r["_id"]["sector"], r["_id"]["month"]
        sector_map.setdefault(s, {})[m] = r["count"]
    sector_totals  = {s: sum(v.values()) for s, v in sector_map.items()}
    top_sectors    = sorted(sector_totals, key=lambda x: -sector_totals[x])[:8]
    sector_trend   = [
        {"sector": s, "data": [sector_map[s].get(m, 0) for m in months]}
        for s in top_sectors
    ]

    # ── Country trend: top 8 by volume ──
    country_map: dict[str, dict[str, int]] = {}
    for r in country_trend_raw:
        c, m = r["_id"]["country"], r["_id"]["month"]
        country_map.setdefault(c, {})[m] = r["count"]
    country_totals  = {c: sum(v.values()) for c, v in country_map.items()}
    top_countries   = sorted(country_totals, key=lambda x: -country_totals[x])[:8]
    country_trend   = [
        {"country": c, "data": [country_map[c].get(m, 0) for m in months]}
        for c in top_countries
    ]

    # ── Sector heatmap ──
    sector_heatmap = [
        {"sector": s, "months": [{"month": m, "count": sector_map[s].get(m, 0)} for m in months]}
        for s in top_sectors
    ]
    heatmap_max = max(
        (sector_map[s].get(m, 0) for s in top_sectors for m in months),
        default=0,
    )

    # ── CVE exposure — fix severity case, exclude FPs ──
    fp_match = [{"$match": {"cve_id": {"$nin": fp_ids}}}] if fp_ids else []
    cve_pipeline = [
        *fp_match,
        {"$group": {
            "_id": "$tech",
            "total":    {"$sum": 1},
            "critical": {"$sum": {"$cond": [{"$eq": [{"$toUpper": "$cve_severity"}, "CRITICAL"]}, 1, 0]}},
            "high":     {"$sum": {"$cond": [{"$eq": [{"$toUpper": "$cve_severity"}, "HIGH"]},     1, 0]}},
            "medium":   {"$sum": {"$cond": [{"$eq": [{"$toUpper": "$cve_severity"}, "MEDIUM"]},   1, 0]}},
        }},
        {"$sort": {"critical": -1, "total": -1}},
        {"$limit": 10},
    ]
    cve_raw = await _cve_col().aggregate(cve_pipeline).to_list(10)
    cve_exposure = [
        {"tech": r["_id"], "total": r["total"], "critical": r["critical"],
         "high": r["high"], "medium": r["medium"]}
        for r in cve_raw
    ]

    # ── Period-over-period ──
    unique_ta_count      = unique_ta_raw[0]["count"]      if unique_ta_raw      else 0
    prev_unique_ta_count = prev_unique_ta_raw[0]["count"] if prev_unique_ta_raw else 0
    prev_active_sectors  = prev_sector_raw[0]["count"]    if prev_sector_raw    else 0

    return {
        "total_incidents":    total,
        "prev_total":         prev_total,
        "unique_ta_count":    unique_ta_count,
        "prev_unique_ta":     prev_unique_ta_count,
        "active_sectors":     len(top_sectors),
        "prev_active_sectors": prev_active_sectors,
        "months":             months,
        "top_sectors":        top_sectors,
        "top_countries":      top_countries,
        "sector_trend":       sector_trend,
        "country_trend":      country_trend,
        "ta_leaderboard":     [{"name": r["_id"], "count": r["count"]} for r in ta_raw],
        "news_type_breakdown": [{"name": r["_id"] or "Unknown", "count": r["count"]} for r in news_type_raw],
        "sector_heatmap":     sector_heatmap,
        "heatmap_max":        heatmap_max,
        "cve_exposure":       cve_exposure,
    }
