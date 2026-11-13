import asyncio
import statistics
from collections import defaultdict
from datetime import date, timedelta
from itertools import combinations

from app.database import get_database
from app.config import COLLECTION_NAME, IOC_COLLECTION
from app.services.exec_dashboard_service import (
    get_exec_dashboard,
    _col,
    _cve_col,
    _get_fp_ids,
    NON_INCIDENT_TYPES,
)
from app.services.spike_service import get_spikes


def build_view_config(role: str) -> dict:
    admin_set = {"admin", "superadmin"}
    return {
        "role": role,
        "sections": {
            "kpis":                     True,
            "sector_risk":              True,
            "ta_leaderboard":           True,
            "exec_brief_button":        role in {"exec"} | admin_set,
            "source_reliability_spread": role in {"analyst"} | admin_set,
            "cluster_list":             role in {"analyst"} | admin_set,
            "ioc_enrichment_hits":      role in {"analyst", "soc"} | admin_set,
            "fp_feedback_queue":        role in {"analyst"} | admin_set,
            "critical_cve_feed":        role in {"soc"} | admin_set,
            "live_ioc_stream":          role in {"soc"} | admin_set,
            "sigma_export_quick":       role in {"soc"} | admin_set,
            "spike_alerts":             role in {"soc", "analyst"} | admin_set,
        },
    }


async def _get_critical_cves(client_id: str) -> list[dict]:
    try:
        cve_col = _cve_col()
        cursor = cve_col.find(
            {"$or": [{"epss_score": {"$gte": 0.5}}, {"cisa_kev": True}], "client_id": client_id},
            {"_id": 0, "cve_id": 1, "cve_score": 1, "cve_severity": 1, "epss_score": 1,
             "cisa_kev": 1, "first_seen": 1, "tech": 1},
        ).sort("epss_score", -1).limit(20)
        return await cursor.to_list(length=20)
    except Exception:
        return []


async def _get_recent_clusters(client_id: str) -> list[dict]:
    try:
        from app.services.cluster_service import get_recent_campaigns
        campaigns = await get_recent_campaigns(days=30, client_id=client_id, min_size=2)
        return [
            {
                "cluster_id": str(c.get("cluster_id", "")),
                "summary_title": c.get("summary_title") or "",
                "size": c.get("size") or 0,
                "threat_actors": c.get("dominant_tas") or [],
                "last_seen": c.get("last_seen") or "",
            }
            for c in campaigns[:10]
        ]
    except Exception:
        return []


async def _get_pending_fp_queue(client_id: str) -> list[dict]:
    try:
        ioc_col = get_database()[IOC_COLLECTION]
        return await ioc_col.aggregate([
            {"$match": {"confidence_score": {"$gte": 40, "$lt": 75}, "client_id": client_id}},
            {"$sort": {"last_seen": -1}},
            {"$limit": 20},
            {"$project": {"_id": 0, "value": 1, "type": 1, "last_seen": 1, "confidence_score": 1}},
        ]).to_list(20)
    except Exception:
        return []


async def _get_source_reliability_spread(client_id: str) -> dict:
    try:
        col = _col()
        raw = await col.aggregate([
            {"$match": {"source_reliability": {"$exists": True, "$ne": ""}}},
            {"$group": {"_id": "$source_reliability", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}},
        ]).to_list(20)
        return {r["_id"]: r["count"] for r in raw}
    except Exception:
        return {}


# ── Tier 1 helpers ────────────────────────────────────────────

def _compute_sector_risk_scores(sector_trend: list[dict]) -> list[dict]:
    """0-100 risk score per sector from monthly trend data."""
    if not sector_trend:
        return []

    all_last = [s["data"][-1] if s["data"] else 0 for s in sector_trend]
    max_last = max(all_last) or 1

    results = []
    for s in sector_trend:
        counts = s["data"]
        last = counts[-1] if counts else 0

        vol_score = (last / max_last) * 50

        if len(counts) >= 4:
            mid = len(counts) // 2
            first_avg = statistics.mean(counts[:mid]) if counts[:mid] else 0
            second_avg = statistics.mean(counts[mid:]) if counts[mid:] else 0
            if first_avg > 0:
                ratio = min(second_avg / first_avg, 2.0)
                trend_score = max(0, (ratio - 1.0) * 20)
            else:
                trend_score = 10 if second_avg > 0 else 0
        else:
            trend_score = 0

        if len(counts) >= 3:
            history = counts[:-1]
            mean = statistics.mean(history)
            try:
                std = statistics.stdev(history) if len(history) >= 2 else 0.5
            except statistics.StatisticsError:
                std = 0.5
            std = std or 0.5
            z = (last - mean) / std
            spike_score = min(30, max(0, z * 10))
        else:
            spike_score = 0

        results.append({
            "sector": s["sector"],
            "risk_score": min(100, round(vol_score + trend_score + spike_score)),
        })

    results.sort(key=lambda x: -x["risk_score"])
    return results


# ── Tier 2 helpers ────────────────────────────────────────────

def _compute_ta_velocity(ta_monthly_raw: list[dict], months: list[str]) -> list[dict]:
    """Ramp rate per TA: (last_month / avg_prev_months - 1) * 100."""
    series: dict[str, dict[str, int]] = defaultdict(dict)
    for r in ta_monthly_raw:
        actor = r["_id"]["actor"]
        month = r["_id"]["month"]
        series[actor][month] = r["count"]

    results = []
    for actor, monthly in series.items():
        counts = [monthly.get(m, 0) for m in months]
        if len(counts) < 2 or sum(counts) == 0:
            continue
        last = counts[-1]
        prev = counts[:-1]
        avg_prev = statistics.mean(prev) if prev else 0
        if avg_prev > 0:
            velocity_pct = round((last / avg_prev - 1) * 100)
        elif last > 0:
            velocity_pct = 100
        else:
            velocity_pct = 0
        total = sum(counts)
        results.append({
            "actor": actor,
            "velocity_pct": velocity_pct,
            "last_month": last,
            "avg_prev": round(avg_prev, 1),
            "total": total,
        })

    results.sort(key=lambda x: -x["velocity_pct"])
    return results[:10]


def _compute_sector_cooccurrence(cooccur_raw: list[dict]) -> list[dict]:
    """Count sector pair co-occurrences from article industry arrays."""
    pair_counts: dict[tuple, int] = defaultdict(int)
    for doc in cooccur_raw:
        industries = doc.get("industries") or []
        unique = list(dict.fromkeys(i for i in industries if i))
        if len(unique) >= 2:
            for a, b in combinations(sorted(unique), 2):
                pair_counts[(a, b)] += 1

    results = [
        {"sector_a": a, "sector_b": b, "count": c}
        for (a, b), c in sorted(pair_counts.items(), key=lambda x: -x[1])
    ]
    return results[:15]


def _build_newstype_trend(nt_monthly_raw: list[dict], months: list[str], top_n: int = 6) -> dict:
    """Monthly stacked bar data for incident types."""
    monthly_map: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    totals: dict[str, int] = defaultdict(int)
    for r in nt_monthly_raw:
        nt = r["_id"]["news_type"] or "Unknown"
        mo = r["_id"]["month"]
        cnt = r["count"]
        monthly_map[nt][mo] += cnt
        totals[nt] += cnt

    top_types = sorted(totals, key=lambda x: -totals[x])[:top_n]
    series = [
        {"type": t, "data": [monthly_map[t].get(m, 0) for m in months]}
        for t in top_types
    ]
    return {"months": months, "series": series}


def _build_sector_actor_matrix(
    sa_raw: list[dict],
    top_sectors: list[str],
    top_actors: list[str],
) -> dict:
    """Sector × Actor co-occurrence matrix."""
    co_map = {(r["_id"]["sector"], r["_id"]["actor"]): r["count"] for r in sa_raw}
    matrix = [
        [co_map.get((s, a), 0) for a in top_actors]
        for s in top_sectors
    ]
    max_val = max((max(row) for row in matrix if row), default=0)
    return {"sectors": top_sectors, "actors": top_actors, "matrix": matrix, "max_val": max_val}


# ── Main V2 function ──────────────────────────────────────────

async def get_exec_dashboard_v2(
    days: int = 90,
    incident_only: bool = True,
    confirmed_only: bool = False,
    client_id: str = "default",
    role: str = "analyst",
) -> dict:
    col = _col()
    cutoff = (date.today() - timedelta(days=days)).isoformat()
    prev_cut = (date.today() - timedelta(days=days * 2)).isoformat()

    base_filter: dict = {"posted_on": {"$gte": cutoff}}
    prev_filt: dict   = {"posted_on": {"$gte": prev_cut, "$lt": cutoff}}
    if incident_only:
        type_excl = {"news_type": {"$nin": list(NON_INCIDENT_TYPES)}}
        base_filter = {**base_filter, **type_excl}
        prev_filt   = {**prev_filt,   **type_excl}
    if confirmed_only:
        conf_excl = {"confirmed_incident": True}
        base_filter = {**base_filter, **conf_excl}
        prev_filt   = {**prev_filt,   **conf_excl}

    match = {"$match": base_filter}

    # ── Tier 1 pipelines ──
    prev_ta_pipeline = [
        {"$match": prev_filt},
        {"$unwind": "$threat_actors"},
        {"$match": {"threat_actors": {"$ne": ""}}},
        {"$group": {"_id": "$threat_actors"}},
    ]

    fp_ids = await _get_fp_ids()
    fp_match = [{"$match": {"cve_id": {"$nin": fp_ids}}}] if fp_ids else []
    cve_v2_pipeline = [
        *fp_match,
        {"$group": {
            "_id": "$tech",
            "total":     {"$sum": 1},
            "critical":  {"$sum": {"$cond": [{"$eq": [{"$toUpper": "$cve_severity"}, "CRITICAL"]}, 1, 0]}},
            "high":      {"$sum": {"$cond": [{"$eq": [{"$toUpper": "$cve_severity"}, "HIGH"]},     1, 0]}},
            "medium":    {"$sum": {"$cond": [{"$eq": [{"$toUpper": "$cve_severity"}, "MEDIUM"]},   1, 0]}},
            "max_cvss":  {"$max": "$cve_score"},
            "poc_count": {"$sum": {"$cond": ["$poc_available", 1, 0]}},
        }},
        {"$sort": {"critical": -1, "total": -1}},
        {"$limit": 10},
    ]

    # ── Tier 2 pipelines ──

    # T2-6: Victim-country monthly trend (separate from mentioned_countries)
    victim_country_pipeline = [
        match,
        {"$match": {"victim_countries": {"$exists": True, "$ne": []}}},
        {"$unwind": "$victim_countries"},
        {"$match": {"victim_countries": {"$ne": ""}}},
        {"$group": {
            "_id": {"country": "$victim_countries", "month": {"$substr": ["$posted_on", 0, 7]}},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id.month": 1}},
    ]

    # T2-7: Top TTPs
    ttp_pipeline = [
        match,
        {"$match": {"ttps": {"$exists": True, "$ne": []}}},
        {"$unwind": "$ttps"},
        {"$group": {
            "_id": {"id": "$ttps.id", "name": "$ttps.name"},
            "count": {"$sum": 1},
        }},
        {"$sort": {"count": -1}},
        {"$limit": 15},
    ]

    # T2-8: TA monthly counts (for velocity)
    ta_monthly_pipeline = [
        match,
        {"$unwind": "$threat_actors"},
        {"$match": {"threat_actors": {"$ne": ""}}},
        {"$group": {
            "_id": {"actor": "$threat_actors", "month": {"$substr": ["$posted_on", 0, 7]}},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id.month": 1}},
    ]

    # T2-9: Sector co-occurrence (articles with ≥2 sectors)
    cooccur_pipeline = [
        match,
        {"$match": {"impacted_industries.1": {"$exists": True}}},
        {"$project": {"industries": "$impacted_industries", "_id": 0}},
    ]

    # T2-10: News-type monthly trend
    newstype_monthly_pipeline = [
        match,
        {"$group": {
            "_id": {
                "news_type": "$news_type",
                "month": {"$substr": ["$posted_on", 0, 7]},
            },
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id.month": 1}},
    ]

    (
        base,
        prev_ta_raw,
        cve_v2_raw,
        spike_data,
        victim_country_raw,
        ttp_raw,
        ta_monthly_raw,
        cooccur_raw,
        newstype_monthly_raw,
    ) = await asyncio.gather(
        get_exec_dashboard(days=days, incident_only=incident_only, confirmed_only=confirmed_only),
        col.aggregate(prev_ta_pipeline).to_list(5000),
        _cve_col().aggregate(cve_v2_pipeline).to_list(10),
        get_spikes(lookback_days=max(days, 30), z_threshold=1.5, extra_filter={k: v for k, v in base_filter.items() if k != "posted_on"}),
        col.aggregate(victim_country_pipeline).to_list(5000),
        col.aggregate(ttp_pipeline).to_list(15),
        col.aggregate(ta_monthly_pipeline).to_list(50000),
        col.aggregate(cooccur_pipeline).to_list(50000),
        col.aggregate(newstype_monthly_pipeline).to_list(5000),
    )

    months = base["months"]
    top_sectors = base["top_sectors"]

    # T2-11: Sector × Actor (uses top_sectors from base)
    top_actor_names = [r["name"] for r in base["ta_leaderboard"]][:8]
    sector_actor_pipeline = [
        match,
        {"$unwind": "$impacted_industries"},
        {"$unwind": "$threat_actors"},
        {"$match": {
            "impacted_industries": {"$in": top_sectors[:8]},
            "threat_actors": {"$in": top_actor_names},
        }},
        {"$group": {
            "_id": {"sector": "$impacted_industries", "actor": "$threat_actors"},
            "count": {"$sum": 1},
        }},
    ]
    # T3-15: TA confidence — use confirmed_incident field when available, fall back to news_type proxy
    top_actor_names_for_conf = [r["name"] for r in base["ta_leaderboard"]]
    ta_confidence_pipeline = [
        {"$match": {"posted_on": {"$gte": cutoff}}},
        {"$unwind": "$threat_actors"},
        {"$match": {"threat_actors": {"$in": top_actor_names_for_conf}}},
        {"$group": {
            "_id": "$threat_actors",
            "total":             {"$sum": 1},
            "confirmed_count":   {"$sum": {"$cond": [{"$eq": ["$confirmed_incident", True]}, 1, 0]}},
            "has_field_count":   {"$sum": {"$cond": [{"$ne": ["$confirmed_incident", None]}, 1, 0]}},
            "non_incident_type": {"$sum": {
                "$cond": [{"$in": ["$news_type", list(NON_INCIDENT_TYPES)]}, 1, 0]
            }},
        }},
    ]

    # Overall confirmed incident rate across all articles in window
    confirmed_rate_pipeline = [
        match,
        {"$match": {"confirmed_incident": {"$ne": None}}},
        {"$group": {
            "_id": None,
            "total":     {"$sum": 1},
            "confirmed": {"$sum": {"$cond": [{"$eq": ["$confirmed_incident", True]}, 1, 0]}},
        }},
    ]

    sector_actor_raw, ta_conf_raw, confirmed_rate_raw = await asyncio.gather(
        col.aggregate(sector_actor_pipeline).to_list(10000),
        col.aggregate(ta_confidence_pipeline).to_list(10000),
        col.aggregate(confirmed_rate_pipeline).to_list(1),
    )

    # ── Assemble Tier 1 ──
    prev_ta_names = [r["_id"] for r in prev_ta_raw if r["_id"]]

    cve_exposure_v2 = [
        {
            "tech":      r["_id"],
            "total":     r["total"],
            "critical":  r["critical"],
            "high":      r["high"],
            "medium":    r["medium"],
            "max_cvss":  round(r.get("max_cvss") or 0, 1),
            "poc_count": r.get("poc_count") or 0,
        }
        for r in cve_v2_raw
    ]

    sector_risk_scores = _compute_sector_risk_scores(base["sector_trend"])
    industry_spikes = spike_data.get("industries", [])[:6]

    # ── Assemble Tier 2 ──

    # T2-6: victim country trend top 8
    vc_map: dict[str, dict[str, int]] = {}
    for r in victim_country_raw:
        c, m = r["_id"]["country"], r["_id"]["month"]
        vc_map.setdefault(c, {})[m] = r["count"]
    vc_totals = {c: sum(v.values()) for c, v in vc_map.items()}
    top_vc = sorted(vc_totals, key=lambda x: -vc_totals[x])[:8]
    victim_country_trend = [
        {"country": c, "data": [vc_map[c].get(m, 0) for m in months]}
        for c in top_vc
    ]

    # T2-7: top TTPs
    top_ttps = [
        {"id": r["_id"]["id"], "name": r["_id"]["name"] or r["_id"]["id"], "count": r["count"]}
        for r in ttp_raw
    ]

    # T2-8: TA velocity
    ta_velocity = _compute_ta_velocity(ta_monthly_raw, months)

    # T2-9: sector co-occurrence
    sector_cooccurrence = _compute_sector_cooccurrence(cooccur_raw)

    # T2-10: news-type monthly stacked
    newstype_trend = _build_newstype_trend(newstype_monthly_raw, months)

    # T2-11: sector × actor matrix
    sector_actor_matrix = _build_sector_actor_matrix(
        sector_actor_raw, top_sectors[:8], top_actor_names
    )

    # T3-15: TA confidence scores
    # Use confirmed_incident field when available (new articles); fall back to news_type proxy (old articles)
    ta_confidence: dict[str, int] = {}
    for r in ta_conf_raw:
        actor = r["_id"]
        total = r["total"]
        if not total:
            continue
        if r["has_field_count"] > 0:
            # confirmed_incident field present on at least some articles — use it
            ta_confidence[actor] = round((r["confirmed_count"] / total) * 100)
        else:
            # Fall back to news_type proxy for old articles
            non_incident = r["non_incident_type"]
            ta_confidence[actor] = round(((total - non_incident) / total) * 100)

    # Overall confirmed incident rate (null = field not yet populated)
    _cr = confirmed_rate_raw[0] if confirmed_rate_raw else None
    confirmed_incident_rate = (
        round((_cr["confirmed"] / _cr["total"]) * 100) if _cr and _cr["total"] else None
    )

    view_config = build_view_config(role)
    sections = view_config["sections"]

    async def _empty_list():
        return []

    async def _empty_dict():
        return {}

    critical_cves, recent_clusters_summary, pending_fp_queue, source_reliability_spread = await asyncio.gather(
        _get_critical_cves(client_id) if sections.get("critical_cve_feed") else _empty_list(),
        _get_recent_clusters(client_id) if sections.get("cluster_list") else _empty_list(),
        _get_pending_fp_queue(client_id) if sections.get("fp_feedback_queue") else _empty_list(),
        _get_source_reliability_spread(client_id) if sections.get("source_reliability_spread") else _empty_dict(),
    )

    return {
        **base,
        # Tier 1
        "prev_ta_names":      prev_ta_names,
        "sector_risk_scores": sector_risk_scores,
        "cve_exposure_v2":    cve_exposure_v2,
        "industry_spikes":    industry_spikes,
        # Tier 2
        "victim_country_trend":  victim_country_trend,
        "top_ttps":              top_ttps,
        "ta_velocity":           ta_velocity,
        "sector_cooccurrence":   sector_cooccurrence,
        "newstype_trend":        newstype_trend,
        "sector_actor_matrix":   sector_actor_matrix,
        # Tier 3
        "ta_confidence":            ta_confidence,
        "confirmed_incident_rate":  confirmed_incident_rate,
        # Role-based
        "view_config":              view_config,
        "critical_cves":            critical_cves,
        "recent_clusters_summary":  recent_clusters_summary,
        "pending_fp_queue":         pending_fp_queue,
        "source_reliability_spread": source_reliability_spread,
    }
