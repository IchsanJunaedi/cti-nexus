import time
import statistics
from datetime import datetime, timedelta
from collections import defaultdict
from app.database import get_database
from app.config import COLLECTION_NAME

_CACHE: dict = {}
_CACHE_TTL = 900


async def get_spikes(
    lookback_days: int = 30,
    z_threshold: float = 2.0,
    extra_filter: dict | None = None,
) -> dict:
    import json
    filter_key = json.dumps(extra_filter, sort_keys=True) if extra_filter else ""
    cache_key = f"{lookback_days}|{z_threshold}|{filter_key}"
    now = time.monotonic()
    if cache_key in _CACHE:
        data, ts = _CACHE[cache_key]
        if now - ts < _CACHE_TTL:
            return data

    result = await _compute_spikes(lookback_days, z_threshold, extra_filter or {})
    _CACHE[cache_key] = (result, now)
    return result


async def _compute_spikes(lookback_days: int, z_threshold: float, extra_filter: dict) -> dict:
    col = get_database()[COLLECTION_NAME]
    cutoff = (datetime.utcnow() - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
    # Recent window = last 7 days; baseline = everything before that in the lookback period
    recent_cutoff = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")

    match_filter = {"posted_on": {"$gte": cutoff}, **extra_filter}
    pipeline = [
        {"$match": match_filter},
        {"$facet": {
            "by_actor": [
                {"$unwind": "$threat_actors"},
                {"$match": {"threat_actors": {"$ne": ""}}},
                {"$group": {"_id": {"date": "$posted_on", "entity": "$threat_actors"}, "count": {"$sum": 1}}},
            ],
            "by_country": [
                {"$unwind": "$mentioned_countries"},
                {"$match": {"mentioned_countries": {"$ne": ""}}},
                {"$group": {"_id": {"date": "$posted_on", "entity": "$mentioned_countries"}, "count": {"$sum": 1}}},
            ],
            "by_industry": [
                {"$unwind": "$impacted_industries"},
                {"$match": {"impacted_industries": {"$ne": ""}}},
                {"$group": {"_id": {"date": "$posted_on", "entity": "$impacted_industries"}, "count": {"$sum": 1}}},
            ],
            "daily_total": [
                {"$group": {"_id": "$posted_on", "count": {"$sum": 1}}},
                {"$sort": {"_id": 1}},
            ],
        }},
    ]

    [raw] = await col.aggregate(pipeline).to_list(length=1)

    return {
        "threat_actors": _detect_entity_spikes(raw["by_actor"], recent_cutoff, z_threshold),
        "countries":     _detect_entity_spikes(raw["by_country"], recent_cutoff, z_threshold),
        "industries":    _detect_entity_spikes(raw["by_industry"], recent_cutoff, z_threshold),
        "overall":       _detect_overall_spikes(raw["daily_total"], recent_cutoff, z_threshold),
        "generated_at":  datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "parameters": {
            "lookback_days": lookback_days,
            "z_threshold":   z_threshold,
            "recent_window": "last 7 days",
        },
    }


def _build_series(raw: list[dict]) -> dict[str, dict[str, int]]:
    series: dict[str, dict[str, int]] = defaultdict(dict)
    for doc in raw:
        entity = doc["_id"]["entity"]
        date   = doc["_id"]["date"]
        series[entity][date] = doc["count"]
    return series


def _detect_entity_spikes(raw: list[dict], recent_cutoff: str, z_threshold: float) -> list[dict]:
    series = _build_series(raw)
    spikes = []

    for entity, daily in series.items():
        dates          = sorted(daily)
        baseline_vals  = [daily[d] for d in dates if d < recent_cutoff]
        recent_dates   = [d for d in dates if d >= recent_cutoff]

        if len(baseline_vals) < 5:
            continue

        mean = statistics.mean(baseline_vals)
        if mean < 0.5:
            continue

        try:
            std = statistics.stdev(baseline_vals)
        except statistics.StatisticsError:
            std = 0.0
        if std == 0:
            std = 0.5

        for date in recent_dates:
            count   = daily[date]
            z_score = (count - mean) / std
            if z_score >= z_threshold:
                spikes.append({
                    "entity":        entity,
                    "date":          date,
                    "count":         count,
                    "baseline_mean": round(mean, 2),
                    "z_score":       round(z_score, 2),
                    "severity":      "high" if z_score >= 3.0 else "medium",
                })

    spikes.sort(key=lambda x: x["z_score"], reverse=True)
    return spikes[:20]


def _detect_overall_spikes(daily_total: list[dict], recent_cutoff: str, z_threshold: float) -> list[dict]:
    baseline_vals = [d["count"] for d in daily_total if d["_id"] < recent_cutoff]
    recent        = [d for d in daily_total if d["_id"] >= recent_cutoff]

    if len(baseline_vals) < 5:
        return []

    mean = statistics.mean(baseline_vals)
    try:
        std = statistics.stdev(baseline_vals)
    except statistics.StatisticsError:
        std = 0.0
    if std == 0:
        std = 1.0

    surges = []
    for day in recent:
        z = (day["count"] - mean) / std
        if z >= z_threshold:
            surges.append({
                "date":          day["_id"],
                "count":         day["count"],
                "baseline_mean": round(mean, 2),
                "z_score":       round(z, 2),
                "severity":      "high" if z >= 3.0 else "medium",
            })
    return surges
