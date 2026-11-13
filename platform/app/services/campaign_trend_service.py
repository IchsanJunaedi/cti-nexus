from datetime import datetime, timedelta

from app.database import get_database
from app.config import CLUSTERS_COLLECTION


def _slope(ys: list[float]) -> float:
    n = len(ys)
    if n < 2:
        return 0.0
    xs = list(range(n))
    x_mean = sum(xs) / n
    y_mean = sum(ys) / n
    num = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
    den = sum((x - x_mean) ** 2 for x in xs)
    return num / den if den else 0.0


def _trend_direction(slope: float, recent_avg: float) -> str:
    if recent_avg < 0.5:
        return "dormant"
    if slope > 0.3:
        return "growing"
    if slope < -0.3:
        return "declining"
    return "stable"


async def get_campaign_trends(cluster_id: str) -> dict:
    col = get_database()[CLUSTERS_COLLECTION]
    doc = await col.find_one({"cluster_id": cluster_id}, {"daily_counts": 1, "cluster_name": 1})
    if not doc:
        return {}

    daily = doc.get("daily_counts", [])
    cutoff = (datetime.utcnow() - timedelta(days=90)).strftime("%Y-%m-%d")
    daily = [e for e in daily if e.get("date", "") >= cutoff]
    daily.sort(key=lambda e: e["date"])

    timeline = [{"date": e["date"], "count": e["count"]} for e in daily]

    counts = [e["count"] for e in daily]
    last7 = counts[-7:] if len(counts) >= 7 else counts
    prior7 = counts[-14:-7] if len(counts) >= 14 else counts[: max(0, len(counts) - 7)]

    slope = _slope(last7)
    recent_avg = sum(last7) / len(last7) if last7 else 0.0
    trend_direction = _trend_direction(slope, recent_avg)

    last7_sum = sum(last7)
    prior7_sum = sum(prior7) if prior7 else 0
    if prior7_sum > 0:
        growth_rate = round((last7_sum - prior7_sum) / prior7_sum * 100, 1)
    elif last7_sum > 0:
        growth_rate = 100.0
    else:
        growth_rate = 0.0

    predicted_peak = None
    if slope > 0 and last7:
        current = last7[-1]
        peak_candidate = max(counts) if counts else current
        if current < peak_candidate * 1.5:
            days_to_peak = int((peak_candidate * 1.5 - current) / slope) if slope > 0 else None
            if days_to_peak is not None and 0 < days_to_peak <= 30:
                predicted_peak = (datetime.utcnow() + timedelta(days=days_to_peak)).strftime("%Y-%m-%d")

    return {
        "cluster_id": cluster_id,
        "cluster_name": doc.get("cluster_name", ""),
        "trend_direction": trend_direction,
        "growth_rate": growth_rate,
        "predicted_peak": predicted_peak,
        "timeline": timeline,
        "slope": round(slope, 4),
        "recent_avg": round(recent_avg, 2),
    }


async def get_campaign_evolution(days: int = 30) -> list[dict]:
    col = get_database()[CLUSTERS_COLLECTION]
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

    cursor = col.find(
        {"last_seen": {"$gte": cutoff}},
        {"cluster_id": 1, "cluster_name": 1, "daily_counts": 1, "_id": 0},
    )
    docs = await cursor.to_list(length=500)

    results = []
    for doc in docs:
        trend = await get_campaign_trends(doc["cluster_id"])
        if trend:
            results.append(trend)

    results.sort(key=lambda x: x.get("growth_rate", 0), reverse=True)
    return results
