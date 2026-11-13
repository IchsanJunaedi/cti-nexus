import time
from datetime import datetime, timedelta
from collections import defaultdict
from app.database import get_database
from app.config import COLLECTION_NAME

_CACHE: dict = {}
_CACHE_TTL = 900


async def get_risk_matrix(days: int = 30, compare_days: int = 30) -> dict:
    cache_key = f"{days}|{compare_days}"
    now = time.monotonic()
    if cache_key in _CACHE:
        data, ts = _CACHE[cache_key]
        if now - ts < _CACHE_TTL:
            return data

    result = await _compute_risk_matrix(days, compare_days)
    _CACHE[cache_key] = (result, now)
    return result


async def _compute_risk_matrix(days: int, compare_days: int) -> dict:
    col = get_database()[COLLECTION_NAME]
    now = datetime.utcnow()
    current_start = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    prev_start = (now - timedelta(days=days + compare_days)).strftime("%Y-%m-%d")
    prev_end = current_start

    pipeline = [
        {"$match": {"posted_on": {"$gte": prev_start}}},
        {"$project": {
            "posted_on": 1,
            "impacted_industries": 1,
            "mentioned_countries": 1,
            "threat_actors": 1,
            "attack_techniques": 1,
        }},
    ]

    docs = await col.aggregate(pipeline).to_list(length=None)

    # bucket docs into current and previous periods
    cell_current: dict[tuple, list] = defaultdict(list)
    cell_previous: dict[tuple, list] = defaultdict(list)

    for doc in docs:
        date = doc.get("posted_on", "")
        industries = [i for i in (doc.get("impacted_industries") or []) if i]
        countries = [c for c in (doc.get("mentioned_countries") or []) if c]
        tas = [t for t in (doc.get("threat_actors") or []) if t]
        ttps = [t for t in (doc.get("attack_techniques") or []) if t]

        if not industries or not countries:
            continue

        is_current = date >= current_start
        is_prev = prev_start <= date < prev_end

        for industry in industries:
            for country in countries:
                key = (industry, country)
                if is_current:
                    cell_current[key].append({"tas": tas, "ttps": ttps})
                elif is_prev:
                    cell_previous[key].append({"tas": tas, "ttps": ttps})

    all_keys = set(cell_current.keys()) | set(cell_previous.keys())

    # find global max raw score for normalization
    raw_scores: dict[tuple, float] = {}
    for key in all_keys:
        curr_docs = cell_current.get(key, [])
        if len(curr_docs) < 2:
            continue
        unique_tas = len({t for d in curr_docs for t in d["tas"]})
        unique_ttps = len({t for d in curr_docs for t in d["ttps"]})
        raw = unique_tas * 3 + unique_ttps * 2 + len(curr_docs) * 1
        raw_scores[key] = raw

    max_raw = max(raw_scores.values(), default=1) or 1

    matrix = []
    for key, raw in raw_scores.items():
        industry, country = key
        curr_docs = cell_current.get(key, [])
        prev_docs = cell_previous.get(key, [])
        current_count = len(curr_docs)
        previous_count = len(prev_docs)

        if current_count > previous_count * 1.2:
            trend = "↑"
        elif previous_count > 0 and current_count < previous_count * 0.8:
            trend = "↓"
        else:
            trend = "→"

        risk_score = round(raw / max_raw * 100)

        ta_counts: dict[str, int] = defaultdict(int)
        for d in curr_docs:
            for ta in d["tas"]:
                ta_counts[ta] += 1
        top_actors = [ta for ta, _ in sorted(ta_counts.items(), key=lambda x: -x[1])[:3]]

        matrix.append({
            "industry": industry,
            "country": country,
            "risk_score": risk_score,
            "trend": trend,
            "current_count": current_count,
            "previous_count": previous_count,
            "top_actors": top_actors,
        })

    matrix.sort(key=lambda x: -x["risk_score"])

    industries = sorted({r["industry"] for r in matrix})
    countries = sorted({r["country"] for r in matrix})

    return {
        "matrix": matrix,
        "industries": industries,
        "countries": countries,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
