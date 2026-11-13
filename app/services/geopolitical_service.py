from collections import Counter
from datetime import datetime, timedelta

from app.config import TA_PROFILES_COLLECTION
from app.database import get_ta_database


async def _fetch_ta_profiles_batch(ta_names: list[str]) -> dict[str, dict]:
    """Batch-fetch ta_profiles for given actor names. Returns {lower_name: profile}."""
    if not ta_names or not TA_PROFILES_COLLECTION:
        return {}
    col = get_ta_database()[TA_PROFILES_COLLECTION]
    patterns = [{"_actor_name": {"$regex": f"^{n}$", "$options": "i"}} for n in ta_names]
    cursor = col.find(
        {"$or": patterns},
        {"_id": 0, "_actor_name": 1, "identity": 1, "motivation": 1},
    )
    docs = await cursor.to_list(length=500)
    return {d["_actor_name"].lower(): d for d in docs if d.get("_actor_name")}


async def get_geopolitical_summary(campaigns: list[dict], days: int = 30) -> dict:
    """Aggregate geopolitical threat context from campaign clusters + TA profiles."""
    all_tas: list[str] = []
    for c in campaigns:
        all_tas.extend(c.get("dominant_tas", []))
    unique_tas = list({t for t in all_tas if t})

    profiles = await _fetch_ta_profiles_batch(unique_tas)

    nation_state_activity: dict[str, dict] = {}
    motivation_counter: Counter = Counter()

    # Per-sector: current period vs prior period for trend
    sector_current: Counter = Counter()
    sector_prior: Counter = Counter()
    sector_tas: dict[str, set] = {}

    cutoff_current = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    cutoff_prior   = (datetime.utcnow() - timedelta(days=days * 2)).strftime("%Y-%m-%d")

    for c in campaigns:
        c_tas     = c.get("dominant_tas", [])
        c_sectors = c.get("dominant_industries", [])
        c_ctrs    = c.get("dominant_countries", [])
        cid       = c.get("cluster_id", "")
        last_seen = c.get("last_seen", "") or ""

        in_current = last_seen >= cutoff_current
        in_prior   = cutoff_prior <= last_seen < cutoff_current

        for sector in c_sectors:
            if not sector:
                continue
            if in_current:
                sector_current[sector] += 1
            elif in_prior:
                sector_prior[sector] += 1
            sector_tas.setdefault(sector, set()).update(t for t in c_tas if t)

        for ta_name in c_tas:
            if not ta_name:
                continue
            profile = profiles.get(ta_name.lower(), {})
            identity   = profile.get("identity", {}) or {}
            motivation = profile.get("motivation", {}) or {}

            nation     = identity.get("sponsoring_nation") or "Unknown"
            actor_type = identity.get("actor_type", "")
            prim_mot   = motivation.get("primary_motivation", "unknown") or "unknown"

            motivation_counter[prim_mot] += 1

            if nation not in nation_state_activity:
                nation_state_activity[nation] = {
                    "campaign_count":      0,
                    "campaigns":           [],
                    "primary_motivations": [],
                    "targeted_sectors":    [],
                    "targeted_countries":  [],
                    "actor_type":          actor_type,
                }
            entry = nation_state_activity[nation]
            if cid and cid not in entry["campaigns"]:
                entry["campaigns"].append(cid)
                entry["campaign_count"] += 1
            if prim_mot and prim_mot not in entry["primary_motivations"]:
                entry["primary_motivations"].append(prim_mot)
            for s in c_sectors:
                if s and s not in entry["targeted_sectors"]:
                    entry["targeted_sectors"].append(s)
            for cc in c_ctrs:
                if cc and cc not in entry["targeted_countries"]:
                    entry["targeted_countries"].append(cc)

    # Sector threat trends
    all_sectors = set(sector_current.keys()) | set(sector_prior.keys())
    sector_threat_trends: dict[str, dict] = {}
    for sector in all_sectors:
        cur = sector_current.get(sector, 0)
        pri = sector_prior.get(sector, 0)
        if cur > pri:
            trend = "increasing"
        elif cur < pri:
            trend = "decreasing"
        else:
            trend = "stable"
        sector_threat_trends[sector] = {
            "campaign_count": cur,
            "prior_count":    pri,
            "threat_actors":  sorted(sector_tas.get(sector, set())),
            "trend":          trend,
        }

    # Alert generation
    geopolitical_alerts: list[str] = []

    # Alert: nation-state campaign increases
    for nation, entry in nation_state_activity.items():
        if nation == "Unknown":
            continue
        if entry["campaign_count"] >= 3:
            motivations = ", ".join(entry["primary_motivations"][:2]) or "unknown"
            sectors_str = ", ".join(entry["targeted_sectors"][:3])
            msg = (
                f"Nation-state activity: {nation} linked to {entry['campaign_count']} campaign(s) "
                f"({motivations}) targeting {sectors_str or 'multiple sectors'}"
            )
            geopolitical_alerts.append(msg)

    # Alert: sector trend increases
    for sector, info in sector_threat_trends.items():
        cur = info["campaign_count"]
        pri = info["prior_count"]
        if info["trend"] == "increasing" and pri > 0:
            pct = round((cur - pri) / pri * 100)
            geopolitical_alerts.append(
                f"Threat activity targeting {sector} increased {pct}% "
                f"({pri} → {cur} campaigns) in last {days} days"
            )
        elif info["trend"] == "increasing" and pri == 0 and cur >= 2:
            geopolitical_alerts.append(
                f"New threat activity targeting {sector}: {cur} campaign(s) detected in last {days} days"
            )

    # Alert: multiple nation campaigns converging on same sector
    nation_sector: dict[str, Counter] = {}
    for nation, entry in nation_state_activity.items():
        if nation == "Unknown":
            continue
        nation_sector[nation] = Counter(entry["targeted_sectors"])
    for nation, sc in nation_sector.items():
        for sector, count in sc.items():
            if count >= 2:
                geopolitical_alerts.append(
                    f"{nation}-linked actors running {count} converging campaigns targeting {sector}"
                )

    return {
        "nation_state_activity": nation_state_activity,
        "motivation_breakdown":  dict(motivation_counter),
        "sector_threat_trends":  sector_threat_trends,
        "geopolitical_alerts":   geopolitical_alerts,
        "days":                  days,
        "campaign_count":        len(campaigns),
    }
