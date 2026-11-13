import asyncio
import json
import re
from datetime import date, datetime, timedelta, timezone

from app.config import LLM_PROVIDER, LLM_API_KEY, LLM_MODEL, TA_PROFILES_COLLECTION, COLLECTION_NAME, CLUSTERS_COLLECTION
from app.database import get_database
from app.services.llm_client import get_llm_client
from app.database import get_ta_database
from app.services.attack_sync_service import TECH_ID_RE, lookup_techniques_bulk
from app.services.ioc_service import get_iocs_for_actor

_SYSTEM_PROMPT = """You are a Senior Cyber Threat Intelligence Analyst. Your task is to produce a structured,
analyst-grade threat actor profile based on the input provided (report text, article,
threat intelligence source, or actor name).

The profile must be grounded in verified reporting. For any field where information is
unavailable or unconfirmed, use null and set the corresponding confidence field to "low"
or "unknown". Do not fabricate or infer beyond what is stated in the source material.

Return ONLY a valid JSON object — no preamble, no markdown fencing, no commentary.

Use this exact schema:

{
  "profile_metadata": {
    "generated_at": "<ISO 8601 timestamp>",
    "source_document": "<title or URL of source>",
    "analyst_confidence": "<low | medium | high>",
    "tlp_marking": "<TLP:WHITE | TLP:GREEN | TLP:AMBER | TLP:RED>"
  },
  "identity": {
    "primary_name": "<most common name>",
    "aliases": ["<alias1>", "<alias2>"],
    "tracking_ids": {
      "mitre_group_id": "<Gxxxx or null>",
      "other_ids": ["<vendor-specific IDs e.g. UNC1234, TA505>"]
    },
    "actor_type": "<nation-state | criminal | hacktivist | insider | unknown>",
    "sponsoring_nation": "<country or null>",
    "affiliated_group": "<criminal org, APT cluster, or null>",
    "first_observed": "<YYYY or YYYY-MM or null>",
    "last_active": "<YYYY-MM or 'ongoing' or null>",
    "active_status": "<active | inactive | suspected inactive | unknown>"
  },
  "motivation": {
    "primary_motivation": "<espionage | financial | ransomware | hacktivism | sabotage | unknown>",
    "secondary_motivations": ["<motivation2>"],
    "strategic_objectives": ["<objective1>", "<objective2>"],
    "targeting_approach": "<opportunistic | targeted | both | unknown>"
  },
  "targeting_profile": {
    "targeted_sectors": ["<sector1>", "<sector2>"],
    "targeted_geographies": ["<country or region>"],
    "targeted_organization_types": ["<gov | bfsi | telco | healthcare | energy | etc>"],
    "confirmed_victim_industries": ["<specific industry verticals from reporting>"],
    "high_value_assets_targeted": ["<data types, systems, or roles sought>"]
  },
  "capability_assessment": {
    "sophistication_level": "<low | medium | high | nation-state>",
    "development_capability": "<custom | commodity | mixed>",
    "known_malware": [
      {
        "name": "<malware name>",
        "type": "<backdoor | loader | ransomware | stealer | wiper | rat | rootkit | other>",
        "notes": "<brief description or null>"
      }
    ],
    "known_tools": ["<tool1>", "<tool2>"],
    "exploited_vulnerabilities": [
      {
        "cve_id": "<CVE-YYYY-NNNNN>",
        "product": "<affected product>",
        "notes": "<exploitation context or null>"
      }
    ],
    "attack_techniques": {
      "initial_access": ["<technique ID + name>"],
      "execution": ["<technique ID + name>"],
      "persistence": ["<technique ID + name>"],
      "privilege_escalation": ["<technique ID + name>"],
      "defense_evasion": ["<technique ID + name>"],
      "credential_access": ["<technique ID + name>"],
      "discovery": ["<technique ID + name>"],
      "lateral_movement": ["<technique ID + name>"],
      "collection": ["<technique ID + name>"],
      "exfiltration": ["<technique ID + name>"],
      "command_and_control": ["<technique ID + name>"],
      "impact": ["<technique ID + name>"]
    }
  },
  "infrastructure": {
    "c2_patterns": ["<description of C2 behavior>"],
    "hosting_preferences": ["<bulletproof hosting | cloud abuse | compromised infra | etc>"],
    "known_iocs": {
      "ips": ["<defanged IP>"],
      "domains": ["<defanged domain>"],
      "hashes": ["<SHA256>"],
      "urls": ["<defanged URL>"]
    },
    "infrastructure_reuse": "<yes | no | unknown>",
    "infrastructure_notes": "<any relevant pattern notes or null>"
  },
  "campaign_history": [
    {
      "campaign_name": "<name or null>",
      "date_range": "<YYYY-MM to YYYY-MM or 'ongoing'>",
      "targeted_sectors": ["<sector>"],
      "targeted_regions": ["<region>"],
      "notable_techniques": ["<TTP summary>"],
      "source_reference": "<report title or URL>"
    }
  ],
  "detection_and_defense": {
    "detection_opportunities": [
      {
        "layer": "<network | endpoint | identity | email | cloud>",
        "description": "<what to look for>",
        "mitre_technique_ref": "<T#### or null>"
      }
    ],
    "recommended_mitigations": [
      {
        "mitigation": "<action>",
        "mitre_mitigation_id": "<M#### or null>",
        "priority": "<immediate | short-term | long-term>"
      }
    ],
    "existing_detection_rules": {
      "yara": ["<rule name or source>"],
      "sigma": ["<rule name or source>"]
    }
  },
  "organizational_relevance": {
    "sector_relevance": "<low | medium | high | critical>",
    "relevance_rationale": "<explanation of why this actor is relevant to your sector>",
    "aligned_ttp_to_threat_surface": ["<TTP that maps to your environment>"],
    "monitoring_priority": "<low | medium | high | critical>",
    "recommended_actions": [
      {
        "timeframe": "<immediate | 30-day | 90-day>",
        "action": "<specific recommendation>"
      }
    ]
  },
  "intelligence_gaps": [
    "<unanswered question or unknown field that requires further research>"
  ],
  "references": [
    {
      "title": "<report or article title>",
      "source": "<vendor / publisher>",
      "url": "<URL or null>",
      "date": "<YYYY-MM-DD or null>"
    }
  ]
}"""


def _col():
    return get_ta_database()[TA_PROFILES_COLLECTION]


async def _fetch_recent_news(actor_name: str, days: int = 90, limit: int = 10) -> list[dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    col = get_database()[COLLECTION_NAME]
    # Build patterns for each alias token (split on " / " and ",")
    tokens = [t.strip() for t in re.split(r"[/,]", actor_name) if t.strip()]
    pattern = "|".join(re.escape(t) for t in tokens)
    cursor = col.find(
        {"title": {"$regex": pattern, "$options": "i"}, "posted_on": {"$gte": cutoff}},
        {"_id": 0, "title": 1, "url": 1, "source": 1, "posted_on": 1},
    ).sort("posted_on", -1).limit(limit)
    return await cursor.to_list(length=limit)


def _build_user_message(actor_name: str, news: list[dict]) -> str:
    if not news:
        return actor_name
    lines = [f"Threat actor: {actor_name}", "", "Recent reporting (newest first):"]
    for a in news:
        lines.append(f"- [{a.get('posted_on', 'n/d')}] {a.get('title', '')} (source: {a.get('source', '')}, url: {a.get('url', '')})")
    return "\n".join(lines)


async def _enrich_profile_cves(profile: dict) -> dict:
    """Cross-reference exploited_vulnerabilities from the LLM profile against cve_tracker in MongoDB.

    Steps:
    1. Collect CVE IDs from capability_assessment.exploited_vulnerabilities.
    2. Scan article titles tagged with the actor name for additional CVE IDs.
    3. Bulk-fetch matched records from cve_tracker.
    4. Annotate each exploited_vulnerabilities entry with tracker confirmation data.
    5. Add _article_cves list for CVEs found in articles but absent from the LLM profile.
    """
    actor_name: str = profile.get("_actor_name", "")

    # --- Step 1: CVE IDs from exploited_vulnerabilities ---
    capability = profile.get("capability_assessment") or {}
    exploited_vulns: list[dict] = capability.get("exploited_vulnerabilities") or []

    profile_cve_ids: set[str] = set()
    for entry in exploited_vulns:
        cve_id = (entry.get("cve_id") or "").upper().strip()
        if re.match(r"CVE-\d{4}-\d{4,7}", cve_id, re.IGNORECASE):
            profile_cve_ids.add(cve_id.upper())

    # --- Step 2: CVE IDs from article titles tagged with this actor ---
    article_cve_ids: set[str] = set()
    if actor_name:
        try:
            news_col = get_database()[COLLECTION_NAME]
            tokens = [t.strip() for t in re.split(r"[/,]", actor_name) if t.strip()]
            pattern = "|".join(re.escape(t) for t in tokens)
            # Query articles whose threat_actors field matches actor name or title contains actor name
            cursor = news_col.find(
                {
                    "$or": [
                        {"threat_actors": {"$regex": pattern, "$options": "i"}},
                        {"title": {"$regex": pattern, "$options": "i"}},
                    ]
                },
                {"_id": 0, "title": 1},
            )
            articles = await cursor.to_list(length=500)
            for article in articles:
                title = article.get("title") or ""
                found = re.findall(r"CVE-\d{4}-\d{4,7}", title, re.IGNORECASE)
                for cve in found:
                    article_cve_ids.add(cve.upper())
        except Exception:
            pass  # Do not fail enrichment if article scan errors

    # --- Step 3: Union of all CVE IDs ---
    all_cve_ids = profile_cve_ids | article_cve_ids
    if not all_cve_ids:
        profile["_article_cves"] = []
        return profile

    # --- Step 4: Bulk-fetch from cve_tracker ---
    tracker_map: dict[str, dict] = {}
    try:
        cve_col = get_database()["cve_tracker"]
        cursor = cve_col.find(
            {"cve_id": {"$in": list(all_cve_ids)}},
            {"_id": 0},
        )
        tracker_docs = await cursor.to_list(length=len(all_cve_ids))
        for doc in tracker_docs:
            key = (doc.get("cve_id") or "").upper()
            if key:
                tracker_map[key] = doc
    except Exception:
        pass  # Continue without tracker data if DB query fails

    # --- Step 5: Annotate exploited_vulnerabilities entries ---
    for entry in exploited_vulns:
        cve_id = (entry.get("cve_id") or "").upper().strip()
        tracker_doc = tracker_map.get(cve_id)
        if tracker_doc:
            entry["_confirmed"] = True
            entry["_cve_score"] = tracker_doc.get("cve_score")
            entry["_cve_severity"] = tracker_doc.get("cve_severity")
            entry["_cisa_kev"] = tracker_doc.get("cisa_kev")
            entry["_poc_available"] = tracker_doc.get("poc_available")
            entry["_tech"] = tracker_doc.get("tech")
            entry["_link"] = tracker_doc.get("link")
            entry["_active_exploitation"] = tracker_doc.get("active_exploitation")
        else:
            entry["_confirmed"] = False

    # --- Step 6: Build _article_cves (article-sourced CVEs not in LLM profile) ---
    extra_cve_ids = article_cve_ids - profile_cve_ids
    article_cves_list: list[dict] = []
    for cve_id in sorted(extra_cve_ids):
        tracker_doc = tracker_map.get(cve_id)
        entry: dict = {"cve_id": cve_id}
        if tracker_doc:
            entry["_confirmed"] = True
            entry["_cve_score"] = tracker_doc.get("cve_score")
            entry["_cve_severity"] = tracker_doc.get("cve_severity")
            entry["_cisa_kev"] = tracker_doc.get("cisa_kev")
            entry["_poc_available"] = tracker_doc.get("poc_available")
            entry["_tech"] = tracker_doc.get("tech")
            entry["_link"] = tracker_doc.get("link")
            entry["_active_exploitation"] = tracker_doc.get("active_exploitation")
            entry["_summary"] = tracker_doc.get("summary")
        else:
            entry["_confirmed"] = False
        article_cves_list.append(entry)

    profile["_article_cves"] = article_cves_list
    return profile


async def _enrich_profile_ttps(profile: dict) -> dict:
    """Validate technique IDs in capability_assessment.attack_techniques against the ATT&CK DB.

    Adds capability_assessment._ttp_validation: a flat list of
    {tactic, id, valid, name} for every Txxxx[.xxx] ID found in the LLM output,
    so the UI can flag hallucinated/retired technique IDs.
    """
    capability = profile.get("capability_assessment") or {}
    attack_techniques = capability.get("attack_techniques") or {}

    all_ids: set[str] = set()
    for entries in attack_techniques.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, str):
                all_ids.update(TECH_ID_RE.findall(entry))

    if not all_ids:
        return profile

    lookup = await lookup_techniques_bulk(sorted(all_ids))

    validated: list[dict] = []
    for tactic, entries in attack_techniques.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, str):
                continue
            for tid in TECH_ID_RE.findall(entry):
                info = lookup.get(tid)
                validated.append({
                    "tactic": tactic,
                    "id": tid,
                    "valid": info is not None,
                    "name": info.get("name") if info else None,
                })

    capability["_ttp_validation"] = validated
    profile["capability_assessment"] = capability
    return profile


async def _enrich_profile_iocs(profile: dict) -> dict:
    """Attach real IOCs from the iocs collection, joined by actor name/alias.

    Stored under infrastructure._live_iocs — replaces reliance on the LLM's
    often-hallucinated infrastructure.known_iocs for operational use.
    """
    actor_name = profile.get("_actor_name", "")
    if not actor_name:
        return profile

    live_iocs = await get_iocs_for_actor(actor_name)
    infrastructure = profile.get("infrastructure") or {}
    infrastructure["_live_iocs"] = live_iocs
    profile["infrastructure"] = infrastructure
    return profile


async def _enrich_profile(profile: dict) -> dict:
    """Run all read-time, non-persisted enrichments on a TA profile doc."""
    profile = await _enrich_profile_cves(profile)
    profile = await _enrich_profile_ttps(profile)
    profile = await _enrich_profile_iocs(profile)
    return profile


def _call_llm(actor_name: str, news: list[dict]) -> dict:
    client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
    user_msg = _build_user_message(actor_name, news)
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        response_format={"type": "json_object"},
    )
    raw = completion.choices[0].message.content
    return json.loads(raw)


async def generate_ta_profile(actor_name: str) -> dict:
    news = await _fetch_recent_news(actor_name)
    profile = await asyncio.to_thread(_call_llm, actor_name, news)
    profile["_actor_name"] = actor_name
    profile["_generated_at"] = datetime.now(timezone.utc).isoformat()

    col = _col()
    await col.update_one(
        {"_actor_name": {"$regex": f"^{actor_name}$", "$options": "i"}},
        {"$set": profile},
        upsert=True,
    )
    # Enrich in-memory for the response only — enrichment is NOT persisted to DB
    profile = await _enrich_profile(profile)
    return profile


def _build_month_list(months: int) -> list[str]:
    today = date.today()
    result = []
    for i in range(months - 1, -1, -1):
        year = today.year
        month = today.month - i
        while month <= 0:
            month += 12
            year -= 1
        result.append(f"{year:04d}-{month:02d}")
    return result


async def get_ta_timeline(actor_name: str, months: int = 24) -> dict:
    month_list = _build_month_list(months)
    cutoff_date = month_list[0] + "-01"

    tokens = [t.strip() for t in re.split(r"[/,]", actor_name) if t.strip()]
    pattern = "|".join(re.escape(t) for t in tokens)

    news_col = get_database()[COLLECTION_NAME]
    tweets_col = get_database()["tweets"]
    ransom_col = get_database()["ransomware_victims"]

    article_pipeline = [
        {"$match": {"posted_on": {"$gte": cutoff_date}, "threat_actors": {"$regex": pattern, "$options": "i"}}},
        {"$group": {"_id": {"$substr": ["$posted_on", 0, 7]}, "count": {"$sum": 1}}},
    ]
    tweet_pipeline = [
        {"$match": {"posted_on": {"$gte": cutoff_date}, "mentioned_group": {"$regex": pattern, "$options": "i"}}},
        {"$group": {"_id": {"$substr": ["$posted_on", 0, 7]}, "count": {"$sum": 1}}},
    ]
    ransom_pipeline = [
        {"$match": {"published": {"$gte": cutoff_date}, "group_name": {"$regex": pattern, "$options": "i"}}},
        {"$group": {"_id": {"$substr": ["$published", 0, 7]}, "count": {"$sum": 1}}},
    ]

    article_raw, tweet_raw, ransom_raw = await asyncio.gather(
        news_col.aggregate(article_pipeline).to_list(1000),
        tweets_col.aggregate(tweet_pipeline).to_list(1000),
        ransom_col.aggregate(ransom_pipeline).to_list(1000),
    )

    art_map = {r["_id"]: r["count"] for r in article_raw}
    twt_map = {r["_id"]: r["count"] for r in tweet_raw}
    ran_map = {r["_id"]: r["count"] for r in ransom_raw}

    article_counts = [art_map.get(m, 0) for m in month_list]
    tweet_counts   = [twt_map.get(m, 0) for m in month_list]
    ransom_counts  = [ran_map.get(m, 0) for m in month_list]
    total_counts   = [article_counts[i] + tweet_counts[i] + ransom_counts[i] for i in range(months)]

    last_active_month = next(
        (month_list[i] for i in range(months - 1, -1, -1) if total_counts[i] > 0), None
    )

    last_1    = total_counts[-1] if months >= 1 else 0
    last_3    = sum(total_counts[-3:]) if months >= 3 else sum(total_counts)
    pre_gap   = sum(total_counts[-6:-3]) if months >= 6 else 0

    if last_3 == 0:
        dormancy_state = "DORMANT"
    elif last_1 > 0 and sum(total_counts[-3:-1]) == 0 and any(c > 0 for c in total_counts[:-3]):
        dormancy_state = "RESURGENT"
    else:
        dormancy_state = "ACTIVE"

    # Per-month point state for transition log
    def _pt_state(idx: int) -> str:
        if total_counts[idx] > 0:
            return "ACTIVE"
        window = total_counts[max(0, idx - 2):idx + 1]
        return "DORMANT" if all(c == 0 for c in window) else "ACTIVE"

    state_transitions: list[dict] = []
    prev_st = None
    for i, m in enumerate(month_list):
        st = _pt_state(i)
        if prev_st is not None and st != prev_st:
            state_transitions.append({"month": m, "from": prev_st, "to": st})
        prev_st = st

    linked_campaigns: list[dict] = []
    try:
        if CLUSTERS_COLLECTION:
            clusters_col = get_database()[CLUSTERS_COLLECTION]
            cursor = clusters_col.find(
                {"threat_actors": {"$regex": pattern, "$options": "i"}},
                {"_id": 1, "summary_title": 1, "title": 1, "last_seen": 1},
            ).sort("last_seen", -1).limit(5)
            for doc in await cursor.to_list(length=5):
                linked_campaigns.append({
                    "cluster_id": str(doc["_id"]),
                    "summary_title": doc.get("summary_title") or doc.get("title") or "",
                    "last_seen": doc.get("last_seen") or "",
                })
    except Exception:
        pass

    return {
        "actor": actor_name,
        "months": month_list,
        "article_counts": article_counts,
        "tweet_counts": tweet_counts,
        "ransom_counts": ransom_counts,
        "total_counts": total_counts,
        "dormancy_state": dormancy_state,
        "last_active_month": last_active_month,
        "state_transitions": state_transitions,
        "linked_campaigns": linked_campaigns,
    }


async def get_dormancy_states(actor_names: list[str]) -> dict[str, str]:
    if not actor_names:
        return {}
    cutoff_90 = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
    cutoff_30 = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    lower_names = [n.lower() for n in actor_names]

    news_col = get_database()[COLLECTION_NAME]
    pipeline = [
        {"$match": {"posted_on": {"$gte": cutoff_90}}},
        {"$unwind": "$threat_actors"},
        {"$match": {"$expr": {"$in": [{"$toLower": "$threat_actors"}, lower_names]}}},
        {"$group": {
            "_id": {"$toLower": "$threat_actors"},
            "total_90": {"$sum": 1},
            "total_30": {"$sum": {"$cond": [{"$gte": ["$posted_on", cutoff_30]}, 1, 0]}},
        }},
    ]
    raw = await news_col.aggregate(pipeline).to_list(len(actor_names) + 100)
    activity = {r["_id"]: r for r in raw}

    states: dict[str, str] = {}
    for name in actor_names:
        rec = activity.get(name.lower())
        if not rec or rec["total_90"] == 0:
            states[name] = "DORMANT"
        elif rec["total_30"] > 0:
            # active in last 30d; if nothing in days 31-90 → resurgent
            if rec["total_90"] - rec["total_30"] == 0:
                states[name] = "RESURGENT"
            else:
                states[name] = "ACTIVE"
        else:
            states[name] = "DORMANT"
    return states


async def get_ta_profile(actor_name: str) -> dict | None:
    col = _col()
    doc = await col.find_one(
        {"_actor_name": {"$regex": f"^{actor_name}$", "$options": "i"}},
        {"_id": 0},
    )
    if doc is None:
        return None
    doc = await _enrich_profile(doc)
    return doc
