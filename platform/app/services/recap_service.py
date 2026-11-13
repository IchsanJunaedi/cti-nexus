"""Daily recap service.

Generates a per-day recap of News Room + X Intel activity (yesterday) plus a
short forecast for the next 1–3 days. Recaps are persisted to the
`daily_recaps` collection so analysts can revisit any prior day.
"""

import asyncio
import json
import re
from datetime import datetime, timedelta, timezone

from app.config import (
    COLLECTION_NAME,
    TWEETS_COLLECTION,
    IOC_COLLECTION,
    TA_GROUPS_COLLECTION,
)
from app.database import get_database, get_ta_database
from app.services.cluster_service import get_recent_campaigns
from app.services.llm_client import get_llm_client
from app.config import LLM_PROVIDER, LLM_API_KEY, LLM_MODEL
from app.services import ransomware_service
from app.services import cisa_kev_catalog_service
from app.services import spike_service
from app.services import domain_watch_service
from app.services import pkg_vuln_service
from app.services import scraper_health_service
from app.services.client_service import get_client


RECAP_COLLECTION = "daily_recaps"
CVE_COLLECTION = "cve_tracker"

# In-process progress tracker for generate_daily_recap, keyed by date_iso.
# Single-process/single-worker assumption — fine for the low-frequency manual
# generate/force-regen action this backs; not meant to survive a restart.
_PROGRESS: dict[str, dict] = {}


def _progress_key(date_iso: str, client_id: str) -> str:
    return f"{date_iso}|{client_id}"


def _set_progress(date_iso: str, client_id: str, stage: str, pct: int, done: bool = False, error: str | None = None) -> None:
    _PROGRESS[_progress_key(date_iso, client_id)] = {
        "stage": stage,
        "pct": pct,
        "done": done,
        "error": error,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def get_progress(date_iso: str, client_id: str = "default") -> dict:
    return _PROGRESS.get(_progress_key(date_iso, client_id)) or {"stage": "idle", "pct": 0, "done": True, "error": None}


SYSTEM_PROMPT = """You are a Senior Cyber Threat Intelligence Analyst producing a daily desk-brief for analysts.

Output STRICT JSON (no markdown, no code fences). Schema:

{
  "headline": "<one sentence overall posture for yesterday>",
  "recap": {
    "summary": "<3-5 sentence narrative recap of yesterday's notable cyber events from both news and social/X chatter>",
    "top_stories": [
      {"title": "<article title>", "why_it_matters": "<1 sentence>", "source": "<source name>", "url": "<url copied verbatim from input, or empty string if none given>"}
    ],
    "top_tweets": [
      {"author": "<username>", "summary": "<what they reported>", "signal": "<incident|cve|ttp|other>", "url": "<url copied verbatim from input, or empty string if none given>"}
    ],
    "active_threat_actors": ["<name>", "..."],
      "new_threat_actors_added": [{"name": "<name>", "source": "<source>"}],
    "notable_cves": ["CVE-YYYY-NNNNN", "..."],
    "active_campaigns": [
      {"theme": "<cluster theme>", "article_count": <int>, "why_it_matters": "<1 sentence>"}
    ],
    "apac_signals": ["<APAC-specific items>", "..."],
    "ransomware": {
      "victims": [{"group": "<group name>", "victim": "<victim>", "country": "<country>", "industry": "<industry>"}],
      "most_active_note": "<1 sentence — which group(s) were most active today, or empty string if no victims>"
    },
    "kev_additions": [
      {"cve_id": "CVE-YYYY-NNNNN", "vendor_product": "<vendor/product>", "due_date": "<remediation due date>"}
    ],
    "mitre_ttps": [
      {"id": "<technique id>", "name": "<technique name>", "count": <int>}
    ],
    "domain_watch": [
      {"domain": "<newly registered lookalike domain>", "note": "<why it matters, e.g. targets which watched brand>"}
    ],
    "package_vulns": [
      {"advisory_id": "<id>", "package": "<name>", "ecosystem": "<ecosystem>", "severity": "<severity>", "fixed_version": "<version or 'none'>"}
    ]
  },
  "forecast": {
    "summary": "<2-3 sentence forecast for next 1-3 days based ONLY on the signals provided>",
    "likely_events": [
      {"event": "<predicted event>", "basis": "<concrete signal that justifies this — must reference items in the input>", "confidence": "low|med|high"}
    ],
    "watch_items": ["<thing analysts should keep eye on today>", "..."]
  },
  "forecast_review": [
    {"event": "<previous day's predicted event>", "verdict": "hit|miss|unclear", "justification": "<1 sentence>"}
  ]
}

Rules:
- Ground every forecast item in a concrete input signal. If there is no basis, omit the item.
- Do not invent CVE IDs, threat actor names, or campaigns not in the input.
- Copy article/tweet "url" fields verbatim from the input. Never invent or guess a URL — if an item has none, use an empty string.
- Keep top_stories to <=8, top_tweets to <=6, likely_events to <=5.
- If yesterday had no notable activity, say so plainly — do not fabricate.
- Detected spike/anomaly data is the strongest available grounding for the forecast — when a relevant spike exists (a threat actor, country, industry, or overall volume anomaly), prefer it as the "basis" for a likely_events item over weaker signals.
- If scraper health is degraded (see SCRAPER HEALTH section), say so explicitly in the headline and do not characterize low article/tweet volume as a calm day — it may just be an outage.
- forecast_review: judge each of PREVIOUS DAY'S FORECASTED EVENTS (if given) against today's collected signals. "hit" = today's signals confirm it happened, "miss" = it clearly did not happen, "unclear" = not enough signal either way. If no previous forecast was given, return an empty list — do not invent one.
"""


def _yesterday_window(date_str: str | None) -> tuple[str, str, str]:
    """Return (date_iso, start, end) where start/end are inclusive ISO dates.

    date_str is the recap target date (the day being summarized). If None,
    defaults to yesterday in UTC.
    """
    if date_str:
        d = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    else:
        d = (datetime.now(timezone.utc) - timedelta(days=1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
    iso = d.strftime("%Y-%m-%d")
    return iso, iso, iso


def _client_query(date_iso: str, client_id: str) -> dict:
    """Doc lookup filter for (date, client_id) — matches pre-migration default
    docs that predate the client_id field, same idiom as domain_watch_service._client_filter."""
    if client_id == "default":
        return {"date": date_iso, "$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"date": date_iso, "client_id": client_id}


def _client_relevant(item: dict, client: dict | None, country_fields: list[str], industry_fields: list[str]) -> bool:
    """True if `item` matches one of the client's tracked countries or sectors.
    No client (org-wide/"default") or a client with no countries/sectors configured
    sees everything — relevance filtering only kicks in once a client has a profile."""
    if not client:
        return True
    c_countries = {c.strip().lower() for c in (client.get("countries") or [])}
    c_sectors = {s.strip().lower() for s in (client.get("sectors") or [])}
    if not c_countries and not c_sectors:
        return True

    def _vals(field: str) -> list[str]:
        v = item.get(field)
        if not v:
            return []
        return [v] if isinstance(v, str) else list(v)

    def _matches(value: str, tracked: set[str]) -> bool:
        # Substring match, not exact-equality: client profiles store loose terms
        # ("technology", "gov", "energy") while article/tweet taxonomy uses longer
        # labels ("Information Technology & Software", "Government & Public Sector",
        # "Energy & Utilities"). Either side containing the other counts as a match.
        v = value.strip().lower()
        return any(t in v or v in t for t in tracked)

    for f in country_fields:
        if any(_matches(str(v), c_countries) for v in _vals(f)):
            return True
    for f in industry_fields:
        if any(_matches(str(v), c_sectors) for v in _vals(f)):
            return True
    return False


_RELIABILITY_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5}


async def _collect_articles(date_iso: str) -> list[dict]:
    col = get_database()[COLLECTION_NAME]
    cursor = col.find(
        {"posted_on": date_iso},
        {
            "_id": 1, "title": 1, "url": 1, "source": 1, "posted_on": 1,
            "threat_actors": 1, "impacted_industries": 1, "countries": 1,
            "mentioned_countries": 1, "ttps": 1, "cves": 1,
            "source_reliability": 1, "description": 1, "incident": 1,
        },
    ).limit(200)
    docs = await cursor.to_list(length=200)
    # source_reliability is an Admiralty grade string (A best .. F worst, missing/unknown
    # treated as worst). Sort in Python — a plain ascending Mongo sort would put docs with
    # a missing/empty grade ahead of "A" since Mongo sorts absent fields first.
    docs.sort(key=lambda a: _RELIABILITY_RANK.get((a.get("source_reliability") or "").upper(), 99))
    return docs


async def _collect_tweets(date_iso: str) -> list[dict]:
    col = get_database()[TWEETS_COLLECTION]
    # tweets store posted_on as ISO datetime (e.g. "2026-05-22T13:00:57+00:00"),
    # so use a prefix-range match rather than equality.
    next_day = (datetime.strptime(date_iso, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
    cursor = col.find(
        {
            "posted_on": {"$gte": date_iso, "$lt": next_day},
            "related_cyber": {"$ne": False},
        },
        {
            "_id": 1, "tweet_id": 1, "url": 1, "text": 1, "author_username": 1,
            "posted_on": 1, "mentioned_group": 1, "cve_list": 1,
            "industries_impacted": 1, "victim_countries": 1,
            "confirmed_incident": 1, "incident_confidence": 1,
            "apac_indicator": 1, "ot_status": 1, "zero_day_list": 1,
            "databreach_list": 1,
        },
    ).sort("incident_confidence", -1).limit(150)
    return await cursor.to_list(length=150)


async def _collect_iocs(date_iso: str) -> list[dict]:
    col = get_database()[IOC_COLLECTION]
    # iocs.first_seen is plain "YYYY-MM-DD" — use date-range so this also
    # works if upstream ever switches to ISO timestamps.
    next_day = (datetime.strptime(date_iso, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
    cursor = col.find(
        {"first_seen": {"$gte": date_iso, "$lt": next_day}},
        {"_id": 0, "type": 1, "value": 1, "first_seen": 1, "confidence_score": 1},
    ).limit(200)
    return await cursor.to_list(length=200)


async def _collect_cves(date_iso: str) -> list[dict]:
    """CVEs first registered in the tracker on date_iso.

    cve_tracker stores `registered_date` / `detected_on` as
    "YYYY-MM-DD HH:MM:SS" (space-separated, not ISO-T). Lexicographic
    "$gte: date, $lt: next-day" still works for that format.
    """
    col = get_database()[CVE_COLLECTION]
    next_day = (datetime.strptime(date_iso, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
    cursor = col.find(
        {
            "$or": [
                {"registered_date": {"$gte": date_iso, "$lt": next_day}},
                {"detected_on": {"$gte": date_iso, "$lt": next_day}},
                {"published": {"$gte": date_iso, "$lt": next_day}},
            ],
            "false_positive": {"$ne": True},
        },
        {
            "_id": 0, "cve_id": 1, "cve_score": 1, "cve_severity": 1,
            "cisa_kev": 1, "epss_score": 1, "poc_available": 1,
            "summary": 1, "tech": 1,
        },
    ).limit(50)
    return await cursor.to_list(length=50)


async def _collect_new_threat_actors(date_iso: str) -> list[dict]:
    col = get_ta_database()[TA_GROUPS_COLLECTION]
    cursor = col.find(
        {"added_date": date_iso},
        {"_id": 0, "name": 1, "source": 1},
    ).limit(50)
    return await cursor.to_list(length=50)


async def _collect_campaigns() -> list[dict]:
    """Recent active campaigns (last 7d) — context for forecast."""
    try:
        return await get_recent_campaigns(days=7, min_size=3)
    except Exception:
        return []


async def _collect_ransomware(date_iso: str) -> list[dict]:
    """Ransomware victims published on date_iso."""
    try:
        docs, _total = await ransomware_service.get_victims(
            page=1, page_size=100, date_start=date_iso, date_end=date_iso,
        )
        return docs
    except Exception:
        return []


async def _collect_kev_additions(date_iso: str) -> list[dict]:
    """CVEs newly added to the CISA KEV catalog on date_iso."""
    try:
        col = get_database()["cisa_kev_catalog"]
        cursor = col.find(
            {"date_added": date_iso},
            {
                "_id": 0, "cve_id": 1, "vendor_project": 1, "product": 1,
                "vulnerability_name": 1, "due_date": 1,
            },
        ).limit(100)
        return await cursor.to_list(length=100)
    except Exception:
        return []


async def _collect_spikes(date_iso: str) -> dict:
    """Z-score entity/volume anomalies, filtered to spikes detected on date_iso."""
    try:
        spikes = await spike_service.get_spikes(lookback_days=30, z_threshold=2.0)
    except Exception:
        return {"threat_actors": [], "countries": [], "industries": [], "overall": []}

    def _on_date(items: list[dict]) -> list[dict]:
        return [s for s in (items or []) if s.get("date") == date_iso][:10]

    return {
        "threat_actors": _on_date(spikes.get("threat_actors")),
        "countries": _on_date(spikes.get("countries")),
        "industries": _on_date(spikes.get("industries")),
        "overall": _on_date(spikes.get("overall")),
    }


async def _collect_domain_watch(date_iso: str, client_id: str = "default") -> list[dict]:
    """Newly registered lookalike domains flagged on date_iso, for this client's watchlist."""
    try:
        docs, _total = await domain_watch_service.list_results(
            newly_registered_only=True, page=1, page_size=100,
            sort_by="timestamp", sort_dir="desc", client_id=client_id,
        )
        return [d for d in docs if str(d.get("timestamp", "")).startswith(date_iso)][:50]
    except Exception:
        return []


async def _collect_pkg_vulns(date_iso: str, client_id: str = "default") -> list[dict]:
    """Package advisories newly published/modified on date_iso, for this client's tracked packages."""
    try:
        docs, _total = await pkg_vuln_service.list_vulns(
            page=1, page_size=200, sort_by="adjusted_score", sort_dir="desc", client_id=client_id,
        )
        return [
            d for d in docs
            if d.get("published") == date_iso or d.get("modified") == date_iso
        ][:50]
    except Exception:
        return []


def _collect_ttps(articles: list[dict]) -> list[dict]:
    """Top ~10 MITRE technique IDs/names by frequency across the day's articles."""
    counts: dict[str, dict] = {}
    for a in articles:
        for ttp in (a.get("ttps") or []):
            if isinstance(ttp, dict):
                key = ttp.get("id") or ttp.get("technique_id") or ttp.get("name") or ""
                name = ttp.get("name", "")
            else:
                key = str(ttp)
                name = str(ttp)
            if not key:
                continue
            entry = counts.setdefault(key, {"id": key, "name": name, "count": 0})
            entry["count"] += 1
    return sorted(counts.values(), key=lambda x: -x["count"])[:10]


def _collect_ioc_detail(iocs: list[dict]) -> list[dict]:
    """Top ~15 IOCs by confidence_score (type, value, score)."""
    scored = [i for i in iocs if i.get("confidence_score") is not None]
    scored.sort(key=lambda i: -i["confidence_score"])
    return [
        {"type": i.get("type"), "value": i.get("value"), "confidence_score": i.get("confidence_score")}
        for i in scored[:15]
    ]


async def _collect_scraper_health() -> dict:
    """Recent scraper health — degraded feeds should not be mistaken for a calm day."""
    try:
        return await scraper_health_service.get_health_summary(days=1)
    except Exception:
        return {}


def _truncate(s: str, n: int) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[: n - 1] + "…"


def _build_user_message(
    date_iso: str,
    articles: list[dict],
    tweets: list[dict],
    iocs: list[dict],
    cves: list[dict],
    campaigns: list[dict],
    new_tas: list[dict],
    ransomware: list[dict],
    kev_additions: list[dict],
    spikes: dict,
    domain_hits: list[dict],
    pkg_vulns: list[dict],
    ttps: list[dict],
    ioc_detail: list[dict],
    scraper_health: dict,
    prev_forecast_events: list[dict] | None = None,
    client_context: str | None = None,
) -> str:
    article_lines = []
    for a in articles[:60]:
        actors = ", ".join((a.get("threat_actors") or [])[:3])
        cves_a = ", ".join((a.get("cves") or [])[:3])
        sr = a.get("source_reliability")
        sr_str = f" SR={sr}" if sr is not None else ""
        article_lines.append(
            f"- [{a.get('source', '?')}{sr_str}] {_truncate(a.get('title',''), 200)}"
            + (f" | actors: {actors}" if actors else "")
            + (f" | CVEs: {cves_a}" if cves_a else "")
            + (f" | url: {a.get('url')}" if a.get("url") else "")
        )

    tweet_lines = []
    for t in tweets[:50]:
        flags = []
        if t.get("confirmed_incident"):
            flags.append("CONFIRMED-INCIDENT")
        if t.get("apac_indicator"):
            flags.append("APAC")
        if t.get("ot_status"):
            flags.append("OT")
        if t.get("zero_day_list"):
            flags.append("0DAY")
        if t.get("databreach_list"):
            flags.append("BREACH")
        groups = ", ".join((t.get("mentioned_group") or [])[:3])
        cves_t = ", ".join((t.get("cve_list") or [])[:3])
        flag_str = f" [{' '.join(flags)}]" if flags else ""
        tweet_lines.append(
            f"- {t.get('author_username','?')}{flag_str}: {_truncate(t.get('text',''), 240)}"
            + (f" | groups: {groups}" if groups else "")
            + (f" | CVEs: {cves_t}" if cves_t else "")
            + (f" | url: {t.get('url')}" if t.get("url") else "")
        )

    cve_lines = []
    for c in cves[:30]:
        bits = []
        if c.get("cve_score") is not None:
            bits.append(f"CVSS {c['cve_score']}")
        if c.get("cve_severity"):
            bits.append(c["cve_severity"])
        if c.get("tech"):
            bits.append(f"tech: {c['tech']}")
        if c.get("cisa_kev"):
            bits.append("KEV")
        if c.get("poc_available"):
            bits.append("PoC")
        if c.get("epss_score") is not None:
            bits.append(f"EPSS {c['epss_score']}")
        cve_lines.append(f"- {c.get('cve_id','?')} ({', '.join(bits)}): {_truncate(c.get('summary',''), 160)}")

    ioc_counts: dict[str, int] = {}
    for i in iocs:
        ioc_counts[i.get("type", "unknown")] = ioc_counts.get(i.get("type", "unknown"), 0) + 1
    ioc_line = ", ".join(f"{k}={v}" for k, v in sorted(ioc_counts.items(), key=lambda x: -x[1])) or "none"

    camp_lines = []
    for c in (campaigns or [])[:8]:
        theme = c.get("theme") or c.get("label") or "(unlabeled)"
        size = c.get("size") or len(c.get("article_ids") or [])
        actors = ", ".join((c.get("threat_actors") or [])[:3])
        camp_lines.append(
            f"- {theme} — {size} articles" + (f" | actors: {actors}" if actors else "")
        )

    new_ta_lines = []
    for ta in (new_tas or []):
        src = ta.get("source") or "manual"
        new_ta_lines.append(f"- {ta.get('name','?')} (source: {src})")

    ransom_lines = [
        f"- {r.get('group_name','?')} — {r.get('victim','?')} ({r.get('country','?')}, {r.get('industry','?')})"
        for r in (ransomware or [])[:40]
    ]

    kev_lines = [
        f"- {k.get('cve_id','?')} — {k.get('vendor_project','?')} {k.get('product','')} — due {k.get('due_date','?')}: {_truncate(k.get('vulnerability_name',''), 120)}"
        for k in (kev_additions or [])[:40]
    ]

    def _spike_lines(items: list[dict]) -> list[str]:
        return [
            f"- {s.get('entity', s.get('date'))}: count={s.get('count')} (baseline={s.get('baseline_mean')}, z={s.get('z_score')}, {s.get('severity')})"
            for s in (items or [])
        ]

    spike_block = (
        "  Threat actors:\n" + (chr(10).join(_spike_lines(spikes.get("threat_actors"))) or "    (none)")
        + "\n  Countries:\n" + (chr(10).join(_spike_lines(spikes.get("countries"))) or "    (none)")
        + "\n  Industries:\n" + (chr(10).join(_spike_lines(spikes.get("industries"))) or "    (none)")
        + "\n  Overall volume:\n" + (chr(10).join(_spike_lines(spikes.get("overall"))) or "    (none)")
    )

    domain_lines = [f"- {d.get('domain','?')} (tld: {d.get('tld','?')})" for d in (domain_hits or [])[:30]]

    pkg_lines = [
        f"- {p.get('advisory_id','?')} — {p.get('package_name','?')} ({p.get('ecosystem','?')}) "
        f"[{p.get('adjusted_severity') or p.get('severity','?')}] fixed in: {p.get('fixed_version') or 'none'}"
        for p in (pkg_vulns or [])[:40]
    ]

    ttp_lines = [f"- {t.get('id','?')} {t.get('name','')} (x{t.get('count')})" for t in (ttps or [])]

    ioc_detail_lines = [
        f"- [{i.get('type','?')}] {i.get('value','?')} (confidence: {i.get('confidence_score')})"
        for i in (ioc_detail or [])
    ]

    health = scraper_health or {}
    health_line = (
        f"accept_rate={health.get('accept_rate', '?')}% "
        f"accepted={health.get('total_accepted', '?')} rejected={health.get('total_rejected', '?')} "
        "(last 24h across all scrapers)"
    ) if health else "  (health summary unavailable)"

    prev_forecast_lines = [
        f"- {ev.get('event','?')} (confidence: {ev.get('confidence','?')}, basis: {_truncate(ev.get('basis',''), 150)})"
        for ev in (prev_forecast_events or [])
    ]
    prev_forecast_block = (
        chr(10).join(prev_forecast_lines) if prev_forecast_lines
        else "  (no forecast on record for the previous day — return an empty forecast_review list)"
    )

    client_block = f"\n{client_context}\n" if client_context else ""

    return f"""DAILY RECAP TARGET DATE: {date_iso} (UTC)
{client_block}
== NEWS ROOM ARTICLES POSTED {date_iso} ({len(articles)} total) ==
{chr(10).join(article_lines) if article_lines else "  (none)"}

== X / TWITTER POSTS ON {date_iso} ({len(tweets)} cyber-relevant) ==
{chr(10).join(tweet_lines) if tweet_lines else "  (none)"}

== NEW / UPDATED CVES ON {date_iso} ({len(cves)} total) ==
{chr(10).join(cve_lines) if cve_lines else "  (none)"}

== NEW IOCS ON {date_iso} ({len(iocs)} total) ==
{ioc_line}

== NEW THREAT ACTORS ADDED TO DATABASE ON {date_iso} ({len(new_tas)} total) ==
{chr(10).join(new_ta_lines) if new_ta_lines else "  (none)"}

== ACTIVE CAMPAIGN CLUSTERS (last 7d, momentum context for forecast) ==
{chr(10).join(camp_lines) if camp_lines else "  (none)"}

== RANSOMWARE VICTIMS PUBLISHED {date_iso} ({len(ransomware)} total) ==
{chr(10).join(ransom_lines) if ransom_lines else "  (none)"}

== CISA KEV ADDITIONS ON {date_iso} ({len(kev_additions)} total) ==
{chr(10).join(kev_lines) if kev_lines else "  (none)"}

== SPIKE / ANOMALY DETECTION (z-score, entities spiking ON {date_iso}) ==
{spike_block}

== NEWLY REGISTERED LOOKALIKE DOMAINS ON {date_iso} ({len(domain_hits)} total) ==
{chr(10).join(domain_lines) if domain_lines else "  (none)"}

== PACKAGE VULNERABILITIES NEWLY PUBLISHED/MODIFIED ON {date_iso} ({len(pkg_vulns)} total) ==
{chr(10).join(pkg_lines) if pkg_lines else "  (none)"}

== TOP MITRE TTPS ACROSS TODAY'S ARTICLES ==
{chr(10).join(ttp_lines) if ttp_lines else "  (none)"}

== TOP IOCS BY CONFIDENCE ==
{chr(10).join(ioc_detail_lines) if ioc_detail_lines else "  (none)"}

== SCRAPER HEALTH (last 24h) ==
  {health_line}

== PREVIOUS DAY'S FORECASTED EVENTS (score these in forecast_review) ==
{prev_forecast_block}

Now produce the JSON recap+forecast per the schema. Remember: forecast must cite concrete signals from above.
"""


def _extract_json(raw: str) -> dict:
    if not raw:
        return {}
    s = raw.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    try:
        return json.loads(s)
    except Exception:
        m = re.search(r"\{.*\}", s, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
    return {"_raw": raw}


async def generate_daily_recap(date: str | None = None, force: bool = False, client_id: str = "default") -> dict:
    """Generate (or fetch cached) recap for given date (defaults to yesterday) and client.

    If a recap for (date, client_id) already exists and force=False, return the cached one.
    client_id="default" is the org-wide recap; any other client_id produces a recap scoped
    to that client's tracked countries/sectors (app.services.client_service), reusing the
    cached org-wide recap as cheap context instead of re-deriving posture/forecast from scratch.
    """
    date_iso, _, _ = _yesterday_window(date)
    col = get_database()[RECAP_COLLECTION]

    if not force:
        existing = await col.find_one(_client_query(date_iso, client_id))
        if existing:
            existing["_id"] = str(existing["_id"])
            existing["cached"] = True
            _set_progress(date_iso, client_id, "cached", 100, done=True)
            return existing

    _set_progress(date_iso, client_id, "starting", 0)
    try:
        return await _generate_daily_recap_inner(date_iso, col, client_id)
    except Exception as e:
        prev_pct = _PROGRESS.get(_progress_key(date_iso, client_id), {}).get("pct", 0)
        _set_progress(date_iso, client_id, "error", prev_pct, done=True, error=str(e))
        raise


async def _generate_daily_recap_inner(date_iso: str, col, client_id: str) -> dict:
    _set_progress(date_iso, client_id, "loading previous day", 5)
    prev_date_iso = (datetime.strptime(date_iso, "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d")
    prev_doc = await col.find_one(_client_query(prev_date_iso, client_id))
    prev_forecast_events = ((prev_doc or {}).get("forecast") or {}).get("likely_events", [])

    client_profile = None
    org_context = ""
    if client_id != "default":
        client_profile = await get_client(client_id)
        if not client_profile:
            raise ValueError(f"unknown client_id: {client_id}")
        # Reuse the (cached, if already generated today) org-wide recap as free context —
        # avoids re-deriving posture/forecast per client and keeps this call's prompt small.
        org_doc = await generate_daily_recap(date=date_iso, force=False, client_id="default")
        org_forecast_summary = (org_doc.get("forecast") or {}).get("summary", "")
        org_context = f"Org-wide headline: {org_doc.get('headline','')}\nOrg-wide forecast: {org_forecast_summary}"

    _set_progress(date_iso, client_id, "collecting data", 10)
    (
        articles, tweets, iocs, cves, campaigns, new_tas,
        ransomware, kev_additions, spikes, domain_hits, pkg_vulns, scraper_health,
    ) = await asyncio.gather(
        _collect_articles(date_iso),
        _collect_tweets(date_iso),
        _collect_iocs(date_iso),
        _collect_cves(date_iso),
        _collect_campaigns(),
        _collect_new_threat_actors(date_iso),
        _collect_ransomware(date_iso),
        _collect_kev_additions(date_iso),
        _collect_spikes(date_iso),
        _collect_domain_watch(date_iso, client_id),
        _collect_pkg_vulns(date_iso, client_id),
        _collect_scraper_health(),
    )

    # Client-relevance filtering — trims org-wide article/tweet/ransomware/campaign volume
    # down to this client's tracked countries/sectors *before* the LLM call, which is where
    # the token savings actually come from. domain_hits/pkg_vulns are already client-scoped
    # at the DB layer (per-client watchlists); kev/spikes/health stay org-wide since they're
    # deadline/context signals relevant to everyone, not filterable by client.
    if client_profile is not None:
        articles = [a for a in articles if _client_relevant(a, client_profile, ["mentioned_countries", "countries"], ["impacted_industries"])]
        tweets = [t for t in tweets if _client_relevant(t, client_profile, ["victim_countries"], ["industries_impacted"])]
        ransomware = [r for r in ransomware if _client_relevant(r, client_profile, ["country"], ["industry"])]
        campaigns = [c for c in campaigns if _client_relevant(c, client_profile, ["dominant_countries"], ["dominant_industries"])]

    _set_progress(date_iso, client_id, "data collected", 40)
    ttps = _collect_ttps(articles)
    ioc_detail = _collect_ioc_detail(iocs)

    client_context = None
    if client_profile is not None:
        client_context = (
            "== CLIENT SCOPE ==\n"
            f"This recap is personalized for client: {client_profile.get('name', client_id)} ({client_id}).\n"
            f"Tracked countries: {', '.join(client_profile.get('countries') or []) or 'none'}. "
            f"Tracked sectors: {', '.join(client_profile.get('sectors') or []) or 'none'}.\n"
            f"{org_context}\n"
            "News/tweet/ransomware/campaign items below are already filtered to this client's "
            "tracked countries/sectors; package vulns and domain watch hits are already scoped "
            "to this client's own tracked packages/domains.\n"
            "IMPORTANT — the schema's \"apac_signals\" field: for this client-scoped recap, "
            "ignore the \"APAC\" framing and instead populate it with signals specific to this "
            "client's own tracked countries/regions listed above (not general Asia-Pacific "
            "unless that happens to be one of the tracked countries). If nothing is regionally "
            "specific to this client beyond what's already in the summary, return an empty list."
        )

    user_msg = _build_user_message(
        date_iso, articles, tweets, iocs, cves, campaigns, new_tas,
        ransomware, kev_additions, spikes, domain_hits, pkg_vulns,
        ttps, ioc_detail, scraper_health,
        prev_forecast_events=prev_forecast_events,
        client_context=client_context,
    )

    _set_progress(date_iso, client_id, "calling LLM", 50)

    def _call_llm() -> tuple[str, dict]:
        client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            response_format={"type": "json_object"},
        )
        usage = {}
        try:
            u = completion.usage
            usage = {
                "prompt_tokens": getattr(u, "prompt_tokens", None),
                "completion_tokens": getattr(u, "completion_tokens", None),
                "total_tokens": getattr(u, "total_tokens", None),
            }
        except Exception:
            pass
        return completion.choices[0].message.content, usage

    try:
        raw, usage = await asyncio.to_thread(_call_llm)
    except TypeError:
        def _call_llm_no_format() -> tuple[str, dict]:
            client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
            completion = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
            )
            return completion.choices[0].message.content, {}
        raw, usage = await asyncio.to_thread(_call_llm_no_format)

    _set_progress(date_iso, client_id, "parsing response", 90)
    parsed = _extract_json(raw)
    parse_error = "_raw" in parsed

    # Full CVE detail (CVSS/KEV/PoC/EPSS) keyed by ID, for the renderer's badges —
    # the LLM schema only carries CVE ID strings in notable_cves.
    cve_details = {
        c["cve_id"]: {
            "cve_score": c.get("cve_score"),
            "cve_severity": c.get("cve_severity"),
            "cisa_kev": bool(c.get("cisa_kev")),
            "poc_available": bool(c.get("poc_available")),
            "epss_score": c.get("epss_score"),
        }
        for c in cves if c.get("cve_id")
    }

    counts = {
        "articles": len(articles),
        "tweets": len(tweets),
        "iocs": len(iocs),
        "cves": len(cves),
        "campaigns": len(campaigns),
        "new_threat_actors": len(new_tas),
        "ransomware_victims": len(ransomware),
        "kev_additions": len(kev_additions),
        "domain_watch_hits": len(domain_hits),
        "package_vulns": len(pkg_vulns),
    }
    prev_counts = (prev_doc or {}).get("counts") or {}
    counts_delta = {k: counts[k] - prev_counts[k] for k in counts if k in prev_counts}

    doc = {
        "date": date_iso,
        "client_id": client_id,
        "client_name": (client_profile or {}).get("name", "Default"),
        "yesterday": parsed.get("recap", {}),
        "forecast": parsed.get("forecast", {}),
        "headline": parsed.get("headline", ""),
        "parse_error": parse_error,
        "counts": counts,
        "counts_delta": counts_delta,
        "spikes": spikes,
        "scraper_health": scraper_health,
        "cve_details": cve_details,
        "ioc_detail": ioc_detail,
        "forecast_review": parsed.get("forecast_review", []),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": LLM_MODEL or LLM_PROVIDER or "default",
        "token_usage": usage,
        "raw_llm": raw if parse_error else None,
    }

    _set_progress(date_iso, client_id, "saving", 95)
    await col.update_one({"date": date_iso, "client_id": client_id}, {"$set": doc}, upsert=True)
    saved = await col.find_one({"date": date_iso, "client_id": client_id})
    if saved:
        saved["_id"] = str(saved["_id"])
        saved["cached"] = False
    _set_progress(date_iso, client_id, "done", 100, done=True)
    return saved or doc


async def get_recap(date: str, client_id: str = "default") -> dict | None:
    col = get_database()[RECAP_COLLECTION]
    doc = await col.find_one(_client_query(date, client_id))
    if not doc:
        return None
    doc["_id"] = str(doc["_id"])
    return doc


def _client_list_query(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


async def list_recaps(limit: int = 30, client_id: str = "default") -> list[dict]:
    col = get_database()[RECAP_COLLECTION]
    cursor = col.find(
        _client_list_query(client_id),
        {"date": 1, "headline": 1, "counts": 1, "generated_at": 1},
    ).sort("date", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs
