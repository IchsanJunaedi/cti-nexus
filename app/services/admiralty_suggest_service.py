"""LLM-assisted Admiralty rating suggestion for a news source.

Pulls this source's article history (volume, span, topic diversity, overlap
with other sources) and asks the LLM to propose a Reliability (A-F) /
Credibility (1-6) pair per NATO AJP-2.1, following the same rubric as
app/services/source_score_db_service.py. The analyst still confirms the
value via the normal add/edit endpoints — this never writes to the DB.
"""

import json
import re
from datetime import datetime, timedelta, timezone

CORROBORATION_WINDOW_DAYS = 7

from app.config import COLLECTION_NAME, LLM_PROVIDER, LLM_API_KEY, LLM_MODEL
from app.database import get_database
from app.services.llm_client import get_llm_client
from app.services.source_score_db_service import RELIABILITY_LABELS, CREDIBILITY_LABELS

SYSTEM_PROMPT = """You are a CTI analyst applying the NATO Admiralty System (AJP-2.1) to rate a news source.

Rate two things, independently:
- Source Reliability (A-F): how trustworthy the origin is, based on track record on THIS topic
- Information Credibility (1-6): how trustworthy this source's typical reporting is, independent of the source rating

Reliability scale:
A Completely reliable — long, consistently accurate, topic-specific history. Reserve; rare.
B Usually reliable — strong track record, minor lapses.
C Fairly reliable — accurate before, but short or mixed track record.
D Not usually reliable — wrong more often than right, cannot be fully dismissed.
E Unreliable — clear history of inaccuracy, deception, or manipulation.
F Reliability cannot be judged — new source, no track record, insufficient access.

Credibility scale:
1 Confirmed by other sources — genuinely independent corroboration.
2 Probably true — logical, consistent with known facts, partly corroborated.
3 Possibly true — plausible but not independently confirmed.
4 Doubtful — unconfirmed, partly inconsistent.
5 Improbable — contradicts known facts or internally inconsistent.
6 Truth cannot be judged — insufficient information.

Hard rules:
- NEVER conflate the two ratings; they are independent axes.
- Do NOT count republished/syndicated content from another outlet as independent corroboration. A CORROBORATION
  CHECK section below lists CVEs also covered by other sources in the same window — use the paired titles to
  judge syndication vs. genuine independent collection before crediting it toward Credibility=1 or 2.
- NEVER assign A casually — only with a long, well-documented, topic-specific history.
- When unsure, prefer F or 6 over guessing. A thin or brand-new history should default to F/F6-ish territory.
- You only have the metadata below (no ground-truth fact-check). Base the rating on volume, time span, and
  topical consistency of what this scraper has collected — this is a starting suggestion for a human analyst,
  not a final verdict.

Output STRICT JSON, no markdown, no code fences:
{"reliability_grade": "A|B|C|D|E|F", "credibility_code": "1|2|3|4|5|6", "reasoning": "<2-3 sentences citing the metadata below>"}
"""


def _truncate(s: str, n: int) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[: n - 1] + "…"


async def _collect_corroboration(col, source_name: str, recent_docs: list[dict], cutoff: str) -> list[dict]:
    """For CVEs this source covered in the last N days, find OTHER sources that
    also covered them in the same window. Raw (cve, source, title) triples only —
    the LLM, not this code, judges whether overlap looks like independent
    corroboration or syndicated/republished content (per skill's own worked example).
    """
    cves = sorted({c for d in recent_docs for c in (d.get("cves") or [])})
    if not cves:
        return []

    cursor = col.find(
        {
            "cves": {"$in": cves},
            "posted_on": {"$gte": cutoff},
            "source": {"$not": {"$regex": f"^{re.escape(source_name)}$", "$options": "i"}},
        },
        {"_id": 0, "source": 1, "title": 1, "cves": 1, "posted_on": 1},
    ).limit(100)
    other_docs = await cursor.to_list(length=100)

    by_cve: dict[str, list[dict]] = {}
    for d in other_docs:
        for c in (d.get("cves") or []):
            if c in cves:
                by_cve.setdefault(c, []).append({
                    "source": d.get("source"),
                    "title": _truncate(d.get("title", ""), 120),
                })

    return [
        {"cve": c, "other_sources": entries[:5]}
        for c, entries in sorted(by_cve.items())
    ]


async def _collect_source_stats(source_name: str) -> dict:
    col = get_database()[COLLECTION_NAME]
    query = {"source": {"$regex": f"^{re.escape(source_name)}$", "$options": "i"}}

    cursor = col.find(
        query,
        {"_id": 0, "title": 1, "posted_on": 1, "threat_actors": 1, "cves": 1, "impacted_industries": 1},
    ).sort("posted_on", -1).limit(100)
    docs = await cursor.to_list(length=100)
    total = await col.count_documents(query)

    dates = sorted(d.get("posted_on") for d in docs if d.get("posted_on"))
    actors = sorted({a for d in docs for a in (d.get("threat_actors") or [])})
    industries = sorted({i for d in docs for i in (d.get("impacted_industries") or [])})
    sample_titles = [_truncate(d.get("title", ""), 140) for d in docs[:20]]

    cutoff = (datetime.now(timezone.utc) - timedelta(days=CORROBORATION_WINDOW_DAYS)).strftime("%Y-%m-%d")
    recent_docs = [d for d in docs if (d.get("posted_on") or "") >= cutoff]
    corroboration = await _collect_corroboration(col, source_name, recent_docs, cutoff)

    return {
        "total_articles": total,
        "sampled": len(docs),
        "earliest_sampled_date": dates[0] if dates else None,
        "latest_sampled_date": dates[-1] if dates else None,
        "distinct_threat_actors_covered": actors[:15],
        "distinct_industries_covered": industries[:15],
        "sample_titles": sample_titles,
        "corroboration_window_days": CORROBORATION_WINDOW_DAYS,
        "recent_article_count": len(recent_docs),
        "corroboration": corroboration,
    }


def _build_user_message(source_name: str, stats: dict) -> str:
    corrob_lines = []
    for entry in stats["corroboration"]:
        others = ", ".join(f"{o['source']} (\"{o['title']}\")" for o in entry["other_sources"])
        corrob_lines.append(f"- {entry['cve']}: also covered by {others}")

    return f"""SOURCE: {source_name}

Total articles collected from this source: {stats['total_articles']}
Sampled (most recent {stats['sampled']}): {stats['earliest_sampled_date']} → {stats['latest_sampled_date']}
Distinct threat actors covered in sample: {', '.join(stats['distinct_threat_actors_covered']) or 'none'}
Distinct industries covered in sample: {', '.join(stats['distinct_industries_covered']) or 'none'}

Sample titles:
{chr(10).join(f'- {t}' for t in stats['sample_titles']) or '  (none)'}

== CORROBORATION CHECK (last {stats['corroboration_window_days']} days, {stats['recent_article_count']} articles from this source) ==
CVEs this source covered that OTHER sources also covered in the same window:
{chr(10).join(corrob_lines) if corrob_lines else '  (none found — either no recent CVE-tagged articles, or no other source covered the same CVEs recently)'}

For each corroboration line, judge from the paired titles whether it looks like genuinely independent
coverage (different framing/angle) or a syndicated/republished/wire-copy of the same underlying report —
per the Admiralty rule, only independent collection counts as corroboration for Credibility=1.

Rate this source's Reliability (A-F) and typical Credibility (1-6). Remember: no ground-truth fact-check is
available here — reason from volume, time span, topical consistency, and the corroboration check above, and
default to F/6-leaning territory when the history is thin.
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
    return {}


async def suggest_rating(source_name: str) -> dict:
    import asyncio

    stats = await _collect_source_stats(source_name)
    user_msg = _build_user_message(source_name, stats)

    def _call_llm() -> str:
        client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            response_format={"type": "json_object"},
        )
        return completion.choices[0].message.content

    try:
        raw = await asyncio.to_thread(_call_llm)
    except TypeError:
        def _call_llm_no_format() -> str:
            client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
            completion = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
            )
            return completion.choices[0].message.content
        raw = await asyncio.to_thread(_call_llm_no_format)

    parsed = _extract_json(raw)
    grade = str(parsed.get("reliability_grade", "")).upper()
    code = str(parsed.get("credibility_code", ""))

    if grade not in RELIABILITY_LABELS:
        grade = "F"
    if code not in CREDIBILITY_LABELS:
        code = "6"

    return {
        "source_name": source_name,
        "reliability_grade": grade,
        "credibility_code": code,
        "admiralty_code": f"{grade}{code}",
        "reasoning": parsed.get("reasoning", ""),
        "stats": stats,
        "model": LLM_MODEL or LLM_PROVIDER or "default",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
