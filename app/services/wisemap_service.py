import re
import asyncio
from datetime import datetime, timezone
from bson import ObjectId

from ClaudeCode.ScraperNewsWeb.scripts.wisemap_cti import WiseMappingXMLBuilder, WiseMappingClient, CTIReport, IOCExtractor, MapNode, COLORS
from app.config import (
    WISEMAP_ENABLED, WISEMAP_BASE_URL, WISEMAP_EMAIL, WISEMAP_PASSWORD,
    MINDMAPS_COLLECTION,
    PIR_COLLECTION, COLLECTION_NAME, TA_GROUPS_COLLECTION, TA_PROFILES_COLLECTION,
)
from app.database import get_database
from app.database import get_ta_database

TECHNIQUE_RE = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')


def _mindmaps_col():
    return get_database()[MINDMAPS_COLLECTION]


# ── Cache helpers ─────────────────────────────────────────────────────────────

async def get_cached_mindmap(feature_type: str, doc_id: str) -> dict | None:
    return await _mindmaps_col().find_one(
        {"feature_type": feature_type, "doc_id": doc_id},
        {"_id": 0},
    )


async def _save_mindmap(feature_type: str, doc_id: str, title: str,
                        wxml: str, wisemap_url: str = "") -> dict:
    doc = {
        "feature_type": feature_type,
        "doc_id": doc_id,
        "title": title,
        "wxml": wxml,
        "wisemap_url": wisemap_url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    await _mindmaps_col().update_one(
        {"feature_type": feature_type, "doc_id": doc_id},
        {"$set": doc},
        upsert=True,
    )
    return doc


# ── Generate + push/save ──────────────────────────────────────────────────────

async def generate_mindmap(report_or_raw, feature_type: str, doc_id: str) -> dict:
    if isinstance(report_or_raw, CTIReport):
        wxml = WiseMappingXMLBuilder().build(report_or_raw)
        title = report_or_raw.title
        summary = report_or_raw.summary
    else:
        title, wxml = report_or_raw
        summary = ""

    wisemap_url = ""
    if WISEMAP_ENABLED:
        client = WiseMappingClient(WISEMAP_BASE_URL, WISEMAP_EMAIL, WISEMAP_PASSWORD)
        stub = CTIReport(title=title, summary=summary)
        url = await asyncio.to_thread(client.push, stub, wxml)
        if url:
            wisemap_url = url

    return await _save_mindmap(feature_type, doc_id, title, wxml, wisemap_url)


async def get_or_generate(feature_type: str, doc_id: str, build_fn) -> dict | None:
    cached = await get_cached_mindmap(feature_type, doc_id)
    if cached:
        return cached
    report = await build_fn()
    if report is None:
        return None
    return await generate_mindmap(report, feature_type, doc_id)


# ── CTIReport builders ────────────────────────────────────────────────────────

def _extract_ttps(text: str) -> list[dict]:
    ids = sorted(set(TECHNIQUE_RE.findall(text)))
    return [{"id": t, "name": t, "tactic": "Unknown"} for t in ids]


_NEWSLETTER_SECTION_META = [
    ("highlight",   "⭐ Highlight",    "#f18f01"),
    ("apac",        "🌏 APAC",         "#2e86ab"),
    ("global_news", "🌐 Global News",  "#0f3460"),
    ("indonesia",   "🇮🇩 Indonesia",   "#533483"),
]


async def build_newsletter_report(doc_id: str):
    doc = await get_database()["newsletters"].find_one({"_id": ObjectId(doc_id)})
    if not doc:
        return None

    sections = doc.get("sections", {})
    title = f"Newsletter Week {doc.get('week', '?')}/{doc.get('year', '?')}"

    branches = []
    for key, label, color in _NEWSLETTER_SECTION_META:
        raw = sections.get(key)
        articles = [raw] if isinstance(raw, dict) and raw else (raw or [])
        if not articles:
            continue
        section_node = MapNode(
            text=f"{label} ({len(articles)})",
            color=color,
            children=[
                MapNode(
                    text=a.get("title", "Untitled")[:120],
                    color=COLORS["default"],
                    note=a.get("summary", "")[:500],
                    link=a.get("url", ""),
                )
                for a in articles
            ],
        )
        branches.append(section_node)

    wxml = WiseMappingXMLBuilder().build_from_nodes(title, branches)
    return (title, wxml)


async def build_threat_actor_report(doc_id: str) -> CTIReport | None:
    ta_db = get_ta_database()
    doc = await ta_db[TA_GROUPS_COLLECTION].find_one({"_id": ObjectId(doc_id)})
    if not doc:
        return None

    actor_name = doc.get("name", doc_id)
    profile = await ta_db[TA_PROFILES_COLLECTION].find_one(
        {"_actor_name": {"$regex": f"^{re.escape(actor_name)}$", "$options": "i"}},
        {"_id": 0},
    ) if TA_PROFILES_COLLECTION else None

    ttps = []
    malware = []
    targets = []
    references = []
    aliases = []

    if profile:
        identity = profile.get("identity", {})
        aliases = identity.get("aliases", [])

        raw_ttps = profile.get("ttps", [])
        for t in (raw_ttps if isinstance(raw_ttps, list) else []):
            tid = t.get("technique_id", t.get("id", ""))
            tname = t.get("technique_name", t.get("name", tid))
            tactic = t.get("tactic", "Unknown")
            if tid or tname:
                ttps.append({"id": tid, "name": tname, "tactic": tactic})

        for m in profile.get("known_malware", []):
            malware.append({
                "name": m.get("name", ""),
                "type": m.get("type", ""),
                "note": m.get("note", m.get("description", "")),
            })

        targeting = profile.get("targeting", {})
        targets = targeting.get("sectors", []) + targeting.get("regions", [])

        for ref in profile.get("references", []):
            url = ref.get("url", ref) if isinstance(ref, dict) else ref
            if url:
                references.append(str(url))

    summary_parts = []
    if aliases:
        summary_parts.append(f"Aliases: {', '.join(aliases[:5])}")
    if profile:
        motivation = profile.get("identity", {}).get("primary_motivation", "")
        if motivation:
            summary_parts.append(f"Motivation: {motivation}")

    return CTIReport(
        title=f"Threat Actor: {actor_name}",
        threat_actor=actor_name,
        summary=" | ".join(summary_parts),
        ttps=ttps,
        malware=malware,
        targets=targets,
        references=references[:20],
    )


async def build_cve_report_by_cve_id(cve_id: str) -> tuple | None:
    doc = await get_database()["cve_tracker"].find_one({"cve_id": cve_id})
    if not doc:
        return None
    return await build_cve_report(str(doc["_id"]), _doc=doc)


async def build_cve_report(doc_id: str, *, _doc: dict | None = None) -> tuple | None:
    doc = _doc or await get_database()["cve_tracker"].find_one({"_id": ObjectId(doc_id)})
    if not doc:
        return None

    cve_id        = doc.get("cve_id", doc_id)
    summary       = doc.get("summary", "")
    tech          = doc.get("tech", "")
    severity      = doc.get("cve_severity", "")
    score         = doc.get("cve_score", 0)
    cvss          = doc.get("cvss_vector", "")
    published     = (doc.get("published", "") or "")[:10]
    poc_available = doc.get("poc_available", False)
    cisa_kev      = doc.get("cisa_kev", False)
    solutions     = doc.get("solutions", "")
    affected      = doc.get("affected", []) or []
    references    = doc.get("reference", []) or []
    pocs          = doc.get("pocs", []) or []
    kev_desc      = doc.get("cisa_kev_description", "")
    kev_action    = doc.get("cisa_kev_action", "")

    branches = []

    # Overview
    overview_children = [
        MapNode(text=f"Severity: {severity} (Score: {score})", color=COLORS["vulnerability"]),
        MapNode(text=f"Published: {published}", color=COLORS["default"]) if published else None,
        MapNode(text=f"Tech Stack: {tech}", color=COLORS["default"]) if tech else None,
        MapNode(text=f"CVSS: {cvss}", color=COLORS["default"]) if cvss else None,
    ]
    branches.append(MapNode(
        text="Overview",
        color=COLORS["vulnerability"],
        note=summary,
        children=[c for c in overview_children if c],
    ))

    # Affected Versions
    if affected:
        aff_children = []
        for entry in affected[:10]:
            for prod, vers in entry.items():
                for v in (vers or [])[:5]:
                    aff_children.append(MapNode(text=f"{prod}: {v}", color=COLORS["host"]))
        if aff_children:
            branches.append(MapNode(text="Affected Versions", color=COLORS["host"], children=aff_children))

    # TTPs from summary text
    combined = f"{summary} {kev_desc}"
    ttps = _extract_ttps(combined)
    if ttps:
        ttp_children = []
        for t in ttps:
            tid = t.get("id", "")
            link = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/" if tid else ""
            ttp_children.append(MapNode(text=tid, color=COLORS["mitre"], link=link))
        branches.append(MapNode(text="TTPs / ATT&CK", color=COLORS["ttp"], children=ttp_children))

    # POC / Exploits
    if poc_available or pocs:
        poc_children = [
            MapNode(text=p.get("url", "")[:80], color=COLORS["malware"],
                    link=p.get("url", ""), note=p.get("type", "poc"))
            for p in pocs[:10] if p.get("url")
        ] or [MapNode(text="POC available (no URL on record)", color=COLORS["malware"])]
        branches.append(MapNode(text="⚡ POC / Exploits", color=COLORS["malware"], children=poc_children))

    # CISA KEV
    if cisa_kev:
        kev_children = []
        if kev_action:
            kev_children.append(MapNode(text=f"Required Action: {kev_action[:120]}", color=COLORS["actor"]))
        branches.append(MapNode(
            text="🔴 CISA KEV — Exploited in Wild",
            color=COLORS["actor"],
            note=kev_desc,
            children=kev_children,
        ))

    # Solution
    if solutions and solutions.strip() and solutions.strip() != "No solution yet":
        sol_text = solutions[:100] + ("…" if len(solutions) > 100 else "")
        branches.append(MapNode(
            text="Solution",
            color=COLORS["network"],
            note=solutions,
            children=[MapNode(text=sol_text, color=COLORS["network"])],
        ))

    # References
    ref_children = [MapNode(
        text=f"NVD — {cve_id}", color=COLORS["default"],
        link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )]
    for r in references[:8]:
        url = r.get("url", "") if isinstance(r, dict) else str(r)
        if url:
            ref_children.append(MapNode(text=url[:80], color=COLORS["default"], link=url))
    branches.append(MapNode(text="References", color=COLORS["default"], children=ref_children))

    wxml = WiseMappingXMLBuilder().build_from_nodes(cve_id, branches)
    return (cve_id, wxml)


async def build_pir_report(doc_id: str) -> CTIReport | None:
    col = get_database()[PIR_COLLECTION]
    doc = await col.find_one({"_id": ObjectId(doc_id)})
    if not doc:
        return None

    from app.services.pir_service import get_pir_articles
    result = await get_pir_articles(doc_id, page=1, page_size=30)
    articles = result[0] if result else []
    total = result[1] if result else 0

    all_titles = " ".join(a.get("title", "") for a in articles)
    iocs = IOCExtractor.extract(all_titles)
    cves = iocs.pop("CVEs", [])

    threat_actors = sorted({ta for a in articles for ta in a.get("threat_actors", []) if ta})
    references = [a["url"] for a in articles if a.get("url")][:20]

    criteria = doc.get("criteria", {})
    summary_parts = [f"Coverage: {total} articles"]
    if threat_actors:
        summary_parts.append(f"Actors: {', '.join(threat_actors[:5])}")
    if criteria.get("keywords"):
        summary_parts.append(f"Keywords: {', '.join(criteria['keywords'][:5])}")

    return CTIReport(
        title=doc.get("title", doc_id),
        summary=" | ".join(summary_parts),
        threat_actor=", ".join(threat_actors[:3]) if threat_actors else "",
        ttps=_extract_ttps(all_titles),
        iocs=iocs,
        vulnerabilities=[{"cve": c, "description": ""} for c in cves],
        targets=criteria.get("industries", []) + criteria.get("countries", []),
        references=references,
    )


async def build_cluster_report(cluster_id: str) -> CTIReport | None:
    from app.services.cluster_service import get_clusters
    clusters = await get_clusters(days=30)
    cluster = next((c for c in clusters if c["cluster_id"] == cluster_id), None)
    if not cluster:
        return None

    articles = cluster.get("articles", [])
    all_titles = " ".join(a.get("title", "") for a in articles)
    iocs = IOCExtractor.extract(all_titles)
    iocs.pop("CVEs", [])

    references = [a["url"] for a in articles if a.get("url")][:20]
    sources = cluster.get("sources", [])

    return CTIReport(
        title=cluster.get("cluster_name", cluster_id),
        summary=f"{cluster.get('article_count', 0)} articles | {len(sources)} sources | {cluster.get('confidence', '')}",
        ttps=_extract_ttps(all_titles),
        iocs=iocs,
        targets=sources,
        references=references,
    )


async def build_ransomware_report(group_name: str) -> CTIReport | None:
    col = get_database()["ransomware_victims"]
    docs = await col.find(
        {"group_name": {"$regex": f"^{re.escape(group_name)}$", "$options": "i"}},
        {"country": 1, "industry": 1, "victim_name": 1, "published": 1},
    ).sort("published", -1).limit(100).to_list(100)

    if not docs:
        return None

    industries = sorted({d["industry"] for d in docs if d.get("industry")})
    countries = sorted({d["country"] for d in docs if d.get("country")})
    victims = [d["victim_name"] for d in docs if d.get("victim_name")][:20]

    targets = industries + countries

    malware_node = [{"name": f"{group_name} toolset", "type": "ransomware", "note": ""}]

    return CTIReport(
        title=f"Ransomware: {group_name}",
        threat_actor=group_name,
        summary=f"{len(docs)} victims | {len(industries)} industries | {len(countries)} countries",
        malware=malware_node,
        targets=targets,
        iocs={"Victims": victims} if victims else {},
    )
