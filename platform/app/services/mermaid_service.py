import re
from collections import Counter
from datetime import datetime, timezone
from bson import ObjectId

from app.config import (
    MINDMAPS_COLLECTION, PIR_COLLECTION, COLLECTION_NAME,
    TA_GROUPS_COLLECTION, TA_PROFILES_COLLECTION,
)
from app.database import get_database, get_ta_database

TECHNIQUE_RE = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')


def _col():
    return get_database()[MINDMAPS_COLLECTION]


# ── Syntax helpers ────────────────────────────────────────────────────────────

def _esc(text: str, limit: int = 80) -> str:
    text = str(text or '').strip()
    for ch in '()[]{}"\n\r\t`#;':
        text = text.replace(ch, ' ')
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:limit]


def _ind(level: int) -> str:
    return '    ' * level


def _node(level: int, text: str, limit: int = 80) -> str:
    t = _esc(text, limit)
    return f'{_ind(level)}{t}\n' if t else ''


def _branch(level: int, label: str, items: list, limit: int = 60) -> str:
    if not items:
        return ''
    out = _node(level, label)
    for item in items[:10]:
        out += _node(level + 1, str(item), limit)
    return out


def build_syntax(root_title: str, branches: list[str]) -> str:
    body = ''.join(b for b in branches if b)
    return f'mindmap\n{_ind(1)}root(({_esc(root_title, 60)}))\n{body}'


# ── Cache helpers ─────────────────────────────────────────────────────────────

async def get_cached_mindmap(feature_type: str, doc_id: str) -> dict | None:
    return await _col().find_one(
        {"feature_type": feature_type, "doc_id": doc_id},
        {"_id": 0},
    )


async def save_mindmap(feature_type: str, doc_id: str, title: str, syntax: str) -> dict:
    doc = {
        "feature_type": feature_type,
        "doc_id": doc_id,
        "title": title,
        "mermaid_syntax": syntax,
        "custom_syntax": None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    await _col().update_one(
        {"feature_type": feature_type, "doc_id": doc_id},
        {"$set": doc},
        upsert=True,
    )
    return doc


async def save_custom_syntax(feature_type: str, doc_id: str, custom_syntax: str) -> dict | None:
    await _col().update_one(
        {"feature_type": feature_type, "doc_id": doc_id},
        {"$set": {
            "custom_syntax": custom_syntax,
            "edited_at": datetime.now(timezone.utc).isoformat(),
        }},
    )
    return await get_cached_mindmap(feature_type, doc_id)


async def get_or_generate(feature_type: str, doc_id: str, build_fn) -> dict | None:
    cached = await get_cached_mindmap(feature_type, doc_id)
    if cached and cached.get("mermaid_syntax"):
        return cached
    result = await build_fn()
    if result is None:
        return None
    title, syntax = result
    return await save_mindmap(feature_type, doc_id, title, syntax)


def get_display_syntax(doc: dict) -> str:
    return doc.get("custom_syntax") or doc.get("mermaid_syntax") or ""


# ── Feature builders ──────────────────────────────────────────────────────────

def _extract_ttps(text: str) -> list[str]:
    return sorted(set(TECHNIQUE_RE.findall(text)))[:10]


async def build_newsletter_mindmap(doc_id: str):
    doc = await get_database()["newsletters"].find_one({"_id": ObjectId(doc_id)})
    if not doc:
        return None

    title = f"Newsletter Week {doc.get('week','?')}/{doc.get('year','?')}"
    sections = doc.get("sections", {})
    section_meta = [
        ("highlight",   "Highlights"),
        ("apac",        "APAC"),
        ("global_news", "Global News"),
        ("indonesia",   "Indonesia"),
    ]
    branches = []
    for key, label in section_meta:
        raw = sections.get(key)
        articles = [raw] if isinstance(raw, dict) and raw else (raw or [])
        if not articles:
            continue
        branches.append(_node(2, f"{label} ({len(articles)})"))
        for a in articles[:8]:
            branches.append(_node(3, a.get("title", "")[:60]))

    return (title, build_syntax(title, branches))


async def build_threat_actor_mindmap(doc_id: str):
    ta_db = get_ta_database()
    doc = None
    try:
        doc = await ta_db[TA_GROUPS_COLLECTION].find_one({"_id": ObjectId(doc_id)})
    except Exception:
        pass
    if not doc:
        doc = await ta_db[TA_GROUPS_COLLECTION].find_one(
            {"name": {"$regex": f"^{re.escape(doc_id)}$", "$options": "i"}}
        )
    if not doc:
        return None

    actor_name = doc.get("name", doc_id)
    profile = None
    if TA_PROFILES_COLLECTION:
        profile = await ta_db[TA_PROFILES_COLLECTION].find_one(
            {"_actor_name": {"$regex": f"^{re.escape(actor_name)}$", "$options": "i"}},
            {"_id": 0},
        )

    branches = []
    if profile:
        identity = profile.get("identity", {})
        id_items = []
        if identity.get("actor_type"):
            id_items.append(f"Type: {identity['actor_type']}")
        if identity.get("sponsoring_nation"):
            id_items.append(f"Nation: {identity['sponsoring_nation']}")
        if identity.get("active_status"):
            id_items.append(f"Status: {identity['active_status']}")
        id_items.extend(identity.get("aliases", [])[:3])
        branches.append(_branch(2, "Identity", id_items))

        mot = profile.get("motivation", {})
        mot_items = [m for m in [mot.get("primary_motivation")] + mot.get("secondary_motivations", [])[:2] if m]
        branches.append(_branch(2, "Motivation", mot_items))

        cap = profile.get("capability_assessment", {})
        cap_items = []
        if cap.get("sophistication_level"):
            cap_items.append(f"Sophistication: {cap['sophistication_level']}")
        for m in cap.get("known_malware", [])[:5]:
            name = m.get("name") if isinstance(m, dict) else m
            if name:
                cap_items.append(f"Malware: {name}")
        for t in cap.get("known_tools", [])[:3]:
            cap_items.append(f"Tool: {t}")
        branches.append(_branch(2, "Capabilities", cap_items))

        tgt = profile.get("targeting_profile", {})
        tgt_items = tgt.get("targeted_sectors", [])[:5] + tgt.get("targeted_geographies", [])[:4]
        branches.append(_branch(2, "Targets", tgt_items))

        inf = profile.get("infrastructure", {})
        inf_items = inf.get("c2_patterns", [])[:3] + inf.get("hosting_preferences", [])[:2]
        branches.append(_branch(2, "Infrastructure", inf_items))

    return (f"Threat Actor: {actor_name}", build_syntax(actor_name, branches))


async def build_cve_mindmap_by_id(cve_id: str):
    doc = await get_database()["cve_tracker"].find_one({"cve_id": cve_id})
    if not doc:
        return None
    return _build_cve_from_doc(doc)


async def build_cve_mindmap(doc_id: str):
    try:
        doc = await get_database()["cve_tracker"].find_one({"_id": ObjectId(doc_id)})
    except Exception:
        doc = await get_database()["cve_tracker"].find_one({"cve_id": doc_id})
    if not doc:
        return None
    return _build_cve_from_doc(doc)


def _build_cve_from_doc(doc: dict):
    cve_id = doc.get("cve_id", str(doc.get("_id", "")))
    summary = doc.get("summary", "")
    branches = []

    overview = []
    if doc.get("cve_severity"):
        overview.append(f"Severity: {doc['cve_severity']} {doc.get('cve_score','')}")
    if (doc.get("published") or "")[:10]:
        overview.append(f"Published: {doc['published'][:10]}")
    if doc.get("tech"):
        overview.append(f"Tech: {doc['tech']}")
    if doc.get("cisa_kev"):
        overview.append("CISA KEV — Exploited in Wild")
    if doc.get("poc_available"):
        overview.append("POC Available")
    branches.append(_branch(2, "Overview", overview))

    aff_items = []
    for entry in (doc.get("affected") or [])[:5]:
        for prod, vers in entry.items():
            for v in (vers or [])[:2]:
                aff_items.append(f"{prod}: {v}")
    branches.append(_branch(2, "Affected", aff_items))

    ttps = _extract_ttps(f"{summary} {doc.get('cisa_kev_description','')}")
    branches.append(_branch(2, "ATT&CK TTPs", ttps))

    poc_items = [p.get("url", "")[:60] for p in (doc.get("pocs") or [])[:5] if p.get("url")]
    branches.append(_branch(2, "POC Exploits", poc_items))

    solutions = doc.get("solutions", "") or ""
    if solutions.strip() and solutions.strip() != "No solution yet":
        branches.append(_branch(2, "Solution", [solutions[:80]]))

    return (cve_id, build_syntax(cve_id, branches))


async def build_pir_mindmap(doc_id: str):
    col = get_database()[PIR_COLLECTION]
    doc = await col.find_one({"_id": ObjectId(doc_id)})
    if not doc:
        return None

    from app.services.pir_service import get_pir_articles
    result = await get_pir_articles(doc_id, page=1, page_size=30)
    articles = result[0] if result else []

    all_titles = " ".join(a.get("title", "") for a in articles)
    threat_actors = sorted({ta for a in articles for ta in a.get("threat_actors", []) if ta})
    ttps = _extract_ttps(all_titles)

    criteria = doc.get("criteria", {})
    branches = []
    branches.append(_branch(2, "Threat Actors", threat_actors[:8]))
    branches.append(_branch(2, "Industries", criteria.get("industries", [])[:6]))
    branches.append(_branch(2, "Countries", criteria.get("countries", [])[:6]))
    branches.append(_branch(2, "Keywords", criteria.get("keywords", [])[:6]))
    branches.append(_branch(2, "TTPs", criteria.get("ttps", []) + ttps))
    branches.append(_branch(2, "Coverage", [f"{len(articles)} matching articles"]))

    title = doc.get("title", doc_id)
    return (title, build_syntax(title, branches))


async def build_cluster_mindmap(cluster_id: str):
    from app.services.cluster_service import get_clusters
    clusters = await get_clusters(days=30)
    cluster = next((c for c in clusters if c["cluster_id"] == cluster_id), None)
    if not cluster:
        return None

    name = cluster.get("cluster_name", cluster_id)
    branches = []
    branches.append(_branch(2, "Adversary", cluster.get("dominant_tas", [])[:5]))
    branches.append(_branch(2, "Capability", cluster.get("attack_techniques", [])[:8]))

    ioc_vals = [f"{i['type']}: {i['value']}"[:50] for i in cluster.get("iocs", [])[:8]]
    branches.append(_branch(2, "Infrastructure", ioc_vals))

    branches.append(_branch(2, "Victim Industries", cluster.get("dominant_industries", [])[:5]))
    branches.append(_branch(2, "Victim Countries", cluster.get("dominant_countries", [])[:5]))
    branches.append(_branch(2, "CVEs", cluster.get("cve_ids", [])[:6]))
    branches.append(_branch(2, "Stats", [
        f"{cluster.get('article_count', 0)} articles",
        f"{cluster.get('source_count', 0)} sources",
        f"First: {cluster.get('first_date', '')}",
        f"Last: {cluster.get('last_date', '')}",
    ]))

    return (name, build_syntax(name, branches))


async def build_ransomware_mindmap(group_name: str):
    col = get_database()["ransomware_victims"]
    docs = await col.find(
        {"group_name": {"$regex": f"^{re.escape(group_name)}$", "$options": "i"}},
        {"country": 1, "industry": 1, "victim_name": 1, "published": 1},
    ).sort("published", -1).limit(100).to_list(100)

    if not docs:
        return None

    industries = Counter(d["industry"] for d in docs if d.get("industry")).most_common(10)
    countries = Counter(d["country"] for d in docs if d.get("country")).most_common(8)
    victims = [d["victim_name"] for d in docs if d.get("victim_name")][:12]

    branches = []
    branches.append(_branch(2, f"Victims {len(docs)}", victims[:10]))
    branches.append(_branch(2, "Industries", [f"{ind} ({cnt})" for ind, cnt in industries]))
    branches.append(_branch(2, "Countries", [f"{ctr} ({cnt})" for ctr, cnt in countries]))

    title = f"Ransomware: {group_name}"
    return (title, build_syntax(group_name, branches))


_BUILDERS = {
    "newsletter":   build_newsletter_mindmap,
    "threat_actor": build_threat_actor_mindmap,
    "cve":          build_cve_mindmap,
    "pir":          build_pir_mindmap,
    "cluster":      build_cluster_mindmap,
    "ransomware":   build_ransomware_mindmap,
}
