import asyncio
import hashlib
import re
import time
from collections import Counter
from datetime import datetime, timedelta

import numpy as np
from pymongo.operations import UpdateOne
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.database import get_database
from app.database import get_ta_database
from app.config import COLLECTION_NAME, TA_GROUPS_COLLECTION, SOURCE_SCORES_COLLECTION, CLUSTERS_COLLECTION, PIR_COLLECTION
from app.services.campaign_scoring_service import compute_campaign_severity
from app.services.killchain_service import analyze_kill_chain
from app.services.cve_priority_service import prioritize_campaign_cves
from app.services.campaign_link_service import compute_campaign_links
from app.services.diamond_model_service import build_diamond_models

_STOP_WORDS = frozenset({
    'the','a','an','is','in','on','at','to','for','of','and','or','with',
    'by','from','as','its','it','was','are','were','has','have','had',
    'be','been','being','their','they','this','that','these','those',
    'after','about','over','into','out','up','down','via','more','how',
    'what','when','where','who','why','which','says','say','said','using',
    'used','use','can','will','now','also','just','but','not','all','our',
    'your','than','amid','inside','across','against','between','per','vs',
    'new','top','get','got','one','two','three','first','last','next',
})

_LOWERCASE_INNER = frozenset({'and','or','of','the','in','on','at','by','for','vs','a','an'})

_MONTHS = frozenset({
    'january','february','march','april','may','june','july',
    'august','september','october','november','december',
})

_CACHE: dict = {}
_CACHE_TTL = 900
_clusters_index_ensured = False


# ── Tokenizers ────────────────────────────────────────────────────────────────

def _tokenize_for_dedup(title: str) -> frozenset:
    tokens = re.sub(r'[^\w\s]', ' ', title.lower()).split()
    return frozenset(t for t in tokens if t not in _STOP_WORDS and len(t) > 3)


def _tfidf_tokenize(text: str) -> list[str]:
    cve_tokens = [m.lower() for m in re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)]
    text_no_cve = re.sub(r'CVE-\d{4}-\d+', ' ', text, flags=re.IGNORECASE)
    words = re.sub(r'[^\w\s]', ' ', text_no_cve.lower()).split()
    filtered = [w for w in words if w not in _STOP_WORDS and len(w) > 3]
    return cve_tokens + filtered


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ── Named-entity helpers ──────────────────────────────────────────────────────

def _is_named_entity_token(tok: str, title: str) -> bool:
    if re.match(r'^cve-\d{4}-\d+$', tok):
        return True
    if re.match(r'^20\d{2}$', tok):
        return True
    if tok in _MONTHS:
        return True
    for word in title.split():
        w = re.sub(r'[^\w]', '', word)
        if w.lower() == tok and len(w) > 2 and w[0].isupper():
            return True
    return False


# ── External DB lookups ───────────────────────────────────────────────────────

async def _fetch_ta_names() -> list[str]:
    try:
        col = get_ta_database()[TA_GROUPS_COLLECTION]
        cursor = col.find({}, {"name": 1, "_id": 0})
        groups = await cursor.to_list(length=2000)
        return [g["name"].lower() for g in groups if g.get("name")]
    except Exception:
        return []


async def _fetch_low_reliability_sources() -> set[str]:
    try:
        col = get_ta_database()[SOURCE_SCORES_COLLECTION]
        cursor = col.find(
            {"reliability_grade": {"$in": ["D", "E", "F"]}},
            {"source_name": 1, "_id": 0},
        )
        docs = await cursor.to_list(length=1000)
        return {d["source_name"].lower() for d in docs if d.get("source_name")}
    except Exception:
        return set()


def _article_ta_names(title: str, ta_names: list[str]) -> frozenset:
    title_lower = title.lower()
    return frozenset(name for name in ta_names if name in title_lower)


# ── Cluster naming ────────────────────────────────────────────────────────────

def _confidence_label(source_count: int) -> str:
    if source_count >= 5:
        return "high"
    if source_count >= 3:
        return "medium"
    return "low"


def _cluster_id(cluster_name: str) -> str:
    normalized = re.sub(r'\s+', ' ', cluster_name.strip().lower())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _derive_cluster_name(articles: list[dict]) -> str:
    """
    Extract a short cluster name from article titles.
    Named entities (CVEs, years, proper nouns) qualify at a lower frequency
    threshold and score higher in run selection.
    """
    titles = [a.get("title", "").strip() for a in articles if a.get("title")]
    if not titles:
        return "Unknown Cluster"
    if len(titles) == 1:
        return titles[0]

    n = len(titles)
    base_threshold = max(2, n * 0.5)
    entity_threshold = max(2, n * 0.3)

    freq: Counter = Counter()
    for title in titles:
        toks: set[str] = set(re.sub(r'[^\w\s]', ' ', title.lower()).split())
        for cve in re.findall(r'CVE-\d{4}-\d+', title, re.IGNORECASE):
            toks.add(cve.lower())
        for tok in toks:
            freq[tok] += 1

    core: set[str] = set()
    entity_tokens: set[str] = set()
    for tok, cnt in freq.items():
        if tok in _STOP_WORDS or len(tok) <= 2:
            continue
        is_ent = any(_is_named_entity_token(tok, t) for t in titles)
        if is_ent and cnt >= entity_threshold:
            core.add(tok)
            entity_tokens.add(tok)
        elif cnt >= base_threshold:
            core.add(tok)

    if not core:
        return titles[0]

    best_words: list[str] = []
    best_score = 0

    for title in titles:
        words = title.split()
        pairs: list[tuple[str, str]] = []
        for w in words:
            if re.match(r'CVE-\d{4}-\d+', w, re.IGNORECASE):
                pairs.append((w, w.lower()))
            else:
                pairs.append((re.sub(r'^[^\w]+|[^\w]+$', '', w),
                               re.sub(r'[^\w]', '', w.lower())))

        run: list[str] = []
        run_score = 0

        for display, lk in pairs:
            if lk in core:
                run.append(display)
                run_score += 3 if lk in entity_tokens else 1
            elif lk in _STOP_WORDS and run:
                run.append(display)
            else:
                while run and re.sub(r'[^\w]', '', run[-1].lower()) in _STOP_WORDS:
                    run.pop()
                if run and run_score > best_score:
                    best_score = run_score
                    best_words = run[:]
                run = []
                run_score = 0

        while run and re.sub(r'[^\w]', '', run[-1].lower()) in _STOP_WORDS:
            run.pop()
        if run and run_score > best_score:
            best_score = run_score
            best_words = run[:]

    if not best_words:
        return titles[0]

    cased = []
    for i, w in enumerate(best_words):
        lw = re.sub(r'[^\w]', '', w.lower())
        if i == 0 or lw not in _LOWERCASE_INNER:
            cased.append(w[0].upper() + w[1:] if w else w)
        else:
            cased.append(w.lower())

    return ' '.join(cased)


# ── Cluster persistence ───────────────────────────────────────────────────────

async def _ensure_clusters_index() -> None:
    global _clusters_index_ensured
    if not _clusters_index_ensured:
        col = get_database()[CLUSTERS_COLLECTION]
        await col.create_index("cluster_id", unique=True, background=True)
        _clusters_index_ensured = True


async def _persist_and_tag(clusters: list[dict]) -> None:
    """Upsert cluster records and set re_emerged on each cluster dict."""
    await _ensure_clusters_index()
    col = get_database()[CLUSTERS_COLLECTION]
    today = datetime.utcnow().strftime("%Y-%m-%d")
    dormant_cutoff = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")

    ids = [c["cluster_id"] for c in clusters]
    existing: dict[str, dict] = {}
    async for rec in col.find({"cluster_id": {"$in": ids}}, {"cluster_id": 1, "last_seen": 1}):
        existing[rec["cluster_id"]] = rec

    re_emerged_ids: set[str] = set()
    ops: list[UpdateOne] = []

    for c in clusters:
        cid = c["cluster_id"]
        rec = existing.get(cid)
        if rec and rec.get("last_seen", "") < dormant_cutoff:
            re_emerged_ids.add(cid)

        new_iocs = c.get("new_iocs", [])
        new_tas = c.get("new_tas", [])
        daily_entry = {
            "date": today,
            "count": c["article_count"],
            "new_iocs": len(new_iocs) if isinstance(new_iocs, list) else 0,
            "new_tas": len(new_tas) if isinstance(new_tas, list) else 0,
        }

        ops.append(UpdateOne(
            {"cluster_id": cid},
            {
                "$set": {
                    "cluster_name": c["cluster_name"],
                    "last_seen": today,
                    "last_count": c["article_count"],
                },
                "$setOnInsert": {"first_seen": today},
                "$max": {"peak_count": c["article_count"]},
                "$push": {"daily_counts": {"$each": [daily_entry], "$slice": -90}},
            },
            upsert=True,
        ))

    if ops:
        await col.bulk_write(ops)

    for c in clusters:
        c["re_emerged"] = c["cluster_id"] in re_emerged_ids


# ── Public API ────────────────────────────────────────────────────────────────

async def get_clusters(
    days: int = 30,
    threshold: float = 0.35,
    exclude_low_reliability: bool = False,
) -> list[dict]:
    cache_key = f"{days}|{threshold}|{exclude_low_reliability}"
    now = time.monotonic()
    if cache_key in _CACHE:
        data, ts = _CACHE[cache_key]
        if now - ts < _CACHE_TTL:
            return data

    result = await _compute_clusters(days, threshold, exclude_low_reliability)
    _CACHE[cache_key] = (result, now)
    return result


async def _compute_clusters(
    days: int,
    threshold: float,
    exclude_low_reliability: bool,
) -> list[dict]:
    col = get_database()[COLLECTION_NAME]
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

    cursor = col.find(
        {"posted_on": {"$gte": cutoff}},
        {"_id": 1, "title": 1, "url": 1, "source": 1, "posted_on": 1},
    ).sort("posted_on", -1).limit(1000)
    articles = await cursor.to_list(length=1000)

    # ── Pass 1: exact (title, date) dedup ────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for a in articles:
        key = (re.sub(r'\s+', ' ', a.get("title", "")).strip().lower(),
               a.get("posted_on", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(a)
    articles = deduped

    # ── Pass 2: fuzzy title dedup (Jaccard > 0.85, dates ≤ 2 days apart) ─
    def _parse_date(s: str) -> datetime | None:
        try:
            return datetime.strptime(s, "%Y-%m-%d")
        except (ValueError, TypeError):
            return None

    tok_cache = [_tokenize_for_dedup(a.get("title", "")) for a in articles]
    date_cache = [_parse_date(a.get("posted_on", "")) for a in articles]

    fuzzy_dupes: set[int] = set()
    for i in range(len(articles)):
        if i in fuzzy_dupes:
            continue
        di = date_cache[i]
        ti = tok_cache[i]
        for j in range(i + 1, len(articles)):
            if j in fuzzy_dupes:
                continue
            dj = date_cache[j]
            if di and dj and (di - dj).days > 2:
                break  # articles sorted date-DESC; remaining j are too old
            if _jaccard(ti, tok_cache[j]) > 0.85:
                fuzzy_dupes.add(j)

    articles = [a for idx, a in enumerate(articles) if idx not in fuzzy_dupes]

    if len(articles) < 2:
        return []

    # ── TF-IDF vectorization ──────────────────────────────────────────────
    titles = [a.get("title", "") for a in articles]
    vectorizer = TfidfVectorizer(tokenizer=_tfidf_tokenize, token_pattern=None, lowercase=False, min_df=1)
    try:
        tfidf_matrix = vectorizer.fit_transform(titles)
    except ValueError:
        return []

    # ── External lookups (run in parallel via gathered awaits) ────────────
    ta_names, low_rel_sources = await _gather_lookups(exclude_low_reliability)

    article_ta_sets = [_article_ta_names(a.get("title", ""), ta_names) for a in articles]

    # ── Greedy TF-IDF clustering with fixed-centroid logic ────────────────
    clusters: list[dict] = []

    for idx, (article, ta_set) in enumerate(zip(articles, article_ta_sets)):
        article_vec = tfidf_matrix[idx]
        is_low_rel = (
            exclude_low_reliability
            and article.get("source", "").lower() in low_rel_sources
        )

        best_cluster = None
        best_sim = -1.0
        ta_forced = False

        for cluster in clusters:
            ta_overlap = bool(ta_set and cluster["ta_names"] and ta_set & cluster["ta_names"])

            compare_vec = (
                cluster["sum_vec"] / cluster["count"]
                if cluster["count"] >= 3
                else cluster["centroid_vec"]
            )
            sim = float(cosine_similarity(article_vec, compare_vec)[0, 0])

            if ta_overlap:
                effective = max(sim, threshold + 0.01)
                if not ta_forced or effective > best_sim:
                    best_sim = effective
                    best_cluster = cluster
                    ta_forced = True
            elif not ta_forced and sim >= threshold and sim > best_sim:
                best_sim = sim
                best_cluster = cluster

        if best_cluster:
            best_cluster["articles"].append(article)
            best_cluster["sum_vec"] = best_cluster["sum_vec"] + article_vec
            best_cluster["count"] += 1
            best_cluster["ta_names"] |= ta_set
        elif not is_low_rel:
            clusters.append({
                "centroid_vec": article_vec,
                "sum_vec": article_vec.copy(),
                "count": 1,
                "ta_names": set(ta_set),
                "articles": [article],
            })

    # ── Build result ──────────────────────────────────────────────────────
    result = []
    for cluster in clusters:
        arts = cluster["articles"]
        if len(arts) < 2:
            continue
        sources = list({a["source"] for a in arts if a.get("source")})
        sorted_arts = sorted(arts, key=lambda x: x.get("posted_on", ""), reverse=True)
        dates = [a.get("posted_on", "") for a in sorted_arts if a.get("posted_on")]
        cname = _derive_cluster_name(sorted_arts)
        result.append({
            "cluster_id":    _cluster_id(cname),
            "cluster_name":  cname,
            "article_count": len(arts),
            "source_count":  len(sources),
            "sources":       sources,
            "confidence":    _confidence_label(len(sources)),
            "first_date":    dates[-1] if dates else "",
            "last_date":     dates[0]  if dates else "",
            "re_emerged":    False,     # populated by _persist_and_tag
            "articles": [
                {
                    "id":        str(a["_id"]),
                    "title":     a.get("title", ""),
                    "url":       a.get("url", ""),
                    "source":    a.get("source", ""),
                    "posted_on": a.get("posted_on", ""),
                }
                for a in sorted_arts
            ],
        })

    result.sort(key=lambda x: (x["source_count"], x["article_count"]), reverse=True)
    result = result[:100]

    await _persist_and_tag(result)

    return result


async def get_recent_campaigns(
    days: int = 7,
    client_id: str | None = None,
    min_size: int = 3,
) -> list[dict]:
    col = get_database()[COLLECTION_NAME]
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

    cursor = col.find(
        {"posted_on": {"$gte": cutoff}},
        {
            "_id": 1, "title": 1, "url": 1, "source": 1, "posted_on": 1,
            "threat_actors": 1, "impacted_industries": 1, "countries": 1,
            "ttps": 1, "cves": 1, "source_reliability": 1,
        },
    ).sort("posted_on", -1).limit(2000)
    articles = await cursor.to_list(length=2000)

    if len(articles) < 2:
        return []

    for a in articles:
        a["_id_str"] = str(a["_id"])

    titles = [a.get("title", "") for a in articles]
    vectorizer = TfidfVectorizer(tokenizer=_tfidf_tokenize, token_pattern=None, lowercase=False, min_df=1)
    try:
        tfidf_matrix = vectorizer.fit_transform(titles)
    except ValueError:
        return []

    n = len(articles)
    parent = list(range(n))

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(x: int, y: int) -> None:
        px, py = _find(x), _find(y)
        if px != py:
            parent[px] = py

    sim_matrix = cosine_similarity(tfidf_matrix)
    for i in range(n):
        for j in range(i + 1, n):
            if sim_matrix[i, j] >= 0.75:
                _union(i, j)

    groups: dict[int, list[int]] = {}
    for idx in range(n):
        root = _find(idx)
        groups.setdefault(root, []).append(idx)

    member_ids_all: list[str] = []
    for positions in groups.values():
        if len(positions) >= min_size:
            for p in positions:
                member_ids_all.append(articles[p]["_id_str"])

    ioc_col = get_database()["iocs"]
    from bson import ObjectId as _ObjId
    valid_oids = []
    for mid in member_ids_all:
        try:
            valid_oids.append(_ObjId(mid))
        except Exception:
            pass

    ioc_map: dict[str, list[dict]] = {}
    if valid_oids:
        async for ioc in ioc_col.find(
            {"sources.doc_id": {"$in": [str(o) for o in valid_oids]}},
            {"_id": 1, "type": 1, "value": 1, "sources": 1},
        ):
            for s in ioc.get("sources", []):
                did = s.get("doc_id")
                if did:
                    ioc_map.setdefault(did, []).append({
                        "id": str(ioc["_id"]),
                        "type": ioc.get("type", ""),
                        "value": ioc.get("value", ""),
                    })

    results = []
    members_by_cluster: dict[str, list[dict]] = {}
    for root, positions in groups.items():
        if len(positions) < min_size:
            continue

        members = [articles[p] for p in positions]
        sorted_members = sorted(members, key=lambda x: x.get("posted_on", ""), reverse=True)

        dates = [a.get("posted_on", "") for a in sorted_members if a.get("posted_on")]
        first_seen = dates[-1] if dates else ""
        last_seen  = dates[0]  if dates else ""

        # ── Velocity metrics ──────────────────────────────────────────────
        _today = datetime.utcnow().date()
        _yesterday = _today - timedelta(days=1)
        _today_s = _today.strftime("%Y-%m-%d")
        _yesterday_s = _yesterday.strftime("%Y-%m-%d")

        def _parse_d(s: str):
            try:
                return datetime.strptime(s, "%Y-%m-%d").date()
            except (ValueError, TypeError):
                return None

        _first_dt = _parse_d(first_seen)
        _last_dt  = _parse_d(last_seen)
        days_active = (_last_dt - _first_dt).days if _first_dt and _last_dt else 0
        velocity_articles_per_day = len(members) / max(1, days_active)

        if velocity_articles_per_day > 3:
            velocity_label = "surging"
        elif velocity_articles_per_day > 1:
            velocity_label = "active"
        elif velocity_articles_per_day > 0.3:
            velocity_label = "moderate"
        else:
            velocity_label = "slow"

        _cutoff_3d = (_today - timedelta(days=3)).strftime("%Y-%m-%d")
        _recent_count = sum(1 for a in members if a.get("posted_on", "") >= _cutoff_3d)
        _prior_count  = len(members) - _recent_count
        _prior_days   = max(1, days_active - 3)
        _rate_recent  = _recent_count / 3.0
        _rate_prior   = _prior_count / _prior_days
        acceleration  = round(_rate_recent - _rate_prior, 4)
        velocity_alert = acceleration > 2.0

        _recent_aids: set[str] = {
            a["_id_str"] for a in members
            if a.get("posted_on", "") in (_today_s, _yesterday_s)
        }
        _new_iocs_set: set[str] = set()
        for _a in members:
            if _a["_id_str"] in _recent_aids:
                for _ioc in ioc_map.get(_a["_id_str"], []):
                    _new_iocs_set.add(f"{_ioc['type']}:{_ioc['value']}")
        new_iocs_24h = len(_new_iocs_set)

        summary_member = max(
            members,
            key=lambda a: _RELIABILITY_SCORE.get(
                (a.get("source_reliability") or "").upper(), 0
            ),
            default=members[0],
        )

        dominant_tas: list[str] = []
        ta_counter: Counter = Counter()
        dominant_industries: list[str] = []
        ind_counter: Counter = Counter()
        dominant_countries: list[str] = []
        ctr_counter: Counter = Counter()
        attack_techniques: list[str] = []
        tech_set: set[str] = set()
        cve_ids: list[str] = []
        cve_set: set[str] = set()
        member_article_ids: list[str] = []
        titles_list: list[str] = []
        iocs: list[dict] = []
        ioc_seen: set[str] = set()

        for a in members:
            aid = a["_id_str"]
            member_article_ids.append(aid)
            titles_list.append(a.get("title", ""))
            for ta in a.get("threat_actors", []):
                if ta:
                    ta_counter[ta] += 1
            for ind in a.get("impacted_industries", []):
                if ind:
                    ind_counter[ind] += 1
            for ctr in a.get("countries", []):
                if ctr:
                    ctr_counter[ctr] += 1
            for ttp in a.get("ttps", []):
                ttp_str = ttp.get("name", "") if isinstance(ttp, dict) else ttp
                if ttp_str and ttp_str not in tech_set:
                    tech_set.add(ttp_str)
                    attack_techniques.append(ttp_str)
            for cve in a.get("cves", []):
                if cve and cve not in cve_set:
                    cve_set.add(cve)
                    cve_ids.append(cve)
            for ioc in ioc_map.get(aid, []):
                key = f"{ioc['type']}:{ioc['value']}"
                if key not in ioc_seen:
                    ioc_seen.add(key)
                    iocs.append(ioc)

        dominant_tas = [ta for ta, _ in ta_counter.most_common(5)]
        dominant_industries = [ind for ind, _ in ind_counter.most_common(5)]
        dominant_countries = [ctr for ctr, _ in ctr_counter.most_common(5)]

        cluster_name = _derive_cluster_name(sorted_members)
        cid = _cluster_id(cluster_name)
        members_by_cluster[cid] = members

        results.append({
            "cluster_id":            cid,
            "cluster_name":          cluster_name,
            "size":                  len(members),
            "first_seen":            first_seen,
            "last_seen":             last_seen,
            "member_article_ids":    member_article_ids,
            "titles":                titles_list,
            "summary_title":         summary_member.get("title", ""),
            "dominant_tas":          dominant_tas,
            "dominant_industries":   dominant_industries,
            "dominant_countries":    dominant_countries,
            "attack_techniques":     attack_techniques[:20],
            "kill_chain":            analyze_kill_chain(attack_techniques),
            "iocs":                  iocs[:50],
            "cve_ids":               cve_ids[:20],
            "velocity_articles_per_day": round(velocity_articles_per_day, 2),
            "velocity_label":            velocity_label,
            "acceleration":              acceleration,
            "velocity_alert":            velocity_alert,
            "new_iocs_24h":              new_iocs_24h,
            "days_active":               days_active,
        })

    priority_results = await asyncio.gather(
        *[prioritize_campaign_cves(r["cve_ids"], r, client_id=client_id or "default") for r in results]
    )
    for r, prio in zip(results, priority_results):
        r["prioritized_cves"] = prio

    severity_results = await asyncio.gather(
        *[compute_campaign_severity(r, articles_raw=members_by_cluster.get(r["cluster_id"])) for r in results]
    )
    for r, sev in zip(results, severity_results):
        r.update(sev)

    results.sort(key=lambda x: x["severity_score"], reverse=True)
    await _match_pirs(results, client_id)

    await build_diamond_models(results)

    links = compute_campaign_links(results)
    _index: dict[str, list[dict]] = {}
    for lk in links:
        for own_id, peer_id, peer_name in [
            (lk["source_id"], lk["target_id"], lk["target_name"]),
            (lk["target_id"], lk["source_id"], lk["source_name"]),
        ]:
            _index.setdefault(own_id, []).append({
                "cluster_id":      peer_id,
                "cluster_name":    peer_name,
                "link_score":      lk["score"],
                "link_type":       lk["link_type"],
                "shared_elements": {
                    "tas":  lk["shared_tas"],
                    "ttps": lk["shared_ttps"],
                    "iocs": lk["shared_iocs"],
                },
            })
    for r in results:
        r["related_campaigns"] = sorted(
            _index.get(r["cluster_id"], []),
            key=lambda x: x["link_score"],
            reverse=True,
        )

    return results


_RELIABILITY_SCORE = {"A": 6, "B": 5, "C": 4, "D": 3, "E": 2, "F": 1}


async def _gather_lookups(exclude_low_reliability: bool) -> tuple[list[str], set[str]]:
    import asyncio
    ta_task = asyncio.create_task(_fetch_ta_names())
    lr_task = asyncio.create_task(
        _fetch_low_reliability_sources() if exclude_low_reliability
        else _empty_set()
    )
    ta_names = await ta_task
    low_rel = await lr_task
    return ta_names, low_rel


async def _empty_set() -> set:
    return set()


async def _match_pirs(clusters: list[dict], client_id: str | None) -> None:
    """Annotate each cluster dict with matched_pirs: [{id, title}]."""
    if not PIR_COLLECTION:
        for c in clusters:
            c["matched_pirs"] = []
        return

    col = get_database()[PIR_COLLECTION]
    cid = client_id or "default"
    if cid == "default":
        filt = {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    else:
        filt = {"client_id": cid}
    filt["status"] = "active"

    docs = await col.find(filt, {"_id": 1, "title": 1, "description": 1, "priority": 1, "status": 1, "criteria": 1}).to_list(500)

    for cluster in clusters:
        tas  = {t.lower() for t in cluster.get("dominant_tas", [])}
        inds = {i.lower() for i in cluster.get("dominant_industries", [])}
        ctrs = {c.lower() for c in cluster.get("dominant_countries", [])}

        matched: list[dict] = []
        for pir in docs:
            crit = pir.get("criteria", {})
            pir_tas  = {t.lower() for t in crit.get("threat_actors", [])}
            pir_inds = {i.lower() for i in crit.get("industries", [])}
            pir_ctrs = {c.lower() for c in crit.get("countries", [])}
            if (tas & pir_tas) or (inds & pir_inds) or (ctrs & pir_ctrs):
                matched.append({
                    "id":          str(pir["_id"]),
                    "title":       pir.get("title", ""),
                    "description": pir.get("description", ""),
                    "priority":    pir.get("priority", ""),
                    "status":      pir.get("status", ""),
                    "criteria":    pir.get("criteria", {}),
                })

        cluster["matched_pirs"] = matched
