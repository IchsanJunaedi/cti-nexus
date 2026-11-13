"""
confidence_service.py — Compute a 0–100 confidence score for an article.

Score components:
  - Source reliability (Admiralty A–F → 0–100)
  - Source credibility (Admiralty 1–6 → 0–100)
  - TTP richness bonus (up to 20 pts)
  - Threat Actor match bonus (up to 10 pts)

Final = clamp( (reliability + credibility) / 2 + ttp_bonus + ta_bonus, 0, 100 )
"""

from app.config import SOURCE_SCORES_COLLECTION, CLUSTERS_COLLECTION
from app.database import get_database
from app.database import get_ta_database
import asyncio
from datetime import datetime, timedelta, timezone

_RELIABILITY_SCORE = {"A": 100, "B": 80, "C": 60, "D": 40, "E": 20, "F": 50}
_CREDIBILITY_SCORE = {"1": 100, "2": 80, "3": 60, "4": 40, "5": 20, "6": 50}


def _reliability_to_score(grade: str) -> int:
    return _RELIABILITY_SCORE.get(grade.upper(), 50)


def _credibility_to_score(code: str) -> int:
    return _CREDIBILITY_SCORE.get(str(code), 50)


def compute_score(
    reliability_grade: str | None,
    credibility_code: str | None,
    ttp_count: int,
    ta_count: int,
) -> int:
    rel = _reliability_to_score(reliability_grade) if reliability_grade else 50
    cred = _credibility_to_score(credibility_code) if credibility_code else 50
    base = (rel + cred) / 2
    ttp_bonus = min(ttp_count * 5, 20)
    ta_bonus = min(ta_count * 10, 10)
    return min(100, max(0, round(base + ttp_bonus + ta_bonus)))


async def _get_source_rating(source_name: str) -> dict | None:
    col = get_ta_database()[SOURCE_SCORES_COLLECTION]
    return await col.find_one(
        {"source_name": {"$regex": f"^{source_name}$", "$options": "i"}}
    )


async def compute_article_confidence(article: dict) -> int:
    source = article.get("source", "")
    rating = await _get_source_rating(source) if source else None

    reliability_grade = rating.get("reliability_grade") if rating else None
    credibility_code = rating.get("credibility_code") if rating else None
    ttp_count = len(article.get("ttps", []))
    ta_count = len(article.get("threat_actors", []))

    return compute_score(reliability_grade, credibility_code, ttp_count, ta_count)


async def store_article_confidence(article_id: str, score: int) -> bool:
    from bson import ObjectId
    from app.config import COLLECTION_NAME
    col = get_database()[COLLECTION_NAME]
    result = await col.update_one(
        {"_id": ObjectId(article_id)},
        {"$set": {"confidence_score": score}},
    )
    return result.matched_count > 0


async def compute_and_store(article_id: str) -> int | None:
    from bson import ObjectId
    from app.config import COLLECTION_NAME
    col = get_database()[COLLECTION_NAME]
    doc = await col.find_one({"_id": ObjectId(article_id)})
    if doc is None:
        return None
    score = await compute_article_confidence(doc)
    await col.update_one({"_id": doc["_id"]}, {"$set": {"confidence_score": score}})
    return score


_IOC_HALF_LIFE: dict[str, float] = {
    "ip": 30.0,
    "domain": 60.0,
    "url": 30.0,
    "url_with_path": 30.0,
    "email": 30.0,
    "sha256": 90.0,
    "sha1": 90.0,
    "md5": 90.0,
    "cve": 90.0,
}


def _enrichment_signal(ioc: dict) -> dict:
    counts = {"malicious": 0, "suspicious": 0, "clean": 0}
    providers = (ioc.get("enrichment") or {}).get("providers") or []
    for p in providers:
        v = p.get("verdict", "").lower()
        if v in counts:
            counts[v] += 1
    return counts


def compute_ioc_confidence(ioc_doc: dict, now: datetime) -> int:
    last_seen_str = ioc_doc.get("last_seen", "")
    try:
        last_seen = datetime.strptime(last_seen_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        last_seen = now

    age_days = max((now - last_seen).total_seconds() / 86400, 0)

    base = 50

    recency_bonus = 30 if age_days <= 7 else 0

    sources = ioc_doc.get("sources") or ioc_doc.get("source_article_ids") or []
    source_bonus = min(len(sources) * 10, 30)

    tp = ioc_doc.get("tp_count", 0)
    fp = ioc_doc.get("fp_count", 0)
    verdict_bonus = 20 * tp / (tp + fp + 1)

    raw = base + recency_bonus + source_bonus + verdict_bonus

    sig = _enrichment_signal(ioc_doc)
    if sig["malicious"] > 0:
        raw += 25
    elif sig["suspicious"] > 0:
        raw += 10
    elif sig["clean"] > 0:
        raw -= 20

    ioc_type = ioc_doc.get("type", "ip")
    half_life = _IOC_HALF_LIFE.get(ioc_type, 30.0)
    decayed = raw * (0.5 ** (age_days / half_life))

    # Malicious infra still ages but slower: after decay, floor at 60 when a live
    # malicious verdict exists so aged-but-confirmed-bad IOCs remain actionable.
    if sig["malicious"] > 0:
        decayed = max(decayed, 60)

    return max(0, min(100, int(round(decayed))))


_ACTIONABILITY_LABELS = [
    (75, "block_now"),
    (50, "investigate"),
    (25, "monitor"),
    (0,  "archive"),
]

_BLOCK_HASH_TYPES = {"sha256", "sha1", "md5"}
_BLOCK_NET_TYPES  = {"ip", "domain"}


def _recommended_action(label: str, ioc_type: str) -> str:
    if label == "block_now":
        if ioc_type in _BLOCK_HASH_TYPES:
            return "Add to EDR blocklist"
        if ioc_type in _BLOCK_NET_TYPES:
            return "Add to firewall blocklist immediately"
        return "Add to firewall blocklist immediately"
    if label == "investigate":
        return "Verify in environment, check for matches in last 30 days"
    if label == "monitor":
        return "Add to watchlist, no immediate action"
    return "Low priority, aging indicator"


async def compute_ioc_actionability(ioc: dict, now: datetime) -> dict:
    last_seen_str = ioc.get("last_seen", "")
    try:
        last_seen = datetime.strptime(last_seen_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        last_seen = now
    age_days = max((now - last_seen).total_seconds() / 86400, 0)

    if age_days <= 1:
        recency = 100
    elif age_days <= 3:
        recency = 80
    elif age_days <= 7:
        recency = 60
    elif age_days <= 30:
        recency = 30
    else:
        recency = 0

    doc_id = None
    for s in ioc.get("sources", []):
        if s.get("doc_id"):
            doc_id = s["doc_id"]
            break

    campaign_score = 0
    if doc_id and CLUSTERS_COLLECTION:
        try:
            cutoff = (now.date() - timedelta(days=7)).strftime("%Y-%m-%d")
            col = get_database()[CLUSTERS_COLLECTION]
            hit = await col.find_one(
                {"member_article_ids": doc_id, "last_seen": {"$gte": cutoff}},
                {"_id": 1},
            )
            if hit:
                campaign_score = 100
        except Exception:
            pass

    seen_count = ioc.get("seen_count", 1)
    if seen_count >= 5:
        corroboration = 100
    elif seen_count >= 3:
        corroboration = 70
    elif seen_count >= 2:
        corroboration = 40
    else:
        corroboration = 10

    confidence = ioc.get("confidence_score", 50) or 50

    score = round(
        recency       * 0.40
        + campaign_score * 0.25
        + confidence  * 0.20
        + corroboration * 0.15
    )
    score = max(0, min(100, score))

    label = "archive"
    for threshold, lbl in _ACTIONABILITY_LABELS:
        if score >= threshold:
            label = lbl
            break

    sig = _enrichment_signal(ioc)
    if sig["malicious"] >= 2:
        label = "block_now"
    elif sig["malicious"] == 1 and label in ("monitor", "archive"):
        label = "investigate"

    # Liveness gate: don't recommend blocking dead infra, and route sinkholed
    # infra to archive (it's already in a defender's hands).
    liveness = ioc.get("liveness")
    if liveness == "dead" and label == "block_now":
        label = "investigate"
    elif liveness == "sinkholed":
        label = "archive"

    recommended_action = _recommended_action(label, ioc.get("type", ""))
    if liveness == "sinkholed":
        recommended_action = "Infrastructure sinkholed by a third party — no action needed, archive for attribution/history"
    elif liveness == "dead" and label == "investigate":
        recommended_action += " (infrastructure currently unresponsive — re-verify before blocking)"

    return {
        "actionability_score": score,
        "actionability_label": label,
        "recommended_action":  recommended_action,
    }


async def recompute_all_confidence(batch_size: int = 500) -> dict:
    from app.config import COLLECTION_NAME
    col = get_database()[COLLECTION_NAME]

    # Load all source ratings into a dict for fast lookup
    sr_col = get_ta_database()[SOURCE_SCORES_COLLECTION]
    ratings_raw = await sr_col.find({}).to_list(5000)
    ratings: dict[str, dict] = {r["source_name"].lower(): r for r in ratings_raw}

    updated = 0
    cursor = col.find({}, {"source": 1, "ttps": 1, "threat_actors": 1})
    async for doc in cursor:
        source = (doc.get("source") or "").lower()
        rating = ratings.get(source)
        score = compute_score(
            reliability_grade=rating.get("reliability_grade") if rating else None,
            credibility_code=rating.get("credibility_code") if rating else None,
            ttp_count=len(doc.get("ttps", [])),
            ta_count=len(doc.get("threat_actors", [])),
        )
        await col.update_one({"_id": doc["_id"]}, {"$set": {"confidence_score": score}})
        updated += 1

    return {"updated": updated}
