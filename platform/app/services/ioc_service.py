import asyncio
import re
from bson import ObjectId
from datetime import datetime, timezone
from pymongo.operations import UpdateOne
from app.database import get_database, get_ta_database
from app.config import IOC_COLLECTION, COLLECTION_NAME, TA_WATCHLIST_COLLECTION
from app.services.confidence_service import compute_ioc_confidence, compute_ioc_actionability

_VALID_TYPES = {"ip", "domain", "url", "url_with_path", "email", "sha256", "sha1", "md5", "cve"}

_TYPE_MAP = {
    "ips": "ip",
    "domains": "domain",
    "urls": "url",
    "urls_with_path": "url_with_path",
    "emails": "email",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "cves": "cve",
}


def _col():
    return get_database()[IOC_COLLECTION]


async def upsert_ioc(
    ioc_type: str,
    value: str,
    source_url: str,
    source_name: str,
    feature_type: str,
    doc_id: str | None = None,
    context: str | None = None,
    client_id: str = "default",
) -> None:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    source_entry = {
        "url": source_url,
        "source_name": source_name,
        "feature_type": feature_type,
        "doc_id": doc_id,
        "first_seen": today,
        "context": context or "",
    }
    col = _col()
    now = datetime.now(timezone.utc)
    existing = await col.find_one({"type": ioc_type, "value": value})
    if existing:
        url_set = {s.get("url") for s in existing.get("sources", [])}
        if source_url not in url_set:
            updated = dict(existing)
            updated["sources"] = existing.get("sources", []) + [source_entry]
            updated["last_seen"] = today
            updated["seen_count"] = existing.get("seen_count", 1) + 1
            score = compute_ioc_confidence(updated, now)
            updated["confidence_score"] = score
            act = await compute_ioc_actionability(updated, now)
            await col.update_one(
                {"type": ioc_type, "value": value},
                {
                    "$push": {"sources": source_entry},
                    "$inc": {"seen_count": 1},
                    "$set": {
                        "last_seen": today,
                        "confidence_score": score,
                        "confidence_decayed_at": now,
                        **act,
                    },
                },
            )
    else:
        from app.services.fp_analytics_service import auto_suppress_check
        suppress = await auto_suppress_check(ioc_type, value, source_name)
        new_doc = {
            "type": ioc_type,
            "value": value,
            "sources": [source_entry],
            "first_seen": today,
            "last_seen": today,
            "seen_count": 1,
            "tags": [],
            "threat_actors": [],
            "tlp": "TLP:AMBER",
            "kill_chain_phase": None,
            "mitre_techniques": [],
            "tp_count": 0,
            "fp_count": 0,
            "feedback_log": [],
            "auto_suppressed": suppress["should_suppress"] and suppress["confidence"] > 0.8,
            "suppression_reason": suppress["reason"] if suppress["should_suppress"] and suppress["confidence"] > 0.8 else "",
        }
        score = compute_ioc_confidence(new_doc, now)
        new_doc["confidence_score"] = score
        new_doc["confidence_decayed_at"] = now
        act = await compute_ioc_actionability(new_doc, now)
        new_doc.update(act)
        await col.insert_one(new_doc)


async def persist_iocs_from_extraction(
    ioc_dict: dict,
    source_url: str,
    source_name: str,
    feature_type: str = "article",
    doc_id: str | None = None,
) -> int:
    """Persist IOCs from extract_iocs() output. Returns count of IOCs processed."""
    tasks = []
    for field_key, ioc_type in _TYPE_MAP.items():
        for value in ioc_dict.get(field_key, []):
            tasks.append(upsert_ioc(
                ioc_type=ioc_type,
                value=value,
                source_url=source_url,
                source_name=source_name,
                feature_type=feature_type,
                doc_id=doc_id,
            ))
    if tasks:
        sem = asyncio.Semaphore(10)
        async def _bounded(coro):
            async with sem:
                return await coro
        await asyncio.gather(*[_bounded(t) for t in tasks])
    return len(tasks)


_VALID_ACTIONABILITY = {"block_now", "investigate", "monitor", "archive"}
_VALID_VERDICTS = {"malicious", "suspicious", "clean", "unknown"}
_VALID_TLP = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}
_VALID_KILL_CHAIN = {
    "reconnaissance", "weaponization", "delivery", "exploitation",
    "installation", "command-and-control", "actions-on-objectives",
}


async def get_iocs(
    ioc_type: str | None = None,
    search: str | None = None,
    tags: list[str] | None = None,
    page: int = 1,
    page_size: int = 50,
    client_id: str = "default",
    sort_by: str | None = None,
    actionability: str | None = None,
    enrichment_verdict: str | None = None,
) -> tuple[list[dict], int]:
    col = _col()
    query: dict = {}
    if ioc_type and ioc_type in _VALID_TYPES:
        query["type"] = ioc_type
    if search:
        query["value"] = {"$regex": search, "$options": "i"}
    if tags:
        query["tags"] = {"$in": tags}
    if actionability:
        labels = [l.strip() for l in actionability.split(",") if l.strip() in _VALID_ACTIONABILITY]
        if labels:
            query["actionability_label"] = {"$in": labels}
    if enrichment_verdict and enrichment_verdict in _VALID_VERDICTS:
        query["enrichment.providers"] = {"$elemMatch": {"verdict": enrichment_verdict}}

    sort_field = "confidence_score" if sort_by == "confidence" else "last_seen"
    skip = (page - 1) * page_size
    cursor = col.find(query, {"sources": 0, "enrichment.providers.raw": 0}).sort(sort_field, -1).skip(skip).limit(page_size)
    docs, total = await asyncio.gather(cursor.to_list(page_size), col.count_documents(query))
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs, total


async def get_ioc_detail(ioc_type: str, value: str, client_id: str = "default") -> dict | None:
    doc = await _col().find_one({"type": ioc_type, "value": value})
    if not doc:
        return None
    doc["_id"] = str(doc["_id"])
    return doc


async def get_ioc_stats(client_id: str = "default") -> dict:
    col = _col()
    pipeline = [
        {"$group": {"_id": "$type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    by_type_raw, total = await asyncio.gather(
        col.aggregate(pipeline).to_list(20),
        col.count_documents({}),
    )
    return {
        "total": total,
        "by_type": [{"type": r["_id"], "count": r["count"]} for r in by_type_raw],
    }


async def tag_ioc_threat_actors(ioc_type: str, value: str, threat_actors: list[str]) -> bool:
    result = await _col().update_one(
        {"type": ioc_type, "value": value},
        {"$addToSet": {"threat_actors": {"$each": threat_actors}}},
    )
    return result.matched_count > 0


async def untag_ioc_threat_actor(ioc_type: str, value: str, actor: str) -> bool:
    result = await _col().update_one(
        {"type": ioc_type, "value": value},
        {"$pull": {"threat_actors": actor}},
    )
    return result.matched_count > 0


async def tag_ioc(ioc_type: str, value: str, tags: list[str], client_id: str = "default") -> bool:
    result = await _col().update_one(
        {"type": ioc_type, "value": value},
        {"$addToSet": {"tags": {"$each": tags}}},
    )
    return result.matched_count > 0


async def set_ioc_tlp(ioc_type: str, value: str, tlp: str) -> bool:
    if tlp not in _VALID_TLP:
        raise ValueError(f"Invalid TLP: {tlp}")
    result = await _col().update_one(
        {"type": ioc_type, "value": value},
        {"$set": {"tlp": tlp}},
    )
    return result.matched_count > 0


async def set_ioc_kill_chain(ioc_type: str, value: str, phase: str) -> bool:
    if phase not in _VALID_KILL_CHAIN:
        raise ValueError(f"Invalid kill chain phase: {phase}")
    result = await _col().update_one(
        {"type": ioc_type, "value": value},
        {"$set": {"kill_chain_phase": phase}},
    )
    return result.matched_count > 0


async def add_ioc_techniques(ioc_type: str, value: str, techniques: list[str]) -> bool:
    result = await _col().update_one(
        {"type": ioc_type, "value": value},
        {"$addToSet": {"mitre_techniques": {"$each": techniques}}},
    )
    return result.matched_count > 0


async def remove_ioc_technique(ioc_type: str, value: str, technique: str) -> bool:
    result = await _col().update_one(
        {"type": ioc_type, "value": value},
        {"$pull": {"mitre_techniques": technique}},
    )
    return result.matched_count > 0


async def delete_ioc(ioc_id: str) -> bool:
    try:
        oid = ObjectId(ioc_id)
    except Exception:
        return False
    result = await _col().delete_one({"_id": oid})
    return result.deleted_count > 0


async def bulk_delete_iocs(ioc_ids: list[str]) -> int:
    oids = []
    for ioc_id in ioc_ids:
        try:
            oids.append(ObjectId(ioc_id))
        except Exception:
            pass
    if not oids:
        return 0
    result = await _col().delete_many({"_id": {"$in": oids}})
    return result.deleted_count


async def submit_feedback(
    ioc_id: str,
    user_id: str,
    client_id: str,
    verdict: str,
    note: str | None,
) -> dict | None:
    from app.services.audit_service import write_audit
    col = _col()
    try:
        oid = ObjectId(ioc_id)
    except Exception:
        return None
    now = datetime.now(timezone.utc)
    feedback_entry = {
        "user_id": user_id,
        "client_id": client_id,
        "verdict": verdict,
        "note": note or "",
        "ts": now.isoformat(),
    }
    inc_field = "tp_count" if verdict == "tp" else "fp_count"
    doc = await col.find_one_and_update(
        {"_id": oid},
        {
            "$push": {"feedback_log": feedback_entry},
            "$inc": {inc_field: 1},
        },
        return_document=True,
    )
    if doc is None:
        return None
    score = compute_ioc_confidence(doc, now)
    doc["confidence_score"] = score
    act = await compute_ioc_actionability(doc, now)
    doc = await col.find_one_and_update(
        {"_id": oid},
        {"$set": {"confidence_score": score, "confidence_decayed_at": now, **act}},
        return_document=True,
    )
    await write_audit(
        user_id,
        "ioc_feedback",
        target_id=ioc_id,
        detail={"verdict": verdict, "note": note or ""},
    )

    from app.services.fp_analytics_service import invalidate_fp_cache, get_fp_analytics
    invalidate_fp_cache()
    source_fp_warning = None
    if verdict == "fp":
        analytics = await get_fp_analytics(force=True)
        for src in doc.get("sources", []):
            sname = src.get("source_name", "")
            sr = analytics.get("fp_by_source", {}).get(sname)
            if sr and sr["total_iocs"] >= 5 and sr["fp_rate"] > 0.5:
                source_fp_warning = {
                    "source_name": sname,
                    "fp_rate": sr["fp_rate"],
                    "fp_count": sr["fp_count"],
                    "total_iocs": sr["total_iocs"],
                }
                break

    doc["_id"] = str(doc["_id"])
    if source_fp_warning:
        doc["source_fp_warning"] = source_fp_warning
    return doc


async def decay_sweep() -> dict:
    col = _col()
    now = datetime.now(timezone.utc)
    cutoff = datetime(now.year, now.month, now.day, now.hour, now.minute, now.second, tzinfo=timezone.utc)
    from datetime import timedelta
    cutoff = now - timedelta(hours=24)

    query = {
        "$or": [
            {"confidence_decayed_at": {"$exists": False}},
            {"confidence_decayed_at": {"$lt": cutoff}},
        ]
    }

    scanned = 0
    updated = 0
    ops: list[UpdateOne] = []

    async for doc in col.find(query):
        scanned += 1
        score = compute_ioc_confidence(doc, now)
        doc["confidence_score"] = score
        act = await compute_ioc_actionability(doc, now)
        ops.append(UpdateOne(
            {"_id": doc["_id"]},
            {"$set": {"confidence_score": score, "confidence_decayed_at": now, **act}},
        ))
        if len(ops) >= 500:
            result = await col.bulk_write(ops)
            updated += result.modified_count
            ops = []

    if ops:
        result = await col.bulk_write(ops)
        updated += result.modified_count

    return {"scanned": scanned, "updated": updated}


async def get_ioc_ta_links(ioc_type: str, value: str) -> dict | None:
    ioc = await _col().find_one({"type": ioc_type, "value": value}, {"sources": 1, "threat_actors": 1})
    if ioc is None:
        return None

    # Manual tags directly on the IOC doc
    manual_tas: set[str] = {ta for ta in ioc.get("threat_actors", []) if ta}

    # Collect article ObjectIds from sources
    doc_ids = []
    for s in ioc.get("sources", []):
        raw_id = s.get("doc_id")
        if raw_id:
            try:
                doc_ids.append(ObjectId(raw_id))
            except Exception:
                pass

    # Fetch threat_actors from linked articles
    article_ta_counts: dict[str, int] = {}
    if doc_ids:
        news_col = get_database()[COLLECTION_NAME]
        articles = await news_col.find(
            {"_id": {"$in": doc_ids}},
            {"threat_actors": 1},
        ).to_list(len(doc_ids))
        for art in articles:
            for ta in art.get("threat_actors", []):
                if ta:
                    article_ta_counts[ta] = article_ta_counts.get(ta, 0) + 1

    # Union all TA names
    all_ta_names = manual_tas | set(article_ta_counts.keys())
    if not all_ta_names:
        return {"threat_actors": []}

    # Check watchlist
    ta_db = get_ta_database()
    watchlist_names = await ta_db[TA_WATCHLIST_COLLECTION].distinct("name")
    watchlist_lower = {n.lower() for n in watchlist_names}

    # Match each TA against ATT&CK groups by name or alias
    attack_col = ta_db["attack_groups"]
    result_tas = []
    for ta_name in sorted(all_ta_names, key=lambda n: -article_ta_counts.get(n, 0)):
        is_watched = ta_name.lower() in watchlist_lower
        is_manual = ta_name in manual_tas
        attack_match = await attack_col.find_one(
            {
                "$or": [
                    {"name": {"$regex": f"^{re.escape(ta_name)}$", "$options": "i"}},
                    {"aliases": {"$regex": f"^{re.escape(ta_name)}$", "$options": "i"}},
                ]
            },
            {"group_id": 1, "name": 1, "aliases": 1, "domains": 1},
        )
        entry: dict = {
            "name": ta_name,
            "article_count": article_ta_counts.get(ta_name, 0),
            "is_watched": is_watched,
            "source": "manual" if is_manual and ta_name not in article_ta_counts else (
                "both" if is_manual else "article"
            ),
        }
        if attack_match:
            entry["attack_group_id"] = attack_match.get("group_id", "")
            entry["attack_group_name"] = attack_match.get("name", "")
            entry["attack_group_aliases"] = attack_match.get("aliases", [])[:6]
            entry["attack_group_domains"] = attack_match.get("domains", [])
        result_tas.append(entry)

    return {"threat_actors": result_tas}


async def get_iocs_for_actor(actor_name: str, limit: int = 50) -> list[dict]:
    """Return real, non-suppressed IOCs tagged to this threat actor (by name or alias), most confident first."""
    tokens = [t.strip() for t in re.split(r"[/,]", actor_name) if t.strip()]
    if not tokens:
        return []
    pattern = "|".join(re.escape(t) for t in tokens)
    cursor = _col().find(
        {
            "threat_actors": {"$regex": pattern, "$options": "i"},
            "auto_suppressed": {"$ne": True},
        },
        {"_id": 0, "type": 1, "value": 1, "confidence_score": 1, "actionability_label": 1,
         "first_seen": 1, "last_seen": 1, "tags": 1, "mitre_techniques": 1, "kill_chain_phase": 1},
    ).sort("confidence_score", -1).limit(limit)
    return await cursor.to_list(length=limit)


_RELATED_PROJECTION = {"_id": 0, "type": 1, "value": 1, "confidence_score": 1, "actionability_label": 1}
_RELATED_CAP = 50


async def get_related_iocs(ioc_type: str, value: str) -> dict | None:
    col = _col()
    ioc = await col.find_one(
        {"type": ioc_type, "value": value},
        {"pulse_ids": 1, "threat_actors": 1, "sources": 1},
    )
    if ioc is None:
        return None

    self_filter = {"$nor": [{"type": ioc_type, "value": value}]}
    pulse_ids = ioc.get("pulse_ids") or []
    threat_actors = ioc.get("threat_actors") or []
    doc_ids = list({s.get("doc_id") for s in ioc.get("sources", []) if s.get("doc_id")})

    async def _related(field: str, values: list) -> list[dict]:
        if not values:
            return []
        cursor = col.find(
            {field: {"$in": values}, **self_filter}, _RELATED_PROJECTION
        ).limit(_RELATED_CAP)
        return await cursor.to_list(_RELATED_CAP)

    by_pulse, by_threat_actor, by_article = await asyncio.gather(
        _related("pulse_ids", pulse_ids),
        _related("threat_actors", threat_actors),
        _related("sources.doc_id", doc_ids),
    )

    return {
        "by_pulse": by_pulse,
        "by_threat_actor": by_threat_actor,
        "by_source_article": by_article,
    }
