"""ATT&CK STIX sync service — Enterprise, ICS, Mobile."""
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from pymongo import UpdateOne

from app.database import get_database

TECH_ID_RE = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')

_DOMAINS: dict[str, dict] = {
    "enterprise": {
        "key": "enterprise",
        "label": "Enterprise ATT&CK",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "stix_domain": "enterprise-attack",
    },
    "ics": {
        "key": "ics",
        "label": "ICS ATT&CK",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
        "stix_domain": "ics-attack",
    },
    "mobile": {
        "key": "mobile",
        "label": "Mobile ATT&CK",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
        "stix_domain": "mobile-attack",
    },
}

_TIMEOUT = httpx.Timeout(300.0)
_HEADERS = {"User-Agent": "ScraperNewsWeb-CTI/1.0 (ATT&CK sync)"}


def _normalize_keys(obj: dict) -> dict:
    if not any(k.startswith("x_mitre_") for k in obj):
        return obj
    return {(k.replace("_", "-") if k.startswith("x_mitre_") else k): v for k, v in obj.items()}


_RELEASES_URL = "https://api.github.com/repos/mitre-attack/attack-stix-data/releases/latest"


def _ver_tuple(v: str) -> tuple:
    try:
        return tuple(int(p) for p in v.lstrip("v").split("."))
    except ValueError:
        return ()


async def get_latest_release_version() -> str | None:
    """Latest published ATT&CK version (e.g. '19.2') from GitHub releases; None on failure."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0), headers=_HEADERS) as client:
            r = await client.get(_RELEASES_URL, headers={"Accept": "application/vnd.github+json"})
            r.raise_for_status()
            return r.json().get("tag_name", "").lstrip("v") or None
    except Exception as e:
        print(f"[ATT&CK sync] Release check failed: {e}")
        return None


async def upstream_is_newer() -> bool:
    """True if the latest upstream release is newer than the oldest synced domain version."""
    latest = await get_latest_release_version()
    if not latest:
        return False
    synced = [s.get("version") for s in await get_sync_status() if s.get("status") == "success" and s.get("version")]
    if not synced:
        return False
    return _ver_tuple(latest) > min(_ver_tuple(v) for v in synced)


def _db():
    return get_database()


def _col(name: str):
    return _db()[name]


def _mitre_ref(obj: dict) -> dict:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref
    return {}


def _extract_id(obj: dict) -> str:
    return _mitre_ref(obj).get("external_id", "")


def _extract_url(obj: dict) -> str:
    return _mitre_ref(obj).get("url", "")


async def _ensure_indexes() -> None:
    db = _db()
    await db["attack_techniques"].create_index([("attack_id", 1)])
    await db["attack_techniques"].create_index([("domains", 1)])
    await db["attack_techniques"].create_index([("tactics", 1)])
    await db["attack_techniques"].create_index([("is_subtechnique", 1)])
    await db["attack_techniques"].create_index([("name", "text"), ("description", "text")])
    await db["attack_tactics"].create_index([("tactic_id", 1)])
    await db["attack_tactics"].create_index([("domains", 1)])
    await db["attack_tactics"].create_index([("shortname", 1)])
    await db["attack_mitigations"].create_index([("mitigation_id", 1)])
    await db["attack_mitigations"].create_index([("domains", 1)])
    await db["attack_groups"].create_index([("group_id", 1)])
    await db["attack_groups"].create_index([("domains", 1)])
    await db["attack_groups"].create_index([("name", "text"), ("aliases", "text")])
    await db["attack_software"].create_index([("software_id", 1)])
    await db["attack_software"].create_index([("domains", 1)])
    await db["attack_software"].create_index([("name", "text")])
    await db["attack_detection_strategies"].create_index([("det_id", 1)])
    await db["attack_detection_strategies"].create_index([("domains", 1)])
    await db["attack_analytics"].create_index([("analytic_id", 1)])
    await db["attack_analytics"].create_index([("domains", 1)])
    await db["attack_relationships"].create_index([("source_ref", 1)])
    await db["attack_relationships"].create_index([("target_ref", 1)])
    await db["attack_relationships"].create_index([("relationship_type", 1)])
    await db["attack_relationships"].create_index([("source_ref", 1), ("relationship_type", 1)])
    await db["attack_relationships"].create_index([("target_ref", 1), ("relationship_type", 1)])


async def _bulk_write(collection_name: str, ops: list) -> None:
    for i in range(0, len(ops), 500):
        await _col(collection_name).bulk_write(ops[i:i + 500], ordered=False)


async def sync_domain(domain_key: str) -> dict:
    """Fetch and upsert one ATT&CK domain. Returns sync result dict."""
    if domain_key not in _DOMAINS:
        raise ValueError(f"Unknown domain: {domain_key}")

    meta = _DOMAINS[domain_key]
    stix_domain = meta["stix_domain"]
    started_at = datetime.now(timezone.utc)

    # Snapshot previous counts for delta tracking
    prev_log = await _col("attack_sync_log").find_one({"_id": domain_key}) or {}
    prev_counts = {
        "technique_count": prev_log.get("technique_count", 0),
        "group_count": prev_log.get("group_count", 0),
        "software_count": prev_log.get("software_count", 0),
        "mitigation_count": prev_log.get("mitigation_count", 0),
    }

    # Mark syncing immediately so UI shows in-progress state
    await _col("attack_sync_log").update_one(
        {"_id": domain_key},
        {"$set": {
            "domain_key": domain_key,
            "label": meta["label"],
            "status": "syncing",
            "last_attempted": started_at.isoformat(),
            "error": None,
        }},
        upsert=True,
    )

    await _ensure_indexes()

    try:
        import json as _json
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS, follow_redirects=True) as client:
            async with client.stream("GET", meta["url"]) as resp:
                resp.raise_for_status()
                total_bytes = int(resp.headers.get("content-length", 0))
                downloaded = 0
                last_reported = 0
                chunks: list[bytes] = []
                async for chunk in resp.aiter_bytes(chunk_size=512 * 1024):  # 512KB chunks
                    chunks.append(chunk)
                    downloaded += len(chunk)
                    # update progress every ~5MB
                    if downloaded - last_reported >= 5 * 1024 * 1024:
                        last_reported = downloaded
                        pct = f"{downloaded * 100 // total_bytes}%" if total_bytes else f"{downloaded // 1024 // 1024}MB"
                        await _col("attack_sync_log").update_one(
                            {"_id": domain_key},
                            {"$set": {
                                "phase": "downloading",
                                "bytes_downloaded": downloaded,
                                "bytes_total": total_bytes,
                                "download_pct": pct,
                            }},
                        )
                raw_bytes = b"".join(chunks)
        bundle = _json.loads(raw_bytes)
    except Exception as e:
        err = str(e)
        await _col("attack_sync_log").update_one(
            {"_id": domain_key},
            {"$set": {"status": "error", "phase": None, "error": err, "last_attempted": started_at.isoformat()}},
            upsert=True,
        )
        raise

    await _col("attack_sync_log").update_one(
        {"_id": domain_key},
        {"$set": {"phase": "parsing & writing"}},
    )

    # attack-stix-data ships STIX 2.1 (x_mitre_*); parser below uses x-mitre-* keys.
    objects: list[dict] = [_normalize_keys(o) for o in bundle.get("objects", [])]
    counts: dict[str, int] = {
        "technique_count": 0,
        "tactic_count": 0,
        "mitigation_count": 0,
        "group_count": 0,
        "software_count": 0,
        "detection_strategy_count": 0,
        "analytic_count": 0,
        "relationship_count": 0,
    }
    version = ""
    mitre_modified = ""

    by_type: dict[str, list[dict]] = {}
    for obj in objects:
        by_type.setdefault(obj["type"], []).append(obj)

    # ── Collection metadata ──────────────────────────────────────
    for obj in by_type.get("x-mitre-collection", []):
        version = obj.get("x-mitre-version", "")
        mitre_modified = obj.get("modified", "")

    # Fallback: extract version/date from any attack-pattern if collection missing
    if not version or not mitre_modified:
        for obj in by_type.get("attack-pattern", []):
            if not version:
                version = obj.get("x-mitre-version", "")
            if not mitre_modified:
                mitre_modified = obj.get("modified", "")
            if version and mitre_modified:
                break

    # ── Techniques (attack-pattern) ──────────────────────────────
    tech_ops: list = []
    for obj in by_type.get("attack-pattern", []):
        if obj.get("revoked") or obj.get("x-mitre-deprecated"):
            continue
        attack_id = _extract_id(obj)
        if not attack_id:
            continue
        tactics = [
            kc["phase_name"]
            for kc in obj.get("kill_chain_phases", [])
            if kc.get("kill_chain_name", "").startswith("mitre")
        ]
        parent_id = None
        if obj.get("x-mitre-is-subtechnique") and "." in attack_id:
            parent_id = attack_id.split(".")[0]
        doc: dict[str, Any] = {
            "attack_id": attack_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "url": _extract_url(obj),
            "tactics": tactics,
            "is_subtechnique": bool(obj.get("x-mitre-is-subtechnique")),
            "parent_id": parent_id,
            "version": obj.get("x-mitre-version", ""),
            "created": obj.get("created", ""),
            "modified": obj.get("modified", ""),
            "platforms": obj.get("x-mitre-platforms", []),
            "data_sources": obj.get("x-mitre-data-sources", []),
            "detection": obj.get("x-mitre-detection", ""),
        }
        tech_ops.append(UpdateOne(
            {"_id": obj["id"]},
            {"$set": doc, "$addToSet": {"domains": stix_domain}},
            upsert=True,
        ))
    await _bulk_write("attack_techniques", tech_ops)
    counts["technique_count"] = len(tech_ops)

    # ── Tactics (x-mitre-tactic) ─────────────────────────────────
    tactic_ops: list = []
    for obj in by_type.get("x-mitre-tactic", []):
        tactic_id = _extract_id(obj)
        doc = {
            "tactic_id": tactic_id,
            "name": obj.get("name", ""),
            "shortname": obj.get("x-mitre-shortname", ""),
            "description": obj.get("description", ""),
            "url": _extract_url(obj),
        }
        tactic_ops.append(UpdateOne(
            {"_id": obj["id"]},
            {"$set": doc, "$addToSet": {"domains": stix_domain}},
            upsert=True,
        ))
    await _bulk_write("attack_tactics", tactic_ops)
    counts["tactic_count"] = len(tactic_ops)

    # ── Mitigations (course-of-action) ───────────────────────────
    mit_ops: list = []
    for obj in by_type.get("course-of-action", []):
        if obj.get("x-mitre-deprecated"):
            continue
        mit_id = _extract_id(obj)
        if not mit_id or not mit_id.startswith("M"):
            continue
        doc = {
            "mitigation_id": mit_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "url": _extract_url(obj),
            "modified": obj.get("modified", ""),
        }
        mit_ops.append(UpdateOne(
            {"_id": obj["id"]},
            {"$set": doc, "$addToSet": {"domains": stix_domain}},
            upsert=True,
        ))
    await _bulk_write("attack_mitigations", mit_ops)
    counts["mitigation_count"] = len(mit_ops)

    # ── Groups (intrusion-set) ────────────────────────────────────
    grp_ops: list = []
    for obj in by_type.get("intrusion-set", []):
        if obj.get("x-mitre-deprecated"):
            continue
        group_id = _extract_id(obj)
        if not group_id:
            continue
        doc = {
            "group_id": group_id,
            "name": obj.get("name", ""),
            "aliases": obj.get("aliases", []),
            "description": obj.get("description", ""),
            "url": _extract_url(obj),
            "created": obj.get("created", ""),
            "modified": obj.get("modified", ""),
        }
        grp_ops.append(UpdateOne(
            {"_id": obj["id"]},
            {"$set": doc, "$addToSet": {"domains": stix_domain}},
            upsert=True,
        ))
    await _bulk_write("attack_groups", grp_ops)
    counts["group_count"] = len(grp_ops)

    # ── Detection strategies (DETxxxx) + analytics (ANxxxx) — ATT&CK v18+ ──
    det_ops: list = []
    for obj in by_type.get("x-mitre-detection-strategy", []):
        if obj.get("x-mitre-deprecated") or obj.get("revoked"):
            continue
        det_id = _extract_id(obj)
        if not det_id:
            continue
        doc = {
            "det_id": det_id,
            "name": obj.get("name", ""),
            "analytic_refs": obj.get("x-mitre-analytic-refs", []),
            "url": _extract_url(obj),
            "modified": obj.get("modified", ""),
        }
        det_ops.append(UpdateOne(
            {"_id": obj["id"]},
            {"$set": doc, "$addToSet": {"domains": stix_domain}},
            upsert=True,
        ))
    await _bulk_write("attack_detection_strategies", det_ops)
    counts["detection_strategy_count"] = len(det_ops)

    an_ops: list = []
    for obj in by_type.get("x-mitre-analytic", []):
        if obj.get("x-mitre-deprecated") or obj.get("revoked"):
            continue
        an_id = _extract_id(obj)
        if not an_id:
            continue
        doc = {
            "analytic_id": an_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "platforms": obj.get("x-mitre-platforms", []),
            "log_sources": [
                {"name": ls.get("name", ""), "channel": ls.get("channel", "")}
                for ls in obj.get("x-mitre-log-source-references", [])
            ],
            "mutable_elements": obj.get("x-mitre-mutable-elements", []),
            "url": _extract_url(obj),
            "modified": obj.get("modified", ""),
        }
        an_ops.append(UpdateOne(
            {"_id": obj["id"]},
            {"$set": doc, "$addToSet": {"domains": stix_domain}},
            upsert=True,
        ))
    await _bulk_write("attack_analytics", an_ops)
    counts["analytic_count"] = len(an_ops)

    # ── Software (malware + tool) ─────────────────────────────────
    sw_ops: list = []
    for sw_type in ("malware", "tool"):
        for obj in by_type.get(sw_type, []):
            if obj.get("x-mitre-deprecated"):
                continue
            sw_id = _extract_id(obj)
            if not sw_id:
                continue
            doc = {
                "software_id": sw_id,
                "name": obj.get("name", ""),
                "software_type": sw_type,
                "aliases": obj.get("x-mitre-aliases", []),
                "description": obj.get("description", ""),
                "url": _extract_url(obj),
                "platforms": obj.get("x-mitre-platforms", []),
                "modified": obj.get("modified", ""),
            }
            sw_ops.append(UpdateOne(
                {"_id": obj["id"]},
                {"$set": doc, "$addToSet": {"domains": stix_domain}},
                upsert=True,
            ))
    await _bulk_write("attack_software", sw_ops)
    counts["software_count"] = len(sw_ops)

    # ── Relationships ─────────────────────────────────────────────
    await _col("attack_relationships").delete_many({"domain": stix_domain})
    rel_ops: list = []
    for obj in by_type.get("relationship", []):
        if obj.get("x-mitre-deprecated") or obj.get("revoked"):
            continue
        src_ref = obj.get("source_ref", "")
        tgt_ref = obj.get("target_ref", "")
        if not src_ref or not tgt_ref:
            continue
        rel_doc = {
            "_id": obj["id"],
            "relationship_type": obj.get("relationship_type", ""),
            "source_ref": src_ref,
            "source_type": src_ref.split("--")[0] if "--" in src_ref else "",
            "target_ref": tgt_ref,
            "target_type": tgt_ref.split("--")[0] if "--" in tgt_ref else "",
            "description": obj.get("description", ""),
            "domain": stix_domain,
        }
        rel_ops.append(UpdateOne({"_id": obj["id"]}, {"$set": rel_doc}, upsert=True))
    await _bulk_write("attack_relationships", rel_ops)
    counts["relationship_count"] = len(rel_ops)

    finished_at = datetime.now(timezone.utc)
    delta = {
        f"delta_{k}": (counts.get(k, 0) - prev_counts.get(k, 0)) if prev_counts.get(k) else None
        for k in ("technique_count", "group_count", "software_count", "mitigation_count")
    }
    sync_doc = {
        "domain": stix_domain,
        "domain_key": domain_key,
        "label": meta["label"],
        "version": version,
        "mitre_modified": mitre_modified,
        "last_sync": finished_at.isoformat(),
        "status": "success",
        "error": None,
        "phase": None,
        "bytes_downloaded": None,
        "bytes_total": None,
        "download_pct": None,
        **counts,
        **delta,
    }
    await _col("attack_sync_log").update_one(
        {"_id": domain_key}, {"$set": sync_doc}, upsert=True
    )

    prev_version = prev_log.get("version")
    if version and prev_version and version != prev_version:
        await _notify_version_change(meta["label"], domain_key, prev_version, version, counts, delta)
    return sync_doc


async def _notify_version_change(
    label: str, domain_key: str, old: str, new: str, counts: dict, delta: dict
) -> None:
    from app.services.notification_service import create_notification

    parts = []
    for key, name in (("technique", "techniques"), ("group", "groups"),
                      ("software", "software"), ("mitigation", "mitigations")):
        d = delta.get(f"delta_{key}_count")
        if d:
            parts.append(f"{d:+d} {name}")
    body = f"{label} updated from v{old} to v{new}."
    if parts:
        body += " " + ", ".join(parts) + "."
    try:
        await create_notification(
            type="attack_update",
            title=f"MITRE ATT&CK v{new} available",
            body=body,
            severity="info",
            data={"domain": domain_key, "old_version": old, "new_version": new},
            action={"label": "Open ATT&CK DB", "tab": "intelligence"},
            dedupe_key=f"attack_update:{domain_key}:{new}",
        )
    except Exception as e:
        print(f"[ATT&CK sync] Notification failed: {e}")


async def sync_all_domains() -> list[dict]:
    results = []
    for key in _DOMAINS:
        try:
            r = await sync_domain(key)
        except Exception as e:
            r = {"domain_key": key, "status": "error", "error": str(e)}
        results.append(r)
    return results


async def get_sync_status() -> list[dict]:
    logs = await _col("attack_sync_log").find({}).to_list(length=10)
    present = {d["_id"] for d in logs}
    for key, meta in _DOMAINS.items():
        if key not in present:
            logs.append({
                "_id": key,
                "domain_key": key,
                "label": meta["label"],
                "stix_domain": meta["stix_domain"],
                "version": None,
                "last_sync": None,
                "status": "never",
            })
    for d in logs:
        d.pop("_id", None)
    return logs


# ── Query functions ────────────────────────────────────────────

async def get_techniques(
    domain: str | None = None,
    tactic: str | None = None,
    search: str | None = None,
    is_subtechnique: bool | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[dict], int]:
    filt: dict = {}
    if domain:
        filt["domains"] = domain
    if tactic:
        filt["tactics"] = tactic
    if is_subtechnique is not None:
        filt["is_subtechnique"] = is_subtechnique
    if search:
        filt["$text"] = {"$search": search}
    col = _col("attack_techniques")
    total = await col.count_documents(filt)
    skip = (page - 1) * page_size
    docs = await col.find(filt, {"description": 0, "detection": 0}).sort("attack_id", 1).skip(skip).limit(page_size).to_list(length=page_size)
    for d in docs:
        d.pop("_id", None)
    return docs, total


async def lookup_techniques_bulk(attack_ids: list[str]) -> dict[str, dict]:
    """Bulk-fetch lightweight technique info for a list of ATT&CK technique IDs.

    Returns {attack_id: {attack_id, name, tactics, domains, is_subtechnique}} for IDs
    that exist in attack_techniques; unrecognized IDs are simply absent from the result.
    """
    ids = sorted({a.strip().upper() for a in attack_ids if a and a.strip()})
    if not ids:
        return {}
    docs = await _col("attack_techniques").find(
        {"attack_id": {"$in": ids}},
        {"_id": 0, "attack_id": 1, "name": 1, "tactics": 1, "domains": 1, "is_subtechnique": 1},
    ).to_list(length=len(ids))
    return {d["attack_id"]: d for d in docs}


async def get_technique(attack_id: str) -> dict | None:
    doc = await _col("attack_techniques").find_one({"attack_id": attack_id})
    if not doc:
        return None
    stix_id = doc.pop("_id", None)

    mit_rels = await _col("attack_relationships").find(
        {"target_ref": stix_id, "relationship_type": "mitigates"}
    ).to_list(length=100)
    mit_ids = [r["source_ref"] for r in mit_rels]
    mitigations = []
    if mit_ids:
        mits = await _col("attack_mitigations").find({"_id": {"$in": mit_ids}}).to_list(length=100)
        mitigations = [{"mitigation_id": m.get("mitigation_id"), "name": m.get("name"), "description": m.get("description", "")[:300]} for m in mits]

    group_rels = await _col("attack_relationships").find(
        {"target_ref": stix_id, "source_type": "intrusion-set", "relationship_type": "uses"}
    ).to_list(length=200)
    grp_ids = [r["source_ref"] for r in group_rels]
    groups = []
    if grp_ids:
        grps = await _col("attack_groups").find({"_id": {"$in": grp_ids}}).to_list(length=200)
        groups = [{"group_id": g.get("group_id"), "name": g.get("name")} for g in grps]

    sub_techniques = []
    if not doc.get("is_subtechnique"):
        subs = await _col("attack_techniques").find({"parent_id": attack_id}).sort("attack_id", 1).to_list(length=100)
        sub_techniques = [{"attack_id": s.get("attack_id"), "name": s.get("name")} for s in subs]

    sw_rels = await _col("attack_relationships").find(
        {"target_ref": stix_id, "source_type": {"$in": ["malware", "tool"]}, "relationship_type": "uses"}
    ).to_list(length=200)
    sw_ids = [r["source_ref"] for r in sw_rels]
    software = []
    if sw_ids:
        sws = await _col("attack_software").find({"_id": {"$in": sw_ids}}).to_list(length=200)
        software = [{"software_id": s.get("software_id"), "name": s.get("name"), "software_type": s.get("software_type")} for s in sws]

    det_rels = await _col("attack_relationships").find(
        {"target_ref": stix_id, "source_type": "x-mitre-detection-strategy", "relationship_type": "detects"}
    ).to_list(length=50)
    detection_strategies = []
    if det_rels:
        dets = await _col("attack_detection_strategies").find(
            {"_id": {"$in": [r["source_ref"] for r in det_rels]}}
        ).sort("det_id", 1).to_list(length=50)
        an_ids = [a for d in dets for a in d.get("analytic_refs", [])]
        analytics = {
            a["_id"]: a
            for a in await _col("attack_analytics").find({"_id": {"$in": an_ids}}).to_list(length=200)
        }
        for d in dets:
            detection_strategies.append({
                "det_id": d.get("det_id"),
                "name": d.get("name"),
                "url": d.get("url", ""),
                "analytics": [
                    {
                        "analytic_id": a.get("analytic_id"),
                        "description": a.get("description", ""),
                        "platforms": a.get("platforms", []),
                        "log_sources": a.get("log_sources", []),
                        "mutable_elements": a.get("mutable_elements", []),
                    }
                    for ref in d.get("analytic_refs", [])
                    if (a := analytics.get(ref))
                ],
            })

    doc["detection_strategies"] = detection_strategies
    doc["mitigations"] = mitigations
    doc["groups"] = groups
    doc["software"] = software
    doc["sub_techniques"] = sub_techniques
    return doc


async def get_tactics(domain: str | None = None) -> list[dict]:
    filt = {"domains": domain} if domain else {}
    docs = await _col("attack_tactics").find(filt).sort("tactic_id", 1).to_list(length=50)
    for d in docs:
        d.pop("_id", None)
    return docs


async def get_groups(
    domain: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[dict], int]:
    filt: dict = {}
    if domain:
        filt["domains"] = domain
    if search:
        filt["$text"] = {"$search": search}
    col = _col("attack_groups")
    total = await col.count_documents(filt)
    skip = (page - 1) * page_size
    docs = await col.find(filt, {"description": 0}).sort("group_id", 1).skip(skip).limit(page_size).to_list(length=page_size)
    for d in docs:
        d.pop("_id", None)
    return docs, total


async def get_group(group_id: str) -> dict | None:
    doc = await _col("attack_groups").find_one({"group_id": group_id})
    if not doc:
        return None
    stix_id = doc.pop("_id", None)

    rels = await _col("attack_relationships").find(
        {"source_ref": stix_id, "target_type": "attack-pattern", "relationship_type": "uses"}
    ).to_list(length=500)
    tech_ids = [r["target_ref"] for r in rels]
    rel_descs = {r["target_ref"]: r.get("description", "") for r in rels}
    techniques = []
    if tech_ids:
        techs = await _col("attack_techniques").find({"_id": {"$in": tech_ids}}).sort("attack_id", 1).to_list(length=500)
        techniques = [
            {"attack_id": t.get("attack_id"), "name": t.get("name"), "tactics": t.get("tactics", []), "context": rel_descs.get(t.get("_id", ""), "")[:200]}
            for t in techs
        ]

    sw_rels = await _col("attack_relationships").find(
        {"source_ref": stix_id, "relationship_type": "uses", "target_type": {"$in": ["malware", "tool"]}}
    ).to_list(length=200)
    sw_ids = [r["target_ref"] for r in sw_rels]
    software = []
    if sw_ids:
        sws = await _col("attack_software").find({"_id": {"$in": sw_ids}}).to_list(length=200)
        software = [{"software_id": s.get("software_id"), "name": s.get("name"), "software_type": s.get("software_type")} for s in sws]

    doc["techniques"] = techniques
    doc["software"] = software
    return doc


async def get_software(
    domain: str | None = None,
    sw_type: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[dict], int]:
    filt: dict = {}
    if domain:
        filt["domains"] = domain
    if sw_type:
        filt["software_type"] = sw_type
    if search:
        filt["$text"] = {"$search": search}
    col = _col("attack_software")
    total = await col.count_documents(filt)
    skip = (page - 1) * page_size
    docs = await col.find(filt, {"description": 0}).sort("software_id", 1).skip(skip).limit(page_size).to_list(length=page_size)
    for d in docs:
        d.pop("_id", None)
    return docs, total


async def get_software_item(software_id: str) -> dict | None:
    doc = await _col("attack_software").find_one({"software_id": software_id})
    if not doc:
        return None
    stix_id = doc.pop("_id", None)

    grp_rels = await _col("attack_relationships").find(
        {"target_ref": stix_id, "source_type": "intrusion-set", "relationship_type": "uses"}
    ).to_list(length=200)
    grp_ids = [r["source_ref"] for r in grp_rels]
    groups = []
    if grp_ids:
        grps = await _col("attack_groups").find({"_id": {"$in": grp_ids}}).to_list(length=200)
        groups = [{"group_id": g.get("group_id"), "name": g.get("name")} for g in grps]

    tech_rels = await _col("attack_relationships").find(
        {"source_ref": stix_id, "target_type": "attack-pattern", "relationship_type": "uses"}
    ).to_list(length=300)
    tech_ids = [r["target_ref"] for r in tech_rels]
    techniques = []
    if tech_ids:
        techs = await _col("attack_techniques").find({"_id": {"$in": tech_ids}}).sort("attack_id", 1).to_list(length=300)
        techniques = [{"attack_id": t.get("attack_id"), "name": t.get("name"), "tactics": t.get("tactics", [])} for t in techs]

    doc["groups"] = groups
    doc["techniques"] = techniques
    return doc


async def get_mitigations(
    domain: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[dict], int]:
    filt: dict = {}
    if domain:
        filt["domains"] = domain
    if search:
        filt["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
        ]
    col = _col("attack_mitigations")
    total = await col.count_documents(filt)
    skip = (page - 1) * page_size
    docs = await col.find(filt).sort("mitigation_id", 1).skip(skip).limit(page_size).to_list(length=page_size)
    for d in docs:
        d.pop("_id", None)
    return docs, total


async def get_navigator_layer(
    domain: str | None = None,
    tactic: str | None = None,
    search: str | None = None,
    is_subtechnique: bool | None = None,
    group_id: str | None = None,
) -> dict:
    """Generate Navigator v4.5 layer JSON from ATT&CK DB with current filters."""
    filt: dict = {}
    if domain:
        filt["domains"] = domain
    if tactic:
        filt["tactics"] = tactic
    if is_subtechnique is not None:
        filt["is_subtechnique"] = is_subtechnique
    if search:
        filt["$text"] = {"$search": search}

    if group_id:
        grp = await _col("attack_groups").find_one({"group_id": group_id})
        if grp:
            rels = await _col("attack_relationships").find(
                {"source_ref": grp["_id"], "target_type": "attack-pattern", "relationship_type": "uses"}
            ).to_list(length=500)
            filt["_id"] = {"$in": [r["target_ref"] for r in rels]}

    techniques = await _col("attack_techniques").find(
        filt, {"attack_id": 1, "name": 1, "tactics": 1}
    ).to_list(length=2000)

    nav_domain = domain or "enterprise-attack"
    description = f"Techniques used by {group_id}" if group_id else (
        f"Techniques: tactic={tactic}" if tactic else (
            f"Techniques: domain={domain}" if domain else "ATT&CK DB export"
        )
    )

    return {
        "name": "CTI Platform — ATT&CK DB",
        "versions": {"attack": "16", "navigator": "4.5", "layer": "4.5"},
        "domain": nav_domain,
        "description": description,
        "techniques": [
            {"techniqueID": t["attack_id"], "color": "#0C969C", "score": 1, "enabled": True, "metadata": [], "links": []}
            for t in techniques if t.get("attack_id")
        ],
        "gradient": {"colors": ["#ffffff", "#0C969C"], "minValue": 0, "maxValue": 1},
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#162B2C",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
