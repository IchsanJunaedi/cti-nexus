"""
stix_service.py — Build STIX 2.1 bundles as plain Python dicts (no stix2 library).

Exports:
    build_ta_stix_bundle(actor_name)  → STIX bundle dict for a TA profile
    build_ioc_stix_bundle(ioc_type, limit) → STIX bundle dict for IOCs
    build_pir_stix_bundle()           → STIX bundle dict for active PIRs
"""

import uuid
from datetime import datetime, timezone

from app.config import PIR_COLLECTION
from app.database import get_database
from app.services.ioc_service import get_iocs
from app.services.ta_profile_service import get_ta_profile

# ── Constants ────────────────────────────────────────────────────────────────

# Fixed identity UUID — deterministic, represents this CTI platform.
_IDENTITY_UUID = "b67d2b96-5e1e-4b78-9e5f-8f3a1c2d4e7a"

_SPEC = "2.1"

# Standard FIRST TLP 2.0 marking-definition IDs (deterministic, per FIRST spec).
_TLP_MARKING_IDS: dict[str, str] = {
    "TLP:CLEAR":        "marking-definition--613f2e26-407d-48c7-9eca-b8e91ba1f680",
    "TLP:GREEN":        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER":        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER+STRICT": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    "TLP:RED":          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

_TLP_CREATED: dict[str, str] = {
    "TLP:CLEAR":        "2022-10-22T00:00:00Z",
    "TLP:GREEN":        "2022-10-22T00:00:00Z",
    "TLP:AMBER":        "2022-10-22T00:00:00Z",
    "TLP:AMBER+STRICT": "2022-10-22T00:00:00Z",
    "TLP:RED":          "2022-10-22T00:00:00Z",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid4() -> str:
    return str(uuid.uuid4())


def _uuid5(name: str) -> str:
    """Deterministic UUID5 based on DNS namespace + lowercase name."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, name.lower().strip()))


def _identity_object() -> dict:
    ts = _now()
    return {
        "type": "identity",
        "id": f"identity--{_IDENTITY_UUID}",
        "spec_version": _SPEC,
        "created": ts,
        "modified": ts,
        "name": "CTI Platform",
        "identity_class": "system",
    }


def _build_tlp_marking(tlp: str) -> dict:
    md_id = _TLP_MARKING_IDS[tlp]
    created = _TLP_CREATED[tlp]
    return {
        "type": "marking-definition",
        "id": md_id,
        "spec_version": _SPEC,
        "created": created,
        "definition_type": "tlp",
        "name": tlp,
        "definition": {"tlp": tlp.split(":")[-1].lower()},
    }


def _make_bundle(objects: list[dict]) -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{_uuid4()}",
        "spec_version": _SPEC,
        "objects": objects,
    }


# ── IOC → STIX pattern ───────────────────────────────────────────────────────

_IOC_PATTERN_MAP = {
    "ip":           "[ipv4-addr:value = '{value}']",
    "domain":       "[domain-name:value = '{value}']",
    "url":          "[url:value = '{value}']",
    "url_with_path": "[url:value = '{value}']",
    "sha256":       "[file:hashes.'SHA-256' = '{value}']",
    "sha1":         "[file:hashes.'SHA-1' = '{value}']",
    "md5":          "[file:hashes.MD5 = '{value}']",
    "email":        "[email-addr:value = '{value}']",
    "cve":          "[vulnerability:name = '{value}']",
}


def _ioc_pattern(ioc_type: str, value: str) -> str | None:
    tmpl = _IOC_PATTERN_MAP.get(ioc_type)
    if tmpl is None:
        return None
    # Escape single quotes inside the value to avoid breaking the pattern string.
    safe_value = value.replace("'", "\\'")
    return tmpl.format(value=safe_value)


# ── STIX object builders ──────────────────────────────────────────────────────

def _build_indicator(ioc: dict, ts: str) -> dict | None:
    """Build a STIX 2.1 indicator from an IOC document."""
    ioc_type = ioc.get("type", "")
    value = ioc.get("value", "")
    pattern = _ioc_pattern(ioc_type, value)
    if not pattern:
        return None

    first_seen = ioc.get("first_seen", ts[:10])
    # valid_from must be RFC 3339 / ISO 8601 with timezone
    valid_from = f"{first_seen}T00:00:00Z" if len(first_seen) == 10 else first_seen

    indicator_id = f"indicator--{_uuid5(f'{ioc_type}:{value}')}"

    obj: dict = {
        "type": "indicator",
        "id": indicator_id,
        "spec_version": _SPEC,
        "created": ts,
        "modified": ts,
        "name": f"{ioc_type}: {value}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": valid_from,
        "indicator_types": [_ioc_type_to_indicator_type(ioc_type)],
    }

    labels = list(ioc.get("tags") or [])
    mitre_techniques = ioc.get("mitre_techniques") or []
    if mitre_techniques:
        labels.extend(mitre_techniques)
    if labels:
        obj["labels"] = labels

    tlp = ioc.get("tlp")
    if tlp and tlp in _TLP_MARKING_IDS:
        obj["object_marking_refs"] = [_TLP_MARKING_IDS[tlp]]

    kill_chain_phase = ioc.get("kill_chain_phase")
    if kill_chain_phase:
        obj["kill_chain_phases"] = [
            {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": kill_chain_phase}
        ]

    if mitre_techniques:
        ext_refs = []
        for tech_id in mitre_techniques:
            ext_refs.append({
                "source_name": "mitre-attack",
                "external_id": tech_id,
                "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
            })
        obj["external_references"] = ext_refs

    seen_count = ioc.get("seen_count")
    if seen_count is not None:
        obj["x_seen_count"] = seen_count

    last_seen = ioc.get("last_seen")
    if last_seen:
        obj["x_last_seen"] = last_seen

    return obj


def _ioc_type_to_indicator_type(ioc_type: str) -> str:
    mapping = {
        "ip": "malicious-activity",
        "domain": "malicious-activity",
        "url": "malicious-activity",
        "url_with_path": "malicious-activity",
        "sha256": "malicious-activity",
        "sha1": "malicious-activity",
        "md5": "malicious-activity",
        "email": "compromised",
        "cve": "anomalous-activity",
    }
    return mapping.get(ioc_type, "unknown")


def _build_threat_actor(actor_name: str, profile: dict, ts: str) -> dict:
    ta_id = f"threat-actor--{_uuid5(actor_name)}"
    identity_info = profile.get("identity", {})
    motivation = profile.get("motivation", {})
    targeting = profile.get("targeting_profile", {})
    meta = profile.get("profile_metadata", {})

    obj: dict = {
        "type": "threat-actor",
        "id": ta_id,
        "spec_version": _SPEC,
        "created": ts,
        "modified": ts,
        "name": identity_info.get("primary_name") or actor_name,
    }

    aliases = identity_info.get("aliases", [])
    if aliases:
        obj["aliases"] = aliases

    actor_type = identity_info.get("actor_type")
    if actor_type:
        obj["threat_actor_types"] = [actor_type]

    primary_motive = motivation.get("primary_motivation")
    if primary_motive:
        obj["primary_motivation"] = primary_motive

    secondary = motivation.get("secondary_motivations", [])
    if secondary:
        obj["secondary_motivations"] = secondary

    sectors = targeting.get("targeted_sectors", [])
    if sectors:
        obj["sectors"] = sectors

    countries = targeting.get("targeted_geographies", [])
    if countries:
        obj["x_targeted_countries"] = countries

    sponsoring_nation = identity_info.get("sponsoring_nation")
    if sponsoring_nation:
        obj["x_sponsoring_nation"] = sponsoring_nation

    active_status = identity_info.get("active_status")
    if active_status:
        obj["x_active_status"] = active_status

    sophistication = profile.get("capability_assessment", {}).get("sophistication_level")
    if sophistication:
        obj["sophistication"] = sophistication

    tlp = meta.get("tlp_marking")
    if tlp:
        obj["x_tlp"] = tlp

    confidence = meta.get("analyst_confidence")
    if confidence:
        confidence_map = {"low": 33, "medium": 66, "high": 85}
        obj["confidence"] = confidence_map.get(confidence, 50)

    # External references: MITRE group ID
    ext_refs = []
    mitre_id = identity_info.get("tracking_ids", {}).get("mitre_group_id")
    if mitre_id:
        ext_refs.append({
            "source_name": "mitre-attack",
            "external_id": mitre_id,
            "url": f"https://attack.mitre.org/groups/{mitre_id}/",
        })
    other_ids = identity_info.get("tracking_ids", {}).get("other_ids", [])
    for oid in other_ids:
        ext_refs.append({"source_name": "vendor", "external_id": oid})
    if ext_refs:
        obj["external_references"] = ext_refs

    return obj


def _build_attack_pattern(technique_str: str, tactic: str, ts: str) -> dict:
    """
    Build STIX attack-pattern from a technique string like 'T1566 Phishing' or
    plain text description.
    """
    # Try to extract a MITRE technique ID from the string.
    import re
    match = re.match(r"(T\d{4}(?:\.\d{3})?)\s*(.*)", technique_str.strip())
    if match:
        tech_id = match.group(1)
        tech_name = match.group(2).strip() or technique_str.strip()
        ext_refs = [
            {
                "source_name": "mitre-attack",
                "external_id": tech_id,
                "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
            }
        ]
    else:
        tech_id = None
        tech_name = technique_str.strip()
        ext_refs = []

    obj: dict = {
        "type": "attack-pattern",
        "id": f"attack-pattern--{_uuid5(technique_str)}",
        "spec_version": _SPEC,
        "created": ts,
        "modified": ts,
        "name": tech_name,
        "x_tactic": tactic,
    }
    if ext_refs:
        obj["external_references"] = ext_refs

    return obj


def _build_malware(malware_entry: dict | str, ts: str) -> dict:
    """Build STIX malware object from a malware entry dict or plain name string."""
    if isinstance(malware_entry, dict):
        name = malware_entry.get("name", "Unknown Malware")
        mal_type = malware_entry.get("type", "unknown")
        notes = malware_entry.get("notes")
    else:
        name = str(malware_entry)
        mal_type = "unknown"
        notes = None

    obj: dict = {
        "type": "malware",
        "id": f"malware--{_uuid5(name)}",
        "spec_version": _SPEC,
        "created": ts,
        "modified": ts,
        "name": name,
        "is_family": False,
        "malware_types": [mal_type],
    }
    if notes:
        obj["description"] = notes

    return obj


def _build_relationship(
    rel_type: str,
    source_ref: str,
    target_ref: str,
    ts: str,
    description: str | None = None,
) -> dict:
    obj: dict = {
        "type": "relationship",
        "id": f"relationship--{_uuid4()}",
        "spec_version": _SPEC,
        "created": ts,
        "modified": ts,
        "relationship_type": rel_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }
    if description:
        obj["description"] = description
    return obj


def _build_course_of_action(pir: dict, ts: str) -> dict:
    pir_id_str = str(pir.get("_id", pir.get("id", _uuid4())))
    title = pir.get("title", "Unnamed PIR")
    description = pir.get("description", "")
    priority = pir.get("priority", "")
    owner = pir.get("owner", "")

    coa_name = f"PIR: {title}"
    coa_id = f"course-of-action--{_uuid5(coa_name)}"

    desc_parts = []
    if description:
        desc_parts.append(description)
    if priority:
        desc_parts.append(f"Priority: {priority}")
    if owner:
        desc_parts.append(f"Owner: {owner}")
    criteria = pir.get("criteria", {})
    if criteria:
        if criteria.get("threat_actors"):
            desc_parts.append(f"Threat Actors: {', '.join(criteria['threat_actors'])}")
        if criteria.get("industries"):
            desc_parts.append(f"Industries: {', '.join(criteria['industries'])}")
        if criteria.get("countries"):
            desc_parts.append(f"Countries: {', '.join(criteria['countries'])}")
        if criteria.get("ttps"):
            desc_parts.append(f"TTPs: {', '.join(criteria['ttps'])}")
        if criteria.get("keywords"):
            desc_parts.append(f"Keywords: {', '.join(criteria['keywords'])}")

    obj: dict = {
        "type": "course-of-action",
        "id": coa_id,
        "spec_version": _SPEC,
        "created": ts,
        "modified": ts,
        "name": coa_name,
        "x_pir_id": pir_id_str,
        "x_pir_status": pir.get("status", "active"),
        "x_pir_priority": priority,
    }
    if desc_parts:
        obj["description"] = "\n".join(desc_parts)
    if pir.get("start_date"):
        obj["x_start_date"] = pir["start_date"]
    if pir.get("end_date"):
        obj["x_end_date"] = pir["end_date"]

    return obj


# ── Public service functions ──────────────────────────────────────────────────

async def build_ta_stix_bundle(actor_name: str) -> dict:
    """
    Fetch a TA profile and convert it to a STIX 2.1 bundle containing:
      - identity (producing org)
      - threat-actor
      - attack-pattern objects (from capability_assessment.attack_techniques)
      - malware objects (from capability_assessment.known_malware)
      - indicator objects (from infrastructure.known_iocs)
      - relationship objects linking TA → attack-patterns, malware, indicators
    """
    ts = _now()
    objects: list[dict] = []

    # Producing identity
    identity = _identity_object()
    objects.append(identity)
    identity_ref = identity["id"]

    # Fetch profile
    profile = await get_ta_profile(actor_name)
    if profile is None:
        # Return a minimal bundle with just the identity if no profile found
        return _make_bundle(objects)

    # Threat actor object
    ta_obj = _build_threat_actor(actor_name, profile, ts)
    ta_ref = ta_obj["id"]
    objects.append(ta_obj)

    # Relationship: identity created-by threat-actor (optional context)
    # We skip this to avoid noise; just link the TA to the platform via the bundle.

    # ── Attack Patterns ────────────────────────────────────────────────────
    capability = profile.get("capability_assessment", {})
    attack_techniques = capability.get("attack_techniques", {})

    seen_technique_ids: set[str] = set()
    for tactic, techniques in attack_techniques.items():
        if not isinstance(techniques, list):
            continue
        for tech_str in techniques:
            if not tech_str:
                continue
            ap_obj = _build_attack_pattern(tech_str, tactic, ts)
            if ap_obj["id"] not in seen_technique_ids:
                seen_technique_ids.add(ap_obj["id"])
                objects.append(ap_obj)
                # Relationship: threat-actor uses attack-pattern
                objects.append(
                    _build_relationship("uses", ta_ref, ap_obj["id"], ts)
                )

    # ── Malware ────────────────────────────────────────────────────────────
    known_malware = capability.get("known_malware", [])
    seen_malware_ids: set[str] = set()
    for mal_entry in known_malware:
        mal_obj = _build_malware(mal_entry, ts)
        if mal_obj["id"] not in seen_malware_ids:
            seen_malware_ids.add(mal_obj["id"])
            objects.append(mal_obj)
            # Relationship: threat-actor uses malware
            objects.append(
                _build_relationship("uses", ta_ref, mal_obj["id"], ts)
            )

    # ── IOC Indicators from infrastructure.known_iocs ─────────────────────
    infra = profile.get("infrastructure", {})
    known_iocs = infra.get("known_iocs", {})

    # Map infrastructure IOC field names → ioc_service types
    infra_type_map = {
        "ips": "ip",
        "domains": "domain",
        "hashes": "sha256",
        "urls": "url",
    }
    seen_indicator_ids: set[str] = set()
    for field, ioc_type in infra_type_map.items():
        values = known_iocs.get(field, [])
        if not isinstance(values, list):
            continue
        for value in values:
            if not value:
                continue
            # Defang reversal: replace [.] with . and hxxp with http
            clean_value = value.replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")
            fake_ioc = {"type": ioc_type, "value": clean_value, "first_seen": ts[:10]}
            ind_obj = _build_indicator(fake_ioc, ts)
            if ind_obj and ind_obj["id"] not in seen_indicator_ids:
                seen_indicator_ids.add(ind_obj["id"])
                objects.append(ind_obj)
                # Relationship: threat-actor indicates indicator
                objects.append(
                    _build_relationship("indicates", ind_obj["id"], ta_ref, ts)
                )

    return _make_bundle(objects)


async def build_ioc_stix_bundle(
    ioc_type: str | None = None,
    limit: int = 500,
    actionability: str | None = None,
) -> dict:
    """
    Fetch IOCs from the ioc_service and convert them to STIX 2.1 indicator objects.
    Returns a STIX 2.1 bundle dict.
    """
    ts = _now()
    objects: list[dict] = []

    # Producing identity
    identity = _identity_object()
    objects.append(identity)

    # Fetch IOCs — use page_size=limit on page 1
    iocs, _total = await get_iocs(ioc_type=ioc_type, actionability=actionability, page=1, page_size=min(limit, 2000))

    seen_tlp: set[str] = set()
    indicators: list[dict] = []
    for ioc in iocs:
        ind_obj = _build_indicator(ioc, ts)
        if ind_obj:
            indicators.append(ind_obj)
            tlp = ioc.get("tlp")
            if tlp and tlp in _TLP_MARKING_IDS:
                seen_tlp.add(tlp)

    for tlp in seen_tlp:
        objects.append(_build_tlp_marking(tlp))
    objects.extend(indicators)

    return _make_bundle(objects)


async def build_article_stix_bundle(article_id: str) -> dict | None:
    """
    Fetch a single article and convert it to a STIX 2.1 bundle containing:
      - identity (producing org)
      - report object (the article)
      - attack-pattern objects (from article.ttps)
      - threat-actor stubs (from article.threat_actors)
      - relationship objects
    Returns None if the article is not found.
    """
    from bson import ObjectId
    from app.config import COLLECTION_NAME
    from app.database import get_database

    col = get_database()[COLLECTION_NAME]
    try:
        doc = await col.find_one({"_id": ObjectId(article_id)})
    except Exception:
        return None
    if doc is None:
        return None

    ts = _now()
    objects: list[dict] = []

    identity = _identity_object()
    objects.append(identity)

    # Collect sub-object IDs for the report's object_refs
    object_refs: list[str] = [identity["id"]]

    # ── Threat Actor stubs ─────────────────────────────────────────────────
    ta_refs: list[str] = []
    for ta_name in doc.get("threat_actors", []):
        ta_id = f"threat-actor--{_uuid5(ta_name)}"
        ta_obj: dict = {
            "type": "threat-actor",
            "id": ta_id,
            "spec_version": _SPEC,
            "created": ts,
            "modified": ts,
            "name": ta_name,
        }
        objects.append(ta_obj)
        object_refs.append(ta_id)
        ta_refs.append(ta_id)

    # ── Attack Patterns (TTPs) ─────────────────────────────────────────────
    ap_refs: list[str] = []
    seen_ap: set[str] = set()
    for ttp in doc.get("ttps", []):
        tech_str = f"{ttp.get('id', '')} {ttp.get('name', '')}".strip()
        if not tech_str:
            continue
        ap_obj = _build_attack_pattern(tech_str, "unknown", ts)
        if ap_obj["id"] not in seen_ap:
            seen_ap.add(ap_obj["id"])
            objects.append(ap_obj)
            object_refs.append(ap_obj["id"])
            ap_refs.append(ap_obj["id"])

    # ── Relationships ──────────────────────────────────────────────────────
    for ta_ref in ta_refs:
        for ap_ref in ap_refs:
            objects.append(_build_relationship("uses", ta_ref, ap_ref, ts))

    # ── Report object (the article itself) ────────────────────────────────
    report_id = f"report--{_uuid5(article_id)}"
    report_obj: dict = {
        "type": "report",
        "id": report_id,
        "spec_version": _SPEC,
        "created": ts,
        "modified": ts,
        "name": doc.get("title", "Untitled"),
        "published": f"{doc.get('posted_on', ts[:10])}T00:00:00Z",
        "report_types": ["threat-report"],
        "object_refs": object_refs,
    }
    if doc.get("url"):
        report_obj["external_references"] = [
            {"source_name": doc.get("source", "unknown"), "url": doc["url"]}
        ]
    if doc.get("news_type"):
        report_obj["labels"] = [doc["news_type"]]
    if doc.get("impacted_industries"):
        report_obj["x_impacted_industries"] = doc["impacted_industries"]
    if doc.get("mentioned_countries"):
        report_obj["x_mentioned_countries"] = doc["mentioned_countries"]
    confidence_score = doc.get("confidence_score")
    if confidence_score is not None:
        report_obj["confidence"] = confidence_score

    objects.insert(1, report_obj)  # place report right after identity

    return _make_bundle(objects)


async def build_pir_stix_bundle() -> dict:
    """
    Fetch active PIRs from the PIR_COLLECTION and represent each as a
    STIX 2.1 course-of-action object.
    Returns a STIX 2.1 bundle dict.
    """
    ts = _now()
    objects: list[dict] = []

    # Producing identity
    identity = _identity_object()
    objects.append(identity)
    identity_ref = identity["id"]

    # Fetch active PIRs
    col = get_database()[PIR_COLLECTION]
    pir_docs = await col.find({"status": "active"}).sort("priority", 1).to_list(500)

    for pir in pir_docs:
        coa_obj = _build_course_of_action(pir, ts)
        objects.append(coa_obj)

        # Relationship: identity created-by is the CTI platform (optional context)
        # Link each COA back to the identity as the creator.
        objects.append(
            _build_relationship(
                "derived-from",
                coa_obj["id"],
                identity_ref,
                ts,
                description="PIR managed by CTI Platform",
            )
        )

    return _make_bundle(objects)
