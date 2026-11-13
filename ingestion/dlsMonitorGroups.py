"""Sync ransomware leak-site (DLS) group metadata from cyberiskvision/dls-monitor.

Stores one doc per group in news_db.dls_groups and folds "aka" aliases into
threatintel.groups so actor matching (modules/nlp.py) recognises them.
Only the clearnet GitHub raw JSON is fetched; onion hosts are stored as data only.
"""
from datetime import datetime
import re
import requests

from modules import dbMongo

GROUPS_URL = "https://raw.githubusercontent.com/cyberiskvision/dls-monitor/main/groups.json"
SOURCE = "dls-monitor"

_AKA_RE = re.compile(r"\b(?:aka|a\.k\.a\.?|also known as)\s+([^;,()\n`]+)", re.IGNORECASE)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def parse_aliases(meta: str | None) -> list[str]:
    """Extract alias names from free-text meta such as 'aka blackcat - fileserver ...'."""
    if not meta:
        return []
    aliases = []
    for m in _AKA_RE.finditer(meta):
        cand = re.split(r"\s+-\s+|\s+/\s+", m.group(1).strip())[0].strip(" .")
        if cand and ".onion" not in cand and len(cand) <= 40:
            aliases.append(cand)
    return aliases


def is_marketplace(meta: str | None) -> bool:
    return bool(meta) and "not a ransomware group" in meta.lower()


def build_doc(group: dict) -> dict:
    name = str(group["name"]).strip()
    meta = group.get("meta")
    locations = [
        {
            "fqdn": loc.get("fqdn"),
            "title": loc.get("title"),
            "version": loc.get("version"),
            "available": bool(loc.get("available")),
            "updated": loc.get("updated"),
            "lastscrape": loc.get("lastscrape"),
            "enabled": bool(loc.get("enabled", True)),
        }
        for loc in group.get("locations", [])
        if loc.get("fqdn")
    ]
    aliases = parse_aliases(meta)
    return {
        "name": name,
        "name_norm": dbMongo._normalize_actor_core(name),
        "aliases": aliases,
        "aliases_norm": [dbMongo._normalize_actor_core(a) for a in aliases],
        "meta": meta,
        "flags": {
            "captcha": bool(group.get("captcha")),
            "parser": bool(group.get("parser")),
            "javascript_render": bool(group.get("javascript_render")),
        },
        "locations": locations,
        "profile_urls": [p for p in group.get("profile", []) if isinstance(p, str) and _URL_RE.match(p)],
        "source": SOURCE,
        "fetched_at": datetime.utcnow(),
    }


def main():
    resp = requests.get(GROUPS_URL, timeout=60)
    resp.raise_for_status()
    groups = resp.json()

    new, updated, skipped = 0, 0, 0
    for group in groups:
        if not group.get("name") or is_marketplace(group.get("meta")):
            skipped += 1
            continue
        doc = build_doc(group)
        if not doc["name_norm"]:
            skipped += 1
            continue
        if dbMongo.upsert_dls_group(doc):
            new += 1
        else:
            updated += 1
        # ensure TA group exists, then fold aliases into it (not as separate groups)
        dbMongo.upsert_ta_group_from_feed(doc["name"])
        dbMongo.add_ta_aliases(doc["name"], doc["aliases"])

    print(f"dls-monitor: {new} new, {updated} updated, {skipped} skipped of {len(groups)}")


if __name__ == "__main__":
    main()
