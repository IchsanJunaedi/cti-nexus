"""Leak-site (DLS) intel for ransomware groups, ingested from cyberiskvision/dls-monitor.

Data lives in news_db.dls_groups (written by ScraperNewsRevamp/dlsMonitorGroups.py).
Onion hostnames are defanged server-side; the raw fqdn is never returned to clients.
"""
import re
from app.database import get_database
from app.services.ta_service import normalize_actor_core

COLLECTION = "dls_groups"

_URL_SCHEME = re.compile(r"^https?://", re.I)


def _col():
    return get_database()[COLLECTION]


def defang_host(fqdn: str | None) -> str:
    """abc.onion -> abc[.]onion (no scheme, not clickable)."""
    if not fqdn:
        return ""
    host = _URL_SCHEME.sub("", str(fqdn)).strip().rstrip("/")
    return host.replace(".", "[.]")


def _shape(doc: dict) -> dict:
    locations = doc.get("locations", [])
    hosts = [
        {
            "host": defang_host(loc.get("fqdn")),
            "title": loc.get("title"),
            "version": loc.get("version"),
            "available": bool(loc.get("available")),
            "enabled": bool(loc.get("enabled", True)),
            "lastscrape": loc.get("lastscrape"),
        }
        for loc in locations
    ]
    scrapes = [h["lastscrape"] for h in hosts if h["lastscrape"]]
    return {
        "name": doc.get("name"),
        "aliases": doc.get("aliases", []),
        "meta": doc.get("meta"),
        "flags": doc.get("flags", {}),
        "hosts": hosts,
        "hosts_up": sum(1 for h in hosts if h["available"]),
        "hosts_total": len(hosts),
        "last_scrape": max(scrapes) if scrapes else None,
        "profile_urls": doc.get("profile_urls", []),
        "source": doc.get("source"),
        "fetched_at": doc.get("fetched_at"),
    }


async def get_dls_group(group_name: str) -> dict | None:
    """Match a ransomware group name (or alias) to its leak-site record. None if not tracked."""
    core = normalize_actor_core(group_name)
    if not core:
        return None
    doc = await _col().find_one(
        {"$or": [{"name_norm": core}, {"aliases_norm": core}]},
        {"_id": 0},
    )
    return _shape(doc) if doc else None


async def get_dls_stats() -> dict:
    groups = 0
    hosts_up = 0
    hosts_total = 0
    latest = None
    async for doc in _col().find({}, {"locations.available": 1, "fetched_at": 1, "_id": 0}):
        groups += 1
        locs = doc.get("locations", [])
        hosts_total += len(locs)
        hosts_up += sum(1 for loc in locs if loc.get("available"))
        fa = doc.get("fetched_at")
        if fa and (latest is None or fa > latest):
            latest = fa
    return {"groups": groups, "hosts_up": hosts_up, "hosts_total": hosts_total, "last_synced": latest}


async def ensure_indexes() -> None:
    col = _col()
    # must match ScraperNewsRevamp dbMongo.upsert_dls_group spec (same auto name -> conflict otherwise)
    await col.create_index("name_norm", unique=True, background=True)
    await col.create_index("aliases_norm", background=True)
