"""Periodic brand-watch scanner — runs independently of ScraperNewsWeb.

Reads monitored_brands from news_db (added by users via ScraperNewsWeb's
Brand Watch tab), grabs each domain's favicon and hashes it (reusing
tldsweep's grab_favicon_hash, MMH3/Shodan-compatible), searches Shodan for
other hosts serving the same favicon hash (http.favicon.hash), and writes
matches to brand_favicon_matches. Also refreshes per-domain summary
counters on monitored_brands.

tldsweep.py is vendored in this repo (same directory) — see
https://github.com/DarkWebInformer/TLDSweep. Do not diverge it from
upstream without good reason; re-copy on update instead of hand-editing.

Runs as a long-lived daemon (systemd, see supportFile/faviconWatchScanner.service):
sweeps all watched brands, sleeps, repeats.
"""
import argparse
import signal
import time
from datetime import datetime, timezone

import requests
import yaml
from pymongo import MongoClient, UpdateOne
from pymongo.errors import BulkWriteError

import tldsweep

with open("config/config.yml") as _f:
    _cfg = yaml.safe_load(_f)

_mc        = _cfg["news_db"]
_MONGO_URI = (
    f"mongodb://{_mc['user']}:{_mc['pass']}@{_mc['ip']}"
    f"/?authSource={_mc['db']}&authMechanism=SCRAM-SHA-256"
)
_DB_NAME    = _mc["db"]
_SHODAN_KEY = (_cfg.get("shodan") or {}).get("api_key", "")

_BRAND_COL = "monitored_brands"
_MATCH_COL = "brand_favicon_matches"

FAVICON_TIMEOUT    = 5.0
SHODAN_TIMEOUT     = 15.0
SHODAN_PAGE_SIZE   = 100   # Shodan's fixed page size for host search
SWEEP_INTERVAL_SEC = 3600  # re-sweep every 1 hour — far cheaper per-domain than a TLD sweep

_shutdown = False


def _get_db():
    client = MongoClient(_MONGO_URI)
    return client, client[_DB_NAME]


def _cf(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


def _shodan_favicon_search(favicon_hash: str) -> list[dict]:
    """Query Shodan's host search for http.favicon.hash:<hash>. Requires a
    Shodan membership with query credits (not available on the free tier)."""
    if not _SHODAN_KEY:
        print("  [faviconwatch] no shodan api_key configured — skipping search")
        return []
    matches = []
    page = 1
    while True:
        try:
            resp = requests.get(
                "https://api.shodan.io/shodan/host/search",
                params={
                    "key": _SHODAN_KEY,
                    "query": f"http.favicon.hash:{favicon_hash}",
                    "page": page,
                },
                timeout=SHODAN_TIMEOUT,
            )
            if resp.status_code == 401:
                print("  [faviconwatch] shodan 401 — check api_key / membership tier")
                return matches
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            print(f"  [faviconwatch] shodan search error: {e}")
            return matches

        page_matches = data.get("matches", [])
        matches.extend(page_matches)
        total = data.get("total", 0)
        if len(matches) >= total or len(page_matches) < SHODAN_PAGE_SIZE:
            break
        page += 1
    return matches


def _scan_one(db, name: str, client_id: str) -> dict:
    brand_col = db[_BRAND_COL]
    match_col = db[_MATCH_COL]
    now_iso   = datetime.now(timezone.utc).isoformat()

    favicon_hash = tldsweep.grab_favicon_hash(name, FAVICON_TIMEOUT)
    if not favicon_hash:
        brand_col.update_one(
            {"name": name, **_cf(client_id)},
            {"$set": {"last_scan": now_iso, "favicon_hash": None}},
        )
        return {"name": name, "hash": None, "matches": 0, "new": 0, "suspicious": 0}

    shodan_matches = _shodan_favicon_search(favicon_hash) if not favicon_hash.startswith("md5:") else []

    ops = []
    new_count = suspicious_count = 0
    for m in shodan_matches:
        ip_str    = m.get("ip_str", "")
        port      = m.get("port", 0)
        hostnames = m.get("hostnames", []) or []
        org       = m.get("org")
        location  = m.get("location", {}) or {}
        is_own    = any(name in h.lower() for h in hostnames) if hostnames else False
        if not is_own:
            suspicious_count += 1

        ops.append(UpdateOne(
            {"base_name": name, "ip_str": ip_str, "port": port, **_cf(client_id)},
            {
                "$set": {
                    "hostnames": hostnames,
                    "org": org,
                    "country": location.get("country_name"),
                    "city": location.get("city"),
                    "favicon_hash": favicon_hash,
                    "is_own_domain": is_own,
                    "last_seen": now_iso,
                    "client_id": client_id,
                },
                "$setOnInsert": {
                    "first_seen": now_iso,
                    "newly_seen": True,
                    "acknowledged": False,
                    "ack_by": None,
                    "ack_date": None,
                },
            },
            upsert=True,
        ))

    if ops:
        try:
            result = match_col.bulk_write(ops, ordered=False)
            new_count = result.upserted_count
            # existing (matched, not upserted) docs keep whatever newly_seen they
            # already had — clear the flag once a match has been seen on a
            # later scan so "new" reflects only this run's brand-new hits
            if result.matched_count:
                match_col.update_many(
                    {"base_name": name, "last_seen": now_iso,
                     "_id": {"$nin": list(result.upserted_ids.values())}, **_cf(client_id)},
                    {"$set": {"newly_seen": False}},
                )
        except BulkWriteError as e:
            print(f"  [faviconwatch] bulk_write partial failure for {name}: {e.details.get('writeErrors', [])[:1]}")

    brand_col.update_one(
        {"name": name, **_cf(client_id)},
        {"$set": {
            "last_scan": now_iso,
            "favicon_hash": favicon_hash,
            "match_count": len(shodan_matches),
            "new_match_count": new_count,
            "suspicious_count": suspicious_count,
        }},
    )
    return {"name": name, "hash": favicon_hash, "matches": len(shodan_matches),
            "new": new_count, "suspicious": suspicious_count}


def sweep_all() -> None:
    start = time.time()
    client, db = _get_db()
    try:
        pipeline = [{"$group": {"_id": "$client_id"}}]
        clients = [doc["_id"] or "default" for doc in db[_BRAND_COL].aggregate(pipeline)]
        if not clients:
            print("[FaviconWatch] No brands to scan.")
            return

        total_scanned = total_new = total_suspicious = 0
        for client_id in clients:
            brands = list(db[_BRAND_COL].find(_cf(client_id), {"name": 1}))
            print(f"[FaviconWatch] client={client_id}  brands={len(brands)}")
            for b in brands:
                if _shutdown:
                    print("[FaviconWatch] shutdown requested, stopping sweep.")
                    return
                result = _scan_one(db, b["name"], client_id)
                total_scanned += 1
                total_new       += result["new"]
                total_suspicious += result["suspicious"]
                print(f"  {result['name']}: hash={result['hash']} "
                      f"matches={result['matches']} new={result['new']} suspicious={result['suspicious']}")

        elapsed = time.time() - start
        print(f"[FaviconWatch] Done — brands={total_scanned} new_matches={total_new} "
              f"suspicious={total_suspicious} elapsed={elapsed:.1f}s")
    finally:
        client.close()


def _handle_term(signum, frame):
    global _shutdown
    _shutdown = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Brand watch scanner — favicon hash + Shodan search over monitored_brands."
    )
    parser.add_argument("--once", action="store_true",
                        help="Run a single sweep and exit (for cron/Rundeck). "
                             "Without this flag, runs as a daemon looping every "
                             f"{SWEEP_INTERVAL_SEC // 60}m (for systemd).")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _handle_term)
    signal.signal(signal.SIGINT, _handle_term)

    if args.once:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        print(f"[FaviconWatch] Single sweep — {now_str}")
        sweep_all()
        raise SystemExit(0)

    print("[FaviconWatch] Brand watch daemon starting.")
    while True:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        print(f"[FaviconWatch] Sweep starting — {now_str}")
        try:
            sweep_all()
        except Exception as e:
            print(f"[FaviconWatch] Sweep error: {e}")
        if _shutdown:
            break
        for _ in range(SWEEP_INTERVAL_SEC):
            if _shutdown:
                break
            time.sleep(1)
        if _shutdown:
            break
