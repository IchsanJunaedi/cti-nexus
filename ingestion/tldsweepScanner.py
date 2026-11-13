"""Periodic domain-watch scanner — runs independently of ScraperNewsWeb.

Reads monitored_domains from news_db (added by users via ScraperNewsWeb's
Domain Watch tab), sweeps each base domain across tldsweep's 800+ TLD list,
and writes findings to domain_scan_results. Also refreshes per-domain
summary counters on monitored_domains.

tldsweep.py + tldsweep_data.py are vendored in this repo (same directory) —
see https://github.com/DarkWebInformer/TLDSweep. Do not diverge them from
upstream without good reason; re-copy on update instead of hand-editing.

Runs as a long-lived daemon (systemd, see supportFile/tldsweepScanner.service):
sweeps all watched domains, sleeps, repeats. SIGTERM/SIGINT during a sweep
finishes in-flight requests before exiting (tldsweep's own shutdown event).
"""
import argparse
import signal
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import yaml
from pymongo import MongoClient, UpdateOne
from pymongo.errors import BulkWriteError

import tldsweep
from tldsweep_data import COMMON_TLDS

with open("config/config.yml") as _f:
    _cfg = yaml.safe_load(_f)

_mc        = _cfg["news_db"]
_MONGO_URI = (
    f"mongodb://{_mc['user']}:{_mc['pass']}@{_mc['ip']}"
    f"/?authSource={_mc['db']}&authMechanism=SCRAM-SHA-256"
)
_DB_NAME = _mc["db"]

_DOMAIN_COL = "monitored_domains"
_RESULT_COL = "domain_scan_results"

THREADS           = 15   # full-recon workers (whois + tls + http per resolved tld)
DNS_THREADS       = 60
WHOIS_THREADS     = 15
TIMEOUT           = 5.0
CONNECT_TIMEOUT   = 2.0
NEWLY_REG_DAYS    = 90
SWEEP_INTERVAL_SEC = 6 * 3600  # re-sweep every 6 hours


def _get_db():
    client = MongoClient(_MONGO_URI)
    return client, client[_DB_NAME]


def _cf(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


# ── Parked-domain classification ──────────────────────────────────────────────
# Heuristic only, from data tldsweep already collects (no extra network calls):
# HTTP title/redirect/server headers + WHOIS nameservers matched against known
# parking-service signatures. Distinguishes "real site", "parking page", and
# "registered but nothing there" — instead of lumping all under alive/registered.

_PARKING_PROVIDERS = {
    "sedo":         ["sedoparking.com", "sedo.com"],
    "bodis":        ["bodis.com"],
    "parkingcrew":  ["parkingcrew.net"],
    "above.com":    ["above.com"],
    "dan.com":      ["dan.com"],
    "afternic":     ["afternic.com"],
    "hugedomains":  ["hugedomains.com"],
    "parklogic":    ["parklogic.com"],
    "fastpark":     ["fastpark.net"],
    "domainmarket": ["domainmarket.com"],
    "undeveloped":  ["undeveloped.com"],
    "voodoo":       ["voodoo.com"],
    "freeparking":  ["freeparking"],
    "godaddy":      ["godaddy.com/park", "cari.godaddy.com"],
}

_PARKING_TITLE_PATTERNS = [
    "domain for sale", "buy this domain", "this domain is parked",
    "domain is parked free", "parked free, courtesy of", "the domain has expired",
    "this web page is parked", "future home of something quite cool",
    "website coming soon", "domain name for sale", "inquire about this domain",
]


def _classify_parked(r) -> tuple[bool, str | None]:
    """Returns (is_parked, provider_or_None). r is a tldsweep ScanResult."""
    if not r.alive:
        return False, None
    http = r.http
    ns   = r.whois.name_servers if r.whois else []
    haystack = " ".join(filter(None, [
        (http.http_title or "").lower(),
        (http.redirect_url or "").lower(),
        (http.http_server or "").lower(),
        (http.https_server or "").lower(),
        " ".join(ns).lower(),
    ]))
    for provider, sigs in _PARKING_PROVIDERS.items():
        if any(sig in haystack for sig in sigs):
            return True, provider
    title = (http.http_title or "").lower()
    if any(pat in title for pat in _PARKING_TITLE_PATTERNS):
        return True, "generic"
    return False, None


PROGRESS_EVERY = 50  # print a progress line every N TLDs during the full-recon phase


def _sweep_domain(base_name: str) -> list:
    """Full tldsweep recon across COMMON_TLDS. Returns list of ScanResult."""
    t0 = time.time()
    print(f"  [tldsweep] {base_name}: DNS batch scan — {len(COMMON_TLDS)} TLDs, {DNS_THREADS} threads")
    dns_cache = tldsweep.dns_batch_scan(base_name, COMMON_TLDS, TIMEOUT, DNS_THREADS)
    resolved  = [t for t, d in dns_cache.items() if d.resolved]
    print(f"  [tldsweep] {base_name}: DNS done ({time.time()-t0:.1f}s) — "
          f"{len(resolved)} resolved. WHOIS-new-reg pass on resolved subset…")

    whois_cache = {}
    if resolved:
        whois_cache = tldsweep.whois_new_reg_scan(
            base_name, resolved, TIMEOUT, WHOIS_THREADS, NEWLY_REG_DAYS, CONNECT_TIMEOUT,
        )

    print(f"  [tldsweep] {base_name}: full recon (WHOIS+TLS+HTTP) on all {len(COMMON_TLDS)} TLDs, "
          f"{THREADS} threads — this is the slow phase, unresolved TLDs still get a live WHOIS lookup")

    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futs = {
            ex.submit(
                tldsweep.scan_domain, base_name, tld, TIMEOUT,
                True, True, True, True,
                dns_cache.get(tld), whois_cache.get(tld),
                CONNECT_TIMEOUT, NEWLY_REG_DAYS,
            ): tld
            for tld in COMMON_TLDS
        }
        for f in as_completed(futs):
            done += 1
            try:
                results.append(f.result())
            except Exception as e:
                print(f"  [tldsweep] error {base_name}.{futs[f]}: {e}")
            if done % PROGRESS_EVERY == 0 or done == len(futs):
                elapsed = time.time() - t0
                print(f"  [tldsweep] {base_name}: {done}/{len(futs)} TLDs done "
                      f"({elapsed:.0f}s elapsed, {elapsed/done:.2f}s/tld avg)")
    return results


def _scan_one(db, name: str, client_id: str) -> dict:
    dom_col = db[_DOMAIN_COL]
    res_col = db[_RESULT_COL]
    now_iso = datetime.now(timezone.utc).isoformat()

    results = _sweep_domain(name)

    ops = []
    registered = alive = newly_registered = at_risk = parked = 0
    for r in results:
        if not (r.registered or r.alive):
            continue
        is_parked, provider = _classify_parked(r)
        registered      += int(r.registered)
        alive           += int(r.alive)
        newly_registered += int(r.newly_registered)
        at_risk         += int(bool(r.risk_indicators))
        parked          += int(is_parked)
        doc = r.to_dict()
        doc["base_name"] = name
        doc["client_id"] = client_id
        doc["last_updated"] = now_iso
        doc["parked"] = is_parked
        doc["parked_provider"] = provider
        ops.append(UpdateOne(
            {"base_name": name, "tld": r.tld, **_cf(client_id)},
            {"$set": doc},
            upsert=True,
        ))

    if ops:
        try:
            res_col.bulk_write(ops, ordered=False)
        except BulkWriteError as e:
            print(f"  [tldsweep] bulk_write partial failure for {name}: {e.details.get('writeErrors', [])[:1]}")

    dom_col.update_one(
        {"name": name, **_cf(client_id)},
        {"$set": {
            "last_scan": now_iso,
            "tld_count": len(COMMON_TLDS),
            "registered_count": registered,
            "alive_count": alive,
            "newly_registered_count": newly_registered,
            "risk_count": at_risk,
            "parked_count": parked,
        }},
    )
    return {"name": name, "registered": registered, "alive": alive,
            "newly_registered": newly_registered, "risk": at_risk, "parked": parked}


def sweep_all() -> None:
    start = time.time()
    client, db = _get_db()
    try:
        pipeline = [{"$group": {"_id": "$client_id"}}]
        clients = [doc["_id"] or "default" for doc in db[_DOMAIN_COL].aggregate(pipeline)]
        if not clients:
            print("[TldSweep] No domains to scan.")
            return

        total_scanned = total_new = total_risk = 0
        for client_id in clients:
            domains = list(db[_DOMAIN_COL].find(_cf(client_id), {"name": 1}))
            print(f"[TldSweep] client={client_id}  domains={len(domains)}")
            for dom in domains:
                if tldsweep._shutdown.is_set():
                    print("[TldSweep] shutdown requested, stopping sweep.")
                    return
                result = _scan_one(db, dom["name"], client_id)
                total_scanned += 1
                total_new  += result["newly_registered"]
                total_risk += result["risk"]
                print(f"  {result['name']}: registered={result['registered']} "
                      f"alive={result['alive']} parked={result['parked']} "
                      f"newly_reg={result['newly_registered']} risk={result['risk']}")

        elapsed = time.time() - start
        print(f"[TldSweep] Done — domains={total_scanned} newly_registered={total_new} "
              f"at_risk={total_risk} elapsed={elapsed:.1f}s")
    finally:
        client.close()


def _handle_term(signum, frame):
    tldsweep._shutdown.set()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Domain watch scanner — sweeps monitored_domains across tldsweep's TLD list."
    )
    parser.add_argument("--once", action="store_true",
                        help="Run a single sweep and exit (for cron/Rundeck). "
                             "Without this flag, runs as a daemon looping every "
                             f"{SWEEP_INTERVAL_SEC // 3600}h (for systemd).")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _handle_term)

    if args.once:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        print(f"[TldSweep] Single sweep — {now_str}")
        sweep_all()
        raise SystemExit(0)

    print("[TldSweep] Domain watch daemon starting.")
    while True:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        print(f"[TldSweep] Sweep starting — {now_str}")
        try:
            sweep_all()
        except Exception as e:
            print(f"[TldSweep] Sweep error: {e}")
        if tldsweep._shutdown.is_set():
            break
        for _ in range(SWEEP_INTERVAL_SEC):
            if tldsweep._shutdown.is_set():
                break
            time.sleep(1)
        if tldsweep._shutdown.is_set():
            break
