"""OTX AlienVault pulse ingestion — writes IOCs directly to news_db.iocs collection.

Run manually or via cron. Tracks last run time in supportFile/otx_last_run.txt.
Requires config.yml to have:
  otx:
    api_key: "YOUR_OTX_API_KEY"

Add to crontab (example: every 6 hours):
  0 */6 * * * cd /path/to/ScraperNewsRevamp && python3 otxIngestion.py
"""

import sys
import yaml
import requests
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from modules.iocSchema import enrich_new_ioc, compute_ioc_confidence, compute_ioc_actionability

STATE_FILE = "supportFile/otx_last_run.txt"
OTX_BASE   = "https://otx.alienvault.com/api/v1"
PAGE_LIMIT  = 50

_OTX_TYPE_MAP = {
    "IPv4":           "ip",
    "IPv6":           "ip",
    "domain":         "domain",
    "hostname":       "domain",
    "URL":            "url",
    "URI":            "url",
    "FileHash-SHA256": "sha256",
    "FileHash-SHA1":   "sha1",
    "FileHash-MD5":    "md5",
    "email":          "email",
    "CVE":            "cve",
}

with open("config/config.yml", "r") as f:
    cfg = yaml.safe_load(f)

OTX_API_KEY = cfg.get("otx", {}).get("api_key", "")
if not OTX_API_KEY:
    print("[OTX] No api_key in config.yml under otx.api_key — aborting")
    sys.exit(1)

NEWS_DB_URI = (
    f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
    f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
)


def _load_last_run() -> str:
    try:
        with open(STATE_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        # Default: last 7 days on first run
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
        return since


def _save_last_run(ts: str) -> None:
    with open(STATE_FILE, "w") as f:
        f.write(ts)


class _RateLimited(Exception):
    """Raised when the upstream API returns HTTP 429. Caught at entrypoint for graceful exit."""


def _fetch_pulses(modified_since: str) -> list[dict]:
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    pulses  = []
    url     = f"{OTX_BASE}/pulses/subscribed"
    params  = {"modified_since": modified_since, "limit": PAGE_LIMIT}

    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After", "?")
            raise _RateLimited(f"OTX rate limit 429 (Retry-After={retry}s)")
        resp.raise_for_status()
        data = resp.json()
        pulses.extend(data.get("results", []))
        next_url = data.get("next")
        url      = next_url if next_url else None
        params   = {}  # next URL already contains params

    return pulses


def _upsert_ioc(col, ioc_type: str, value: str, pulse: dict, indicator: dict) -> None:
    today       = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    pulse_url   = f"https://otx.alienvault.com/pulse/{pulse['id']}"
    source_name = f"OTX — {pulse.get('name', 'Unknown Pulse')}"
    context     = indicator.get("description") or pulse.get("description", "")[:200]

    source_entry = {
        "url":          pulse_url,
        "source_name":  source_name,
        "feature_type": "otx",
        "doc_id":       pulse["id"],
        "first_seen":   today,
        "context":      context,
    }

    existing = col.find_one({"type": ioc_type, "value": value})
    if existing:
        url_set = {s.get("url") for s in existing.get("sources", [])}
        if pulse_url not in url_set:
            now = datetime.now(timezone.utc)
            updated = dict(existing)
            updated["sources"] = existing.get("sources", []) + [source_entry]
            updated["last_seen"] = today
            updated["seen_count"] = existing.get("seen_count", 1) + 1
            score = compute_ioc_confidence(updated, now)
            updated["confidence_score"] = score
            act = compute_ioc_actionability(updated, now)
            col.update_one(
                {"type": ioc_type, "value": value},
                {
                    "$push": {"sources": source_entry},
                    "$addToSet": {"pulse_ids": pulse["id"]},
                    "$inc":  {"seen_count": 1},
                    "$set":  {
                        "last_seen": today,
                        "confidence_score": score,
                        "confidence_decayed_at": now,
                        **act,
                    },
                },
            )
        else:
            col.update_one(
                {"type": ioc_type, "value": value},
                {"$addToSet": {"pulse_ids": pulse["id"]}},
            )
    else:
        new_doc = {
            "type":       ioc_type,
            "value":      value,
            "sources":    [source_entry],
            "first_seen": today,
            "last_seen":  today,
            "seen_count": 1,
            "tags":       list(pulse.get("tags", [])),
            "pulse_ids":  [pulse["id"]],
        }
        col.insert_one(enrich_new_ioc(new_doc))


def main() -> None:
    modified_since = _load_last_run()
    run_start      = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    print(f"[OTX] Fetching pulses modified since {modified_since}")
    pulses = _fetch_pulses(modified_since)
    print(f"[OTX] Got {len(pulses)} pulses")

    if not pulses:
        _save_last_run(run_start)
        return

    client = MongoClient(NEWS_DB_URI)
    try:
        col        = client[cfg["news_db"]["db"]]["iocs"]
        processed  = 0
        skipped    = 0

        for pulse in pulses:
            for indicator in pulse.get("indicators", []):
                otx_type  = indicator.get("type", "")
                ioc_type  = _OTX_TYPE_MAP.get(otx_type)
                value     = (indicator.get("indicator") or "").strip()
                if not ioc_type or not value:
                    skipped += 1
                    continue
                try:
                    _upsert_ioc(col, ioc_type, value, pulse, indicator)
                    processed += 1
                except Exception as e:
                    print(f"[OTX] Upsert failed {ioc_type}/{value}: {e}")
                    skipped += 1

        print(f"[OTX] Done — processed: {processed}, skipped: {skipped}")
    finally:
        client.close()

    _save_last_run(run_start)


if __name__ == "__main__":
    try:
        main()
    except _RateLimited as e:
        # State (otx_last_run.txt) NOT advanced → next cron resumes same window.
        print(f"[OTX] {e} — stopping gracefully, progress preserved for next run.")
        sys.exit(0)
