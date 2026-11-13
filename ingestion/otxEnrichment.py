"""OTX AlienVault + AbuseIPDB IOC enrichment.

Reads news_db.iocs, enriches IOCs missing a provider entry, writes generic enrichment schema.

Generic enrichment schema (per provider entry in enrichment.providers[]):
  {
    "key":              str,        # provider slug — "otx", "vt", "abuseipdb", etc.
    "name":             str,        # display label
    "updated_at":       str,        # YYYY-MM-DD
    "score":            int,        # 0–100 normalized confidence/abuse/reputation
    "verdict":          str,        # "malicious" | "suspicious" | "clean" | "unknown"
    "tags":             [str],      # freeform labels
    "malware_families": [str],      # optional
    "raw":              dict,       # provider-specific extras — dump anything here
  }

Top-level enrichment document:
  {
    "updated_at": str,              # date of latest provider update
    "providers":  [provider_entry]
  }

Add crontab (every 6h):
  0 */6 * * * cd /path/to/ScraperNewsRevamp && python3 otxEnrichment.py
Requires config.yml:
  otx:
    api_key: ""
  abuseipdb:
    api_key: ""
"""

import sys
import yaml
import requests
from datetime import datetime, timezone
from pymongo import MongoClient

BATCH_SIZE = 20

_OTX_SECTION = {
    "ip":     "IPv4",
    "domain": "domain",
    "url":    "url",
    "sha256": "file",
    "sha1":   "file",
    "md5":    "file",
    "cve":    "cve",
}

with open("config/config.yml", "r") as f:
    cfg = yaml.safe_load(f)

OTX_API_KEY   = cfg.get("otx", {}).get("api_key", "")
ABUSEIPDB_KEY = cfg.get("abuseipdb", {}).get("api_key", "")

if not OTX_API_KEY and not ABUSEIPDB_KEY:
    print("[Enrichment] No API keys configured in config.yml — aborting")
    sys.exit(1)

NEWS_DB_URI = (
    f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
    f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
)


class _RateLimited(Exception):
    """Raised on HTTP 429 from OTX/AbuseIPDB. Caught in main to stop the batch gracefully."""


def _otx_verdict(reputation: int, pulse_count: int) -> str:
    if reputation < 0 or pulse_count >= 5:
        return "malicious"
    if pulse_count >= 1:
        return "suspicious"
    return "unknown"


def _enrich_otx(ioc_type: str, value: str) -> dict | None:
    section = _OTX_SECTION.get(ioc_type)
    if not section or not OTX_API_KEY:
        return None
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=15,
        )
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After", "?")
            raise _RateLimited(f"OTX rate limit 429 (Retry-After={retry}s)")
        if resp.status_code != 200:
            return None
        data          = resp.json()
        pulse_count   = data.get("pulse_info", {}).get("count", 0)
        reputation    = data.get("reputation", 0)
        malware_fams  = [
            m.get("display_name") or m.get("id", "")
            for m in data.get("malware_families", [])
        ][:10]
        tags = data.get("pulse_info", {}).get("tags", [])[:15]

        # Normalize reputation (-N…+N) → 0-100 score (inverted: lower rep = higher threat score)
        raw_rep = max(-10, min(10, reputation))
        score   = int(((raw_rep * -1) + 10) / 20 * 100) if pulse_count > 0 else 0

        # Collect adversary attributions from top-level field and per-pulse adversary
        adversaries: list[str] = []
        top_adv = (data.get("adversary") or "").strip()
        if top_adv:
            adversaries.append(top_adv)
        for pulse in data.get("pulse_info", {}).get("pulses", []):
            adv = (pulse.get("adversary") or "").strip()
            if adv and adv not in adversaries:
                adversaries.append(adv)

        return {
            "key":              "otx",
            "name":             "OTX AlienVault",
            "updated_at":       datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "score":            score,
            "verdict":          _otx_verdict(reputation, pulse_count),
            "tags":             tags,
            "malware_families": malware_fams,
            "adversaries":      adversaries,
            "raw": {
                "pulse_count": pulse_count,
                "reputation":  reputation,
            },
        }
    except _RateLimited:
        raise
    except Exception as e:
        print(f"[OTX] Error {ioc_type}/{value}: {e}")
        return None


def _enrich_abuseipdb(ip: str) -> dict | None:
    if not ABUSEIPDB_KEY:
        return None
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=15,
        )
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After", "?")
            raise _RateLimited(f"AbuseIPDB rate limit 429 (Retry-After={retry}s)")
        if resp.status_code != 200:
            return None
        d     = resp.json().get("data", {})
        score = d.get("abuseConfidenceScore", 0)

        if score >= 75:
            verdict = "malicious"
        elif score >= 25:
            verdict = "suspicious"
        elif score > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "key":              "abuseipdb",
            "name":             "AbuseIPDB",
            "updated_at":       datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "score":            score,
            "verdict":          verdict,
            "tags":             [],
            "malware_families": [],
            "raw": {
                "total_reports": d.get("totalReports", 0),
                "country_code":  d.get("countryCode", ""),
                "isp":           d.get("isp", ""),
                "usage_type":    d.get("usageType", ""),
            },
        }
    except _RateLimited:
        raise
    except Exception as e:
        print(f"[AbuseIPDB] Error {ip}: {e}")
        return None


def _build_enrichment(ioc_type: str, value: str) -> dict:
    providers = []

    otx = _enrich_otx(ioc_type, value)
    if otx:
        providers.append(otx)

    if ioc_type == "ip":
        abuse = _enrich_abuseipdb(value)
        if abuse:
            providers.append(abuse)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return {"updated_at": today, "providers": providers}


def main() -> None:
    client = MongoClient(NEWS_DB_URI)
    try:
        col  = client[cfg["news_db"]["db"]]["iocs"]
        docs = list(col.find(
            {"enrichment": {"$exists": False}, "type": {"$in": list(_OTX_SECTION.keys())}},
            {"_id": 1, "type": 1, "value": 1},
            limit=BATCH_SIZE,
        ))

        if not docs:
            print("[Enrichment] All IOCs already enriched")
            return

        print(f"[Enrichment] Processing {len(docs)} IOCs")
        enriched = failed = 0

        for doc in docs:
            try:
                enrichment = _build_enrichment(doc["type"], doc["value"])
            except _RateLimited as e:
                # Stop hammering the API. Unenriched docs stay {enrichment:$exists:false} → next cron retries.
                print(f"[Enrichment] {e} — stopping batch gracefully, {enriched} done. Resume next cron.")
                break
            try:
                update: dict = {"$set": {"enrichment": enrichment}}
                # Collect adversaries from OTX result and link to ioc.threat_actors
                otx_entry = next((p for p in enrichment.get("providers", []) if p["key"] == "otx"), None)
                adversaries = otx_entry.get("adversaries", []) if otx_entry else []
                if adversaries:
                    update["$addToSet"] = {"threat_actors": {"$each": adversaries}}
                    print(f"[OTX] TA attributed {doc['type']}/{doc['value']}: {adversaries}")
                col.update_one({"_id": doc["_id"]}, update)
                enriched += 1
            except Exception as e:
                print(f"[Enrichment] DB write failed {doc['type']}/{doc['value']}: {e}")
                failed += 1

        print(f"[Enrichment] Done — enriched: {enriched}, failed: {failed}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
