"""TEMPLATE — IOC Enrichment Provider

Copy this file, rename it (e.g. vtEnrichment.py), fill in the three marked sections.
The generic enrichment schema is shared — web UI renders all providers automatically.

Generic provider entry schema (write to enrichment.providers[]):
  {
    "key":              str,   # REQUIRED — unique slug, e.g. "vt", "recorded_future", "misp"
    "name":             str,   # REQUIRED — display label shown in UI
    "updated_at":       str,   # REQUIRED — YYYY-MM-DD
    "score":            int,   # REQUIRED — 0–100 (0=clean, 100=definitely malicious)
    "verdict":          str,   # REQUIRED — "malicious" | "suspicious" | "clean" | "unknown"
    "tags":             [str], # REQUIRED — empty list if none
    "malware_families": [str], # REQUIRED — empty list if none
    "raw":              dict,  # REQUIRED — dump any provider-specific fields here
  }

Top-level enrichment document stored on each IOC:
  {
    "updated_at": str,         # date of most recent provider update
    "providers":  [entry, ...] # one entry per provider
  }

Run via cron:
  0 */6 * * * cd /path/to/ScraperNewsRevamp && python3 <yourScript>.py
"""

import sys
import yaml
import requests
from datetime import datetime, timezone
from pymongo import MongoClient

# ── CONFIG ────────────────────────────────────────────────────────────────────
# IOC types this provider can enrich. Remove types not supported by your provider.
SUPPORTED_TYPES = {"ip", "domain", "url", "sha256", "sha1", "md5", "cve", "email"}

BATCH_SIZE = 20

with open("config/config.yml", "r") as f:
    cfg = yaml.safe_load(f)

# ── SECTION 1: API KEY ────────────────────────────────────────────────────────
# Read your API key from config.yml. Add the relevant section to config.yml:
#   myprovider:
#     api_key: "YOUR_KEY_HERE"
MY_API_KEY = cfg.get("myprovider", {}).get("api_key", "")

if not MY_API_KEY:
    print("[Enrichment] No API key configured — aborting")
    sys.exit(1)

NEWS_DB_URI = (
    f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
    f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
)

# ── SECTION 2: ENRICHMENT FUNCTION ───────────────────────────────────────────
# Return a provider entry dict on success, None on failure/skip.
# Must follow the generic schema above.

def _enrich(ioc_type: str, value: str) -> dict | None:
    if ioc_type not in SUPPORTED_TYPES:
        return None
    try:
        # Call your provider API here
        resp = requests.get(
            f"https://api.myprovider.com/v1/lookup/{ioc_type}/{value}",
            headers={"Authorization": f"Bearer {MY_API_KEY}"},
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()

        # ── Map provider response → generic schema ────────────────────────────
        # score: normalize to 0-100
        raw_score = data.get("risk_score", 0)     # replace with actual field
        score     = min(100, max(0, int(raw_score)))

        # verdict
        if score >= 75:
            verdict = "malicious"
        elif score >= 25:
            verdict = "suspicious"
        elif score > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "key":              "myprovider",                      # ← change to your slug
            "name":             "My Provider Name",                # ← change to display name
            "updated_at":       datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "score":            score,
            "verdict":          verdict,
            "tags":             data.get("tags", [])[:15],         # ← map your tags field
            "malware_families": data.get("malware_families", [])[:10],  # ← map yours
            "raw": {
                # Dump any provider-specific fields here — shown in UI detail modal
                "example_field": data.get("some_provider_field"),
            },
        }
    except Exception as e:
        print(f"[MyProvider] Error {ioc_type}/{value}: {e}")
        return None


# ── SECTION 3: PROVIDER KEY ───────────────────────────────────────────────────
# Must match the "key" field returned by _enrich() above.
# Used to check if this provider already enriched an IOC.
PROVIDER_KEY = "myprovider"   # ← change to match your slug


# ── ENGINE — do not modify below ─────────────────────────────────────────────

def _already_enriched(doc: dict) -> bool:
    """True if this provider already has an entry in enrichment.providers."""
    enrichment = doc.get("enrichment", {})
    for p in enrichment.get("providers", []):
        if p.get("key") == PROVIDER_KEY:
            return True
    return False


def main() -> None:
    client = MongoClient(NEWS_DB_URI)
    try:
        col  = client[cfg["news_db"]["db"]]["iocs"]
        # Fetch IOCs of supported types — includes already partially enriched docs
        docs = list(col.find(
            {"type": {"$in": list(SUPPORTED_TYPES)}},
            {"_id": 1, "type": 1, "value": 1, "enrichment": 1},
            limit=BATCH_SIZE,
        ))

        # Filter out docs already enriched by this provider
        docs = [d for d in docs if not _already_enriched(d)]

        if not docs:
            print(f"[{PROVIDER_KEY}] All IOCs already enriched by this provider")
            return

        print(f"[{PROVIDER_KEY}] Processing {len(docs)} IOCs")
        enriched = failed = 0
        today    = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        for doc in docs:
            entry = _enrich(doc["type"], doc["value"])
            if entry is None:
                continue
            try:
                # Append provider entry to existing providers list (or create fresh)
                existing   = doc.get("enrichment", {})
                providers  = [
                    p for p in existing.get("providers", [])
                    if p.get("key") != PROVIDER_KEY  # replace if re-running
                ]
                providers.append(entry)

                col.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"enrichment": {"updated_at": today, "providers": providers}}},
                )
                enriched += 1
            except Exception as e:
                print(f"[{PROVIDER_KEY}] DB write failed {doc['type']}/{doc['value']}: {e}")
                failed += 1

        print(f"[{PROVIDER_KEY}] Done — enriched: {enriched}, failed: {failed}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
