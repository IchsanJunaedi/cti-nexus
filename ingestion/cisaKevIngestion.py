"""CISA Known Exploited Vulnerabilities (KEV) catalog ingestion — writes full catalog
directly to news_db.cisa_kev_catalog collection. Consumed by ScraperNewsWeb's CVE Tracker
"CISA KEV" sub-tab, independent of per-client tech-stack CVE matching.

Run manually or via cron.

Add to crontab (example: once per day):
  0 6 * * * cd /path/to/ScraperNewsRevamp && python3 cisaKevIngestion.py
"""

import sys
import yaml
import requests
from datetime import datetime, timezone
from pymongo import MongoClient, UpdateOne

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
}
CATALOG_COLLECTION = "cisa_kev_catalog"
TRACKER_COLLECTION = "cve_tracker"

with open("config/config.yml", "r") as f:
    cfg = yaml.safe_load(f)

NEWS_DB_URI = (
    f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
    f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
)


def fetch_kev_catalog() -> list[dict]:
    resp = requests.get(CISA_KEV_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


def main() -> None:
    print("[CISA KEV] Fetching catalog")
    vulnerabilities = fetch_kev_catalog()
    print(f"[CISA KEV] Got {len(vulnerabilities)} entries")

    if not vulnerabilities:
        return

    client = MongoClient(NEWS_DB_URI)
    try:
        db          = client[cfg['news_db']['db']]
        catalog_col = db[CATALOG_COLLECTION]
        tracker_col = db[TRACKER_COLLECTION]

        catalog_col.create_index("cve_id", unique=True, background=True)
        catalog_col.create_index("date_added", background=True)

        tracked_cve_ids = {
            doc['cve_id'].upper()
            for doc in tracker_col.find({}, {'cve_id': 1, '_id': 0})
            if doc.get('cve_id')
        }
        print(f"[CISA KEV] Loaded {len(tracked_cve_ids)} tracked CVE IDs for cross-reference")

        now_iso = datetime.now(timezone.utc).isoformat()
        ops = []
        for vuln in vulnerabilities:
            cve_id = (vuln.get('cveID') or '').strip().upper()
            if not cve_id:
                continue

            doc = {
                "cve_id":              cve_id,
                "vendor_project":      vuln.get('vendorProject', ''),
                "product":             vuln.get('product', ''),
                "vulnerability_name":  vuln.get('vulnerabilityName', ''),
                "date_added":          vuln.get('dateAdded', ''),
                "short_description":   vuln.get('shortDescription', ''),
                "required_action":     vuln.get('requiredAction', ''),
                "due_date":            vuln.get('dueDate', ''),
                "known_ransomware_use": vuln.get('knownRansomwareCampaignUse', 'Unknown'),
                "notes":               vuln.get('notes', ''),
                "cwes":                vuln.get('cwes', []),
                "matched_tracker":     cve_id in tracked_cve_ids,
                "last_synced":         now_iso,
            }
            ops.append(UpdateOne({"cve_id": cve_id}, {"$set": doc}, upsert=True))

        if ops:
            result = catalog_col.bulk_write(ops, ordered=False)
            print(f"[CISA KEV] Upserted {result.upserted_count} new, matched {result.modified_count} existing")

        # Drop stale entries no longer in the upstream catalog
        current_ids = [v.get('cveID', '').strip().upper() for v in vulnerabilities if v.get('cveID')]
        deleted = catalog_col.delete_many({"cve_id": {"$nin": current_ids}})
        if deleted.deleted_count:
            print(f"[CISA KEV] Removed {deleted.deleted_count} stale entries no longer in catalog")

        matched_count = sum(1 for v in vulnerabilities if (v.get('cveID') or '').strip().upper() in tracked_cve_ids)
        print(f"[CISA KEV] Done — {len(vulnerabilities)} total, {matched_count} matched to tracked CVEs")
    finally:
        client.close()


if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.RequestException as e:
        print(f"[CISA KEV] Request failed: {e} — will retry next run.")
        sys.exit(0)
