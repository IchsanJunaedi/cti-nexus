"""
CVE POC Enrichment Script
─────────────────────────
Queries news_db.cve_tracker, calls search_poc() for each CVE,
then updates poc_available + pocs fields in MongoDB.

Usage:
    python scripts/update_cve_poc.py              # only checks CVEs with poc_available=False
    python scripts/update_cve_poc.py --force      # re-checks all CVEs (including confirmed ones)
    python scripts/update_cve_poc.py --dry-run    # print what would change, no DB writes

Fill in search_poc() below with your own POC discovery logic.
"""

import sys, os, argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pymongo import MongoClient
from datetime import date
import time, yaml

# ── Config ───────────────────────────────��────────────────
with open("config/config.yml", 'r') as f:
    cfg = yaml.safe_load(f)

nc  = cfg['news_db']
URI = f"mongodb://{nc['user']}:{nc['pass']}@{nc['ip']}/?authSource={nc['db']}"

# ── POC schema reference ──────────────────────────────────
# Each POC object must follow this shape:
#
#   {
#       "url":    "https://github.com/user/repo",
#       "source": "GitHub",           # GitHub | ExploitDB | PacketStorm | etc.
#       "type":   "poc"               # poc | exploit | metasploit_module | nuclei_template
#   }
#
# Return an empty list [] if no POC found for the CVE.

def search_poc(cve_id: str, cve_doc: dict) -> list[dict]:
    """
    YOUR LOGIC GOES HERE.

    Parameters
    ----------
    cve_id  : str   e.g. "CVE-2024-3400"
    cve_doc : dict  full MongoDB document — includes tech, summary, cvss_vector, etc.
                    useful context if your search needs product name or severity

    Returns
    -------
    list[dict]  list of POC objects, or [] if none found
    """
    # ── placeholder — replace with your implementation ───
    # Examples of what you might do here:
    #   - Search GitHub API for repos matching the CVE ID
    #   - Scrape ExploitDB for matching entries
    #   - Query Nuclei templates index
    #   - Check a threat-intel feed / API

    pocs = []
    return pocs


# ── Main ──────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force",   action="store_true", help="Re-check CVEs that already have poc_available=True")
    parser.add_argument("--dry-run", action="store_true", help="Print changes without writing to DB")
    args = parser.parse_args()

    client = MongoClient(URI)
    col    = client[nc['db']]['cve_tracker']

    query = {} if args.force else {"poc_available": {"$ne": True}}
    total = col.count_documents(query)
    print(f"Checking {total} CVE(s) (force={args.force}, dry_run={args.dry_run})\n")

    updated = 0
    skipped = 0

    for doc in col.find(query, {"_id": 1, "cve_id": 1, "tech": 1, "summary": 1,
                                "cve_score": 1, "cve_severity": 1, "cvss_vector": 1,
                                "poc_available": 1, "pocs": 1}):
        cve_id = doc['cve_id']
        print(f"[{cve_id}] ({doc.get('tech','?')}) score={doc.get('cve_score','?')} ...", end=" ", flush=True)

        pocs = search_poc(cve_id, doc)

        if not pocs:
            print("no POC")
            skipped += 1
            time.sleep(0.5)   # be polite to whatever API you call
            continue

        print(f"FOUND {len(pocs)} POC(s)")
        for p in pocs:
            print(f"      └ [{p.get('type','poc')}] {p.get('source','')}  {p['url']}")

        if not args.dry_run:
            col.update_one(
                {"_id": doc["_id"]},
                {"$set": {
                    "poc_available": True,
                    "pocs":          pocs,
                    "last_updated":  str(date.today()),
                }},
            )
        updated += 1
        time.sleep(0.5)

    client.close()
    print(f"\nDone — updated: {updated}  no POC: {skipped}  total checked: {total}")
    if args.dry_run:
        print("(dry-run: no changes written to DB)")


if __name__ == "__main__":
    main()
