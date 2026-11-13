#!/usr/bin/env python3
"""
Fix CVE + techstack duplicates caused by missing client_id on legacy docs.

Root cause: legacy docs have no client_id field; newer docs have client_id="default".
_client_filter("default") matches BOTH, so same entry appears twice in the UI.

What this script does per collection:
  1. Find keys that have BOTH a legacy doc (no client_id) and a "default" doc.
     → Delete the legacy doc (true duplicate; the "default" doc is canonical).
  2. Set client_id="default" on all remaining legacy docs.

Collections handled:
  news_db:    cve_tracker, cve_tickets
  threatintel: techstack

Run once per environment, then restart the service.
  python scripts/fix_cve_duplicates.py
  python scripts/fix_cve_duplicates.py --dry-run   # count only, no writes

After this script completes, techstack_service._client_filter can be simplified
to remove the $exists: False fallback (same as cve_service already does).
"""

import argparse
import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

NEWS_URI = (
    f"mongodb://{os.getenv('MONGO_USER')}:{os.getenv('MONGO_PASS')}"
    f"@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/"
    f"?authSource={os.getenv('DB_NAME')}"
)
TA_URI = (
    f"mongodb://{os.getenv('TA_MONGO_USER')}:{os.getenv('TA_MONGO_PASS')}"
    f"@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/"
    f"?authSource={os.getenv('TA_DB_NAME')}&authMechanism=SCRAM-SHA-256"
)
NEWS_DB     = os.getenv("DB_NAME",    "news_db")
TA_DB       = os.getenv("TA_DB_NAME", "threatintel")
CVE_COL     = "cve_tracker"
TICKET_COL  = "cve_tickets"
TS_COL      = os.getenv("TECHSTACK_COLLECTION", "techstack")


def _fix_collection(col, key_field: str, dry_run: bool) -> None:
    legacy_ids  = {d[key_field] for d in col.find({"client_id": {"$exists": False}}, {key_field: 1, "_id": 0}) if d.get(key_field)}
    default_ids = {d[key_field] for d in col.find({"client_id": "default"},          {key_field: 1, "_id": 0}) if d.get(key_field)}
    true_dups   = legacy_ids & default_ids

    print(f"  Legacy docs (no client_id):    {len(legacy_ids)}")
    print(f"  Docs with client_id='default': {len(default_ids)}")
    print(f"  True duplicates:               {len(true_dups)}")

    if true_dups:
        if dry_run:
            print(f"  [DRY RUN] Would delete {len(true_dups)} legacy duplicate docs.")
        else:
            res = col.delete_many({key_field: {"$in": list(true_dups)}, "client_id": {"$exists": False}})
            print(f"  Deleted {res.deleted_count} legacy duplicate docs.")

    remaining = len(legacy_ids) - len(true_dups)
    if remaining > 0:
        if dry_run:
            print(f"  [DRY RUN] Would set client_id='default' on {remaining} legacy docs.")
        else:
            res = col.update_many({"client_id": {"$exists": False}}, {"$set": {"client_id": "default"}})
            print(f"  Migrated {res.modified_count} legacy docs → client_id='default'.")
    else:
        print("  No remaining legacy docs to migrate.")

    leftover = col.count_documents({"client_id": {"$exists": False}})
    print(f"  Remaining legacy docs: {leftover}  ← should be 0")


def main():
    parser = argparse.ArgumentParser(description="Fix duplicate docs in cve_tracker, cve_tickets, techstack")
    parser.add_argument("--dry-run", action="store_true", help="Count only, no writes")
    args = parser.parse_args()

    news_client = MongoClient(NEWS_URI)
    ta_client   = MongoClient(TA_URI)

    print(f"\n── cve_tracker (news_db) ────────────────────────────")
    _fix_collection(news_client[NEWS_DB][CVE_COL], "cve_id", args.dry_run)

    print(f"\n── cve_tickets (news_db) ────────────────────────────")
    _fix_collection(news_client[NEWS_DB][TICKET_COL], "cve_id", args.dry_run)

    print(f"\n── techstack (threatintel) ──────────────────────────")
    _fix_collection(ta_client[TA_DB][TS_COL], "name", args.dry_run)

    news_client.close()
    ta_client.close()
    if not args.dry_run:
        print("\nDone. Restart ScraperNewsWeb service.")
        print("After verifying, techstack_service._client_filter can drop the $exists fallback.")


if __name__ == "__main__":
    main()
