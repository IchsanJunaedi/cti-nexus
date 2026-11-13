#!/usr/bin/env python3
"""
Purge CVEs whose tech is not in the active tech stack for a client.

Use after removing a tech stack entry — deleted CVEs may reappear if the
external scraper re-inserts them. This script hard-deletes orphaned docs and
cascades to cve_false_positives + cve_tickets.

Usage:
  python scripts/purge_orphaned_cves.py               # dry-run (preview only)
  python scripts/purge_orphaned_cves.py --execute      # actually delete
  python scripts/purge_orphaned_cves.py --client myco  # target specific client
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
NEWS_DB  = os.getenv("DB_NAME",    "news_db")
TA_DB    = os.getenv("TA_DB_NAME", "threatintel")
TS_COL   = os.getenv("TECHSTACK_COLLECTION", "techstack")


def _client_filter(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


def run(client_id: str, dry_run: bool) -> None:
    news_client = MongoClient(NEWS_URI)
    ta_client   = MongoClient(TA_URI)
    news_db     = news_client[NEWS_DB]
    ta_db       = ta_client[TA_DB]

    ts_cf = _client_filter(client_id)
    active_docs  = list(ta_db[TS_COL].find(ts_cf, {"name": 1, "_id": 0}))
    active_names = [d["name"] for d in active_docs if d.get("name")]

    print(f"\nClient     : {client_id}")
    print(f"Active tech: {active_names or '(none — all CVEs are orphaned)'}")

    cve_col    = news_db["cve_tracker"]
    fp_col     = news_db["cve_false_positives"]
    ticket_col = news_db["cve_tickets"]

    cf = _client_filter(client_id)
    if active_names:
        orphan_filter = {"tech": {"$nin": active_names}, **cf}
    else:
        orphan_filter = {**cf}

    orphan_docs = list(cve_col.find(orphan_filter, {"cve_id": 1, "tech": 1, "_id": 0}))
    cve_ids     = [d["cve_id"] for d in orphan_docs if d.get("cve_id")]

    by_tech: dict[str, int] = {}
    for d in orphan_docs:
        t = d.get("tech") or "(no tech)"
        by_tech[t] = by_tech.get(t, 0) + 1

    print(f"\nOrphaned CVEs found: {len(cve_ids)}")
    for tech, count in sorted(by_tech.items()):
        print(f"  {tech}: {count}")

    if not cve_ids:
        print("\nNothing to delete.")
        return

    if dry_run:
        print("\n[DRY RUN] No changes made. Pass --execute to delete.")
        return

    print(f"\n[EXECUTE] Deleting {len(cve_ids)} CVEs + cascade FP + tickets…")
    r1 = cve_col.delete_many(orphan_filter)
    r2 = fp_col.delete_many({"cve_id": {"$in": cve_ids}, **cf})
    r3 = ticket_col.delete_many({"cve_id": {"$in": cve_ids}, **cf})
    print(f"  cve_tracker          deleted: {r1.deleted_count}")
    print(f"  cve_false_positives  deleted: {r2.deleted_count}")
    print(f"  cve_tickets          deleted: {r3.deleted_count}")
    print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Purge orphaned CVEs not in active tech stack")
    parser.add_argument("--execute",  action="store_true", help="Actually delete (default is dry-run)")
    parser.add_argument("--client",   default="default",   help="Client ID (default: 'default')")
    args = parser.parse_args()

    if args.execute:
        confirm = input(
            "\nWARNING: This permanently deletes CVEs and their FP/ticket records.\n"
            "Type 'yes' to continue: "
        )
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            exit(0)

    run(client_id=args.client, dry_run=not args.execute)
