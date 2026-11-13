#!/usr/bin/env python3
"""
Migrate client-scoped data from one client_id to another.

Usage:
  python scripts/migrate_client_data.py --from default --to mil_command
  python scripts/migrate_client_data.py --from default --to mil_command --move   # also clears source docs
  python scripts/migrate_client_data.py --from default --to mil_command --dry-run

Collections migrated (all client-scoped):
  news_db:      pirs, pir_notes, rfis, iocs, cve_tracker, cve_false_positives, cve_tickets
  threatintel:  techstack
"""

import argparse
import os
import sys
from pymongo import MongoClient, UpdateMany
from dotenv import load_dotenv

load_dotenv()

# ── Connection ────────────────────────────────────────────────

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
NEWS_DB   = os.getenv("DB_NAME",    "news_db")
TA_DB     = os.getenv("TA_DB_NAME", "threatintel")

# Collection names from env (with fallbacks matching ScraperNewsWeb defaults)
COLLECTIONS = {
    "news_db": [
        os.getenv("PIR_COLLECTION",       "pirs"),
        os.getenv("PIR_NOTES_COLLECTION", "pir_notes"),
        os.getenv("RFI_COLLECTION",       "rfis"),
        os.getenv("IOC_COLLECTION",       "iocs"),
        "cve_tracker",
        "cve_false_positives",
        "cve_tickets",
    ],
    "threatintel": [
        os.getenv("TECHSTACK_COLLECTION",    "techstack"),
        os.getenv("TA_WATCHLIST_COLLECTION", "ta_watchlist"),
    ],
}


def _client_filter(from_id: str) -> dict:
    """Match docs belonging to from_id, including legacy docs with no client_id (=default)."""
    if from_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": from_id}


def migrate_collection(col, col_name: str, from_id: str, to_id: str, move: bool, dry_run: bool) -> int:
    filt  = _client_filter(from_id)
    total = col.count_documents(filt)
    if total == 0:
        print(f"  {col_name}: 0 docs — skip")
        return 0

    if dry_run:
        print(f"  {col_name}: {total} docs would be {'moved' if move else 'copied'} → client_id='{to_id}'")
        return total

    # Write to_id docs: update docs that already have to_id OR insert copies
    # Strategy: updateMany sets client_id=to_id on a COPY by insert, then clears source if --move
    # Simplest: for small sets, iterate and upsert; for large sets, use aggregation pipeline update

    # For cve_tracker: compound unique (cve_id, client_id) — use upsert per doc
    if col_name == "cve_tracker":
        copied = 0
        for doc in col.find(filt):
            doc.pop("_id")
            doc["client_id"] = to_id
            col.update_one(
                {"cve_id": doc["cve_id"], "client_id": to_id},
                {"$set": doc},
                upsert=True,
            )
            copied += 1
        action = "Copied"
    else:
        # For other collections: bulk updateMany — sets client_id on matched docs
        # (creates the to_id view from existing docs by updating their client_id)
        # If copy (not move): first duplicate docs with new client_id
        if not move:
            # Duplicate: insert copies with to_id
            docs = list(col.find(filt))
            if docs:
                for doc in docs:
                    doc.pop("_id")
                    doc["client_id"] = to_id
                col.insert_many(docs, ordered=False)
        else:
            # Move: just set client_id on existing docs
            col.update_many(filt, {"$set": {"client_id": to_id}})
        copied = total
        action = "Moved" if move else "Copied"

    # If move and not cve_tracker (already handled above): clear source docs
    if move and col_name != "cve_tracker":
        pass  # already moved via update_many above
    elif move and col_name == "cve_tracker":
        # Remove source docs that are now duplicated
        col.delete_many({"client_id": from_id})

    print(f"  {col_name}: {action} {copied} docs → client_id='{to_id}'")
    return copied


def main():
    parser = argparse.ArgumentParser(description="Migrate CTI platform data between client IDs")
    parser.add_argument("--from",  dest="from_id", required=True, help="Source client_id (e.g. default)")
    parser.add_argument("--to",    dest="to_id",   required=True, help="Target client_id (e.g. mil_command)")
    parser.add_argument("--move",    action="store_true", help="Remove source docs after copy (default: copy only)")
    parser.add_argument("--dry-run", action="store_true", help="Count affected docs without writing")
    args = parser.parse_args()

    if args.from_id == args.to_id:
        print("ERROR: --from and --to must be different")
        sys.exit(1)

    print(f"\nMigration: '{args.from_id}' → '{args.to_id}'")
    print(f"Mode: {'DRY RUN' if args.dry_run else ('MOVE' if args.move else 'COPY')}\n")

    if not args.dry_run and args.move:
        confirm = input(f"WARNING: This will move (not copy) all data from '{args.from_id}' to '{args.to_id}'.\nType 'yes' to continue: ")
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            sys.exit(0)

    news_client = MongoClient(NEWS_URI)
    ta_client   = MongoClient(TA_URI)

    total = 0

    print("── news_db ───────────────────────────────────────")
    news_db = news_client[NEWS_DB]
    for col_name in COLLECTIONS["news_db"]:
        col   = news_db[col_name]
        total += migrate_collection(col, col_name, args.from_id, args.to_id, args.move, args.dry_run)

    print("\n── threatintel ───────────────────────────────────")
    ta_db = ta_client[TA_DB]
    for col_name in COLLECTIONS["threatintel"]:
        col   = ta_db[col_name]
        total += migrate_collection(col, col_name, args.from_id, args.to_id, args.move, args.dry_run)

    news_client.close()
    ta_client.close()

    print(f"\n{'[DRY RUN] Would migrate' if args.dry_run else 'Migrated'} {total} total docs.")
    print("Done.\n")


if __name__ == "__main__":
    main()
