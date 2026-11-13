#!/usr/bin/env python3
"""
Backfill client_id="default" on ta_watchlist documents that predate per-client isolation.

Usage:
  python scripts/migrate_watchlist_client.py
  python scripts/migrate_watchlist_client.py --dry-run
"""

import argparse
import os
import sys
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

TA_URI = (
    f"mongodb://{os.getenv('TA_MONGO_USER')}:{os.getenv('TA_MONGO_PASS')}"
    f"@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/"
    f"?authSource={os.getenv('TA_DB_NAME')}&authMechanism=SCRAM-SHA-256"
)
TA_DB = os.getenv("TA_DB_NAME", "threatintel")
TA_WATCHLIST_COLLECTION = os.getenv("TA_WATCHLIST_COLLECTION", "ta_watchlist")


def main():
    parser = argparse.ArgumentParser(description="Backfill client_id on ta_watchlist docs")
    parser.add_argument("--dry-run", action="store_true", help="Print what would change without writing")
    args = parser.parse_args()

    client = MongoClient(TA_URI)
    col = client[TA_DB][TA_WATCHLIST_COLLECTION]

    query = {"client_id": {"$exists": False}}
    count = col.count_documents(query)

    if count == 0:
        print("No documents missing client_id. Nothing to do.")
        return

    print(f"Found {count} document(s) without client_id.")

    if args.dry_run:
        for doc in col.find(query, {"name": 1}):
            print(f"  Would set client_id=default on: {doc.get('name')}")
        print("Dry run — no changes written.")
        return

    result = col.update_many(query, {"$set": {"client_id": "default"}})
    print(f"Updated {result.modified_count} document(s) → client_id=default")
    client.close()


if __name__ == "__main__":
    main()
