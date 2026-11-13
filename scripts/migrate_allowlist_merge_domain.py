#!/usr/bin/env python3
"""
Merge "url_domain" and "email_domain" IOC allowlist entries into a single "domain" type.

Dedupes by value: if the same domain exists under both old types, keeps one entry
(earliest added_at) and deletes the duplicate.

Usage:
  python scripts/migrate_allowlist_merge_domain.py               # dry-run (preview)
  python scripts/migrate_allowlist_merge_domain.py --execute      # actually write
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
NEWS_DB   = os.getenv("DB_NAME", "news_db")
ALLOW_COL = os.getenv("IOC_ALLOWLIST_COLLECTION", "ioc_allowlist")


def main():
    parser = argparse.ArgumentParser(description="Merge url_domain/email_domain allowlist entries into domain")
    parser.add_argument("--execute", action="store_true", help="Actually write changes (default: dry-run)")
    args = parser.parse_args()

    client = MongoClient(NEWS_URI)
    col = client[NEWS_DB][ALLOW_COL]

    docs = list(col.find({"type": {"$in": ["url_domain", "email_domain"]}}).sort("added_at", 1))
    if not docs:
        print("No url_domain/email_domain entries found. Nothing to do.")
        return

    seen_values: dict[str, dict] = {}
    to_relabel = []
    to_delete = []

    for doc in docs:
        value = doc["value"]
        if value in seen_values:
            to_delete.append(doc["_id"])
        else:
            seen_values[value] = doc
            to_relabel.append(doc["_id"])

    print(f"Found {len(docs)} url_domain/email_domain entries.")
    print(f"  → {len(to_relabel)} will be relabeled to type='domain'")
    print(f"  → {len(to_delete)} duplicate(s) will be deleted (kept earliest added_at)")

    if not args.execute:
        for value, doc in seen_values.items():
            print(f"  would relabel: {doc['type']} '{value}' -> domain")
        print("Dry run — no changes written. Re-run with --execute to apply.")
        return

    if to_delete:
        result = col.delete_many({"_id": {"$in": to_delete}})
        print(f"Deleted {result.deleted_count} duplicate(s).")

    result = col.update_many(
        {"_id": {"$in": to_relabel}},
        {"$set": {"type": "domain"}},
    )
    print(f"Relabeled {result.modified_count} entries to type='domain'.")
    client.close()


if __name__ == "__main__":
    main()
