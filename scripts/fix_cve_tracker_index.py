#!/usr/bin/env python3
"""
One-time fix: replace the single-field unique index on cve_tracker.cve_id
with a compound unique index on (cve_id, client_id).

Run once after deploying multi-client support:
  python scripts/fix_cve_tracker_index.py
"""

import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

NEWS_URI = (
    f"mongodb://{os.getenv('MONGO_USER')}:{os.getenv('MONGO_PASS')}"
    f"@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/"
    f"?authSource={os.getenv('DB_NAME')}"
)
NEWS_DB = os.getenv("DB_NAME", "news_db")
COL     = "cve_tracker"

client = MongoClient(NEWS_URI)
col    = client[NEWS_DB][COL]

existing = col.index_information()
print("\n── Current indexes on cve_tracker ──────────────────")
for idx_name, idx_info in existing.items():
    keys   = idx_info.get("key", [])
    unique = idx_info.get("unique", False)
    print(f"  {idx_name}: keys={keys}  unique={unique}")
print()

# Drop ANY unique index whose key list is exactly [("cve_id", 1)] or [("cve_id", -1)]
dropped = 0
for idx_name, idx_info in list(existing.items()):
    if idx_name == "_id_":
        continue
    keys   = idx_info.get("key", [])
    fields = [k for k, _ in keys]
    unique = idx_info.get("unique", False)
    # Drop if: unique AND only field is cve_id (single-field blocking index)
    if unique and fields == ["cve_id"]:
        print(f"Dropping blocking index: {idx_name}  keys={keys}")
        col.drop_index(idx_name)
        dropped += 1

if dropped == 0:
    print("No single-field unique cve_id index found.")
    print("If backfill still fails, check for a compound index that includes cve_id as first key with unique=True.")
else:
    print(f"Dropped {dropped} blocking index(es).")

# Create correct compound unique index
col.create_index([("cve_id", 1), ("client_id", 1)], unique=True, background=True)
print("Created compound unique index on (cve_id, client_id).")

# Verify
print("\n── Indexes after fix ────────────────────────────────")
for idx_name, idx_info in col.index_information().items():
    print(f"  {idx_name}: keys={idx_info.get('key',[])}  unique={idx_info.get('unique',False)}")

client.close()
print("\nDone. Restart ScraperNewsWeb service before backfilling.")
