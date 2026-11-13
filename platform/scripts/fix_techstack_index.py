#!/usr/bin/env python3
"""
One-time fix: replace the single-field unique index on techstack.name
with a compound unique index on (name, client_id).

Run once after deploying multi-client support:
  python scripts/fix_techstack_index.py
"""

import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

TA_URI = (
    f"mongodb://{os.getenv('TA_MONGO_USER')}:{os.getenv('TA_MONGO_PASS')}"
    f"@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/"
    f"?authSource={os.getenv('TA_DB_NAME')}&authMechanism=SCRAM-SHA-256"
)
TA_DB  = os.getenv("TA_DB_NAME", "threatintel")
COL    = os.getenv("TECHSTACK_COLLECTION", "techstack")

client = MongoClient(TA_URI)
col    = client[TA_DB][COL]

# Drop old single-field unique index if it exists
existing = col.index_information()
dropped  = False
for idx_name, idx_info in existing.items():
    keys = [k for k, _ in idx_info.get("key", [])]
    if keys == ["name"] and idx_info.get("unique"):
        print(f"Dropping old index: {idx_name}")
        col.drop_index(idx_name)
        dropped = True

if not dropped:
    print("No old single-field unique index on 'name' found — already clean.")

# Create compound unique index (name, client_id)
col.create_index([("name", 1), ("client_id", 1)], unique=True, background=True)
print("Created compound unique index on (name, client_id).")

client.close()
print("Done.")
