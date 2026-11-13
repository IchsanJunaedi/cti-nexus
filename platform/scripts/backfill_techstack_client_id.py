#!/usr/bin/env python3
"""
One-off backfill: set client_id='default' on legacy techstack docs missing the field.

Run once after the techstack_service._client_filter fix that removed the
{"client_id": {"$exists": False}} fallback — without this, those legacy docs
become invisible to every client instead of just the "default" client.

Usage: python scripts/backfill_techstack_client_id.py [--dry-run]
"""

import argparse
import asyncio
from app.database import connect, disconnect, get_ta_database
from app.config import TECHSTACK_COLLECTION


async def main(dry_run: bool):
    await connect()
    col = get_ta_database()[TECHSTACK_COLLECTION]
    filt = {"client_id": {"$exists": False}}
    count = await col.count_documents(filt)
    if count == 0:
        print("No orphan techstack docs found.")
    elif dry_run:
        print(f"[DRY RUN] Would set client_id='default' on {count} doc(s).")
    else:
        result = await col.update_many(filt, {"$set": {"client_id": "default"}})
        print(f"Updated {result.modified_count} doc(s) → client_id='default'.")
    await disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    asyncio.run(main(args.dry_run))
