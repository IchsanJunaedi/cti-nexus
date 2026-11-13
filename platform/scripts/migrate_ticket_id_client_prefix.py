#!/usr/bin/env python3
"""
Backfill legacy ticket_id values (format: CTI-YYYY-MM-NNN) to the new
client-scoped format (CTI-{CLIENT_CODE}-YYYY-MM-NNN) in cve_tickets.

Old IDs were already globally unique, so inserting the client code in
place does not require renumbering or risks collisions.

Dry-run by default — prints planned changes only. Pass --apply to write.

Usage:
  python scripts/migrate_ticket_id_client_prefix.py                # dry run, all clients
  python scripts/migrate_ticket_id_client_prefix.py --client pgncom # dry run, one client
  python scripts/migrate_ticket_id_client_prefix.py --apply         # actually update
"""
import argparse
import os
import re
import sys

from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_USER = os.getenv("MONGO_USER", "")
MONGO_PASS = os.getenv("MONGO_PASS", "")
MONGO_HOST = os.getenv("MONGO_HOST", "")
MONGO_PORT = os.getenv("MONGO_PORT", "")
DB_NAME = os.getenv("DB_NAME", "")
MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/?authSource={DB_NAME}"

TICKET_COLLECTION = "cve_tickets"

_LEGACY_RE = re.compile(r"^CTI-(\d{4})-(\d{2})-(\d{3})$")


def client_code(client_id):
    code = re.sub(r"[^A-Za-z0-9]", "", client_id or "").upper()
    return code or "DEFAULT"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", help="only migrate tickets for this client_id")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    args = ap.parse_args()

    db = MongoClient(MONGO_URI)[DB_NAME]
    col = db[TICKET_COLLECTION]

    query = {}
    if args.client:
        query["client_id"] = args.client

    docs = list(col.find(query, {"_id": 1, "cve_id": 1, "client_id": 1, "ticket_id": 1}))

    planned = []
    skipped_no_match = 0
    skipped_already_new = 0

    for d in docs:
        tid = d.get("ticket_id") or ""
        m = _LEGACY_RE.match(tid)
        if not m:
            if tid.startswith("CTI-") and not m:
                skipped_already_new += 1
            else:
                skipped_no_match += 1
            continue
        year, month, seq = m.groups()
        code = client_code(d.get("client_id"))
        new_tid = f"CTI-{code}-{year}-{month}-{seq}"
        planned.append((d["_id"], d.get("cve_id"), d.get("client_id"), tid, new_tid))

    print(f"scanned: {len(docs)}  legacy-format matches: {len(planned)}  "
          f"already-new-format: {skipped_already_new}  unrecognized: {skipped_no_match}")

    for _id, cve_id, cid, old, new in planned:
        print(f"  [{cid}] {cve_id}: {old} -> {new}")

    if not args.apply:
        print("\nDRY RUN — no changes written. Re-run with --apply to commit.")
        return

    # collision check per client+prefix before writing
    seen = set()
    for _id, cve_id, cid, old, new in planned:
        key = (cid, new)
        if key in seen:
            print(f"ABORT: duplicate target ticket_id {new} for client {cid}", file=sys.stderr)
            sys.exit(1)
        seen.add(key)

    for _id, cve_id, cid, old, new in planned:
        col.update_one({"_id": _id}, {"$set": {"ticket_id": new}})

    print(f"\nApplied: {len(planned)} tickets updated.")


if __name__ == "__main__":
    sys.exit(main())
