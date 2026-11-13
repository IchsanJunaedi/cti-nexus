"""
import_db.py — Restore collections exported by export_db.py.
Reads gzipped NDJSON files, upserts docs into target MongoDB.

Usage:
    python scripts/import_db.py --src db_export_20260426_120000
    python scripts/import_db.py --src ./backup --host 192.168.1.10
    python scripts/import_db.py --src ./backup --dry-run
"""

import argparse
import gzip
import json
import os
from bson import ObjectId
from datetime import datetime
from pymongo import MongoClient, ReplaceOne


def _decode(obj):
    if isinstance(obj, dict):
        if "$oid" in obj:
            return ObjectId(obj["$oid"])
        if "$date" in obj:
            try:
                return datetime.fromisoformat(obj["$date"])
            except Exception:
                return obj["$date"]
        return {k: _decode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decode(i) for i in obj]
    return obj


def import_collection(col, gz_path: str, dry_run: bool) -> int:
    ops = []
    with gzip.open(gz_path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            doc = _decode(json.loads(line))
            if not dry_run:
                ops.append(ReplaceOne({"_id": doc["_id"]}, doc, upsert=True))
    if ops and not dry_run:
        col.bulk_write(ops, ordered=False)
    return len(ops)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--src",   required=True, help="Export directory from export_db.py")
    parser.add_argument("--host",  default="10.8.20.78", help="Target MongoDB host")
    parser.add_argument("--port",  default=27017, type=int)
    parser.add_argument("--dry-run", action="store_true", help="Count docs without writing")
    args = parser.parse_args()

    TARGET_DBS = {
        "news_db": {
            "uri": f"mongodb://ti-news:ElbiRxywfCcolEI@{args.host}:{args.port}/?authSource=news_db",
            "db":  "news_db",
        },
        "threatintel": {
            "uri": f"mongodb://ti-api:ElbiRxywfCcolEI@{args.host}:{args.port}/?authSource=threatintel&authMechanism=SCRAM-SHA-256",
            "db":  "threatintel",
        },
    }

    mode = "[DRY RUN] " if args.dry_run else ""
    print(f"{mode}Restoring from: {args.src}  →  {args.host}:{args.port}\n")

    for db_label in sorted(os.listdir(args.src)):
        db_dir = os.path.join(args.src, db_label)
        if not os.path.isdir(db_dir):
            continue
        if db_label not in TARGET_DBS:
            print(f"[!] Unknown DB folder '{db_label}', skipping.")
            continue

        cfg    = TARGET_DBS[db_label]
        client = MongoClient(cfg["uri"])
        db     = client[cfg["db"]]
        print(f"[DB] {db_label}")

        for fname in sorted(os.listdir(db_dir)):
            if not fname.endswith(".ndjson.gz"):
                continue
            col_name = fname.replace(".ndjson.gz", "")
            gz_path  = os.path.join(db_dir, fname)
            n = import_collection(db[col_name], gz_path, args.dry_run)
            print(f"  {col_name:30s} {n:>8,} docs {'(dry run)' if args.dry_run else 'upserted'}")

        client.close()
        print()

    print("Done." + (" (no data written)" if args.dry_run else ""))


if __name__ == "__main__":
    main()
