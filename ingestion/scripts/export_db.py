"""
export_db.py — Python fallback if mongodump not available.
Exports all collections to gzipped NDJSON files (one doc per line).
Restore with import_db.py.

Usage:
    python scripts/export_db.py
    python scripts/export_db.py --out /path/to/output
"""

import argparse
import gzip
import json
import os
from datetime import datetime
from bson import ObjectId
from pymongo import MongoClient

# ── DB configs ────────────────────────────────────────────
DATABASES = [
    {
        "label":    "news_db",
        "uri":      "mongodb://ti-news:ElbiRxywfCcolEI@10.8.20.78/?authSource=news_db",
        "db":       "news_db",
        "collections": [
            "articles",
            "cve_tracker",
            "cve_tickets",
            "cve_false_positives",
            "pir_requirements",
            "scraper_runs",
            "clusters",
        ],
    },
    {
        "label":    "threatintel",
        "uri":      "mongodb://ti-api:ElbiRxywfCcolEI@10.8.20.78/?authSource=threatintel&authMechanism=SCRAM-SHA-256",
        "db":       "threatintel",
        "collections": [
            "groups",
            "whitelist",
            "source_scores",
            "threatintel",   # main scraper collection
        ],
    },
]


class _BSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return {"$oid": str(o)}
        if isinstance(o, datetime):
            return {"$date": o.isoformat()}
        if isinstance(o, bytes):
            return {"$binary": o.hex()}
        return super().default(o)


def export_collection(col, out_path: str) -> int:
    count = 0
    with gzip.open(out_path, "wt", encoding="utf-8") as f:
        for doc in col.find({}):
            f.write(json.dumps(doc, cls=_BSONEncoder) + "\n")
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=f"db_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    print(f"Output: {args.out}\n")

    total_docs = 0
    for db_cfg in DATABASES:
        print(f"[DB] {db_cfg['label']}")
        client = MongoClient(db_cfg["uri"])
        db = client[db_cfg["db"]]

        db_dir = os.path.join(args.out, db_cfg["label"])
        os.makedirs(db_dir, exist_ok=True)

        # Also discover any extra collections not in the list
        existing = set(db.list_collection_names())
        known    = set(db_cfg["collections"])
        extra    = existing - known
        if extra:
            print(f"  [!] Extra collections found (will also export): {', '.join(sorted(extra))}")
        all_cols = sorted(known | extra)

        for col_name in all_cols:
            if col_name not in existing:
                print(f"  {col_name:30s} — not found, skip")
                continue
            out_path = os.path.join(db_dir, f"{col_name}.ndjson.gz")
            n = export_collection(db[col_name], out_path)
            total_docs += n
            print(f"  {col_name:30s} {n:>8,} docs  → {col_name}.ndjson.gz")

        client.close()
        print()

    print(f"Done. Total docs exported: {total_docs:,}")
    print(f"\nRestore with: python scripts/import_db.py --src {args.out}")


if __name__ == "__main__":
    main()
