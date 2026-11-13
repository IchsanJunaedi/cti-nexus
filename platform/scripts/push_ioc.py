#!/usr/bin/env python3
"""
Manually push IOCs into the iocs collection.

Single IOC:
  python scripts/push_ioc.py --type ip --value 1.2.3.4 \\
      --source-url https://example.com --source-name "Manual"

Bulk from file (CSV: type,value[,context]  or  JSON: list of objects):
  python scripts/push_ioc.py --file iocs.csv \\
      --source-url https://report.example.com --source-name "APT Report"

Valid types: ip, domain, url, url_with_path, email, sha256, sha1, md5, cve
"""

import argparse
import asyncio
import csv
import json
import os
import sys
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
load_dotenv()

from app.database import connect, disconnect
from app.services.ioc_service import upsert_ioc

VALID_TYPES = {"ip", "domain", "url", "url_with_path", "email", "sha256", "sha1", "md5", "cve"}


def load_file(path: str) -> list[tuple[str, str, str]]:
    """Return list of (type, value, context) from CSV or JSON file."""
    p = Path(path)
    if not p.exists():
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)

    entries = []
    suffix = p.suffix.lower()

    if suffix == ".json":
        with open(p) as f:
            data = json.load(f)
        if not isinstance(data, list):
            print("[ERROR] JSON file must be a list of objects with 'type' and 'value' keys")
            sys.exit(1)
        for obj in data:
            ioc_type = obj.get("type", "").strip()
            value = obj.get("value", "").strip()
            context = obj.get("context", "").strip()
            entries.append((ioc_type, value, context))
    else:
        # treat as CSV: type,value[,context]
        with open(p, newline="") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader, 1):
                if not row or row[0].startswith("#"):
                    continue
                if len(row) < 2:
                    print(f"[WARN] Line {i}: skipping (need at least 2 columns)")
                    continue
                ioc_type = row[0].strip()
                value = row[1].strip()
                context = row[2].strip() if len(row) > 2 else ""
                entries.append((ioc_type, value, context))

    return entries


async def push(entries: list[tuple[str, str, str]], source_url: str, source_name: str,
               feature_type: str, dry_run: bool) -> None:
    if not dry_run:
        await connect()

    ok = 0
    skipped = 0
    for ioc_type, value, context in entries:
        if not value:
            skipped += 1
            continue
        if ioc_type not in VALID_TYPES:
            print(f"[SKIP] Invalid type '{ioc_type}' for value '{value}'")
            skipped += 1
            continue
        if dry_run:
            print(f"[DRY] {ioc_type:<12} {value}  context={context!r}")
            ok += 1
        else:
            try:
                await upsert_ioc(
                    ioc_type=ioc_type,
                    value=value,
                    source_url=source_url,
                    source_name=source_name,
                    feature_type=feature_type,
                    context=context or None,
                )
                print(f"[OK]  {ioc_type:<12} {value}")
                ok += 1
            except Exception as e:
                print(f"[ERR] {ioc_type:<12} {value}  — {e}")
                skipped += 1

    if not dry_run:
        await disconnect()

    print(f"\nDone. pushed={ok}  skipped={skipped}")
    if dry_run:
        print("[DRY RUN] No changes written. Remove --dry-run to commit.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manually push IOCs to the database")

    # Single IOC
    parser.add_argument("--type", dest="ioc_type",
                        help=f"IOC type: {', '.join(sorted(VALID_TYPES))}")
    parser.add_argument("--value", help="IOC value (e.g. 1.2.3.4, evil.com, abc123...)")
    parser.add_argument("--context", default="", help="Optional context / description")

    # Bulk
    parser.add_argument("--file", help="CSV or JSON file with multiple IOCs")

    # Required source metadata
    parser.add_argument("--source-url", required=True, help="Source URL / report link")
    parser.add_argument("--source-name", required=True, help="Source name label")
    parser.add_argument("--feature-type", default="manual",
                        help="Feature type tag (default: manual)")

    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without writing to DB")

    args = parser.parse_args()

    if args.file:
        entries = load_file(args.file)
    elif args.ioc_type and args.value:
        entries = [(args.ioc_type.strip(), args.value.strip(), args.context.strip())]
    else:
        parser.error("Provide --type + --value for a single IOC, or --file for bulk.")

    print(f"IOCs to process: {len(entries)}")
    if not args.dry_run:
        confirm = input("Confirm push to database? [y/N] ")
        if confirm.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    asyncio.run(push(entries, args.source_url, args.source_name, args.feature_type, args.dry_run))


if __name__ == "__main__":
    main()
