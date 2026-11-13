#!/usr/bin/env python3
"""
Purge false-positive IOCs from the iocs collection.

Targets:
  1. IP type  — values that look like software version numbers (all octets <= 30,
                last octet is 0, suggesting major.minor.patch.0 versioning).
  2. URL+PATH — values containing whitespace (e.g. "like .vscode/tasks.json").
  3. URL+PATH — values whose TLD (last label before the first "/") is not a
                recognised top-level domain.

Usage:
  python scripts/purge_false_positive_iocs.py               # dry-run (preview)
  python scripts/purge_false_positive_iocs.py --execute      # actually delete
"""

import argparse
import os
import re
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

NEWS_URI = (
    f"mongodb://{os.getenv('MONGO_USER')}:{os.getenv('MONGO_PASS')}"
    f"@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/"
    f"?authSource={os.getenv('DB_NAME')}"
)
NEWS_DB  = os.getenv("DB_NAME", "news_db")
IOC_COL  = os.getenv("IOC_COLLECTION", "iocs")

_KNOWN_TLDS = {
    "com", "net", "org", "io", "gov", "edu", "mil", "int", "info", "biz",
    "xyz", "ru", "cn", "de", "uk", "co", "top", "site", "online", "tech",
    "app", "dev", "cloud", "red", "pw", "cc", "tv", "me", "mobi", "ly",
    "to", "sh", "gg", "is", "am", "fm", "ac", "in", "jp", "fr", "eu",
    "au", "nz", "ca", "br", "pl", "nl", "se", "no", "fi", "dk", "ch",
    "at", "be", "il", "sg", "hk", "tw", "kr", "th", "id", "my", "ph",
    "vn", "ua", "tr", "sa", "ae", "za", "ng", "ke", "gh",
}

_RE_DEFANG = re.compile(r'\[\.\]|\[dot\]|\(dot\)', re.IGNORECASE)


def _is_version_number_ip(value: str) -> bool:
    """Return True if an IP-type value looks like a software version (e.g. 12.5.1.0)."""
    clean = _RE_DEFANG.sub('.', value).strip()
    parts = clean.split('.')
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    # Heuristic: all octets <= 30 AND last octet is 0 → version-like
    return all(o <= 30 for o in octets) and octets[3] == 0


def _url_path_tld(value: str) -> str | None:
    """Extract the TLD (label immediately before the first '/') from a url_with_path value."""
    clean = _RE_DEFANG.sub('.', value).strip()
    slash_idx = clean.find('/')
    if slash_idx == -1:
        return None
    domain_part = clean[:slash_idx]
    labels = domain_part.split('.')
    return labels[-1].lower() if labels else None


def _is_false_positive_url_path(value: str) -> bool:
    if re.search(r'\s', value):
        return True
    tld = _url_path_tld(value)
    if tld is None:
        return True
    return tld not in _KNOWN_TLDS


def run(dry_run: bool) -> None:
    client = MongoClient(NEWS_URI)
    col = client[NEWS_DB][IOC_COL]

    fp_ids = []

    # — IPs that are version numbers —
    for doc in col.find({"type": "ip"}):
        if _is_version_number_ip(doc.get("value", "")):
            fp_ids.append(doc["_id"])
            print(f"  [IP/version]     {doc['value']}")

    # — URL+PATH false positives —
    for doc in col.find({"type": "url_with_path"}):
        if _is_false_positive_url_path(doc.get("value", "")):
            fp_ids.append(doc["_id"])
            print(f"  [URL+PATH/fp]    {doc['value']}")

    print(f"\nTotal false positives found: {len(fp_ids)}")

    if not fp_ids:
        print("Nothing to delete.")
        return

    if dry_run:
        print("[DRY RUN] No changes made. Pass --execute to delete.")
        return

    result = col.delete_many({"_id": {"$in": fp_ids}})
    print(f"[EXECUTE] Deleted: {result.deleted_count}")
    print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Purge false-positive IOCs")
    parser.add_argument("--execute", action="store_true", help="Actually delete (default is dry-run)")
    args = parser.parse_args()

    if args.execute:
        confirm = input(
            "\nWARNING: This permanently deletes IOC records.\n"
            "Type 'yes' to continue: "
        )
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            exit(0)

    run(dry_run=not args.execute)
