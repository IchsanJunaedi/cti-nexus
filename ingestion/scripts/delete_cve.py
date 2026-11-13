"""
delete_cve.py
Delete a CVE entry from cve_tracker (and its ticket + FP record if present).

Usage:
    python scripts/delete_cve.py CVE-2026-12345
    python scripts/delete_cve.py CVE-2026-12345 CVE-2026-99999
    python scripts/delete_cve.py CVE-2026-12345 --keep-ticket
"""

import argparse
import yaml
from pymongo import MongoClient


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cve_ids", nargs="+", help="One or more CVE IDs to delete")
    parser.add_argument("--keep-ticket", action="store_true", help="Do not delete associated ticket record")
    args = parser.parse_args()

    with open("config/config.yml") as f:
        cfg = yaml.safe_load(f)

    uri = (
        f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
        f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
    )
    client = MongoClient(uri)
    db = client[cfg['news_db']['db']]

    for cve_id in args.cve_ids:
        cve_id = cve_id.strip().upper()

        # Show what will be deleted before confirming
        doc = db['cve_tracker'].find_one({"cve_id": cve_id}, {"cve_id": 1, "tech": 1, "cve_severity": 1, "published": 1})
        ticket = db['cve_tickets'].find_one({"cve_id": cve_id}, {"ticket_id": 1})
        fp = db['cve_false_positives'].find_one({"cve_id": cve_id})

        print(f"\n{'='*50}")
        print(f"CVE ID  : {cve_id}")
        if doc:
            print(f"Tech    : {doc.get('tech', '—')}")
            print(f"Severity: {doc.get('cve_severity', '—')}")
            print(f"Published: {doc.get('published', '—')}")
        else:
            print("  [not found in cve_tracker]")

        if ticket:
            print(f"Ticket  : {ticket.get('ticket_id', '—')} {'(will be KEPT)' if args.keep_ticket else '(will be deleted)'}")
        if fp:
            print(f"FP flag : present (will be deleted)")

        # Require confirmation per CVE
        confirm = input(f"\nDelete {cve_id}? [y/N] ").strip().lower()
        if confirm != "y":
            print(f"Skipped {cve_id}.")
            continue

        tracker_result = db['cve_tracker'].delete_one({"cve_id": cve_id})
        print(f"cve_tracker     : deleted {tracker_result.deleted_count}")

        if not args.keep_ticket:
            ticket_result = db['cve_tickets'].delete_one({"cve_id": cve_id})
            print(f"cve_tickets     : deleted {ticket_result.deleted_count}")

        fp_result = db['cve_false_positives'].delete_one({"cve_id": cve_id})
        if fp_result.deleted_count:
            print(f"cve_false_positives: deleted {fp_result.deleted_count}")

    client.close()


if __name__ == "__main__":
    main()
