"""
import_cve_tickets.py
Seed MongoDB cve_tickets collection from the CVE Tracker Excel file.
Run once to migrate existing data; safe to re-run (upserts on ticket_id).

Usage:
    python scripts/import_cve_tickets.py --file "CVE Tracker.xlsx"
"""

import argparse
import yaml
import pandas as pd
from datetime import datetime
from pymongo import MongoClient, UpdateOne

EXCEL_TO_DB = {
    "Ticket ID":                    "ticket_id",
    "CVE ID":                       "cve_id",
    "CVE Reported Date":            "cve_reported_date",
    "Affected Asset/Product":       "affected_asset",
    "Affected Version":             "affected_version",
    "Fixed Version":                "fixed_version",
    "Asset Owner":                  "asset_owner",
    "Owner Email":                  "owner_email",
    "Owner Team":                   "owner_team",
    "Active Exploitation":          "active_exploitation",
    "Date Acknowledged by CTI Team":"date_acknowledged",
    "Remediation Date Plan":        "remediation_date_plan",
    "Remediation Status":           "remediation_status",
    "Actual Remediation Date":      "actual_remediation_date",
    "Escalation Required":          "escalation_required",
    "Comments/Notes":               "comments",
    "Risk Acceptance":              "risk_acceptance",
    "Closure Date":                 "closure_date",
}

BOOL_FIELDS = {"escalation_required"}
STR_FIELDS  = {"active_exploitation"}


def _clean(val):
    if pd.isna(val) or val is None:
        return ""
    if isinstance(val, pd.Timestamp):
        return val.strftime("%Y-%m-%d")
    return str(val).strip()


def _to_bool(val):
    if pd.isna(val) or val is None:
        return False
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("yes", "true", "1", "x")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="CVE Tracker.xlsx", help="Path to Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index (default: first sheet)")
    args = parser.parse_args()

    with open("config/config.yml") as f:
        cfg = yaml.safe_load(f)

    uri = (
        f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
        f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
    )
    client = MongoClient(uri)
    col = client[cfg['news_db']['db']]['cve_tickets']
    col.create_index("ticket_id", unique=True, background=True)
    col.create_index("cve_id", background=True)

    df = pd.read_excel(args.file, sheet_name=args.sheet, header=14, usecols="B:U", dtype=str)
    df.columns = [c.strip() for c in df.columns]

    ops = []
    skipped = 0
    for _, row in df.iterrows():
        ticket_id = _clean(row.get("Ticket ID", ""))
        print(ticket_id)
        cve_id    = _clean(row.get("CVE ID", ""))
        if not ticket_id or not cve_id:
            skipped += 1
            continue

        doc = {"updated_at": datetime.utcnow().isoformat()}
        for excel_col, db_field in EXCEL_TO_DB.items():
            raw = row.get(excel_col, "")
            if db_field in BOOL_FIELDS:
                doc[db_field] = _to_bool(raw)
            elif db_field in STR_FIELDS:
                doc[db_field] = _clean(raw)
            else:
                doc[db_field] = _clean(raw)

        ops.append(UpdateOne(
            {"ticket_id": ticket_id},
            {"$set": doc},
            upsert=True,
        ))

    if ops:
        result = col.bulk_write(ops, ordered=False)
        print(f"Upserted {result.upserted_count} new | Modified {result.modified_count} existing | Skipped {skipped} rows")
    else:
        print(f"No valid rows found. Skipped {skipped}.")

    client.close()


if __name__ == "__main__":
    main()
