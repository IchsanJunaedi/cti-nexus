"""
export_cve_tracker_excel.py
Export cve_tickets + cve_tracker (severity/score) to Excel using
CVE_Tracker_template.xlsx as base. Headers at row 15, data from row 16,
columns B–X (23 columns).

Usage:
    python scripts/export_cve_tracker_excel.py
    python scripts/export_cve_tracker_excel.py --out /path/to/output.xlsx
    python scripts/export_cve_tracker_excel.py --template /path/to/template.xlsx
"""

import argparse
import yaml
from datetime import datetime
from pymongo import MongoClient
from openpyxl import load_workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

DEFAULT_TEMPLATE = "supportFile/CVE_Tracker_template.xlsx"

# Columns B–X (23 columns) matching template row 15
COLUMNS = [
    "Ticket ID",                      # B  2
    "CVE ID",                         # C  3
    "CVE Reported Date",              # D  4
    "CVE Detected Date",              # E  5  ← detected_on
    "Time To Detect (Hour)",          # F  6  ← (detected_on - published) in hours
    "Severity",                       # G  7
    "CVSS Score",                     # H  8
    "Affected Asset/Product",         # I  9
    "Affected Version",               # J  10
    "Fixed Version",                  # K  11
    "Asset Owner",                    # L  12
    "Owner Email",                    # M  13
    "Owner Team",                     # N  14
    "Active Exploitation",            # O  15
    "Date Acknowledged by CTI Team",  # P  16  ← acknowledge_time
    "Time To Acknowledge",            # Q  17  ← (acknowledge_time - detected_on) in hours
    "Remediation Date Plan",          # R  18
    "Remediation Status",             # S  19
    "Actual Remediation Date",        # T  20
    "Escalation Required",            # U  21
    "Comments/Notes",                 # V  22
    "Risk Acceptance",                # W  23
    "Closure Date",                   # X  24
]

SEV_FILL = {
    "CRITICAL": ("C00000", "FFFFFF"),
    "HIGH":     ("FF4500", "FFFFFF"),
    "MEDIUM":   ("FFC000", "000000"),
    "LOW":      ("70AD47", "000000"),
}

DT_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
]


def _parse_dt(val) -> datetime | None:
    if not val:
        return None
    s = str(val).strip()
    for fmt in DT_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _fmt_dt(val) -> str:
    """Normalize any datetime string to YYYY-MM-DD HH:MM:SS, or return raw if unparseable."""
    dt = _parse_dt(val)
    if dt:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return str(val) if val else ""


def _hours_between(a_str, b_str) -> str:
    """Return hours difference as rounded float string, or empty string."""
    a = _parse_dt(a_str)
    b = _parse_dt(b_str)
    if a and b:
        diff = abs((b - a).total_seconds()) / 3600
        return round(diff, 2)
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        default=f"CVE_Tracker_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
    )
    parser.add_argument("--template", default=DEFAULT_TEMPLATE)
    args = parser.parse_args()

    with open("config/config.yml") as f:
        cfg = yaml.safe_load(f)

    uri = (
        f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
        f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
    )
    client = MongoClient(uri)
    db = client[cfg["news_db"]["db"]]

    # cve_id → full tracker doc (all fields, no _id)
    cve_lookup = {
        doc["cve_id"]: doc
        for doc in db["cve_tracker"].find({}, {"_id": 0})
    }

    # cve_id → ticket doc
    ticket_lookup = {
        doc["cve_id"]: doc
        for doc in db["cve_tickets"].find({}, {"_id": 0})
    }

    # All CVEs ordered by ticket_id where available, rest appended
    ticketed = list(db["cve_tickets"].find({}, {"_id": 0}).sort("ticket_id", 1))
    ticketed_ids = {t["cve_id"] for t in ticketed}
    unticketed = [
        {"cve_id": cve_id}
        for cve_id in cve_lookup
        if cve_id not in ticketed_ids
    ]
    all_rows = ticketed + unticketed
    print(all_rows)
    client.close()

    exit()

    # ── Load template ────────────────────────────────────────
    wb = load_workbook(args.template)
    ws = wb["CVE Tracker"]

    HEADER_ROW = 15
    DATA_START  = 16
    COL_START   = 2  # column B

    # Clear any existing sample data rows (keep header row intact)
    for row in ws.iter_rows(min_row=DATA_START, max_row=ws.max_row):
        for cell in row:
            cell.value = None

    # Data rows
    for row_idx, t in enumerate(all_rows, start=DATA_START):
        cve_id  = t.get("cve_id", "")
        cve_ref = cve_lookup.get(cve_id, {})
        tk      = ticket_lookup.get(cve_id, t)  # fall back to ticketed row itself

        sev     = str(cve_ref.get("cve_severity", "")).upper()
        score   = cve_ref.get("cve_score", "")

        detected_on      = cve_ref.get("detected_on", "")
        published        = cve_ref.get("published", "")
        acknowledge_time = tk.get("acknowledge_time", "")

        time_to_detect  = _hours_between(published, detected_on)
        time_to_ack     = _hours_between(detected_on, acknowledge_time) if acknowledge_time else ""

        reported_raw = tk.get("cve_reported_date") or published or ""

        values = [
            tk.get("ticket_id", ""),                          # B Ticket ID
            cve_id,                                           # C CVE ID
            _fmt_dt(reported_raw),                            # D CVE Reported Date
            _fmt_dt(detected_on),                             # E CVE Detected Date
            time_to_detect,                                   # F Time To Detect (Hour)
            cve_ref.get("cve_severity", ""),                  # G Severity
            score,                                            # H CVSS Score
            tk.get("affected_asset", ""),                     # I Affected Asset/Product
            tk.get("affected_version", ""),                   # J Affected Version
            tk.get("fixed_version", ""),                      # K Fixed Version
            tk.get("asset_owner", ""),                        # L Asset Owner
            tk.get("owner_email", ""),                        # M Owner Email
            tk.get("owner_team", ""),                         # N Owner Team
            tk.get("active_exploitation", ""),                # O Active Exploitation
            _fmt_dt(acknowledge_time),                        # P Date Acknowledged by CTI Team
            time_to_ack,                                      # Q Time To Acknowledge
            tk.get("remediation_date_plan", ""),              # R Remediation Date Plan
            tk.get("remediation_status", ""),                 # S Remediation Status
            tk.get("actual_remediation_date", ""),            # T Actual Remediation Date
            "Yes" if tk.get("escalation_required") else "No", # U Escalation Required
            tk.get("comments", ""),                           # V Comments/Notes
            tk.get("risk_acceptance", ""),                    # W Risk Acceptance
            tk.get("closure_date", ""),                       # X Closure Date
        ]

        for col_idx, val in enumerate(values):
            cell = ws.cell(row=row_idx, column=COL_START + col_idx, value=val)
            cell.alignment = Alignment(vertical="center", wrap_text=False)

            col_name = COLUMNS[col_idx]

            if col_name == "Severity" and sev in SEV_FILL:
                fg, fc = SEV_FILL[sev]
                cell.fill = PatternFill("solid", fgColor=fg)
                cell.font = Font(bold=True, color=fc, size=10, name="Calibri")
            elif col_name == "CVSS Score" and score:
                try:
                    s = float(score)
                    if s >= 9.0:
                        cell.fill = PatternFill("solid", fgColor="FFD7D7")
                    elif s >= 7.0:
                        cell.fill = PatternFill("solid", fgColor="FFE7CC")
                    elif s >= 4.0:
                        cell.fill = PatternFill("solid", fgColor="FFFACC")
                except (ValueError, TypeError):
                    pass

        ws.row_dimensions[row_idx].height = 18

    # Auto column widths (capped at 45), skip cols that already have template width
    for i, col_name in enumerate(COLUMNS):
        col_letter = get_column_letter(COL_START + i)
        max_len = len(col_name)
        for row_idx in range(DATA_START, DATA_START + len(all_rows)):
            val = ws.cell(row=row_idx, column=COL_START + i).value
            if val:
                max_len = max(max_len, min(len(str(val)), 45))
        ws.column_dimensions[col_letter].width = max_len + 2

    wb.save(args.out)
    print(f"Exported {len(all_rows)} rows ({len(ticketed)} with tickets) → {args.out}")
    print(f"  Template: {args.template}")
    print(f"  Headers at row {HEADER_ROW}, data from row {DATA_START}, columns B–X")


if __name__ == "__main__":
    main()
