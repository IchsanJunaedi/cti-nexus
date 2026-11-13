"""
export_cve_tickets.py
Export MongoDB cve_tickets (joined with cve_tracker for Severity/CVSS) to Excel,
matching the original CVE Tracker.xlsx column layout.

Usage:
    python scripts/export_cve_tickets.py
    python scripts/export_cve_tickets.py --out /path/to/output.xlsx
"""

import argparse
import yaml
from datetime import datetime
from pymongo import MongoClient
import pandas as pd
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter


COLUMNS = [
    "Ticket ID",
    "CVE ID",
    "CVE Reported Date",
    "Severity",
    "CVSS Score",
    "Affected Asset/Product",
    "Affected Version",
    "Fixed Version",
    "Asset Owner",
    "Owner Email",
    "Owner Team",
    "Active Exploitation",
    "Date Acknowledged by CTI Team",
    "Acknowledged By",
    "Acknowledge Time",
    "Detection Time",
    "Remediation Date Plan",
    "Remediation Status",
    "Actual Remediation Date",
    "Escalation Required",
    "Comments/Notes",
    "Risk Acceptance",
    "Closure Date",
    "System",
    "MTTD",
    "Last Updated",
]

SEV_COLORS = {
    "CRITICAL": "C00000",
    "HIGH":     "FF4500",
    "MEDIUM":   "FFC000",
    "LOW":      "70AD47",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=f"CVE_Tracker_Export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
    args = parser.parse_args()

    with open("config/config.yml") as f:
        cfg = yaml.safe_load(f)

    uri = (
        f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
        f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
    )
    client = MongoClient(uri)
    db = client[cfg['news_db']['db']]

    # Load cve_tracker for severity/score lookup
    cve_lookup = {}
    for doc in db['cve_tracker'].find({}, {"cve_id": 1, "cve_severity": 1, "cve_score": 1, "detected_on": 1, "_id": 0}):
        cve_lookup[doc["cve_id"]] = doc

    tickets = list(db['cve_tickets'].find({}, {"_id": 0}).sort("ticket_id", 1))
    client.close()

    rows = []
    for t in tickets:
        cve_id  = t.get("cve_id", "")
        cve_ref = cve_lookup.get(cve_id, {})

        rows.append({
            "Ticket ID":                    t.get("ticket_id", ""),
            "CVE ID":                       cve_id,
            "CVE Reported Date":            t.get("cve_reported_date", ""),
            "Severity":                     cve_ref.get("cve_severity", ""),
            "CVSS Score":                   cve_ref.get("cve_score", ""),
            "Affected Asset/Product":       t.get("affected_asset", ""),
            "Affected Version":             t.get("affected_version", ""),
            "Fixed Version":                t.get("fixed_version", ""),
            "Asset Owner":                  t.get("asset_owner", ""),
            "Owner Email":                  t.get("owner_email", ""),
            "Owner Team":                   t.get("owner_team", ""),
            "Active Exploitation":          t.get("active_exploitation", ""),
            "Date Acknowledged by CTI Team":t.get("date_acknowledged", ""),
            "Acknowledged By":              t.get("acknowledged_by", ""),
            "Acknowledge Time":             t.get("acknowledge_time", ""),
            "Detection Time":               cve_ref.get("detected_on", t.get("detection_time", "")),
            "Remediation Date Plan":        t.get("remediation_date_plan", ""),
            "Remediation Status":           t.get("remediation_status", ""),
            "Actual Remediation Date":      t.get("actual_remediation_date", ""),
            "Escalation Required":          "Yes" if t.get("escalation_required") else "No",
            "Comments/Notes":               t.get("comments", ""),
            "Risk Acceptance":              t.get("risk_acceptance", ""),
            "Closure Date":                 t.get("closure_date", ""),
            "System":                       t.get("system", ""),
            "MTTD":                         t.get("mttd", ""),
            "Last Updated":                 t.get("updated_at", ""),
        })

    df = pd.DataFrame(rows, columns=COLUMNS)

    with pd.ExcelWriter(args.out, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="CVE Tracker")
        ws = writer.sheets["CVE Tracker"]

        # Header styling
        header_fill = PatternFill("solid", fgColor="1F2D3D")
        header_font = Font(bold=True, color="FFFFFF", size=10)
        thin = Side(style="thin", color="3A3A3A")
        border = Border(left=thin, right=thin, top=thin, bottom=thin)

        for col_idx, col_name in enumerate(COLUMNS, start=1):
            cell = ws.cell(row=1, column=col_idx)
            cell.fill      = header_fill
            cell.font      = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border    = border

        ws.row_dimensions[1].height = 30

        # Data rows
        for row_idx, row_data in enumerate(rows, start=2):
            sev = str(row_data.get("Severity", "")).upper()
            sev_color = SEV_COLORS.get(sev)
            for col_idx, col_name in enumerate(COLUMNS, start=1):
                cell = ws.cell(row=row_idx, column=col_idx)
                cell.border    = border
                cell.alignment = Alignment(vertical="center", wrap_text=False)
                if col_name == "Severity" and sev_color:
                    cell.fill = PatternFill("solid", fgColor=sev_color)
                    cell.font = Font(bold=True, color="FFFFFF", size=10)
                elif col_name == "CVSS Score" and row_data.get("CVSS Score"):
                    score = float(row_data["CVSS Score"] or 0)
                    if score >= 9.0:
                        cell.fill = PatternFill("solid", fgColor="FFD7D7")
                    elif score >= 7.0:
                        cell.fill = PatternFill("solid", fgColor="FFE7CC")
                    elif score >= 4.0:
                        cell.fill = PatternFill("solid", fgColor="FFFACC")

        # Auto column widths
        for col_idx, col_name in enumerate(COLUMNS, start=1):
            col_letter = get_column_letter(col_idx)
            max_len = len(col_name)
            for row_idx in range(2, len(rows) + 2):
                val = ws.cell(row=row_idx, column=col_idx).value
                if val:
                    max_len = max(max_len, min(len(str(val)), 40))
            ws.column_dimensions[col_letter].width = max_len + 2

        ws.freeze_panes = "A2"

    print(f"Exported {len(rows)} tickets → {args.out}")


if __name__ == "__main__":
    main()
