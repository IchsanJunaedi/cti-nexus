import io
import os
from copy import copy
from datetime import datetime, timezone, timedelta
from typing import Optional

import openpyxl
from openpyxl.utils import get_column_letter

from app.database import get_database

CVE_COLLECTION    = "cve_tracker"
FP_COLLECTION     = "cve_false_positives"
TICKET_COLLECTION = "cve_tickets"

TEMPLATE_PATH = os.environ.get(
    "CVE_TRACKER_TEMPLATE",
    os.path.join(os.path.dirname(__file__), "..", "templates", "CVE_Tracker_template.xlsx"),
)

TRACKER_SHEET  = "CVE Ticket Tracker"
HEADER_ROW     = 15
DATA_START_ROW = 16

# Column index (1-based) → (field_source, field_name)
# field_source: "ticket" | "cve"
COL_MAP = {
    2:  ("ticket", "ticket_id"),
    3:  ("cve",    "cve_id"),
    4:  ("ticket", "cve_reported_date"),   # fallback: cve.detected_on / cve.published
    5:  ("cve",    "cve_severity"),
    6:  ("cve",    "cve_score"),
    7:  ("ticket", "affected_asset"),       # fallback: cve.tech
    8:  ("ticket", "affected_version"),
    9:  ("ticket", "fixed_version"),        # fallback: cve.solutions
    10: ("ticket", "asset_owner"),
    11: ("ticket", "owner_email"),
    12: ("ticket", "owner_team"),
    13: ("ticket", "active_exploitation"),  # fallback: cve.active_exploitation
    14: ("ticket", "acknowledge_time"),
    15: ("ticket", "remediation_date_plan"),
    16: ("ticket", "remediation_status"),
    17: ("ticket", "actual_remediation_date"),
    18: ("ticket", "escalation_required"),
    19: ("ticket", "comments"),
    20: ("ticket", "risk_acceptance"),
    21: ("ticket", "closure_date"),
}


def _db():
    return get_database()


def _parse_date_bound(date_str: str, end_of_day: bool = False) -> str:
    """Convert YYYY-MM-DD to ISO string usable in string comparison against detected_on."""
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    if end_of_day:
        dt = dt.replace(hour=23, minute=59, second=59)
    return dt.strftime("%Y-%m-%d")


def _cell_value(col_idx: int, cve: dict, ticket: dict) -> object:
    source, field = COL_MAP[col_idx]

    if source == "cve":
        return cve.get(field, "")

    val = ticket.get(field, "")

    # Fallbacks for empty ticket fields
    if (not val or val == "") and col_idx == 4:
        val = cve.get("detected_on") or cve.get("published", "")
    if (not val or val == "") and col_idx == 7:
        val = cve.get("tech", "")
    if (not val or val == "") and col_idx == 9:
        val = cve.get("solutions", "")
    if (not val or val == "") and col_idx == 13:
        val = cve.get("active_exploitation", "")

    if isinstance(val, bool):
        return "Yes" if val else "No"
    return val if val is not None else ""


def _copy_style(src_cell, dst_cell):
    """Copy cell formatting from src to dst."""
    if src_cell.has_style:
        dst_cell.font      = copy(src_cell.font)
        dst_cell.fill      = copy(src_cell.fill)
        dst_cell.border    = copy(src_cell.border)
        dst_cell.alignment = copy(src_cell.alignment)
        dst_cell.number_format = src_cell.number_format


async def export_cves_to_excel(
    date_start: Optional[str],
    date_end: Optional[str],
    search: Optional[str] = None,
    severity: Optional[list] = None,
    tech: Optional[list] = None,
    include_fp: bool = False,
    ack_filter: Optional[str] = None,
    draft_filter: Optional[str] = None,
    kev_filter: Optional[str] = None,
    score_filter: Optional[str] = None,
    updated_filter: Optional[str] = None,
) -> bytes:
    from app.services.cve_ticket_service import get_acked_cve_ids, get_drafted_cve_ids
    db = _db()
    fp_col  = db[FP_COLLECTION]
    cve_col = db[CVE_COLLECTION]
    tkt_col = db[TICKET_COLLECTION]

    # Get false positive IDs
    fp_docs = await fp_col.find({}, {"cve_id": 1, "_id": 0}).to_list(length=50000)
    fp_ids  = [d["cve_id"] for d in fp_docs]

    # Build query mirroring get_cves filter logic
    query: dict = {}
    if not include_fp and fp_ids:
        query["cve_id"] = {"$nin": fp_ids}

    if ack_filter in ("acked", "unacked"):
        acked_ids = await get_acked_cve_ids()
        acked_set = set(acked_ids)
        if ack_filter == "acked":
            existing = query.get("cve_id", {})
            nin = existing.get("$nin", []) if isinstance(existing, dict) else []
            query["cve_id"] = {"$in": [i for i in acked_ids if i not in set(nin)]}
        else:
            existing = query.get("cve_id", {})
            nin = list(existing.get("$nin", []) if isinstance(existing, dict) else [])
            query["cve_id"] = {"$nin": nin + [i for i in acked_set if i not in set(nin)]}

    if draft_filter in ("drafted", "undrafted"):
        drafted_ids = await get_drafted_cve_ids()
        drafted_set = set(drafted_ids)
        if draft_filter == "drafted":
            existing = query.get("cve_id", {})
            nin = existing.get("$nin", []) if isinstance(existing, dict) else []
            query["cve_id"] = {"$in": [i for i in drafted_ids if i not in set(nin)]}
        else:
            existing = query.get("cve_id", {})
            nin = list(existing.get("$nin", []) if isinstance(existing, dict) else [])
            query["cve_id"] = {"$nin": nin + [i for i in drafted_set if i not in set(nin)]}

    if tech:
        query["tech"] = {"$in": tech}

    if severity:
        query["cve_severity"] = {"$in": [s.upper() for s in severity]}

    from app.services.cve_service import apply_extra_filters
    apply_extra_filters(query, kev_filter, score_filter, updated_filter)

    if search:
        query["$or"] = [
            {"cve_id":  {"$regex": search, "$options": "i"}},
            {"summary": {"$regex": search, "$options": "i"}},
            {"tech":    {"$regex": search, "$options": "i"}},
        ]

    if date_start or date_end:
        date_filter: dict = {}
        if date_start:
            date_filter["$gte"] = _parse_date_bound(date_start)
        if date_end:
            date_filter["$lte"] = _parse_date_bound(date_end, end_of_day=True)

        # Filter on detected_on; if field absent, fall back to published
        query["$or"] = [
            {"detected_on": date_filter},
            {"detected_on": {"$in": ["", None]}, "published": date_filter},
        ]

    cves  = await cve_col.find(query).sort("detected_on", -1).to_list(length=50000)
    cve_ids = [c["cve_id"] for c in cves]

    # Fetch tickets for these CVEs
    tkt_docs = await tkt_col.find(
        {"cve_id": {"$in": cve_ids}}, {"_id": 0}
    ).to_list(length=50000)
    tickets: dict[str, dict] = {t["cve_id"]: t for t in tkt_docs}

    # Load template
    template_path = os.path.abspath(TEMPLATE_PATH)
    wb = openpyxl.load_workbook(template_path)
    ws = wb[TRACKER_SHEET]

    # Grab style reference from first data row (before deleting)
    style_ref: list = []
    if ws.max_row >= DATA_START_ROW:
        style_ref = list(ws[DATA_START_ROW])

    # Delete all existing data rows
    if ws.max_row >= DATA_START_ROW:
        ws.delete_rows(DATA_START_ROW, ws.max_row - DATA_START_ROW + 1)

    # Write filtered CVEs
    for row_offset, cve in enumerate(cves):
        row_num = DATA_START_ROW + row_offset
        tkt     = tickets.get(cve.get("cve_id", ""), {})

        for col_idx in range(2, 22):
            if col_idx not in COL_MAP:
                continue
            cell = ws.cell(row=row_num, column=col_idx)
            cell.value = _cell_value(col_idx, cve, tkt)

            # Copy style from reference row if available
            ref_idx = col_idx - 1  # style_ref is 0-indexed list of cells
            if style_ref and ref_idx < len(style_ref):
                _copy_style(style_ref[ref_idx], cell)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.read()
