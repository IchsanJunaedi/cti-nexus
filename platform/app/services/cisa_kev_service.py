import asyncio
from datetime import datetime, timezone

import httpx

from app.database import get_database
from app.services.cve_service import CVE_COLLECTION, get_fp_cve_ids

_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
}
_TIMEOUT = 30


def _col():
    return get_database()[CVE_COLLECTION]


async def fetch_cisa_kev() -> dict[str, dict]:
    """Fetch full CISA KEV catalog. Returns {cve_id_upper: vuln_dict}."""
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        resp = await client.get(_CISA_KEV_URL, headers=_HEADERS)
        resp.raise_for_status()
        data = resp.json()

    catalog: dict[str, dict] = {}
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "").strip().upper()
        if cve_id:
            catalog[cve_id] = vuln
    return catalog


async def save_cisa_kev_hit(cve_id: str, vuln: dict) -> None:
    """Update cve_tracker document with CISA KEV data."""
    col = _col()
    await col.update_many(
        {"cve_id": cve_id},
        {
            "$set": {
                "cisa_kev":              True,
                "cisa_kev_date_added":   vuln.get("dateAdded", ""),
                "cisa_kev_due_date":     vuln.get("dueDate", ""),
                "cisa_kev_vendor":       vuln.get("vendorProject", ""),
                "cisa_kev_product":      vuln.get("product", ""),
                "cisa_kev_name":         vuln.get("vulnerabilityName", ""),
                "cisa_kev_description":  vuln.get("shortDescription", ""),
                "cisa_kev_action":       vuln.get("requiredAction", ""),
                "cisa_kev_checked_at":   datetime.now(timezone.utc).isoformat(),
                "active_exploitation":   "Active Exploitation — Confirmed widespread use by threat actors (high priority)",
            }
        },
    )


async def lookup_all_true_positives() -> dict:
    """Cross-reference all TP CVEs in DB against full CISA KEV catalog."""
    col     = _col()
    fp_ids  = await get_fp_cve_ids()
    query   = {"cve_id": {"$nin": fp_ids}} if fp_ids else {}
    docs    = await col.find(query, {"cve_id": 1, "_id": 0}).to_list(length=10000)
    tp_ids  = {d["cve_id"].upper() for d in docs if d.get("cve_id")}

    catalog = await fetch_cisa_kev()

    matched = []
    saves   = []
    for cve_id_upper in tp_ids:
        if cve_id_upper in catalog:
            matched.append(cve_id_upper)
            saves.append(save_cisa_kev_hit(cve_id_upper, catalog[cve_id_upper]))

    await asyncio.gather(*saves)

    return {
        "checked":  len(tp_ids),
        "matched":  len(matched),
        "catalog_size": len(catalog),
        "matched_cves": matched,
    }
