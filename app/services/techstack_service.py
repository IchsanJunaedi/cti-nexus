import asyncio
from datetime import date, datetime, timedelta
from bson import ObjectId
import httpx
from pymongo.errors import DuplicateKeyError, BulkWriteError
from app.database import get_ta_database, get_database
from app.config import TECHSTACK_COLLECTION, NVD_API_KEY

_SORT_FIELDS   = {"name", "added_date", "source", "exposure", "hosting_type"}
_VALID_EXPOSURE = {"public", "internal", "both"}
_VALID_HOSTING  = {"on_prem", "cloud", "saas"}


def _col():
    return get_ta_database()[TECHSTACK_COLLECTION]


def _client_filter(client_id: str) -> dict:
    return {"client_id": client_id}


async def list_techstack(
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "name",
    sort_dir: str = "asc",
    client_id: str = "default",
) -> tuple[list[dict], int]:
    col = _col()
    query: dict = {**_client_filter(client_id)}
    if search:
        query["name"] = {"$regex": search, "$options": "i"}

    if sort_by not in _SORT_FIELDS:
        sort_by = "name"
    direction = 1 if sort_dir == "asc" else -1

    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, direction).skip(skip).limit(page_size)
    items, total = await asyncio.gather(
        cursor.to_list(length=page_size),
        col.count_documents(query),
    )
    return items, total


async def add_techstack(name: str, client_id: str = "default", exposure: str = "internal", hosting_type: str = "on_prem", vendor: str = "") -> dict:
    col = _col()
    cf = _client_filter(client_id)
    if exposure not in _VALID_EXPOSURE:
        exposure = "internal"
    if hosting_type not in _VALID_HOSTING:
        hosting_type = "on_prem"
    vendor = vendor.strip()
    # Per-client duplicate check (case-insensitive)
    if await col.find_one({"name": {"$regex": f"^{name}$", "$options": "i"}, **cf}):
        return {"success": False, "reason": "duplicate"}
    try:
        await col.insert_one({
            "name": name, "client_id": client_id,
            "added_date": str(date.today()), "source": "manual",
            "exposure": exposure, "hosting_type": hosting_type, "vendor": vendor,
        })
    except DuplicateKeyError:
        return {"success": False, "reason": "index_conflict",
                "hint": "Old unique index on 'name' still exists. Run: python scripts/fix_techstack_index.py"}
    # Cross-client copy of existing CVE docs
    backfilled = await _backfill_cves_for_tech(name, client_id)
    # Fire-and-forget 180-day NVD historical backfill
    asyncio.create_task(backfill_nvd_for_tech(name, client_id))
    return {"success": True, "cve_backfill": backfilled}


async def _backfill_cves_for_tech(tech_name: str, client_id: str) -> int:
    """Copy existing cve_tracker docs for tech_name to client_id. Returns count inserted.
    Non-fatal: if the old single-field cve_id unique index still exists, duplicate-key
    errors are swallowed and the partial upsert count is returned.
    Run scripts/fix_cve_tracker_index.py to replace the old index with compound (cve_id, client_id)."""
    try:
        cve_col = get_database()["cve_tracker"]
        existing = await cve_col.find(
            {"tech": {"$regex": f"^{tech_name}$", "$options": "i"},
             "client_id": {"$ne": client_id}},
            {"_id": 0},
        ).to_list(length=5000)

        if not existing:
            return 0

        from pymongo import UpdateOne
        ops = []
        for doc in existing:
            doc["client_id"] = client_id
            cve_id = doc.get("cve_id")
            if not cve_id:
                continue
            ops.append(UpdateOne(
                {"cve_id": cve_id, "client_id": client_id},
                {"$setOnInsert": doc},
                upsert=True,
            ))

        if not ops:
            return 0

        try:
            result = await cve_col.bulk_write(ops, ordered=False)
            return result.upserted_count
        except BulkWriteError as bwe:
            # Partial success — some docs inserted before index conflict
            upserted = bwe.details.get("nUpserted", 0)
            print(f"[backfill] BulkWriteError for tech '{tech_name}': {len(bwe.details.get('writeErrors', []))} errors, {upserted} upserted. Run fix_cve_tracker_index.py to resolve.")
            return upserted
    except Exception as e:
        print(f"[backfill] Non-fatal error for tech '{tech_name}': {e}")
        return 0



async def backfill_all_cves_for_client(client_id: str = "default") -> dict:
    """Backfill CVEs for ALL tech stacks the client currently has. Returns per-tech counts."""
    items, _ = await list_techstack(page=1, page_size=10000, client_id=client_id)
    results = {}
    total = 0
    for item in items:
        name = item.get("name", "")
        if not name:
            continue
        count = await _backfill_cves_for_tech(name, client_id)
        if count:
            results[name] = count
            total += count
    return {"total_backfilled": total, "by_tech": results}


async def _fetch_nvd_cves(tech: str, days: int = 180) -> list[dict]:
    now = datetime.utcnow()
    start = now - timedelta(days=days)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    tech_encoded = tech.replace(" ", "%20")

    headers = {"User-Agent": "ScraperNewsWeb/2.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    results = []
    start_index = 0
    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={tech_encoded}"
                f"&pubStartDate={start_str}%2B07:00"
                f"&pubEndDate={now_str}%2B07:00"
                f"&startIndex={start_index}&resultsPerPage=100"
            )
            try:
                r = await client.get(url, headers=headers)
                data = r.json()
            except Exception as e:
                print(f"[nvd_backfill] NVD fetch error for '{tech}': {e}")
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            for v in vulns:
                cve_id = v["cve"]["id"]
                summary = next(
                    (d["value"] for d in v["cve"].get("descriptions", []) if d["lang"] == "en"),
                    "",
                )
                results.append({
                    "id": cve_id,
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "summary": summary,
                })
            start_index += len(vulns)
            if start_index >= data.get("totalResults", 0):
                break
            await asyncio.sleep(6)  # NVD rate limit: 5 req/30s without key

    return results


async def _fetch_mitre_details(cve_id: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            f"https://cveawg.mitre.org/api/cve/{cve_id.upper()}", timeout=15
        )
        data = r.json()
    except Exception:
        return {}

    references = []
    try:
        for ref in data["containers"]["cna"]["references"]:
            references.append({"url": ref["url"], "tags": ref.get("tags", "")})
    except KeyError:
        pass

    base_score, vector_string, severity_string = 0, "", ""
    try:
        for cvss in data["containers"]["cna"]["metrics"]:
            for key in cvss:
                if key in ("scenarios", "format"):
                    continue
                if base_score <= cvss[key]["baseScore"]:
                    base_score = cvss[key]["baseScore"]
                    vector_string = cvss[key]["vectorString"]
                    severity_string = cvss[key]["baseSeverity"]
    except (KeyError, TypeError):
        pass

    affected_list = []
    try:
        seen = []
        for aff in data["containers"]["cna"]["affected"]:
            prod = aff["product"]
            if prod in seen:
                continue
            seen.append(prod)
            versions = []
            for ver in aff.get("versions", []):
                if ver.get("status") == "affected":
                    if "lessThan" in ver:
                        versions.append(f"< {ver['lessThan']}")
                    elif "lessThanOrEqual" in ver:
                        versions.append(f"<= {ver['lessThanOrEqual']}")
                    elif "version" in ver:
                        versions.append(f"<= {ver['version']}")
            affected_list.append({prod: versions})
    except (KeyError, TypeError):
        pass

    solution_string = "No solution yet"
    try:
        sols = [s["value"] for s in data["containers"]["cna"]["solutions"] if s["lang"] == "en"]
        if sols:
            solution_string = " ".join(sols)
    except KeyError:
        pass

    meta = data.get("cveMetadata", {})
    published = meta.get("datePublished", "")
    modified = meta.get("dateUpdated") or published

    return {
        "reference": references,
        "cve_score": base_score,
        "cvss_vector": vector_string,
        "cve_severity": severity_string,
        "affected": affected_list,
        "solutions": solution_string,
        "published": published,
        "cve_modified_date": modified,
    }


async def backfill_nvd_for_tech(tech_name: str, client_id: str, days: int = 180) -> int:
    """Fetch CVEs from NVD for `tech_name` over the past `days` days and upsert to cve_tracker."""
    from pymongo import UpdateOne

    print(f"[nvd_backfill] Starting {days}-day backfill: tech='{tech_name}' client='{client_id}'")
    nvd_cves = await _fetch_nvd_cves(tech_name, days=days)

    if not nvd_cves:
        print(f"[nvd_backfill] No CVEs found for '{tech_name}'")
        return 0

    cve_col = get_database()["cve_tracker"]
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    ops = []

    async with httpx.AsyncClient(timeout=20) as client:
        for cve in nvd_cves:
            cve_id = cve["id"]
            details = await _fetch_mitre_details(cve_id, client)
            await asyncio.sleep(2)

            doc = {
                "cve_id":           cve_id,
                "client_id":        client_id,
                "tech":             tech_name,
                "link":             cve["link"],
                "summary":          cve["summary"],
                "published":        details.get("published", ""),
                "reference":        details.get("reference", []),
                "affected":         details.get("affected", []),
                "solutions":        details.get("solutions", "No solution yet"),
                "cve_score":        float(details.get("cve_score") or 0),
                "cve_severity":     details.get("cve_severity", ""),
                "cvss_vector":      details.get("cvss_vector", ""),
                "cve_modified_date": details.get("cve_modified_date", ""),
                "last_updated":     now_str,
            }
            ops.append(UpdateOne(
                {"cve_id": cve_id, "client_id": client_id},
                {
                    "$set": doc,
                    "$setOnInsert": {
                        "poc_available":   False,
                        "pocs":            [],
                        "detected_on":     now_str,
                        "registered_date": now_str,
                    },
                },
                upsert=True,
            ))

    if not ops:
        return 0

    try:
        result = await cve_col.bulk_write(ops, ordered=False)
        count = result.upserted_count + result.modified_count
        print(f"[nvd_backfill] Done: {count} CVE(s) upserted for '{tech_name}'")
        return count
    except BulkWriteError as bwe:
        count = bwe.details.get("nUpserted", 0) + bwe.details.get("nModified", 0)
        print(f"[nvd_backfill] Partial: {count} for '{tech_name}'")
        return count
    except Exception as e:
        print(f"[nvd_backfill] Error: {e}")
        return 0


async def update_techstack_exposure(tech_id: str, exposure: str, client_id: str = "default") -> dict:
    if exposure not in _VALID_EXPOSURE:
        return {"success": False, "reason": "invalid_exposure"}
    try:
        result = await _col().update_one(
            {"_id": ObjectId(tech_id), **_client_filter(client_id)},
            {"$set": {"exposure": exposure}},
        )
    except Exception:
        return {"success": False}
    return {"success": result.matched_count > 0}


async def update_techstack_hosting(tech_id: str, hosting_type: str, client_id: str = "default") -> dict:
    if hosting_type not in _VALID_HOSTING:
        return {"success": False, "reason": "invalid_hosting_type"}
    try:
        result = await _col().update_one(
            {"_id": ObjectId(tech_id), **_client_filter(client_id)},
            {"$set": {"hosting_type": hosting_type}},
        )
    except Exception:
        return {"success": False}
    return {"success": result.matched_count > 0}


async def update_techstack_vendor(tech_id: str, vendor: str, client_id: str = "default") -> dict:
    try:
        result = await _col().update_one(
            {"_id": ObjectId(tech_id), **_client_filter(client_id)},
            {"$set": {"vendor": vendor.strip()}},
        )
    except Exception:
        return {"success": False}
    return {"success": result.matched_count > 0}


async def get_tech_risk_context(client_id: str = "default") -> dict[str, dict]:
    """Return {name_lower: {exposure, hosting_type}} for all tech stacks under client."""
    items, _ = await list_techstack(page=1, page_size=10000, client_id=client_id)
    return {
        item["name"].lower(): {
            "exposure":     item.get("exposure", "internal"),
            "hosting_type": item.get("hosting_type", "on_prem"),
        }
        for item in items if item.get("name")
    }


async def get_tech_vendor_map(client_id: str = "default") -> dict[str, str]:
    """Return {name_lower: vendor} for all tech stacks under client (used to group CVE emails by vendor)."""
    items, _ = await list_techstack(page=1, page_size=10000, client_id=client_id)
    return {item["name"].lower(): item.get("vendor", "") for item in items if item.get("name")}


async def get_exposure_map(client_id: str = "default") -> dict[str, str]:
    """Kept for backwards compatibility. Prefer get_tech_risk_context."""
    ctx = await get_tech_risk_context(client_id)
    return {k: v["exposure"] for k, v in ctx.items()}


async def get_tech_by_id(tech_id: str, client_id: str) -> dict | None:
    try:
        return await _col().find_one({"_id": ObjectId(tech_id), **_client_filter(client_id)})
    except Exception:
        return None


async def delete_techstack(tech_id: str, client_id: str = "default") -> dict:
    col = _col()
    # Get name before deleting so we can cascade-delete CVEs
    doc = await col.find_one({"_id": ObjectId(tech_id), **_client_filter(client_id)}, {"name": 1})
    if not doc:
        return {"success": False}
    result = await col.delete_one({"_id": ObjectId(tech_id)})
    if result.deleted_count == 0:
        return {"success": False}
    # Cascade: delete all CVEs + related FP/ticket records for this tech+client
    tech_name    = doc.get("name", "")
    cves_deleted = 0
    if tech_name:
        db      = get_database()
        cve_col = db["cve_tracker"]
        cf = _client_filter(client_id)

        # Find cve_ids to cascade-delete FP + tickets
        tech_filter = {"tech": {"$regex": f"^{tech_name}$", "$options": "i"}, **cf}
        cve_ids = [d["cve_id"] async for d in cve_col.find(tech_filter, {"cve_id": 1, "_id": 0}) if d.get("cve_id")]

        cve_res = await cve_col.delete_many(tech_filter)
        cves_deleted = cve_res.deleted_count

        if cve_ids:
            await asyncio.gather(
                db["cve_false_positives"].delete_many({"cve_id": {"$in": cve_ids}, **cf}),
                db["cve_tickets"].delete_many({"cve_id": {"$in": cve_ids}, **cf}),
            )

    return {"success": True, "cves_deleted": cves_deleted}
