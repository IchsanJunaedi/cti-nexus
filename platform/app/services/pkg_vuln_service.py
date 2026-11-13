"""Package vulnerability monitoring using osv.dev (primary) and deps.dev (version metadata)."""
import asyncio
import json
import math
import re
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from bson import ObjectId
import httpx
from pymongo.errors import BulkWriteError
from pymongo.operations import UpdateOne
from app.database import get_database

_PKG_COL  = "monitored_packages"
_VULN_COL = "package_vulns"
_DEP_COL  = "package_dep_graph"

_DEPSDEV_URL   = "https://api.deps.dev/v3"
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = 30
_HEADERS = {"User-Agent": "ScraperNewsWeb/3.0", "Accept": "application/json"}

_VALID_ECOSYSTEMS = {"npm", "PyPI", "Go", "Maven", "crates.io", "NuGet", "RubyGems", "Packagist", "Hex"}
_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "NONE": 0}


def _pkg_col():
    return get_database()[_PKG_COL]


def _vuln_col():
    return get_database()[_VULN_COL]


def _dep_col():
    return get_database()[_DEP_COL]


def _client_filter(client_id: str) -> dict:
    if client_id == "default":
        return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
    return {"client_id": client_id}


# ── Index management ──────────────────────────────────────────────────────────

async def ensure_indexes() -> None:
    db = get_database()
    await db[_PKG_COL].create_index(
        [("name", 1), ("ecosystem", 1), ("client_id", 1)], unique=True, background=True,
    )
    await db[_VULN_COL].create_index(
        [("package_name", 1), ("ecosystem", 1), ("advisory_id", 1), ("client_id", 1)],
        unique=True, background=True,
    )
    await db[_VULN_COL].create_index([("severity", 1), ("client_id", 1)], background=True)
    await db[_VULN_COL].create_index([("adjusted_severity", 1), ("client_id", 1)], background=True)
    await db[_VULN_COL].create_index([("package_name", 1), ("client_id", 1)], background=True)
    await db[_VULN_COL].create_index([("kev", 1), ("client_id", 1)], background=True)
    await db[_DEP_COL].create_index([("pkg_id", 1), ("client_id", 1)], unique=True, background=True)


# ── Package management ─────────────────────────────────────────────────────────

async def list_packages(
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "name",
    sort_dir: str = "asc",
    client_id: str = "default",
) -> tuple[list[dict], int]:
    col = _pkg_col()
    query: dict = {**_client_filter(client_id)}
    if search:
        query["$or"] = [
            {"name":      {"$regex": search, "$options": "i"}},
            {"ecosystem": {"$regex": search, "$options": "i"}},
        ]
    valid_sorts = {"name", "ecosystem", "added_date", "vuln_count", "highest_severity", "last_scan"}
    if sort_by not in valid_sorts:
        sort_by = "name"
    direction = 1 if sort_dir == "asc" else -1
    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, direction).skip(skip).limit(page_size)
    items, total = await asyncio.gather(cursor.to_list(page_size), col.count_documents(query))
    return items, total


async def add_package(
    name: str, ecosystem: str,
    version: str | None = None,
    client_id: str = "default",
    source: str = "manual",
) -> dict:
    if ecosystem not in _VALID_ECOSYSTEMS:
        return {"success": False, "reason": f"invalid ecosystem — must be one of {sorted(_VALID_ECOSYSTEMS)}"}
    col = _pkg_col()
    cf = _client_filter(client_id)
    existing = await col.find_one(
        {"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}, "ecosystem": ecosystem, **cf}
    )
    if existing:
        # Update version if new one provided
        if version and existing.get("version") != version:
            await col.update_one({"_id": existing["_id"]}, {"$set": {"version": version}})
        return {"success": False, "reason": "duplicate"}
    exists = await _package_exists_on_registry(name, ecosystem)
    if exists is False:
        return {"success": False, "reason": f'"{name}" not found on {ecosystem} registry — check spelling or ecosystem'}
    await col.insert_one({
        "name": name, "ecosystem": ecosystem,
        "version": version or None,
        "client_id": client_id,
        "added_date": str(date.today()),
        "source": source,
        "last_scan": None, "vuln_count": 0,
        "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
        "highest_severity": "NONE", "latest_version": None,
    })
    asyncio.create_task(scan_package(name, ecosystem, version, client_id))
    return {"success": True}


async def delete_package(pkg_id: str, client_id: str = "default") -> dict:
    col  = _pkg_col()
    vcol = _vuln_col()
    try:
        oid = ObjectId(pkg_id)
    except Exception:
        return {"success": False, "reason": "invalid id"}
    doc = await col.find_one({"_id": oid, **_client_filter(client_id)})
    if not doc:
        return {"success": False, "reason": "not found"}
    name, ecosystem = doc["name"], doc["ecosystem"]
    await asyncio.gather(
        col.delete_one({"_id": oid}),
        vcol.delete_many({"package_name": name, "ecosystem": ecosystem, **_client_filter(client_id)}),
    )
    return {"success": True, "deleted": name}


async def update_package(
    pkg_id: str,
    version: str | None = None,
    ecosystem: str | None = None,
    client_id: str = "default",
) -> dict:
    col = _pkg_col()
    try:
        oid = ObjectId(pkg_id)
    except Exception:
        return {"success": False, "reason": "invalid id"}
    doc = await col.find_one({"_id": oid, **_client_filter(client_id)})
    if not doc:
        return {"success": False, "reason": "not found"}
    updates: dict = {}
    rescan = False
    if ecosystem is not None and ecosystem != doc.get("ecosystem"):
        if ecosystem not in _VALID_ECOSYSTEMS:
            return {"success": False, "reason": f"invalid ecosystem — must be one of {sorted(_VALID_ECOSYSTEMS)}"}
        updates["ecosystem"] = ecosystem
        rescan = True
    if version is not None and version != doc.get("version"):
        updates["version"] = version or None
        rescan = True
    if not updates:
        return {"success": True, "changed": False}
    await col.update_one({"_id": oid}, {"$set": updates})
    if rescan:
        new_eco = updates.get("ecosystem", doc["ecosystem"])
        new_ver = updates.get("version", doc.get("version"))
        vcol = _vuln_col()
        await vcol.delete_many({
            "package_name": doc["name"], "ecosystem": doc["ecosystem"],
            **_client_filter(client_id),
        })
        asyncio.create_task(scan_package(doc["name"], new_eco, new_ver, client_id))
    return {"success": True, "changed": True}


async def get_package_by_id(pkg_id: str, client_id: str = "default") -> dict | None:
    try:
        oid = ObjectId(pkg_id)
    except Exception:
        return None
    return await _pkg_col().find_one({"_id": oid, **_client_filter(client_id)})


# ── Vulnerability queries ──────────────────────────────────────────────────────

async def list_vulns(
    package_name: str | None = None,
    ecosystem: str | None = None,
    severity: str | None = None,
    kev_only: bool = False,
    acknowledged: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "adjusted_score",
    sort_dir: str = "desc",
    client_id: str = "default",
) -> tuple[list[dict], int]:
    col = _vuln_col()
    query: dict = {**_client_filter(client_id)}
    if package_name:
        query["package_name"] = {"$regex": package_name, "$options": "i"}
    if ecosystem:
        query["ecosystem"] = ecosystem
    if severity:
        query["$or"] = [{"severity": severity.upper()}, {"adjusted_severity": severity.upper()}]
    if kev_only:
        query["kev"] = True
    if acknowledged == "true":
        query["acknowledged"] = True
    elif acknowledged == "false":
        query["acknowledged"] = {"$ne": True}
    if search:
        search_or = [
            {"advisory_id": {"$regex": search, "$options": "i"}},
            {"aliases":     {"$regex": search, "$options": "i"}},
            {"summary":     {"$regex": search, "$options": "i"}},
        ]
        try:
            search_or.append({"_id": ObjectId(search)})
        except Exception:
            pass
        if "$or" in query:
            query["$and"] = [{"$or": query.pop("$or")}, {"$or": search_or}]
        else:
            query["$or"] = search_or
    valid_sorts = {"advisory_id", "severity", "cvss_score", "adjusted_score",
                   "epss_score", "published", "modified", "package_name"}
    if sort_by not in valid_sorts:
        sort_by = "adjusted_score"
    direction = 1 if sort_dir == "asc" else -1
    skip = (page - 1) * page_size
    cursor = col.find(query).sort(sort_by, direction).skip(skip).limit(page_size)
    items, total = await asyncio.gather(cursor.to_list(page_size), col.count_documents(query))
    return items, total


async def acknowledge_vuln(vuln_id: str, username: str, client_id: str = "default") -> dict:
    col = _vuln_col()
    try:
        oid = ObjectId(vuln_id)
    except Exception:
        return {"success": False, "reason": "invalid id"}
    doc = await col.find_one({"_id": oid, **_client_filter(client_id)})
    if not doc:
        return {"success": False, "reason": "not found"}
    now     = datetime.now(timezone.utc).isoformat()
    toggled = not doc.get("acknowledged", False)
    update: dict = {"acknowledged": toggled}
    if toggled:
        update["ack_by"]   = username
        update["ack_date"] = now
    else:
        update["ack_by"]   = None
        update["ack_date"] = None
    await col.update_one({"_id": oid}, {"$set": update})
    return {"success": True, "acknowledged": toggled}


async def get_stats(client_id: str = "default") -> dict:
    pkg_col  = _pkg_col()
    vuln_col = _vuln_col()
    cf = _client_filter(client_id)
    pkg_count, vuln_count, crit, high, med, low, unacked, kev_count = await asyncio.gather(
        pkg_col.count_documents(cf),
        vuln_col.count_documents(cf),
        vuln_col.count_documents({"$or": [{"severity": "CRITICAL"}, {"adjusted_severity": "CRITICAL"}], **cf}),
        vuln_col.count_documents({"$or": [{"severity": "HIGH"},     {"adjusted_severity": "HIGH"}],     **cf}),
        vuln_col.count_documents({"$or": [{"severity": "MEDIUM"},   {"adjusted_severity": "MEDIUM"}],   **cf}),
        vuln_col.count_documents({"$or": [{"severity": "LOW"},      {"adjusted_severity": "LOW"}],      **cf}),
        vuln_col.count_documents({"acknowledged": {"$ne": True}, **cf}),
        vuln_col.count_documents({"kev": True, **cf}),
    )
    return {
        "packages": pkg_count,
        "total_vulns": vuln_count,
        "critical": crit,
        "high": high,
        "medium": med,
        "low": low,
        "unacknowledged": unacked,
        "kev_count": kev_count,
    }


# ── CVSS / severity parsing ────────────────────────────────────────────────────

def _parse_severity(osv_vuln: dict) -> tuple[str, float | None]:
    """Extract severity label and CVSS score from an OSV advisory."""
    db_top  = osv_vuln.get("database_specific", {})
    top_sev = db_top.get("severity", "")
    for sev in osv_vuln.get("severity", []):
        score_type = sev.get("type", "")
        vector     = sev.get("score", "")
        if "CVSS" in score_type and vector:
            score = _cvss_vector_to_score(vector)
            if score is not None:
                return _score_to_label(score), score
    if top_sev:
        label = _normalize_sev_str(top_sev)
        return label, _label_to_midpoint(label)
    for affected in osv_vuln.get("affected", []):
        sev_str = affected.get("database_specific", {}).get("severity", "")
        if sev_str:
            label = _normalize_sev_str(sev_str)
            return label, _label_to_midpoint(label)
    return "UNKNOWN", None


def _normalize_sev_str(s: str) -> str:
    s = s.upper().strip()
    return "MEDIUM" if s == "MODERATE" else (s if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN")


def _label_to_midpoint(label: str) -> float | None:
    return {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.0}.get(label)


def _cvss_vector_to_score(vector: str) -> float | None:
    """Compute CVSS v3 base score from vector string."""
    if not vector or "CVSS:3" not in vector:
        return None
    try:
        parts   = vector.split("/")
        metrics = {}
        for part in parts[1:]:
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k] = v

        _AV    = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        _AC    = {"L": 0.77, "H": 0.44}
        _PR_US = {"N": 0.85, "L": 0.62, "H": 0.27}
        _PR_SC = {"N": 0.85, "L": 0.68, "H": 0.50}
        _UI    = {"N": 0.85, "R": 0.62}
        _CIA   = {"N": 0.00, "L": 0.22, "H": 0.56}

        S  = metrics.get("S", "U")
        AV = _AV.get(metrics.get("AV", "N"), 0.85)
        AC = _AC.get(metrics.get("AC", "L"), 0.77)
        PR = (_PR_SC if S == "C" else _PR_US).get(metrics.get("PR", "N"), 0.85)
        UI = _UI.get(metrics.get("UI", "N"), 0.85)
        C  = _CIA.get(metrics.get("C",  "N"), 0.00)
        I  = _CIA.get(metrics.get("I",  "N"), 0.00)
        A  = _CIA.get(metrics.get("A",  "N"), 0.00)

        ISCBase = 1 - (1 - C) * (1 - I) * (1 - A)
        ESC     = 8.22 * AV * AC * PR * UI
        if ISCBase == 0:
            return 0.0
        if S == "U":
            raw = min(10.0, 6.42 * ISCBase + ESC)
        else:
            ISC = 7.52 * (ISCBase - 0.029) - 3.25 * (ISCBase - 0.02) ** 15
            raw = min(10.0, 1.08 * (ISC + ESC))

        return round(min(math.ceil(raw * 10) / 10, 10.0), 1)
    except Exception:
        return None


def _score_to_label(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0:    return "LOW"
    return "UNKNOWN"


def _compute_adjusted_score(cvss: float | None, epss: float | None, kev: bool) -> tuple[float | None, str | None]:
    """Composite score mirrors CVE Tracker logic: cvss × epss_mult × kev_mult."""
    if cvss is None:
        return None, None
    epss_mult = 1.3 if (epss or 0) >= 0.5 else (1.15 if (epss or 0) >= 0.1 else 1.0)
    kev_mult  = 1.5 if kev else 1.0
    adj = min(10.0, cvss * epss_mult * kev_mult)
    adj = round(adj, 1)
    return adj, _score_to_label(adj)


# ── Extraction helpers ─────────────────────────────────────────────────────────

def _extract_fixed_version(osv_vuln: dict) -> str | None:
    latest = None
    for affected in osv_vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed and (latest is None or fixed > latest):
                    latest = fixed
    return latest


def _extract_version_ranges(osv_vuln: dict) -> list[str]:
    ranges = []
    for affected in osv_vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            events     = rng.get("events", [])
            introduced = next((e.get("introduced") for e in events if "introduced" in e), None)
            fixed      = next((e.get("fixed")      for e in events if "fixed"      in e), None)
            parts = []
            if introduced and introduced != "0":
                parts.append(f">= {introduced}")
            if fixed:
                parts.append(f"< {fixed}")
            if parts:
                ranges.append(", ".join(parts))
    return ranges[:5]


def _extract_references(osv_vuln: dict) -> list[str]:
    return [r["url"] for r in osv_vuln.get("references", []) if r.get("url")][:10]


def _extract_date(raw: str | None) -> str | None:
    return raw[:10] if raw else None


# ── External API fetches ───────────────────────────────────────────────────────

async def _fetch_osv_vulns(name: str, ecosystem: str, version: str | None = None) -> list[dict]:
    """Fetch full vulnerability data from osv.dev. Optionally version-pinned."""
    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
            resp = await client.post(_OSV_QUERY_URL, json=payload)
            if resp.status_code != 200:
                print(f"[PkgVuln] osv.dev {name}/{ecosystem}@{version} → HTTP {resp.status_code}")
                return []
            return resp.json().get("vulns", [])
    except Exception as e:
        print(f"[PkgVuln] osv.dev fetch error {name}/{ecosystem}: {e}")
        return []


_DEPSDEV_ECO = {
    "npm": "npm", "PyPI": "pypi", "Go": "go", "Maven": "maven",
    "crates.io": "cargo", "NuGet": "nuget", "RubyGems": "rubygems",
}

_VALIDATION_TIMEOUT = 8  # shorter timeout just for existence check


async def _package_exists_on_registry(name: str, ecosystem: str) -> bool | None:
    """Return True if package found, False if 404, None if ecosystem unsupported or check failed."""
    eco = _DEPSDEV_ECO.get(ecosystem)
    if not eco:
        return None  # Packagist, Hex — skip validation
    enc = urllib.parse.quote(name, safe="")
    url = f"{_DEPSDEV_URL}/systems/{eco}/packages/{enc}"
    try:
        async with httpx.AsyncClient(timeout=_VALIDATION_TIMEOUT, headers=_HEADERS) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                return False
            return resp.status_code == 200
    except Exception:
        return None  # network error — don't block the add

_DEPSDEV_SYSTEM_TO_ECO = {
    "NPM": "npm", "PYPI": "PyPI", "GO": "Go", "MAVEN": "Maven",
    "CARGO": "crates.io", "NUGET": "NuGet", "RUBYGEMS": "RubyGems",
}


async def _fetch_depsdev_latest_version(name: str, ecosystem: str) -> str | None:
    eco = _DEPSDEV_ECO.get(ecosystem)
    if not eco:
        return None
    enc = urllib.parse.quote(name, safe="")
    url = f"{_DEPSDEV_URL}/systems/{eco}/packages/{enc}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            versions = resp.json().get("versions", [])
        if not versions:
            return None
        for v in versions:
            if v.get("isDefault"):
                return v.get("versionKey", {}).get("version")
        return versions[-1].get("versionKey", {}).get("version")
    except Exception:
        return None


async def _fetch_depsdev_deps(name: str, ecosystem: str, version: str) -> dict:
    """Fetch transitive dependency graph from deps.dev :dependencies endpoint."""
    eco = _DEPSDEV_ECO.get(ecosystem)
    if not eco:
        return {"direct": [], "indirect": [], "total": 0, "error": f"Ecosystem {ecosystem} not supported by deps.dev"}
    enc_name = urllib.parse.quote(name, safe="")
    enc_ver  = urllib.parse.quote(version, safe="")
    url = f"{_DEPSDEV_URL}/systems/{eco}/packages/{enc_name}/versions/{enc_ver}:dependencies"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {"direct": [], "indirect": [], "total": 0, "error": f"deps.dev HTTP {resp.status_code}"}
            data = resp.json()
        nodes = data.get("nodes", [])
        direct = [
            {"name": n["versionKey"]["name"], "version": n["versionKey"]["version"],
             "system": n["versionKey"]["system"]}
            for n in nodes if n.get("relation") == "DIRECT"
        ]
        indirect = [
            {"name": n["versionKey"]["name"], "version": n["versionKey"]["version"],
             "system": n["versionKey"]["system"]}
            for n in nodes if n.get("relation") == "INDIRECT"
        ]
        return {
            "direct":   direct,
            "indirect": indirect[:200],
            "total":    len(direct) + len(indirect),
            "error":    data.get("error") or None,
        }
    except Exception as e:
        return {"direct": [], "indirect": [], "total": 0, "error": str(e)}


async def _fetch_depsdev_scorecard(name: str, ecosystem: str, version: str) -> dict | None:
    """Fetch OSSF Scorecard via deps.dev project endpoint. Returns score summary or None."""
    eco = _DEPSDEV_ECO.get(ecosystem)
    if not eco:
        return None
    enc_name = urllib.parse.quote(name, safe="")
    enc_ver  = urllib.parse.quote(version, safe="")
    ver_url  = f"{_DEPSDEV_URL}/systems/{eco}/packages/{enc_name}/versions/{enc_ver}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
            resp = await client.get(ver_url)
            if resp.status_code != 200:
                return None
            ver_data = resp.json()

        project_id: str | None = None
        for rp in ver_data.get("relatedProjects", []):
            if rp.get("relationType") == "SOURCE_REPO":
                project_id = rp.get("projectKey", {}).get("id")
                break
        if not project_id:
            for rp in ver_data.get("relatedProjects", []):
                pid = rp.get("projectKey", {}).get("id", "")
                if pid.startswith("github.com/"):
                    project_id = pid
                    break
        if not project_id:
            return None

        enc_proj = urllib.parse.quote(project_id, safe="")
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
            resp = await client.get(f"{_DEPSDEV_URL}/projects/{enc_proj}")
            if resp.status_code != 200:
                return None
            proj_data = resp.json()

        sc = proj_data.get("scorecard", {})
        if not sc:
            return None
        checks      = sc.get("checks", [])
        check_scores = [c.get("score") for c in checks if c.get("score") is not None]
        avg_score    = round(sum(check_scores) / len(check_scores), 1) if check_scores else None
        risk_checks  = sorted(checks, key=lambda x: (x.get("score") or 10))[:6]
        return {
            "score":      avg_score,
            "date":       (sc.get("date") or "")[:10] or None,
            "project_id": project_id,
            "checks":     [
                {"name": c.get("name", ""), "score": c.get("score"),
                 "reason": (c.get("reason") or "")[:200]}
                for c in risk_checks
            ],
        }
    except Exception:
        return None


async def resolve_package_deps(
    pkg_id: str,
    client_id: str = "default",
    scan_transitive: bool = False,
) -> dict:
    """Resolve transitive dep graph + scorecard for a monitored package, store in package_dep_graph."""
    pkg_doc = await get_package_by_id(pkg_id, client_id)
    if not pkg_doc:
        return {"success": False, "reason": "not found"}

    name      = pkg_doc["name"]
    ecosystem = pkg_doc["ecosystem"]
    version   = pkg_doc.get("version") or pkg_doc.get("latest_version")

    if not version:
        version = await _fetch_depsdev_latest_version(name, ecosystem)
    if not version:
        return {"success": False, "reason": "no version available for dependency resolution"}

    deps_data, scorecard = await asyncio.gather(
        _fetch_depsdev_deps(name, ecosystem, version),
        _fetch_depsdev_scorecard(name, ecosystem, version),
    )

    now_iso = datetime.now(timezone.utc).isoformat()
    cf      = _client_filter(client_id)

    dep_doc = {
        "pkg_id":             pkg_id,
        "package_name":       name,
        "ecosystem":          ecosystem,
        "version":            version,
        "client_id":          client_id,
        "resolved_at":        now_iso,
        "direct_count":       len(deps_data["direct"]),
        "indirect_count":     len(deps_data["indirect"]),
        "total_count":        deps_data["total"],
        "direct_deps":        deps_data["direct"],
        "indirect_deps":      deps_data["indirect"],
        "scorecard_score":    scorecard.get("score") if scorecard else None,
        "scorecard_date":     scorecard.get("date") if scorecard else None,
        "scorecard_project":  scorecard.get("project_id") if scorecard else None,
        "scorecard_checks":   scorecard.get("checks", []) if scorecard else [],
        "error":              deps_data.get("error"),
    }

    await _dep_col().update_one(
        {"pkg_id": pkg_id, **cf},
        {"$set": dep_doc},
        upsert=True,
    )

    pkg_updates: dict = {
        "dep_direct_count":   dep_doc["direct_count"],
        "dep_indirect_count": dep_doc["indirect_count"],
        "dep_total_count":    dep_doc["total_count"],
        "dep_resolved_at":    now_iso,
    }
    if scorecard:
        pkg_updates["scorecard_score"] = scorecard.get("score")
        pkg_updates["scorecard_date"]  = scorecard.get("date")

    await _pkg_col().update_one({"name": name, "ecosystem": ecosystem, **cf}, {"$set": pkg_updates})

    if scan_transitive:
        transitive = deps_data["direct"] + deps_data["indirect"][:50]
        for dep in transitive:
            dep_eco = _DEPSDEV_SYSTEM_TO_ECO.get(dep.get("system", "").upper(), ecosystem)
            asyncio.create_task(scan_package(dep["name"], dep_eco, dep.get("version"), client_id))

    return {
        "success":   True,
        "direct":    dep_doc["direct_count"],
        "indirect":  dep_doc["indirect_count"],
        "total":     dep_doc["total_count"],
        "scorecard": scorecard.get("score") if scorecard else None,
    }


async def get_package_deps(pkg_id: str, client_id: str = "default") -> dict | None:
    return await _dep_col().find_one({"pkg_id": pkg_id, **_client_filter(client_id)})


# ── Composite enrichment (EPSS + KEV) ────────────────────────────────────────

async def _enrich_vulns_composite(vuln_ids_with_cves: list[tuple[str, list[str]]]) -> None:
    """Fetch EPSS + KEV for CVE aliases and write composite scores back to package_vulns."""
    if not vuln_ids_with_cves:
        return

    # Collect all unique CVE IDs across all vulns
    cve_map: dict[str, list[ObjectId]] = {}  # CVE → [oid, ...]
    for oid_str, aliases in vuln_ids_with_cves:
        oid = ObjectId(oid_str)
        for alias in aliases:
            if alias.upper().startswith("CVE-"):
                cve = alias.upper()
                cve_map.setdefault(cve, []).append(oid)

    if not cve_map:
        return

    cve_ids = list(cve_map.keys())

    from app.services.epss_service import fetch_epss_scores
    from app.services.cisa_kev_service import fetch_cisa_kev

    epss_data, kev_catalog = await asyncio.gather(
        fetch_epss_scores(cve_ids),
        fetch_cisa_kev(),
    )

    col = _vuln_col()
    ops = []
    for cve, oids in cve_map.items():
        epss_entry = epss_data.get(cve, {})
        kev_entry  = kev_catalog.get(cve, {})
        epss_score = epss_entry.get("epss") if epss_entry else None
        epss_pct   = epss_entry.get("percentile") if epss_entry else None
        is_kev     = bool(kev_entry)

        for oid in oids:
            # We need cvss_score to compute adjusted — fetch from DB or we have it in loop context.
            # Use update with aggregation pipeline to compute adjusted in-place is complex.
            # Simpler: store EPSS/KEV, recompute adjusted_score in a second pass.
            ops.append(UpdateOne(
                {"_id": oid},
                {"$set": {
                    "epss_score":      epss_score,
                    "epss_percentile": epss_pct,
                    "kev":             is_kev,
                    "kev_date_added":  kev_entry.get("dateAdded") if kev_entry else None,
                }},
            ))

    if ops:
        try:
            await col.bulk_write(ops, ordered=False)
        except Exception as e:
            print(f"[PkgVuln] EPSS/KEV write error: {e}")

    # Second pass: compute adjusted_score now that EPSS/KEV is stored
    docs = await col.find(
        {"_id": {"$in": [oid for _, oids in [(c, cve_map[c]) for c in cve_map] for oid in oids]}},
        {"_id": 1, "cvss_score": 1, "epss_score": 1, "kev": 1},
    ).to_list(5000)

    adj_ops = []
    for doc in docs:
        adj, adj_sev = _compute_adjusted_score(
            doc.get("cvss_score"), doc.get("epss_score"), doc.get("kev", False)
        )
        if adj is not None:
            adj_ops.append(UpdateOne(
                {"_id": doc["_id"]},
                {"$set": {"adjusted_score": adj, "adjusted_severity": adj_sev}},
            ))

    if adj_ops:
        try:
            await col.bulk_write(adj_ops, ordered=False)
        except Exception as e:
            print(f"[PkgVuln] adjusted_score write error: {e}")


# ── Lockfile parsing ──────────────────────────────────────────────────────────

def parse_requirements_txt(content: str) -> list[tuple[str, str, str | None]]:
    """Parse pip requirements.txt / requirements.lock → [(name, 'PyPI', version|None)]."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+")):
            continue
        # Strip extras: package[extra]==version
        line = re.sub(r"\[.*?\]", "", line)
        # pinned: package==1.2.3
        m = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s;]+)", line)
        if m:
            results.append((m.group(1), "PyPI", m.group(2)))
            continue
        # no version
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*$", line)
        if m:
            results.append((m.group(1), "PyPI", None))
    return results


def parse_package_json(content: str) -> list[tuple[str, str, str | None]]:
    """Parse package.json dependencies → [(name, 'npm', version|None)]."""
    import json
    try:
        data = json.loads(content)
    except Exception:
        return []
    results = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver_str in (data.get(section) or {}).items():
            # Strip semver range operators
            ver = re.sub(r"^[\^~>=<*]", "", ver_str).strip() or None
            if ver and re.match(r"\d", ver):
                results.append((name, "npm", ver))
            else:
                results.append((name, "npm", None))
    return results


def parse_package_lock_json(content: str) -> list[tuple[str, str, str | None]]:
    """Parse package-lock.json (v2/v3) → [(name, 'npm', version)]."""
    import json
    try:
        data = json.loads(content)
    except Exception:
        return []
    results = []
    # v2/v3 format uses "packages" key
    packages = data.get("packages", {})
    for path, info in packages.items():
        if not path or path == "":
            continue
        # path is like "node_modules/lodash" or "node_modules/a/node_modules/b"
        name = path.split("node_modules/")[-1]
        if name:
            results.append((name, "npm", info.get("version")))
    # v1 fallback
    if not results:
        for name, info in (data.get("dependencies") or {}).items():
            results.append((name, "npm", info.get("version")))
    return results


def parse_go_mod(content: str) -> list[tuple[str, str, str | None]]:
    """Parse go.mod → [(module_path, 'Go', version)]."""
    results = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require ") or in_require:
            raw = line.replace("require ", "").strip()
            parts = raw.split()
            if len(parts) >= 2:
                name, ver = parts[0], parts[1]
                # Strip go pseudo-versions to semver where possible
                ver = re.sub(r"-[0-9]{14}-[a-f0-9]+$", "", ver)
                results.append((name, "Go", ver.lstrip("v") or None))
    return results


def parse_pom_xml(content: str) -> list[tuple[str, str, str | None]]:
    """Parse Maven pom.xml → [(groupId:artifactId, 'Maven', version)]."""
    results = []
    try:
        root = ET.fromstring(content)
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        # Try both with and without namespace
        deps = root.findall(".//dependency", ns) or root.findall(".//dependency")
        for dep in deps:
            gid = (dep.findtext("groupId", namespaces=ns) or dep.findtext("groupId") or "").strip()
            aid = (dep.findtext("artifactId", namespaces=ns) or dep.findtext("artifactId") or "").strip()
            ver = (dep.findtext("version", namespaces=ns) or dep.findtext("version") or "").strip()
            if gid and aid:
                name = f"{gid}:{aid}"
                results.append((name, "Maven", ver or None))
    except Exception:
        pass
    return results


def parse_poetry_lock(content: str) -> list[tuple[str, str, str | None]]:
    """Parse poetry.lock → [(name, 'PyPI', version)]."""
    results = []
    current_name = None
    current_ver  = None
    for line in content.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if current_name:
                results.append((current_name, "PyPI", current_ver))
            current_name = None
            current_ver  = None
        m = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if m:
            current_name = m.group(1)
        m = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if m:
            current_ver = m.group(1)
    if current_name:
        results.append((current_name, "PyPI", current_ver))
    return results


def detect_and_parse_lockfile(filename: str, content: str) -> list[tuple[str, str, str | None]]:
    """Auto-detect lockfile type by filename and parse it."""
    fname = filename.lower()
    if fname in ("requirements.txt", "requirements.lock", "requirements-dev.txt",
                 "requirements-prod.txt") or fname.endswith(".requirements.txt"):
        return parse_requirements_txt(content)
    if fname == "package-lock.json":
        return parse_package_lock_json(content)
    if fname == "package.json":
        return parse_package_json(content)
    if fname in ("go.mod", "go.sum"):
        return parse_go_mod(content)
    if fname == "pom.xml":
        return parse_pom_xml(content)
    if fname == "poetry.lock":
        return parse_poetry_lock(content)
    # Fallback: try requirements.txt format
    return parse_requirements_txt(content)


async def import_lockfile(
    filename: str,
    content: str,
    client_id: str = "default",
) -> dict:
    """Parse lockfile, bulk-add packages, trigger background scans. Returns import summary."""
    parsed_pkgs = detect_and_parse_lockfile(filename, content)
    if not parsed_pkgs:
        return {"parsed": 0, "added": 0, "skipped": 0, "errors": ["No packages detected — check file format"]}

    added   = 0
    skipped = 0
    errors: list[str] = []
    pkg_list = []

    # Batch inserts — check duplicates in bulk then insert new ones
    col = _pkg_col()
    cf  = _client_filter(client_id)
    now = str(date.today())

    for name, ecosystem, version in parsed_pkgs:
        if not name or ecosystem not in _VALID_ECOSYSTEMS:
            continue
        existing = await col.find_one(
            {"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}, "ecosystem": ecosystem, **cf}
        )
        if existing:
            if version and existing.get("version") != version:
                await col.update_one({"_id": existing["_id"]}, {"$set": {"version": version}})
            skipped += 1
            continue
        try:
            await col.insert_one({
                "name": name, "ecosystem": ecosystem, "version": version,
                "client_id": client_id, "added_date": now, "source": "lockfile",
                "last_scan": None, "vuln_count": 0,
                "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
                "highest_severity": "NONE", "latest_version": None,
            })
            added += 1
            pkg_list.append({"name": name, "ecosystem": ecosystem, "version": version})
        except Exception as e:
            errors.append(f"{name}: {e}")

    # Fire-and-forget background scans for newly added packages
    for pkg in pkg_list:
        asyncio.create_task(scan_package(pkg["name"], pkg["ecosystem"], pkg.get("version"), client_id))

    return {
        "parsed":   len(parsed_pkgs),
        "added":    added,
        "skipped":  skipped,
        "errors":   errors[:20],
        "packages": pkg_list[:50],
    }


# ── Scanning ───────────────────────────────────────────────────────────────────

async def scan_package(
    name: str, ecosystem: str,
    version: str | None = None,
    client_id: str = "default",
) -> dict:
    """Scan one package against osv.dev (version-pinned if available) + deps.dev. Returns summary."""
    pkg_col  = _pkg_col()
    vuln_col = _vuln_col()
    cf = _client_filter(client_id)

    # If no version passed, check DB
    if version is None:
        pkg_doc = await pkg_col.find_one({"name": name, "ecosystem": ecosystem, **cf})
        if pkg_doc:
            version = pkg_doc.get("version")

    latest_ver, vulns = await asyncio.gather(
        _fetch_depsdev_latest_version(name, ecosystem),
        _fetch_osv_vulns(name, ecosystem, version),
    )

    ops = []
    sev_counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    now_iso     = datetime.now(timezone.utc).isoformat()
    new_vuln_ids: list[tuple[str, list[str]]] = []  # (oid_str, aliases)

    for vuln in vulns:
        advisory_id = vuln.get("id", "")
        if not advisory_id:
            continue
        severity, cvss_score = _parse_severity(vuln)
        sev_counts[severity if severity in sev_counts else "UNKNOWN"] += 1
        adj_score, adj_sev = _compute_adjusted_score(cvss_score, None, False)
        doc = {
            "package_name":           name,
            "ecosystem":              ecosystem,
            "pinned_version":         version,
            "advisory_id":            advisory_id,
            "aliases":                vuln.get("aliases", []),
            "summary":                vuln.get("summary", ""),
            "details":                (vuln.get("details") or "")[:2000],
            "severity":               severity,
            "cvss_score":             cvss_score,
            "adjusted_score":         adj_score,
            "adjusted_severity":      adj_sev,
            "published":              _extract_date(vuln.get("published")),
            "modified":               _extract_date(vuln.get("modified")),
            "fixed_version":          _extract_fixed_version(vuln),
            "affected_version_ranges": _extract_version_ranges(vuln),
            "references":             _extract_references(vuln),
            "client_id":              client_id,
            "source":                 "osv.dev",
            "last_updated":           now_iso,
        }
        ops.append(UpdateOne(
            {"package_name": name, "ecosystem": ecosystem, "advisory_id": advisory_id, **cf},
            {"$set": doc, "$setOnInsert": {"acknowledged": False, "ack_by": None, "ack_date": None,
                                           "epss_score": None, "epss_percentile": None,
                                           "kev": False, "kev_date_added": None}},
            upsert=True,
        ))

    inserted_ids: list[str] = []
    if ops:
        try:
            result = await vuln_col.bulk_write(ops, ordered=False)
            inserted_ids = [str(v) for v in result.upserted_ids.values()]
        except BulkWriteError as bwe:
            inserted_ids = [str(v) for v in bwe.details.get("upserted", {}).values()]
        except Exception as e:
            print(f"[PkgVuln] scan {name}/{ecosystem} write error: {e}")

    # Collect vuln IDs + aliases for EPSS/KEV enrichment (only freshly upserted for efficiency)
    if inserted_ids or vulns:
        # Grab all IDs for this package/client to enrich
        docs = await vuln_col.find(
            {"package_name": name, "ecosystem": ecosystem, **cf},
            {"_id": 1, "aliases": 1},
        ).to_list(500)
        vuln_id_alias_pairs = [(str(d["_id"]), d.get("aliases", [])) for d in docs]
        asyncio.create_task(_enrich_vulns_composite(vuln_id_alias_pairs))

    # Update package summary
    highest = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if sev_counts.get(s, 0) > 0), "NONE")
    total_vulns = sum(sev_counts.values())
    await pkg_col.update_one(
        {"name": name, "ecosystem": ecosystem, **cf},
        {"$set": {
            "last_scan":      now_iso,
            "vuln_count":     total_vulns,
            "critical_count": sev_counts.get("CRITICAL", 0),
            "high_count":     sev_counts.get("HIGH", 0),
            "medium_count":   sev_counts.get("MEDIUM", 0),
            "low_count":      sev_counts.get("LOW", 0),
            "highest_severity": highest,
            "latest_version": latest_ver,
        }},
    )

    return {
        "package":     name, "ecosystem": ecosystem,
        "version":     version,
        "vulns_found": total_vulns,
        "critical":    sev_counts.get("CRITICAL", 0),
        "high":        sev_counts.get("HIGH", 0),
    }


async def scan_all_packages(client_id: str = "default") -> dict:
    pkg_col = _pkg_col()
    cf = _client_filter(client_id)
    docs = await pkg_col.find(cf, {"name": 1, "ecosystem": 1, "version": 1}).to_list(1000)
    if not docs:
        return {"scanned": 0, "total_vulns": 0}

    total_vulns = 0
    total_scanned = 0
    BATCH = 10
    for i in range(0, len(docs), BATCH):
        chunk = docs[i:i + BATCH]
        tasks = [scan_package(d["name"], d["ecosystem"], d.get("version"), client_id) for d in chunk]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                total_vulns += r.get("vulns_found", 0)
                total_scanned += 1
        if i + BATCH < len(docs):
            await asyncio.sleep(2)

    return {"scanned": total_scanned, "total_vulns": total_vulns}


async def scan_all_clients() -> dict:
    from app.services.client_service import list_clients
    clients = await list_clients()
    client_ids = [c["client_id"] for c in clients] or ["default"]
    total_scanned = total_vulns = 0
    for cid in client_ids:
        try:
            r = await scan_all_packages(cid)
            total_scanned += r["scanned"]
            total_vulns   += r["total_vulns"]
        except Exception as e:
            print(f"[PkgVuln] Error scanning client {cid}: {e}")
    return {"clients": len(client_ids), "scanned": total_scanned, "total_vulns": total_vulns}
