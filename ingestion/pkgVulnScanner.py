"""Periodic package vulnerability scanner — runs independently of ScraperNewsWeb.

Reads monitored_packages from news_db, queries osv.dev (version-pinned) + deps.dev
(latest version), writes results to package_vulns, enriches with EPSS + CISA KEV.

Schedule: run at 00:00 and 12:00 UTC (e.g. via cron or scripts/ runner).
"""
import math
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone

import requests
import yaml
from pymongo import MongoClient, UpdateOne
from pymongo.errors import BulkWriteError

with open("config/config.yml") as _f:
    _cfg = yaml.safe_load(_f)

_mc        = _cfg["news_db"]
_MONGO_URI = (
    f"mongodb://{_mc['user']}:{_mc['pass']}@{_mc['ip']}"
    f"/?authSource={_mc['db']}&authMechanism=SCRAM-SHA-256"
)
_DB_NAME   = _mc["db"]

_PKG_COL  = "monitored_packages"
_VULN_COL = "package_vulns"

_OSV_URL      = "https://api.osv.dev/v1/query"
_DEPSDEV_URL  = "https://api.deps.dev/v3"
_EPSS_URL     = "https://api.first.org/data/v1/epss"
_KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TIMEOUT      = 30
_HEADERS      = {"User-Agent": "ScraperNewsRevamp/3.0", "Accept": "application/json"}

_DEPSDEV_ECO  = {
    "npm": "npm", "PyPI": "pypi", "Go": "go", "Maven": "maven",
    "crates.io": "cargo", "NuGet": "nuget", "RubyGems": "rubygems",
}
_SEV_ORDER    = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "NONE": 0}

BATCH_SIZE    = 10
BATCH_SLEEP   = 2  # seconds between batches


# ── DB helpers ────────────────────────────────────────────────────────────────

def _get_db():
    client = MongoClient(_MONGO_URI)
    return client, client[_DB_NAME]


# ── CVSS / severity ───────────────────────────────────────────────────────────

def _cvss_vector_to_score(vector: str) -> float | None:
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


def _normalize_sev(s: str) -> str:
    s = s.upper().strip()
    return "MEDIUM" if s == "MODERATE" else (s if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN")


def _label_midpoint(label: str) -> float | None:
    return {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.0}.get(label)


def _parse_severity(vuln: dict) -> tuple[str, float | None]:
    for sev in vuln.get("severity", []):
        if "CVSS" in sev.get("type", "") and sev.get("score"):
            score = _cvss_vector_to_score(sev["score"])
            if score is not None:
                return _score_to_label(score), score
    top = vuln.get("database_specific", {}).get("severity", "")
    if top:
        label = _normalize_sev(top)
        return label, _label_midpoint(label)
    for affected in vuln.get("affected", []):
        s = affected.get("database_specific", {}).get("severity", "")
        if s:
            label = _normalize_sev(s)
            return label, _label_midpoint(label)
    return "UNKNOWN", None


def _compute_adjusted(cvss: float | None, epss: float | None, kev: bool) -> tuple[float | None, str | None]:
    if cvss is None:
        return None, None
    epss_mult = 1.3 if (epss or 0) >= 0.5 else (1.15 if (epss or 0) >= 0.1 else 1.0)
    kev_mult  = 1.5 if kev else 1.0
    adj = round(min(10.0, cvss * epss_mult * kev_mult), 1)
    return adj, _score_to_label(adj)


def _extract_fixed(vuln: dict) -> str | None:
    latest = None
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for ev in rng.get("events", []):
                fx = ev.get("fixed")
                if fx and (latest is None or fx > latest):
                    latest = fx
    return latest


def _extract_ranges(vuln: dict) -> list[str]:
    out = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            evs  = rng.get("events", [])
            intr = next((e.get("introduced") for e in evs if "introduced" in e), None)
            fx   = next((e.get("fixed")      for e in evs if "fixed"      in e), None)
            parts = []
            if intr and intr != "0":
                parts.append(f">= {intr}")
            if fx:
                parts.append(f"< {fx}")
            if parts:
                out.append(", ".join(parts))
    return out[:5]


def _extract_refs(vuln: dict) -> list[str]:
    return [r["url"] for r in vuln.get("references", []) if r.get("url")][:10]


# ── External API calls ────────────────────────────────────────────────────────

def _fetch_osv_vulns(name: str, ecosystem: str, version: str | None) -> list[dict]:
    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    try:
        resp = requests.post(_OSV_URL, json=payload, headers=_HEADERS, timeout=_TIMEOUT)
        if resp.status_code != 200:
            print(f"  [osv] {name}/{ecosystem}@{version} → HTTP {resp.status_code}")
            return []
        return resp.json().get("vulns", [])
    except Exception as e:
        print(f"  [osv] error {name}/{ecosystem}: {e}")
        return []


def _fetch_latest_version(name: str, ecosystem: str) -> str | None:
    eco = _DEPSDEV_ECO.get(ecosystem)
    if not eco:
        return None
    enc = urllib.parse.quote(name, safe="")
    url = f"{_DEPSDEV_URL}/systems/{eco}/packages/{enc}"
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT)
        if resp.status_code != 200:
            return None
        versions = resp.json().get("versions", [])
        for v in versions:
            if v.get("isDefault"):
                return v.get("versionKey", {}).get("version")
        return versions[-1].get("versionKey", {}).get("version") if versions else None
    except Exception:
        return None


def _fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    if not cve_ids:
        return {}
    try:
        resp = requests.get(_EPSS_URL, params={"cve": ",".join(cve_ids)},
                            headers=_HEADERS, timeout=_TIMEOUT)
        if resp.status_code != 200:
            return {}
        out = {}
        for row in resp.json().get("data", []):
            cve = row.get("cve", "").upper()
            if cve:
                out[cve] = {"epss": float(row.get("epss", 0)), "percentile": float(row.get("percentile", 0))}
        return out
    except Exception as e:
        print(f"  [epss] fetch error: {e}")
        return {}


def _fetch_kev() -> dict[str, dict]:
    try:
        resp = requests.get(_KEV_URL, headers=_HEADERS, timeout=_TIMEOUT)
        if resp.status_code != 200:
            return {}
        out = {}
        for v in resp.json().get("vulnerabilities", []):
            cve = v.get("cveID", "").upper()
            if cve:
                out[cve] = {"dateAdded": v.get("dateAdded")}
        return out
    except Exception as e:
        print(f"  [kev] fetch error: {e}")
        return {}


# ── Scan one package ──────────────────────────────────────────────────────────

def _scan_package(db, name: str, ecosystem: str, version: str | None, client_id: str,
                  epss_data: dict, kev_catalog: dict) -> dict:
    pkg_col  = db[_PKG_COL]
    vuln_col = db[_VULN_COL]

    if version is None:
        doc = pkg_col.find_one({"name": name, "ecosystem": ecosystem, "client_id": client_id},
                               {"version": 1, "latest_version": 1})
        if doc:
            version = doc.get("version") or doc.get("latest_version")

    latest_ver = _fetch_latest_version(name, ecosystem)
    vulns      = _fetch_osv_vulns(name, ecosystem, version)

    ops = []
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    now_iso    = datetime.now(timezone.utc).isoformat()

    def _cf():
        if client_id == "default":
            return {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
        return {"client_id": client_id}

    for vuln in vulns:
        advisory_id = vuln.get("id", "")
        if not advisory_id:
            continue
        severity, cvss_score = _parse_severity(vuln)
        sev_counts[severity if severity in sev_counts else "UNKNOWN"] += 1

        # Look up EPSS + KEV via CVE aliases
        aliases  = vuln.get("aliases", [])
        cves     = [a.upper() for a in aliases if a.upper().startswith("CVE-")]
        best_epss = None
        best_epss_pct = None
        is_kev   = False
        kev_date = None
        for cve in cves:
            ep = epss_data.get(cve)
            if ep and (best_epss is None or ep["epss"] > best_epss):
                best_epss     = ep["epss"]
                best_epss_pct = ep.get("percentile")
            kv = kev_catalog.get(cve)
            if kv:
                is_kev   = True
                kev_date = kv.get("dateAdded")

        adj_score, adj_sev = _compute_adjusted(cvss_score, best_epss, is_kev)

        doc = {
            "package_name":            name,
            "ecosystem":               ecosystem,
            "pinned_version":          version,
            "advisory_id":             advisory_id,
            "aliases":                 aliases,
            "summary":                 vuln.get("summary", ""),
            "details":                 (vuln.get("details") or "")[:2000],
            "severity":                severity,
            "cvss_score":              cvss_score,
            "epss_score":              best_epss,
            "epss_percentile":         best_epss_pct,
            "kev":                     is_kev,
            "kev_date_added":          kev_date,
            "adjusted_score":          adj_score,
            "adjusted_severity":       adj_sev,
            "published":               (vuln.get("published") or "")[:10] or None,
            "modified":                (vuln.get("modified") or "")[:10] or None,
            "fixed_version":           _extract_fixed(vuln),
            "affected_version_ranges": _extract_ranges(vuln),
            "references":              _extract_refs(vuln),
            "client_id":               client_id,
            "source":                  "osv.dev",
            "last_updated":            now_iso,
        }
        cf_query = {"package_name": name, "ecosystem": ecosystem,
                    "advisory_id": advisory_id, **_cf()}
        ops.append(UpdateOne(
            cf_query,
            {"$set": doc, "$setOnInsert": {"acknowledged": False, "ack_by": None, "ack_date": None}},
            upsert=True,
        ))

    if ops:
        try:
            vuln_col.bulk_write(ops, ordered=False)
        except BulkWriteError:
            pass
        except Exception as e:
            print(f"  [scan] write error {name}/{ecosystem}: {e}")

    highest    = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if sev_counts.get(s, 0) > 0), "NONE")
    total_vulns = sum(sev_counts.values())

    update: dict = {
        "last_scan":      now_iso,
        "vuln_count":     total_vulns,
        "critical_count": sev_counts.get("CRITICAL", 0),
        "high_count":     sev_counts.get("HIGH", 0),
        "medium_count":   sev_counts.get("MEDIUM", 0),
        "low_count":      sev_counts.get("LOW", 0),
        "highest_severity": highest,
    }
    if latest_ver:
        update["latest_version"] = latest_ver

    pkg_col.update_one({"name": name, "ecosystem": ecosystem, **_cf()}, {"$set": update})

    return {"name": name, "vulns": total_vulns,
            "critical": sev_counts["CRITICAL"], "high": sev_counts["HIGH"]}


# ── Main scan loop ────────────────────────────────────────────────────────────

def scan_all() -> None:
    start = time.time()
    client, db = _get_db()
    try:
        # Fetch EPSS + KEV once upfront — shared across all packages
        print("[PkgVuln] Fetching EPSS + CISA KEV catalog…")
        # Collect all CVE aliases from existing package_vulns to pre-warm EPSS
        all_cves = list({
            alias.upper()
            for doc in db[_VULN_COL].find({}, {"aliases": 1})
            for alias in doc.get("aliases", [])
            if alias.upper().startswith("CVE-")
        })
        print(f"[PkgVuln]   pre-warming EPSS for {len(all_cves)} existing CVEs")
        epss_data   = _fetch_epss(all_cves[:1000])  # API cap
        kev_catalog = _fetch_kev()
        print(f"[PkgVuln]   EPSS={len(epss_data)} KEV={len(kev_catalog)}")

        # Get all clients + packages
        pipeline = [{"$group": {"_id": "$client_id"}}]
        clients = [doc["_id"] or "default" for doc in db[_PKG_COL].aggregate(pipeline)]
        if not clients:
            print("[PkgVuln] No packages to scan.")
            return

        total_scanned = total_vulns = total_crit = total_high = 0

        for client_id in clients:
            cf = {"$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]} \
                 if client_id == "default" else {"client_id": client_id}
            packages = list(db[_PKG_COL].find(cf, {"name": 1, "ecosystem": 1, "version": 1}))
            print(f"[PkgVuln] client={client_id}  packages={len(packages)}")

            for i in range(0, len(packages), BATCH_SIZE):
                chunk = packages[i:i + BATCH_SIZE]
                for pkg in chunk:
                    result = _scan_package(
                        db,
                        pkg["name"], pkg["ecosystem"], pkg.get("version"),
                        client_id, epss_data, kev_catalog,
                    )
                    total_scanned += 1
                    total_vulns   += result["vulns"]
                    total_crit    += result["critical"]
                    total_high    += result["high"]
                    if result["vulns"] > 0:
                        print(f"  {result['name']}: vulns={result['vulns']} C={result['critical']} H={result['high']}")
                if i + BATCH_SIZE < len(packages):
                    time.sleep(BATCH_SLEEP)

        elapsed = time.time() - start
        print(f"[PkgVuln] Done — scanned={total_scanned} vulns={total_vulns} "
              f"critical={total_crit} high={total_high} elapsed={elapsed:.1f}s")
    finally:
        client.close()


if __name__ == "__main__":
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"[PkgVuln] Starting package vulnerability scan — {now_str}")
    scan_all()
