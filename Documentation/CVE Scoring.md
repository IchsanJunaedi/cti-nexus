# CVE Scoring

## EPSS Lookup

File: `app/services/epss_service.py`

Fetch exploit-probability scores from FIRST.org, batch 100 CVE/req:

```
GET https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,...&limit=100
```

Per CVE stored:
- `epss` — 0-1 prob exploit seen in wild next 30d
- `percentile` — rank vs all CVEs
- `date` — score date

Saved to `cve_tracker` doc fields: `epss_score`, `epss_percentile`, `epss_date`, `epss_checked_at`.

```python
async def fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    ...
    for entry in data.get("data", []):
        cve_id = entry.get("cve", "").strip().upper()
        if cve_id:
            results[cve_id] = {
                "epss":        float(entry.get("epss", 0)),
                "percentile":  float(entry.get("percentile", 0)),
                "date":        entry.get("date", ""),
            }
```

`lookup_all_true_positives()` pulls all non-false-positive CVE ids from DB, fetches scores, bulk-saves. False positives skipped (`get_fp_cve_ids`).

## Risk Score Adjustment

File: `app/services/cve_service.py` (`get_cves()`, ~line 209-236)

Per CVE, pull tech's exposure/hosting via `techstack_service.get_tech_risk_context(client_id)`. Default `exposure=internal`, `hosting_type=on_prem` when tech unmatched. KEV/PoC pulled directly off the CVE doc (`cisa_kev`, `poc_available` — populated by CISA KEV sync + PoC scrapers, see `app/models/cve_tracker.py`).

### Multipliers

`app/models/techstack.py`:

```python
EXPOSURE_MULTIPLIER = {"public": 1.5, "both": 1.25, "internal": 1.0}
HOSTING_MULTIPLIER  = {"on_prem": 1.0, "cloud": 1.0, "saas": 0.8}
```

EPSS, KEV, PoC multipliers (inline in `cve_service.py`):

```python
epss_mult = 1.3 if epss >= 0.5 else (1.15 if epss >= 0.1 else 1.0)
kev_mult  = 1.5 if c.get("cisa_kev") else 1.0
poc_mult  = 1.2 if c.get("poc_available") else 1.0
```

### Formula

```
adjusted_risk_score = min(10.0,
    raw_cve_score * exposure_mult * epss_mult * hosting_mult * kev_mult * poc_mult
)
```
Round 1 decimal. `raw_cve_score` = CVE's base `cve_score` field (CVSS).

### Logic + framework basis

- **Exposure** — public-facing tech bumps risk 1.5x, mixed 1.25x, internal-only 1.0x. Mirrors **CVSS Environmental Metrics** (Modified Attack Vector: Network > Adjacent > Local > Physical) — org overrides base score by real deployment context.
- **Hosting** — SaaS lowers risk 0.8x (vendor-managed patching assumed). On-prem/cloud neutral 1.0x.
- **EPSS** — FIRST.org exploit-probability, high (≥0.5) → 1.3x, moderate (≥0.1) → 1.15x, low → 1.0x. Direct use of **FIRST EPSS** model.
- **KEV** — CISA Known Exploited Vulnerabilities listing → 1.5x. Confirmed active exploitation in the wild, strongest real-world signal available (basis for CISA BOD 22-01 mandatory-remediation deadlines). Same weight as `pkg_vuln_service.py`'s existing `kev_mult`, kept consistent across both scoring paths.
- **PoC** — public proof-of-concept/exploit code available → 1.2x. Maps to **CVSS Temporal — Exploit Code Maturity (E)** metric, which formally treats PoC availability as a score modifier (lower attack cost/skill once exploit code public). Weighted below KEV since PoC existing ≠ confirmed exploitation.
- All multipliers stack multiplicatively, capped at 10.0.

### Example

CVE base score 4.7, EPSS 86.68% (0.8668), exposure "internal", hosting "on_prem", KEV-listed, PoC available:

```
exposure_mult = 1.0   (internal)
epss_mult     = 1.3   (epss >= 0.5)
hosting_mult  = 1.0   (on_prem)
kev_mult      = 1.5   (cisa_kev = true)
poc_mult      = 1.2   (poc_available = true)

adjusted = min(10.0, 4.7 * 1.0 * 1.3 * 1.0 * 1.5 * 1.2)
         = min(10.0, 10.9863)
         = 10.0
```
Before KEV/PoC wired in, this CVE scored 6.1 (`4.7 * 1.0 * 1.3 * 1.0`) despite active exploitation — now correctly caps at max severity.

Another, no KEV/PoC: base 5.0, EPSS 0.15, exposure "internal", hosting "saas":

```
exposure_mult = 1.0   (internal)
epss_mult     = 1.15  (epss >= 0.1)
hosting_mult  = 0.8   (saas)
kev_mult      = 1.0   (not KEV)
poc_mult      = 1.0   (no PoC)

adjusted = min(10.0, 5.0 * 1.0 * 1.15 * 0.8 * 1.0 * 1.0)
         = min(10.0, 4.6)
         = 4.6
```
