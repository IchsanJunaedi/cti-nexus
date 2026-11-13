# ScraperNewsWeb CTI Platform — API Documentation

Base URL: `http://localhost:8000`  
Auth: JWT bearer token via `Authorization: Bearer <token>` header **or** `cti_auth` HttpOnly cookie.  
🔒 = requires auth · 🛡️ = requires admin role

---

## Table of Contents

1. [Articles](#1-articles)
2. [CVE Tracker](#2-cve-tracker)
3. [Priority Intelligence Requirements (PIR)](#3-priority-intelligence-requirements-pir)
4. [IOCs](#4-iocs)
5. [Threat Actors](#5-threat-actors)
6. [MITRE ATT&CK](#6-mitre-attck)
7. [Cross-Reference](#7-cross-reference)
8. [STIX 2.1 Export](#8-stix-21-export)
9. [Newsletter](#9-newsletter)
10. [Intelligence / Analytics](#10-intelligence--analytics)
11. [Executive Dashboard](#11-executive-dashboard)
12. [Ransomware](#12-ransomware)
13. [Source Reliability](#13-source-reliability)
14. [Mind Maps](#14-mind-maps)
15. [Scraper Health](#15-scraper-health)
16. [Changelog](#16-changelog)
17. [Tech Stack](#17-tech-stack)
18. [Filtered Articles](#18-filtered-articles)
19. [Authentication](#19-authentication)
20. [OIDC / SSO](#20-oidc--sso)
21. [RFI Tracker](#21-rfi-tracker)
22. [Notifications](#22-notifications)

---

## 1. Articles

### `GET /api/articles/dedup-groups`
Inspect semantic deduplication groups using TF-IDF + cosine similarity.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | int | 7 | Lookback window (1–30) |
| `threshold` | float | 0.75 | Cosine similarity threshold (0.5–0.99) |
| `limit` | int | 500 | Max articles to cluster (50–2000) |

**Response** — array of duplicate groups, each with canonical and duplicate articles.

---

### `GET /api/articles`
List articles with filtering, search, and optional semantic deduplication.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Items per page (1–100) |
| `posted_on_start` | str | — | Start date filter (`YYYY-MM-DD`) |
| `posted_on_end` | str | — | End date filter (`YYYY-MM-DD`) |
| `industry` | str[] | — | Filter by industry (repeatable) |
| `country` | str[] | — | Filter by country (repeatable) |
| `source` | str[] | — | Filter by source (repeatable) |
| `news_type` | str[] | — | Filter by news type (repeatable) |
| `threat_actor` | str[] | — | Filter by threat actor (repeatable) |
| `search` | str | — | Full-text search |
| `victim_country` | str[] | — | Filter by victim country |
| `actor_country` | str[] | — | Filter by actor country |
| `title_keyword` | str[] | — | Filter by title keywords |
| `dedup` | bool | false | Deduplicate results |
| `dedup_threshold` | float | 0.75 | Dedup similarity threshold (0.5–0.99) |

**Response** — `ArticleListResponse`: `{ articles, total, page, page_size }`

---

### `GET /api/filters`
Get all available filter option values (industries, countries, sources, news types, threat actors).

**Response** — `FilterOptions` object with distinct values for each filter dimension.

---

### `GET /api/country-groups`
Get regional country group definitions used for geographic filtering.

**Response** — `{ [region: string]: string[] }` mapping.

---

### `GET /api/dashboard`
Get high-level dashboard statistics.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `posted_on_start` | str | — | Start date (`YYYY-MM-DD`) |
| `posted_on_end` | str | — | End date (`YYYY-MM-DD`) |

**Response** — `DashboardStats` with article counts by type, source, industry, etc.

---

### `POST /api/articles/{article_id}/confidence` 🔒
Compute and store a confidence score (0–100) for a single article.

Score derived from: source Admiralty reliability grade + credibility code + TTP count bonus (5 pts each, max 20) + threat actor count bonus (10 pts each, max 10). Sources with no rating default to 50.

**Response** — `{ "article_id": str, "confidence_score": int }`

---

### `POST /api/articles/confidence/recompute` 🔒
Batch recompute confidence scores for all articles. Loads all source ratings into memory, streams article cursor, updates each document in-place.

**Response** — `{ "updated": int }`

---

## 2. CVE Tracker

### `GET /api/cve`
List CVEs with filtering and sorting.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Items per page (1–100) |
| `tech` | str[] | — | Filter by technology |
| `severity` | str[] | — | Filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `search` | str | — | Search CVE ID or description |
| `date_start` | str | — | Published date start (`YYYY-MM-DD`) |
| `date_end` | str | — | Published date end (`YYYY-MM-DD`) |
| `include_fp` | bool | false | Include false positives |
| `sort_by` | str | `published` | Sort field: `tech`, `severity`, `published` |
| `sort_dir` | str | `desc` | Sort direction: `asc`, `desc` |

**Response** — `CveListResponse`: `{ cves, total, page, page_size }`

---

### `GET /api/cve/stats`
Aggregate CVE statistics.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_fp` | bool | false | Include false positives in counts |

**Response** — `CveStats` with counts by severity, with/without exploits, CISA KEV count, etc.

---

### `GET /api/cve/export` 🔒
Export true-positive CVEs to Excel (`.xlsx`).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `date_start` | str | — | Start date filter (`YYYY-MM-DD`) |
| `date_end` | str | — | End date filter (`YYYY-MM-DD`) |

**Response** — `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` file download. Audit logged.

---

### `GET /api/cve/tech-list`
Get all distinct technology names from the CVE tracker.

**Response** — `{ tech: string[] }`

---

### `GET /api/cve/next-ticket-id`
Get the next available ticket ID for use before creating a ticket.

**Response** — `{ ticket_id: string }`

---

### `GET /api/cve/ack-statuses`
Get acknowledgement status for all CVEs.

**Response** — map of `{ cve_id: { analyst_name, acknowledged_at } }`.

---

### `POST /api/cve/draft-email` 🔒
Draft a notification email for selected CVEs.

**Request body:**
```json
{
  "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"],
  "ticket_id": "TKT-001"
}
```

**Response** — draft email metadata (subject, body, recipients). Audit logged.

---

### `POST /api/cve/{cve_id}/false-positive` 🔒
Mark a CVE as a false positive.

**Response** — `{ "ok": true }`. Audit logged.

---

### `DELETE /api/cve/{cve_id}/false-positive` 🔒
Remove false-positive flag from a CVE.

**Response** — `{ "ok": true }`. Audit logged.

---

### `GET /api/cve/{cve_id}/ticket`
Get the analyst ticket associated with a CVE.

**Response** — `CveTicket` object or `{}` if no ticket exists.

---

### `PUT /api/cve/{cve_id}/ticket` 🔒
Create or update the analyst ticket for a CVE.

**Request body:** `CveTicket` fields (status, notes, assignee, etc.)

**Response** — `{ "ok": true }`. Audit logged.

---

### `POST /api/cve/bulk-false-positive` 🔒
Mark up to 100 CVEs as false positives in one request.

**Request body:**
```json
{ "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"] }
```

**Response** — `{ "ok": true, "marked": <count> }`. Audit logged.

---

### `POST /api/cve/cisa-lookup` 🔒
Cross-reference all true-positive CVEs against the CISA Known Exploited Vulnerabilities catalog. Updates `_cisa_kev` flags in DB.

**Response** — `{ "checked": int, "matched": int }`. Audit logged.

---

### `POST /api/cve/exploit-lookup` 🔒
Run Exploit-DB lookup for all true-positive CVEs.

**Response** — `{ "checked": int, "with_exploits": int }`. Audit logged.

---

### `POST /api/cve/{cve_id}/exploit-lookup` 🔒
Run Exploit-DB lookup for a single CVE.

**Response** — `{ "cve_id", "exploits": [], "error": null }`. Audit logged.

---

### `POST /api/cve/{cve_id}/acknowledge` 🔒
Acknowledge a CVE finding with analyst name.

**Request body:**
```json
{ "analyst_name": "Jane Doe" }
```

**Response** — `{ "ok": true }`. Audit logged.

---

### `GET /api/cve/{cve_id}/mindmap` 🔒
Get mindmap metadata for a CVE. Generates if not cached.

**Response:**
```json
{
  "cve_id": "CVE-2024-1234",
  "title": "...",
  "wisemap_url": "...",
  "has_wxml": true,
  "generated_at": "2026-05-07T..."
}
```

---

### `GET /api/cve/{cve_id}/mindmap/download` 🔒
Download mindmap as `.wxml` file. Regenerates if `regenerate=true`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `regenerate` | bool | false | Force regeneration |

**Response** — `application/xml` file download.

---

## 3. Priority Intelligence Requirements (PIR)

### `GET /api/pir/options`
Get dropdown options for PIR forms (priorities, statuses, categories, etc.).

**Response** — options object.

---

### `GET /api/pir`
List all PIRs.

**Response** — array of PIR objects with keyword criteria, priority, status, alert config.

---

### `GET /api/pir/{pir_id}/articles`
Get articles matching a PIR's criteria.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 15 | Items per page (1–50) |

**Response** — `{ articles, total, page, page_size }`

---

### `GET /api/pir/{pir_id}/note`
Get analyst note for a specific article within a PIR.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | str | ✓ | Article URL |

**Response** — `{ pir_id, url, note, analyst, updated_at }`

---

### `PUT /api/pir/{pir_id}/note` 🔒
Save an analyst note for an article within a PIR.

**Request body:**
```json
{ "url": "https://...", "note": "Analysis text", "analyst": "Jane Doe" }
```

**Response** — updated note object. Audit logged.

---

### `GET /api/pir/{pir_id}/export`
Get JSON export data for a PIR (articles, metadata, notes).

**Response** — full PIR export object.

---

### `GET /api/pir/{pir_id}/export/docx`
Export a PIR as a `.docx` Word document.

**Response** — `application/vnd.openxmlformats-officedocument.wordprocessingml.document` download.

---

### `POST /api/pir` 🔒
Create a new PIR.

**Request body:** `PIRCreate` (title, description, keywords, priority, status, alert config, categories, etc.)

**Response** — created PIR object. Audit logged.

---

### `PUT /api/pir/{pir_id}` 🔒
Update an existing PIR.

**Request body:** `PIRUpdate` (partial — only provided fields updated)

**Response** — updated PIR object. Audit logged.

---

### `DELETE /api/pir/{pir_id}` 🔒
Delete a PIR.

**Response** — `{ "deleted": true }`. Audit logged.

---

## 4. IOCs

### `GET /api/iocs`
List IOCs extracted from newsletters and stored in DB.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ioc_type` | str | — | Filter by type: `ip`, `domain`, `url`, `sha256`, `sha1`, `md5`, `email`, `cve` |
| `search` | str | — | Search by value |
| `page` | int | 1 | Page number |
| `page_size` | int | 50 | Items per page (1–200) |

**Response** — `{ iocs, total, page, page_size }`

---

### `GET /api/iocs/stats`
Aggregate IOC counts grouped by type.

**Response** — `{ [ioc_type: string]: number }`

---

### `GET /api/iocs/{ioc_type}/{value}`
Get detail for a specific IOC.

**Path params:** `ioc_type` (e.g. `ip`), `value` (e.g. `1.2.3.4`)

**Response** — IOC document with source articles, tags, extracted_at, etc.

---

### `POST /api/iocs/{ioc_type}/{value}/tags` 🔒
Add tags to an IOC.

**Request body:**
```json
{ "tags": ["malware", "ransomware"] }
```

**Response** — `{ "ok": true }`

---

## 5. Threat Actors

### `GET /api/ta/groups`
List tracked threat actor groups.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search` | str | — | Filter by name |
| `page` | int | 1 | Page number |
| `page_size` | int | 50 | Items per page (1–500) |
| `sort_by` | str | `name` | Sort field |
| `sort_dir` | str | `asc` | `asc` or `desc` |

**Response** — `TAGroupListResponse`: `{ groups, total, page, page_size }`

---

### `GET /api/ta/stats`
Summary stats for tracked threat actors (article counts, top actors, etc.).

**Response** — stats object.

---

### `POST /api/ta/groups` 🔒
Add a new threat actor group to track.

**Request body:**
```json
{ "name": "APT29" }
```

**Response** — created group object. Audit logged.

---

### `DELETE /api/ta/groups/{group_id}` 🔒
Delete a threat actor group.

**Query params:** `group_name` (str, required)

**Response** — deletion result. Audit logged.

---

### `GET /api/ta/whitelist`
List threat actor names on the filtering whitelist (excluded from auto-tagging).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search` | str | — | Filter by name |
| `page` | int | 1 | Page number |
| `page_size` | int | 50 | Items per page (1–500) |
| `sort_by` | str | `name` | Sort field |
| `sort_dir` | str | `asc` | `asc` or `desc` |

**Response** — `{ items, total, page, page_size }`

---

### `DELETE /api/ta/whitelist/{name}` 🔒
Remove a name from the whitelist (restores auto-tagging).

**Response** — removal result. Audit logged.

---

### `GET /api/ta/watchlist-names`
Get all watchlist actor names as a flat list (for quick lookups).

**Response** — `{ names: string[] }`

---

### `GET /api/ta/watchlist`
List threat actors on the priority watchlist.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search` | str | — | Filter by name |
| `page` | int | 1 | Page number |
| `page_size` | int | 50 | Items per page (1–500) |
| `sort_by` | str | `name` | Sort field |
| `sort_dir` | str | `asc` | `asc` or `desc` |

**Response** — `{ items, total, page, page_size }`

---

### `POST /api/ta/watchlist` 🔒
Add a threat actor to the watchlist.

**Request body:**
```json
{ "name": "Lazarus Group" }
```

**Response** — added watchlist entry. Audit logged.

---

### `DELETE /api/ta/watchlist/{name}` 🔒
Remove a threat actor from the watchlist.

**Response** — removal result. Audit logged.

---

### `POST /api/ta/profile/generate` 🔒
Generate an LLM-synthesized profile for a threat actor. Enriches with CVE cross-references automatically.

**Request body:**
```json
{ "name": "APT29" }
```

**Response** — `{ "success": true, "profile": { ... } }`. Audit logged.

---

### `GET /api/ta/profile/{name}`
Get the stored profile for a threat actor.

**Response:**
```json
{
  "exists": true,
  "profile": {
    "name": "APT29",
    "aliases": [...],
    "ttps": [...],
    "exploited_vulnerabilities": [...],
    "_article_cves": [...],
    ...
  }
}
```
Returns `{ "exists": false, "profile": null }` if no profile generated yet.

---

## 6. MITRE ATT&CK

### `GET /api/mitre/heatmap`
Generate a TTP frequency heatmap from observed articles.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `view` | str | `ta` | Pivot: `ta` (by threat actor) or `industry` |
| `days` | int | 90 | Lookback window (7–365) |
| `top_rows` | int | 15 | Number of rows to show (3–30) |
| `top_ttps` | int | 20 | Number of TTPs to show (5–40) |

**Response** — heatmap matrix with row labels, TTP columns, and hit counts.

---

### `GET /api/mitre/d3fend/{technique_id}`
Get MITRE D3FEND countermeasures for an ATT&CK technique.

**Path param:** `technique_id` — e.g. `T1059`

**Response:**
```json
{
  "technique_id": "T1059",
  "countermeasures": [...]
}
```

---

### `GET /api/attack/techniques/{attack_id}`
Local ATT&CK DB technique detail (e.g. `T1003.001`). Includes `mitigations`, `groups`, `software`, `sub_techniques` and, for ATT&CK v18+ data, `detection_strategies`:

```json
"detection_strategies": [
  {
    "det_id": "DET0363",
    "name": "Detection of Credential Dumping from LSASS Memory via Access and Dump Sequence",
    "url": "https://attack.mitre.org/detectionstrategies/DET0363",
    "analytics": [
      {
        "analytic_id": "AN1030",
        "description": "...",
        "platforms": ["Windows"],
        "log_sources": [{ "name": "WinEventLog:Sysmon", "channel": "EventCode=10" }],
        "mutable_elements": [{ "field": "AccessMask", "description": "..." }]
      }
    ]
  }
]
```

The legacy free-text `detection` field is empty on v19.2 data. `GET /api/attack/status` sync results include `detection_strategy_count` and `analytic_count`.

---

### `GET /api/mitre/navigator-export`
Export ATT&CK Navigator-compatible layer JSON (v4.5 format).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `view` | str | `ta` | `ta` or `industry` |
| `days` | int | 90 | Lookback window (7–365) |

**Response** — `application/json` attachment, downloads as `cti_navigator_{view}_{days}d.json`.

---

### `GET /api/mitre/articles`
Get articles associated with a specific TTP and row value.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ttp_id` | str | ✓ | ATT&CK technique ID (e.g. `T1059`) |
| `row` | str | ✓ | Row value (threat actor or industry name) |
| `view` | str | — | `ta` or `industry` (default `ta`) |
| `days` | int | — | Lookback days (7–365, default 90) |
| `page` | int | — | Page number |
| `page_size` | int | — | Items per page (1–50, default 20) |

**Response** — `{ articles, total, page, page_size }`

---

## 7. Cross-Reference

### `GET /api/crossref/cve/{cve_id}`
Get PIRs and threat actors cross-referenced with a CVE.

**Response:**
```json
{
  "cve_id": "CVE-2024-1234",
  "pirs": [...],
  "threat_actors": [...]
}
```

---

### `GET /api/crossref/pir/{pir_id}`
Get CVEs and threat actors cross-referenced with a PIR.

**Response:**
```json
{
  "pir_id": "...",
  "cves": [...],
  "threat_actors": [...]
}
```

---

### `GET /api/crossref/ta/{actor_name}`
Get CVEs and PIRs cross-referenced with a threat actor. `actor_name` supports path characters (spaces, slashes).

**Response:**
```json
{
  "actor_name": "APT29",
  "cves": [...],
  "pirs": [...]
}
```

---

## 8. STIX 2.1 Export

All STIX endpoints return a downloadable `application/json` STIX 2.1 bundle.

### `GET /api/stix/article/{article_id}` 🔒
Export a STIX 2.1 bundle for a single article.

Includes: `Report` (article title, URL, news_type, confidence_score if computed), `ThreatActor` stubs (one per actor), `AttackPattern` objects (one per TTP with MITRE external refs), `Relationship` (`uses`) objects linking each actor to each technique.

Returns `404` if the article ID does not exist.

**Response** — downloads as `stix-article-{id[:12]}-{date}.json`.

---

### `GET /api/stix/ta/{actor_name}`
Export a STIX 2.1 bundle for a threat actor profile.

Includes: `ThreatActor`, `AttackPattern` (TTPs), `Malware`, `Indicator` (IOCs), `CourseOfAction`, `Relationship` objects.

Returns `404` if no profile has been generated for the actor.

**Response** — downloads as `stix-ta-{name}-{date}.json`.

---

### `GET /api/stix/iocs`
Export IOCs as STIX 2.1 `Indicator` objects.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `type` | str | — | Filter by IOC type: `ip`, `domain`, `url`, `sha256`, `sha1`, `md5`, `email`, `cve` |
| `limit` | int | 500 | Max IOCs to export (1–2000) |

**Response** — downloads as `stix-iocs-{type}-{date}.json`.

---

### `GET /api/stix/pirs`
Export active PIRs as STIX 2.1 `CourseOfAction` objects.

**Response** — downloads as `stix-pirs-{date}.json`.

---

## 9. Newsletter

### `GET /api/newsletter/source-hints`
Get paywall/source hints for all sources (used to warn editors during newsletter composition).

**Response** — `{ [source: string]: { hint: string, paywall: bool } }`

---

### `GET /api/newsletter/history` 🔒
List previously generated newsletters.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Items per page |

**Response** — `{ newsletters, total, page, page_size }`

---

### `GET /api/newsletter/{newsletter_id}/html` 🔒
Get the rendered HTML of a saved newsletter.

**Response** — `text/html`

---

### `POST /api/newsletter/{newsletter_id}/resend` 🔒
Resend a previously generated newsletter via email (SMTP or Microsoft Graph).

**Response** — `{ email_id, method, subject }`

---

### `POST /api/newsletter/preview` 🔒
Generate and save a newsletter preview. Does not send email.

**Request body:**
```json
{
  "highlight": "<article_id>",
  "apac": ["<id>", ...],
  "global_news": ["<id>", ...],
  "indonesia": ["<id>", ...],
  "custom_css": "",
  "custom_intro": "",
  "custom_footer": ""
}
```
Limits: 1 highlight, max 5 articles per section.

**Response** — `{ html, week, year, newsletter_id }`

---

### `POST /api/newsletter/draft-email` 🔒
Generate, save, and send a newsletter via email in one step.

**Request body:** Same as `/preview`.

**Response** — `{ email_id, method, subject, week, year, newsletter_id }`

---

## 10. Intelligence / Analytics

### `GET /api/clusters`
Get semantically clustered article groups using TF-IDF cosine similarity.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | int | 30 | Lookback window (7–90) |
| `threshold` | float | 0.35 | Cosine similarity threshold (0.2–0.7) |
| `exclude_low_reliability` | bool | false | Prevent D/E/F-graded sources from anchoring clusters |

**Response** — `{ clusters: [...], total: int }`

---

### `GET /api/source-scores`
Get computed reliability scores for all known sources.

**Response** — `{ sources: [{ source, reliability_grade, credibility_code, score, label }] }`

---

### `GET /api/spikes`
Detect early-warning spikes in article volume using z-score analysis.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `lookback_days` | int | 30 | Historical baseline window (14–90) |
| `z_threshold` | float | 2.0 | Z-score threshold to flag spike (1.5–4.0) |

**Response** — `{ spikes: [{ source_or_topic, date, count, z_score }] }`

---

## 11. Executive Dashboard

### `GET /api/exec/dashboard`
Executive dashboard v1 — summary metrics for leadership.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | int | 90 | Lookback window (7–365) |
| `incident_only` | bool | true | Restrict to incident-type articles |

**Response** — metrics: top actors, top industries targeted, top countries, TTP breakdown.

---

### `GET /api/exec/dashboard-v2`
Executive dashboard v2 — extended metrics with confirmed-only filter.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | int | 90 | Lookback window (7–365) |
| `incident_only` | bool | true | Restrict to incident-type articles |
| `confirmed_only` | bool | false | Restrict to analyst-confirmed articles |

**Response** — extended v2 metrics object.

---

### `POST /api/exec/brief`
Generate an LLM-synthesized 5-section executive narrative brief from live dashboard v2 metrics.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | int | 90 | Lookback window |
| `incident_only` | bool | true | Incident articles only |
| `confirmed_only` | bool | false | Confirmed articles only |

**Response** — `{ brief: "<markdown text>", generated_at: "<ISO timestamp>" }`

---

## 12. Ransomware

### `GET /api/ransomware/victims`
List ransomware victim records scraped from leak sites.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 50 | Items per page (1–200) |
| `group` | str | — | Filter by ransomware group |
| `country` | str | — | Filter by victim country |
| `industry` | str | — | Filter by victim industry |
| `date_start` | str | — | Published date start (`YYYY-MM-DD`) |
| `date_end` | str | — | Published date end (`YYYY-MM-DD`) |

**Response** — `{ victims, total, page, page_size }`

---

### `GET /api/ransomware/victims/filters`
Get available filter options for ransomware victims (groups, countries, industries).

**Response** — `{ groups: [], countries: [], industries: [] }`

---

### `GET /api/ransomware/related-articles`
Get news articles related to ransomware activity.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Items per page (1–100) |

**Response** — `{ articles, total, page, page_size }`

---

### GET /api/ransomware/dls

Leak-site (DLS) intel for one ransomware group (source: dls-monitor). Hostnames are defanged.

| Param | Type | Description |
|---|---|---|
| `group` | string (required) | Group name or alias |

**Response** — `{"dls": {"name", "aliases", "meta", "flags": {"captcha","parser","javascript_render"}, "hosts": [{"host","title","version","available","enabled","lastscrape"}], "hosts_up", "hosts_total", "last_scrape", "profile_urls", "source", "fetched_at"} | null}`

### GET /api/ransomware/dls/stats

**Response** — `{"groups", "hosts_up", "hosts_total", "last_synced"}`

### GET /api/ransomware/group-detail

Now includes a `dls` field (same shape as `/dls`, or `null`).

## 13. Source Reliability

NATO Admiralty scale ratings (A–F reliability, 1–6 credibility) stored per source.

### `GET /api/sr/entries`
List source reliability entries.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search` | str | — | Filter by source name |
| `grade` | str | — | Filter by reliability grade (A–F) |
| `page` | int | 1 | Page number |
| `page_size` | int | 50 | Items per page (1–500) |
| `sort_by` | str | `source_name` | Sort field |
| `sort_dir` | str | `asc` | `asc` or `desc` |

**Response** — `{ entries, total, page, page_size }`

---

### `GET /api/sr/stats`
Aggregate source reliability statistics (grade distribution, counts).

**Response** — stats object.

---

### `GET /api/sr/labels`
Get human-readable labels for all reliability grades and credibility codes.

**Response:**
```json
{
  "reliability": { "A": "Completely reliable", "B": "Usually reliable", ... },
  "credibility": { "1": "Confirmed by other sources", ... }
}
```

---

### `POST /api/sr/entries` 🔒
Add a new source reliability rating.

**Request body:**
```json
{
  "source_name": "BleepingComputer",
  "analyst_name": "Jane Doe",
  "reliability_grade": "B",
  "credibility_code": "2",
  "notes": "Optional notes"
}
```

**Response** — created entry. Audit logged.

---

### `PUT /api/sr/entries/{entry_id}` 🔒
Update an existing source reliability rating.

**Request body:** Same fields as POST (excluding `source_name`).

**Response** — updated entry. Audit logged.

---

### `DELETE /api/sr/entries/{entry_id}` 🔒
Delete a source reliability rating.

**Response** — deletion result. Audit logged.

---

## 14. Mind Maps

Mind maps are generated as Wisemap `.wxml` files. Feature types: `newsletter`, `threat_actor`, `cve`, `pir`, `cluster`, `ransomware`.

### `GET /api/mindmap/{feature_type}/{doc_id}` 🔒
Get mindmap metadata. Generates if not cached.

**Response:**
```json
{
  "feature_type": "threat_actor",
  "doc_id": "APT29",
  "title": "...",
  "wisemap_url": "...",
  "has_wxml": true,
  "generated_at": "2026-05-07T..."
}
```

---

### `GET /api/mindmap/{feature_type}/{doc_id}/download` 🔒
Download mindmap as `.wxml` file.

**Response** — `application/xml` attachment.

---

### `POST /api/mindmap/{feature_type}/{doc_id}/regenerate` 🔒
Force regeneration of the mindmap (ignores cache).

**Response** — same metadata shape as GET.

---

## 15. Scraper Health

### `GET /api/scraper/health`
Get health summary for all scrapers (last run times, article counts, error rates).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | int | 7 | Lookback window (1–90) |

**Response** — per-scraper health metrics.

---

### `GET /api/scraper/articles`
Get recent articles fetched by a specific scraper script.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `script` | str | ✓ | Scraper script name |
| `days` | int | — | Lookback window (1–90, default 7) |

**Response** — list of articles from that scraper.

---

## 16. Changelog

### `GET /api/changelog`
List all changelog versions.

**Response** — `[{ version: string, date: string }]`

---

### `GET /api/changelog/{version}`
Get full changelog entry for a specific version.

**Response** — `{ version, date, content }` or `404`.

---

## 17. Tech Stack

### `GET /api/techstack`
List tracked technologies (used to match CVEs).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search` | str | — | Filter by name |
| `page` | int | 1 | Page number |
| `page_size` | int | 50 | Items per page (1–500) |
| `sort_by` | str | `name` | Sort field |
| `sort_dir` | str | `asc` | `asc` or `desc` |

**Response** — `TechStackListResponse`: `{ items, total, page, page_size }`

---

### `POST /api/techstack` 🔒
Add a technology to the tracked tech stack.

**Request body:**
```json
{ "name": "Apache Log4j" }
```

**Response** — created entry. Audit logged.

---

### `DELETE /api/techstack/{tech_id}` 🔒
Remove a technology from the tech stack.

**Response** — deletion result. Audit logged.

---

## 18. Filtered Articles

Articles that were filtered out by scrapers before ingestion.

### `GET /api/filtered-articles`
List filtered-out articles.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Items per page (1–100) |
| `search` | str | — | Search by title or URL |

**Response** — `{ items: [{ id, title, url, script_name, created_at }], total, page, page_size }`

---

### `POST /api/filtered-articles/{article_id}/restore` 🔒
Restore a filtered article back into the main collection.

**Response** — `{ "success": true }` or `404`.

---

## 19. Authentication

### `GET /api/auth/policy`
Get the current password policy (min length, complexity requirements, etc.).

**Response** — `{ min_length, require_upper, require_lower, require_digit, require_special, hint }`

---

### `PUT /api/auth/policy` 🛡️
Update the password policy.

**Request body:** `PolicySettings` fields + optional `force_all_change: bool` (forces all users to reset on next login).

**Response** — `{ ok: true, flagged_users: int, hint: string }`. Audit logged.

---

### `POST /api/auth/login`
Authenticate and receive a JWT token. Sets `cti_auth` HttpOnly cookie.

**Request body:**
```json
{ "username": "analyst", "password": "secret" }
```

**Response** — `TokenResponse`: `{ access_token, username, role, force_pw_change }`

---

### `POST /api/auth/logout` 🔒
Clear the `cti_auth` session cookie.

**Response** — `{ "ok": true }`

---

### `POST /api/auth/change-password` 🔒
Change the current user's password. Validated against current policy.

**Request body:**
```json
{ "new_password": "NewSecureP@ss1" }
```

**Response** — `{ "ok": true }`. Audit logged.

---

### `POST /api/auth/init`
Bootstrap first admin user. Fails with `409` if any users already exist.

**Request body:**
```json
{ "username": "admin", "password": "InitialP@ss1", "role": "admin" }
```

**Response** — created user record.

---

### `GET /api/auth/me` 🔒
Get the current authenticated user's profile.

**Response** — `{ username, role }`

---

### `GET /api/auth/users` 🛡️
List all users.

**Response** — array of user objects (username, role, last_sign_in, created_by).

---

### `POST /api/auth/users` 🛡️
Create a new user.

**Request body:**
```json
{ "username": "analyst2", "password": "SecureP@ss1", "role": "analyst" }
```

**Response** — created user object. Audit logged.

---

### `POST /api/auth/users/{username}/reset-password` 🛡️
Reset another user's password. SSO-provisioned accounts are blocked.

**Request body:**
```json
{ "new_password": "NewSecureP@ss1" }
```

**Response** — `{ "ok": true }`. Audit logged.

---

### `GET /api/auth/audit-log` 🛡️
Get the system audit log.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 50 | Items per page (1–200) |
| `user` | str | — | Filter by username |
| `action` | str | — | Filter by action type |

**Response** — `{ logs: [{ user, action, target_id, detail, ip, timestamp }], total, page, page_size }`

---

## 20. OIDC / SSO

### `GET /auth/login`
Initiate OIDC/SSO login flow. Redirects to identity provider. Returns `302` to `/` if OIDC is disabled.

---

### `GET /auth/callback`
OIDC authorization code callback. Exchanges `code` for a JWT, sets `cti_auth` cookie, and redirects to `/#token=<jwt>`. On failure redirects to `/?error=sso_failed`.

| Query param | Required | Description |
|-------------|----------|-------------|
| `code` | ✓ | Authorization code from IdP |
| `state` | ✓ | CSRF state token |

---

### `GET /auth/logout`
Clear session and redirect to IdP logout URL (if configured), otherwise to `/`.

---

## 21. RFI Tracker

Track inbound intelligence requests from consumers through to analyst response. All endpoints require auth.

### `GET /api/rfi` 🔒
List RFIs with optional status filter and pagination.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | str | — | Filter by status: `open`, `in_progress`, `closed` |
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Results per page (1–100) |

**Response** — `{ rfis: RFIOut[], total: int, page: int, page_size: int }`

---

### `GET /api/rfi/{rfi_id}` 🔒
Get a single RFI by ID.

Returns `404` if not found.

**Response** — `RFIOut`

---

### `POST /api/rfi` 🔒
Create a new RFI.

**Body:**
```json
{
  "requester": "analyst@org",
  "question": "Any new Lazarus TTPs targeting finance?",
  "due_date": "2026-05-14",
  "status": "open",
  "linked_pir": "<pir_id or null>",
  "response": ""
}
```

**Response** — created `RFIOut` with `id`, `created_at`, `updated_at`.

---

### `PUT /api/rfi/{rfi_id}` 🔒
Update an RFI (partial — all fields optional).

| Field | Type | Description |
|-------|------|-------------|
| `requester` | str | Requester name/email |
| `question` | str | Intelligence question |
| `due_date` | str | Due date `YYYY-MM-DD` |
| `status` | str | `open` / `in_progress` / `closed` |
| `linked_pir` | str | PIR `_id` reference |
| `response` | str | Analyst response text |

Returns `404` if not found.

**Response** — updated `RFIOut`.

---

### `DELETE /api/rfi/{rfi_id}` 🔒
Delete an RFI permanently.

Returns `404` if not found.

**Response** — `{ "deleted": true }`

---

**RFIOut schema:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | str | MongoDB ObjectId |
| `requester` | str | Who submitted the request |
| `question` | str | Intelligence question |
| `due_date` | str\|null | Due date `YYYY-MM-DD` |
| `status` | str | `open` / `in_progress` / `closed` |
| `linked_pir` | str\|null | Linked PIR ID |
| `response` | str | Analyst response |
| `created_at` | str | ISO 8601 UTC timestamp |
| `updated_at` | str | ISO 8601 UTC timestamp |

---

## 22. Notifications

In-app notification feed (post-login modal + header bell). Read state is per user. All endpoints require auth.

### `GET /api/notifications`
List notifications, newest first (max 100).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `unread` | bool | false | Only items the caller has not read |

**Response:**
```json
[
  {
    "id": "6ace0997495024b3cb876a08",
    "type": "attack_update",
    "title": "MITRE ATT&CK v19.2 available",
    "body": "Enterprise ATT&CK updated from v18.1 to v19.2. +97 techniques.",
    "severity": "info",
    "data": { "domain": "enterprise", "old_version": "18.1", "new_version": "19.2" },
    "action": { "label": "Open ATT&CK DB", "tab": "intelligence" },
    "popup": true,
    "created_at": "2026-10-13T10:36:07.554000",
    "read": false
  }
]
```

---

### `POST /api/notifications/{notif_id}/read`
Mark one notification read for the caller. `404` if the ID is invalid or unknown.

---

### `POST /api/notifications/read-all`
Mark all notifications read for the caller. **Response:** `{ "updated": <int> }`

---

## Error Responses

All endpoints return standard HTTP status codes:

| Code | Meaning |
|------|---------|
| `400` | Bad request / validation error |
| `401` | Unauthenticated |
| `403` | Forbidden (insufficient role) |
| `404` | Resource not found |
| `409` | Conflict (e.g. duplicate username) |
| `422` | Password policy violation |
| `500` | Internal server error |
| `501` | Feature not implemented (e.g. python-docx missing) |

Error body: `{ "detail": "<message>" }`
