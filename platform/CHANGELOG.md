# Changelog

## [Unreleased]

### New Features

#### Ransomware Group Leak-Site Intel (dls-monitor)

Group-detail modal now shows leak-site (DLS) infrastructure for each ransomware group: hosts up/total, last scrape, CAPTCHA/JS flags, analyst notes, reference URLs. Source: `cyberiskvision/dls-monitor` `groups.json`, ingested by `ScraperNewsRevamp/dlsMonitorGroups.py` into `news_db.dls_groups`. Onion hosts are defanged server-side (`abc[.]onion`), rendered non-clickable with a copy button; raw hostnames never reach the browser.

- **`app/services/dls_service.py`** (new): `get_dls_group` (match by normalized name or alias), `get_dls_stats`, `defang_host`, `ensure_indexes`.
- **`app/services/ransomware_service.py`**: `get_group_detail` returns `dls` (null when group not tracked).
- **`app/routers/ransomware.py`**: `GET /api/ransomware/dls?group=`, `GET /api/ransomware/dls/stats`.
- **`app/main.py`**: create `dls_groups` indexes at startup.
- **`static/js/newsroom/ransomware_treemap.js`**: "Leak sites" section in group modal.

#### In-App Notifications (post-login modal + header bell)

Generic notification feed so any service can alert analysts in the UI. First producer: MITRE ATT&CK version changes. Unread items open in a modal after login (once per browser session); a header bell shows the unread count and reopens the list. Read state is per user.

- **`app/services/notification_service.py`** (new): `create_notification()` (optional `dedupe_key` — unique sparse index — prevents duplicates; `popup=False` keeps an item bell-only), `list_notifications`, `mark_read`, `mark_all_read`. Collection `notifications`.
- **`app/routers/notifications.py`** (new): `GET /api/notifications?unread=`, `POST /api/notifications/{id}/read`, `POST /api/notifications/read-all`.
- **`static/js/newsroom/notifications.js`** (new): modal + bell, action button switches to a tab (e.g. "Open ATT&CK DB").
- **`templates/newsroom.html`**, **`static/js/newsroom/auth.js`**, **`templates/login.html`**: modal markup, bell, `loadNotifications(true)` after in-page login; `cti_notif_shown` session flag cleared on login/logout so each new login shows the modal.
- **`app/main.py`**: registers `notifications_router`.

#### ATT&CK Sync: New Source, Release Check, Detection Strategies + Analytics

- **`app/services/attack_sync_service.py`**: sync source moved from the stale `mitre/cti` repo to `mitre-attack/attack-stix-data` (`master`) for Enterprise, ICS and Mobile. That repo ships STIX 2.1 (`x_mitre_*` keys); new `_normalize_keys()` maps them to the `x-mitre-*` keys the parser reads. Without it version/deprecation/platform fields silently came back empty.
- **`app/services/attack_sync_service.py`**: `upstream_is_newer()` / `get_latest_release_version()` compare the latest GitHub release tag to the oldest synced version. Version change on sync creates an `attack_update` notification (dedupe key `attack_update:{domain}:{version}`; first-ever sync does not notify).
- **`app/main.py`**: `_attack_sync_loop` runs the release check daily and syncs immediately when upstream is newer (7-day interval still applies as fallback).
- **`app/services/attack_sync_service.py`**: imports ATT&CK v18+ detection strategies (`DETxxxx`) and analytics (`ANxxxx`) into new collections `attack_detection_strategies` and `attack_analytics`; sync result adds `detection_strategy_count` and `analytic_count`. v19.2 totals — Enterprise 697/1758, ICS 97/97, Mobile 124/211 (strategies/analytics).
- **`app/services/attack_sync_service.py`**: `get_technique()` returns `detection_strategies` (each with nested analytics: platforms, log sources, tunable fields). Legacy `detection` text is empty on v19.2 data.
- **`static/js/newsroom/attack_db.js`**: technique modal "Detection" section; falls back to legacy text when no strategies exist.

### Fixes

#### CVE Tracker: Grey Out Ticket Form on "No Risk (Not Affected)"

Marking CVE ticket's Risk Acceptance as "No Risk (Not Affected)" left rest of form fully editable — analyst had nothing left to fill but fields stayed active/misleading.

- **`static/js/newsroom/cve.js`**: `_cveRiskChange(val)` disables + greys (`opacity:0.4`) all non-readonly ticket fields (affected asset/version, fixed version, owner fields, active exploitation, remediation dates/status, closure date, escalation, comments) when Risk Acceptance = `No Risk (Not Affected)`; re-enables on any other value. Wired to `risk_acceptance` select's `onchange` and called on ticket render so existing "Not Affected" tickets open already greyed. Also fixed pre-existing bug in `select-risk` option rendering (`o` → `esc(o)`, unescaped).

## [3.23.0] - 2026-09-02

### New Features

#### Daily CTI Recap: Bug Fixes

Three correctness bugs found by re-reading the recap pipeline end to end.

- **`app/services/recap_service.py`**: `_collect_articles` sorted `source_reliability` descending (`F` first, `A` last) — the 200-doc cap and 60-article prompt slice were feeding the LLM the *least* reliable sources first. Now sorted in Python by an explicit A→F rank, missing/empty grade treated as worst rather than sorting ahead of `A`.
- **`app/services/recap_service.py`**, **`scripts/get_daily_recap_html.py`**: `url` was collected but never reached the LLM or the rendered HTML. Added to the prompt lines and JSON schema for both articles and tweets, LLM instructed to copy verbatim/never invent; renderer emits `<a href>`, validated `http(s)`-only before insertion.
- **`app/services/recap_service.py`**, **`scripts/get_daily_recap_html.py`**: silent LLM-parse failures saved an empty recap with no indication anything broke. New `parse_error: true` flag on the doc; renderer shows a warning banner when set or when `headline` is empty.
- Investigated whether `posted_on` (publication date) vs. an ingest/scrape timestamp caused missed same-day articles (`recap_service.py:94`, original concern). Checked `ScraperNewsRevamp` scrapers directly — nearly all set `posted_on = datetime.now().date()` at scrape time, so it already functions as the ingest date; no separate ingest field exists anywhere on article docs. No code change; filter left as-is.

#### Daily CTI Recap: 8 New Data Feeds + Renderer Refactor

Recap covered News/X/CVE/IOC/campaigns/new-TAs but ignored ransomware, KEV deadlines, anomaly detection, domain-squat monitoring, package vulnerabilities, MITRE TTPs, and scraper outages — a quiet day and a scraper outage looked identical.

- **`app/services/recap_service.py`**: new fault-isolated collectors — `_collect_ransomware`, `_collect_kev_additions` (`cisa_kev_catalog`), `_collect_spikes` (z-score anomalies via `spike_service`, filtered to target day), `_collect_domain_watch`, `_collect_pkg_vulns`, `_collect_ttps` (rollup from the article projection already being thrown away), `_collect_ioc_detail` (top 15 by confidence), `_collect_scraper_health`. Each has its own `try/except` + `.limit()`. New persisted doc keys only (`spikes`, `scraper_health`, `cve_details`, `ioc_detail`) — no renames.
- **`scripts/get_daily_recap_html.py`**: `render_html` (one giant f-string) split into one function per section, composed by a thin top-level function. Added severity badges (CVSS/KEV/PoC/EPSS on CVEs, severity on package vulns). Fixed a pre-existing bug in `_e()` — truthy check meant `_e(0)` rendered blank, which would've broken every new zero-count section.

#### Daily CTI Recap: Day-over-Day Deltas + Forecast Scoring

Pipeline never showed trend or checked whether its own forecasts came true.

- **`app/services/recap_service.py`**: `counts_delta` computed against the previous day's doc, rendered as colored `(+N)/(-N)`; missing prior day degrades to no delta, no crash. `forecast_review` — prior day's `likely_events` fed back to the LLM alongside today's signals, scored `hit`/`miss`/`unclear` with justification; no prior forecast → empty list.

#### Daily CTI Recap: Live Generation Progress Bar

Generate/Force Regen showed only a static "this can take 10-30s" text with no feedback for the actual wait.

- **`app/services/recap_service.py`**: in-process `_PROGRESS` tracker, staged through `starting → loading previous day → collecting data → calling LLM → parsing response → saving → done`, cached/error paths handled; new `get_progress()`.
- **`app/routers/recap.py`**: `GET /api/recap/progress/status`.
- **`static/js/newsroom/recap.js`**, **`templates/partials/tab_recap.html`**: polls the new endpoint every second while `/generate` is in flight, drives an animated progress bar + stage label.

#### Daily CTI Recap: Per-Client Personalization

Recap was org-wide only; no way to scope it to a client's tracked countries/sectors without burning a full independent LLM pass per client.

- **`app/services/recap_service.py`**: `generate_daily_recap`/`get_recap`/`list_recaps`/`get_progress` all take `client_id` (default `"default"`, backward-compatible with pre-existing docs that have no `client_id` field). Non-default clients filter articles/tweets/ransomware/campaigns to the client's tracked countries/sectors (`clients` collection, existing newsletter-feature schema) *before* the LLM call — that's where the token savings come from, not a second schema. Reuses the cached org-wide doc's headline/forecast as free context instead of re-deriving posture per client. `pkg_vulns`/`domain_watch` were already per-client-siloed at the DB layer, just threaded `client_id` through.
- **Fix**: client-relevance filter initially used exact string match, but client profiles store loose sector terms (`"technology"`, `"gov"`) against full article taxonomy labels (`"Information Technology & Software"`, `"Government & Public Sector"`) — never matched, silently zeroing out Top Stories/Tweets/TTPs for every real client. Switched to substring match.
- **`app/main.py`**: `_daily_recap_loop` → `_generate_all_recaps()` — generates the org-wide recap, then every client from `client_service.list_clients()`, each independently error-isolated. Runs on the existing schedule, no separate cron needed; picks up newly-created clients automatically on the next run.
- Renamed "APAC Signals" → "Regional Signals" for client-scoped recaps (was a hardcoded Asia-Pacific bucket regardless of the client's actual tracked region); LLM instructed to populate it with the client's own tracked countries instead. Org-wide/default recap keeps "APAC Signals".
- **`app/routers/recap.py`**: `client_id` query param on all recap endpoints, 404 on unknown client.
- **`scripts/get_daily_recap_html.py`**: `--client-id` flag, distinct default output filename when non-default, title/heading show client name.
- **`templates/partials/tab_recap.html`**, **`static/js/newsroom/recap.js`**: client selector (hidden unless `/api/clients` returns >1 — non-admins silently stay on org-wide).

---

## [3.22.0] - 2026-08-28

### New Features

#### News Room: Relevant Industry News Panel

Newsroom had per-client scoped panels for TA Watchlist and Tech Stack, but nothing surfacing news for the industries/sectors already configured per client — analysts had to eyeball the Industry filter manually.

- **`app/routers/auth.py`**: `GET /api/auth/me` now also returns `client_sectors` / `clients_sectors_map` (mirrors existing `client_countries` / `clients_map` pattern).
- **`static/js/newsroom/auth.js`**: `getActiveClientSectors()`; superadmin client-switcher load also caches `window._clientsSectorsMap`.
- **`static/js/newsroom/autorefresh.js`**: non-superadmin init also hydrates `_clientsSectorsMap` from `/api/auth/me`.
- **`static/js/newsroom/ta.js`**: `loadIndustryNewsPanel()` — new panel, same shape as `loadWatchlistPanel()`/`loadTechStackPanel()`, queries `/api/articles` scoped to the active client's configured sectors.
- **`templates/partials/tab_newsroom.html`**, **`static/js/newsroom/core.js`**, **`tabs.js`**, **`render.js`**: new `industry` panel wired into `loadAllPanels`, `refreshPanel`, pager.

#### Fix: Client Sector Codes Didn't Match Article Industry Values

Panel initially returned zero articles even for industries known relevant to the client. Root cause: client sector codes (`gov`, `bfsi`, `healthcare`, …, labeled via `_SECTOR_LABELS` as `Government`, `BFSI`, `Healthcare`, …) were compared with exact `$in` match against `impacted_industries`, but that field holds LLM-generated free text (`Government & Public Sector`, `Finance & Insurance`, `Healthcare & Life Sciences`, …) — no string ever matched.

- **`static/js/newsroom/ta.js`**: `_SECTOR_TO_DB_INDUSTRIES` lookup table maps each sector code to its real `impacted_industries` DB values; `loadIndustryNewsPanel()` expands the client's sector codes through this table before querying.
- Known gap: DB categories with no sector-code owner (`General`, `Critical Infrastructure`, `Non-profit & NGOs`, `Legal & Professional Services`, `Media & Entertainment`, `Real Estate & Construction`, `Transportation & Logistics`) stay unreachable from this panel until added to the sector picker.

---

## [3.21.0] - 2026-08-26

### New Features

#### CVE Tracker: Draft Email Modal (.eml / Direct Send)

Draft Email button silently produced nothing — `EMAIL_METHOD` defaulted to Microsoft Graph with no Azure credentials configured, throwing before any feedback reached the analyst. Rebuilt as a modal flow with a working fallback path that doesn't depend on Graph/SMTP being configured.

- **`app/services/cve_email_service.py`**: `draft_email_for_cves()` takes `mode` (`send`/`eml`), `lang` (`en`/`id`), `recipients` override. New `_build_eml_bytes()` builds a standalone `.eml` via stdlib `email.message.EmailMessage` — no Graph/SMTP dependency, works even with `.env` unconfigured. `get_cve_email_recipients()` reuses the client's existing newsletter `recipients` list — one recipient list for both, no separate CVE-recipient management.
- **`app/routers/cve.py`**: `GET /api/cve/email-recipients` (feeds modal); `POST /api/cve/draft-email` streams the `.eml` file (`message/rfc822`) when `mode=eml`, otherwise unchanged JSON dispatch response.
- **`scripts/cve_notification_email_en.html`**, **`scripts/cve_notification_email_id.html`** *(new)*: bilingual Jinja templates (ported from the client's `.eml` sample), replacing the old single-language `cve_notification_email.html`. Affected-asset table left as a manual-fill placeholder (no CMDB source available).
- **`templates/newsroom.html`**: `#cve-email-modal-overlay` — mode radio (.eml / Direct Send), language radio (EN/ID), recipient checklist (editable per-send).
- **`static/js/newsroom/cve.js`**: `openCveEmailModal()` / `confirmCveEmailAction()` replace the old direct-fire `draftCveEmail()`; `.eml` mode downloads via blob, send mode keeps prior toast flow.

#### CVE Tracker: Multi-Tech-Stack Email Merge by Vendor

Related CVEs on different products from the same vendor (e.g. FortiOS + FortiWeb, both Fortinet) had to be drafted as separate emails even when hitting the same client on the same day — Draft Email was hard-gated to one tech stack per email.

- **`app/models/techstack.py`**, **`app/services/techstack_service.py`**, **`app/routers/techstack.py`**: new `vendor` field on tech stack docs, `PATCH /api/techstack/{id}/vendor`, `get_tech_vendor_map()`.
- **`templates/partials/tab_cvetracker.html`**, **`static/js/newsroom/techstack.js`**: editable Vendor column in Tech Stack management + vendor field on the add-form.
- **`app/services/cve_email_service.py`**: CVEs grouped into `product_groups` (one CVE table + patch/remediation section per product — never mixed across products); one email covers all products sharing a tagged vendor. Subject auto-adjusts to `"N CVE(s) across {vendor} products (A, B)"` when merged.
- **`static/js/newsroom/cve.js`**: `_cveDraftEmailGate()` allows multi-tech selection only when every selected tech stack shares one non-empty vendor tag; still-blocked selections show a persistent inline hint (not just a hover tooltip) explaining why, plus a toast on click.

#### CVE Tracker: CTI Tracking ID Persistence + Export Filter

Draft Email minted a fresh CTI tracking ID on every click regardless of whether the CVE already had one from acknowledgment (or a prior draft) — email footer and the Excel tracker could show two different numbers for the same CVE.

- **`app/services/cve_ticket_service.py`**: `get_tickets_map()` resolves each selected CVE's existing `ticket_id`; `mark_drafted()` tags drafted CVEs with `email_drafted_at`/`email_draft_mode`/`email_draft_lang` and only assigns a fresh tracking ID to CVEs that don't already have one. `get_drafted_cve_ids()` powers the new filter.
- **`app/services/cve_email_service.py`**: per-CVE tracking ID reused from the CVE's existing ticket where present; email footer lists a CVE ID → Tracking ID table (was a single shared ID) so multi-CVE drafts never collapse distinct tracking numbers into one.
- **`app/services/cve_service.py`**, **`app/services/cve_export_service.py`**, **`app/routers/cve.py`**: new `draft_filter` (`drafted`/`undrafted`) param on CVE list/stats/export, mirroring the existing `ack_filter` pattern.
- **`templates/partials/tab_cvetracker.html`**, **`static/js/newsroom/cve.js`**: "Drafted Only" filter checkbox — export Excel scoped to drafted CVEs for quarterly/semesterly tracking review.

---

## [3.20.0] - 2026-08-24

### New Features

#### Domain Watch: TLD Sweep Monitoring (new tab)

New tab lets analysts watch a base domain and get flagged on newly-registered/live/at-risk lookalikes across 800+ TLDs — powered by [tldsweep](https://github.com/DarkWebInformer/TLDSweep), vendored into ScraperNewsRevamp and scanned independently of this app (same split as `pkg_vuln_service.py` / `pkgVulnScanner.py`: web owns the watchlist + read of results, Revamp owns the scan).

- **`app/models/domain_watch.py`**, **`app/services/domain_watch_service.py`**, **`app/routers/domain_watch.py`** *(new)*: CRUD for `monitored_domains` (`/api/domainwatch/domains`) + read access to `domain_scan_results` (`/api/domainwatch/results`, `/api/domainwatch/domains/{id}/results`), per-`client_id`, same shape as `pkg_vuln`.
- **`templates/partials/tab_domainwatch.html`**, **`static/js/newsroom/domainwatch.js`** *(new)*: watchlist table (TLDs hit / registered / live / newly-registered / at-risk counters) + results modal (per-TLD hit: IP, registrar, created date, TLS cert expiry, risk flags). Wired into `newsroom.html` nav + `tabs.js` (`switchTab('domainwatch', …)`).
- **`app/main.py`**: router registered, `ensure_indexes()` called on startup.

#### Domain Watch: Acknowledge Workflow

Every registered/live TLD hit resurfaced on every view with no way to mark "already checked" — analysts had no way to tell new findings from ones they'd already triaged.

- **`app/models/domain_watch.py`** (`DomainScanResult`): added `acknowledged` / `ack_by` / `ack_date`, same pattern as `PackageVuln`.
- **`app/services/domain_watch_service.py`**: `acknowledge_result()` (toggle), `acknowledged` filter on `list_results()`, `unacknowledged` count in `get_stats()`.
- **`app/routers/domain_watch.py`**: `POST /api/domainwatch/results/{id}/ack`.
- **`static/js/newsroom/domainwatch.js`**: "Unacked Only" filter + per-row Ack/Undo button in the results modal, acked rows dimmed; new "Unacknowledged" stat tile.

#### Domain Watch: Parked-Domain Classification

Most TLD-sweep hits turned out unreachable or parking pages, not real sites — "registered, no DNS" (WHOIS-only hit) and "parked ad page" were both bucketed under the same LIVE/registered badges as genuine lookalike sites, burying the findings that actually matter.

- **`ScraperNewsRevamp/tldsweepScanner.py`** (`_classify_parked()`): heuristic against data tldsweep already collects (no extra scanning) — HTTP title/redirect/server headers + WHOIS nameservers matched against known parking providers (Sedo, Bodis, ParkingCrew, GoDaddy park, Dan.com, Afternic, HugeDomains, etc.) and generic "domain for sale"-style title phrases. Writes `parked` / `parked_provider` onto each `domain_scan_results` doc, `parked_count` onto `monitored_domains`.
- **`app/models/domain_watch.py`** / **`app/services/domain_watch_service.py`** / **`app/routers/domain_watch.py`**: `parked` / `parked_provider` fields, `parked_only` / `exclude_parked` filters, `parked` count in stats.
- **`static/js/newsroom/domainwatch.js`**: results modal now shows three-way status — **LIVE** (real), **PARKED** (w/ provider), **NO SITE** (registered, unresolved) — instead of one blanket badge. "Hide Parked" filter + "Parked" stat tile/column.

### Bug Fixes

#### Domain Watch: Cert-Expiry Date Mis-Rendered

`_dwCertExpiryCell()` assumed `tls.not_after` was ISO (`YYYY-MM-DD`) and sliced the first 10 characters — but tldsweep reports it in OpenSSL cert format (`"Oct 20 14:23:45 2026 GMT"`), so the UI showed `"Oct 20 14:"` instead of the date. Days-left math was already correct (parsed via `Date`, unaffected) — only the display slice was wrong. Fixed to render from the parsed `Date` object (`toISOString().slice(0,10)`).

#### Domain Watch: Domain-Name Cell Showed Pointer Cursor With No Click Handler

`.ta-name` carries a global `cursor:pointer` (used elsewhere for click-to-open rows), but the watchlist's domain-name cell never got an `onclick` — cursor implied clickable, nothing fired, "View" button was the only way in. Wired `onclick="dwShowResults(...)"` onto the cell to match.

## [3.19.0] - 2026-08-18

### New Features

#### CVE Tracker: Ticket Fixed Version Auto-Fill

`affected_asset` / `affected_version` already pre-filled a new ticket from the CVE's `affected` data; `fixed_version` didn't, despite the answer already being embedded in the same field — the `lessThan`/`lessThanOrEqual` upper bound MITRE reports (e.g. `"< 2.17.1"`) is the first patched version, it just wasn't extracted.

- **`static/js/newsroom/cve.js`** (`_renderCveTicketBody`): strips the `<`/`<=` prefix off each `affected` version string via `/^<=?\s*(.+)$/`, dedupes, joins into `fixed_version`. Only applies when opening a new (unticketed) CVE — same guard as the existing asset/version pre-fill. Field stays a plain text input, analyst can edit or clear before saving; a saved ticket's stored value always wins over the CVE-derived guess.

## [3.18.0] - 2026-08-17

### New Features

#### Source Reliability: LLM-Assisted Admiralty Rating Suggestion

Analysts rated each source's Admiralty code (`app/routers/source_reliability.py`) by hand, no starting point. Added an LLM-generated suggestion (deepseek, via the existing shared `llm_client.py` used by recap/newsletter/exec-brief) the analyst can accept, edit, or ignore — never auto-written to the DB.

- **`app/services/admiralty_suggest_service.py`** *(new)*: `suggest_rating(source_name)` — pulls the source's article history from `COLLECTION_NAME` (all-time count for track-record length, 100 most recent for date span / distinct threat-actors / distinct industries / sample titles), runs a **corroboration check** scoped to the last 7 days (`CORROBORATION_WINDOW_DAYS`) — finds CVEs this source covered that other sources also covered in the same window, returns raw `(cve, other_source, title)` triples. System prompt carries the full NATO AJP-2.1 rubric (matches `RELIABILITY_LABELS`/`CREDIBILITY_LABELS` in `source_score_db_service.py`) and explicitly pushes the syndication-vs-independent-corroboration judgment call onto the LLM rather than a code heuristic — same posture as the skill's own worked vendor-badge example. Defaults to F/6 on parse failure or unrecognized grade/code.
- **`app/routers/source_reliability.py`**: `GET /api/sr/entries/suggest?source_name=X`, auth-gated, 502 on LLM failure.
- **`templates/newsroom.html`** / **`static/js/newsroom/source_reliability.js`**: "Suggest via LLM" button in the add/edit modal — prefills Reliability/Credibility dropdowns, shows reasoning text; analyst still hits Save to commit.

### Bug Fixes

#### Source Reliability: Source-Name Dropdown Unclickable

`_srRenderSourceDd()` built each list item as `` `<li onclick="srSourcePick(${JSON.stringify(s)})">` `` — `JSON.stringify` wraps the name in double quotes, which collide with the `onclick="..."` attribute's own delimiter, truncating the attribute at the first embedded quote and leaving an invalid/no-op handler. Native `<select>` dropdowns (grade/code) were unaffected since the browser renders those outside page DOM — only this custom list broke.

- **`static/js/newsroom/source_reliability.js`**: list items now carry `data-source="…"` (HTML-escaped) instead of an inline `onclick`; a delegated `document` click listener matches `#sr-source-dd li[data-source]` and calls `srSourcePick()`. Also closes the same bug class for source names containing `'` or `"`.

### New Features

#### CVE Tracker: KEV + PoC now factored into Adjusted Risk Score

`adjusted_risk_score` previously only weighted exposure/hosting/EPSS — CISA KEV-listed and PoC-available CVEs displayed their badges but scored identical to CVEs without either signal.

- **`app/services/cve_service.py`** (`get_cves()`): added `kev_mult` (1.5x if `cisa_kev` true — matches existing `pkg_vuln_service.py` weight, aligned to CISA BOD 22-01 confirmed-exploitation signal) and `poc_mult` (1.2x if `poc_available` true — maps to CVSS Temporal Exploit Code Maturity metric). Both stack multiplicatively into the existing formula, capped at 10.0. New `kev_multiplier` / `poc_multiplier` fields added to each CVE dict alongside existing `epss_multiplier` / `hosting_multiplier`.
- **`Documentation/CVE Scoring.md`** *(renamed from `EPSS and Risk Scoring.md`)*: documents full formula, per-factor framework justification (CVSS Environmental Metrics, FIRST EPSS, CISA KEV, CVSS Exploit Code Maturity), worked examples.

## [3.16.1] - 2026-07-16

### Bug Fixes

#### News Room Top Filter Bar Not Reaching All Sections

Top filter bar (search/date/country/industry/actor) applied fully to APAC/Global/Local panels but silently dropped fields for other sections — inconsistent top-to-bottom filtering.

- **Watchlist** (`static/js/newsroom/ta.js`): `country` filter now applied (was search/date/industry only).
- **TechStack** (`static/js/newsroom/ta.js`): `country` filter now applied.
- **Ransomware Activity articles** (`static/js/newsroom/render.js`, `app/routers/ransomware.py`, `app/services/ransomware_service.py`): `country` filter now applied — required new `country` param on `GET /api/ransomware/related-articles` / `get_related_articles()`, matched against `mentioned_countries`.
- **Ransomware Victims** (`static/js/newsroom/render.js`, `app/routers/ransomware.py`, `app/services/ransomware_service.py`): `search` filter now applied — required new `search` param on `GET /api/ransomware/victims` / `get_victims()`, regex match against victim org name.
- CVE Tracker tab left untouched — has its own dedicated filter row, top bar is hidden there by design.

## [3.16.0] - 2026-07-15

### New Features

#### Ransomware Group Activity Treemap Dashboard

Exec dashboard had no view of ransomware group/region/industry activity — only a raw filterable victim table + article feed in News Room. Modeled on darkfeed.io's "Ransom View": treemap (not a 2D matrix) since group drives the visual, region/industry surface on click.

- **`app/services/ransomware_service.py`**: `get_group_treemap(days)` — per-group victim counts for current vs. prior equal-length window, `pct` change (`None` = "NEW" group); `get_group_detail(group_name)` — top country, top industry, top 5 countries/industries, 12-month trend, all-time total, 10 most recent victims.
- **`app/routers/ransomware.py`**: `GET /api/ransomware/treemap`, `GET /api/ransomware/group-detail`.
- **`templates/partials/tab_exec.html`**: new full-width "RANSOMWARE GROUP ACTIVITY (TREEMAP)" card, own 1D/1W/1M/3M/1Y range toolbar independent of the page-level days selector.
- **`static/js/newsroom/ransomware_treemap.js`** *(new)*: hand-rolled squarified-treemap layout (no new chart dependency — Chart.js has no treemap type), diverging green→gray→red color scale by % change, click-through group detail modal (stat row, 12-mo bar chart, sector/country ranking bars, victims table) — fully unlocked, no blur/paywall pieces (unlike the darkfeed.io reference it was modeled on).

#### Ransomware Group → Threat Actor Watchlist

- Detail modal header gets a WATCH/UNWATCH button reusing the existing `/api/ta/watchlist` endpoints, `requireTAAuth` auth gate, and active-client resolution (`_clientHeader()`/`getActiveClientId()`) — no new client-picker needed, honors whatever client is already selected in the header switcher.
- Uses `_cveToast` instead of `_taStatus` (the latter assumes `#ta-status` exists, which it doesn't outside the TA Room tab — would have thrown).

#### Manual Victim Enrichment (Country / Industry)

Ransomware feed source often ships blank/"Not Found" country or industry. Added analyst-editable fields instead of an external enrichment integration (scoped down from that option after discussion).

- **`app/services/ransomware_service.py`**: `update_victim(victim_id, country, industry)` — partial update, blank input leaves existing value untouched.
- **`app/routers/ransomware.py`**: `PATCH /api/ransomware/victims/{victim_id}`, `require_auth`, audit-logged (`edit_ransomware_victim`).
- **`get_victims`/`get_group_detail`**: now expose Mongo `_id` as `id` (previously stripped) so the frontend has an edit target.
- **`templates/newsroom.html`**: new `#rw-edit-modal-overlay` (country/industry inputs) and `#rw-full-modal-overlay` (full paginated victim list with its own group/country/industry filters).
- Edit affordance intentionally kept **out of** the compact News Room panel row (too small to carry it) — only available via the new "⛶ Expand" button → full-list modal, and inside the treemap group-detail modal's victims table.

### Improvements

- **`templates/partials/tab_intelligence.html`**: TA Watchlist's `tawOpenNavigator()` button changed from `.filter-btn`/"⧉ Navigator" to `.btn-apply`/"⧉ Open Navigator" — now matches the other 3 ATT&CK Navigator buttons in the app.
- **`static/js/newsroom/render.js`**: Ransomware Activity panel row redesigned — Published/Discovered dates moved under the group name (matching the existing Victim/Industry stacking pattern) to free up width; Country now wraps instead of ellipsis-truncating; grid went from 4 columns to 3.

---

## [3.15.0] - 2026-07-10

### Bug Fixes

#### IntelGraph — Delete Diagram/Scenario Used Native Browser `confirm()` Instead of App Modal

Delete-diagram and delete-scenario confirmations were plain `window.confirm()` calls — jarring, unstyled, blocking, inconsistent with the rest of the app's dark/light theme.

- New `src/components/ConfirmDialog.tsx` — `useConfirm()` hook, promise-based (`await confirm(message)` returns `boolean`), renders a themed overlay modal (`.confirm-overlay`/`.confirm-box`) instead of blocking the JS thread.
- `TopBar.tsx`: diagram delete (`diagrams-del` button) now awaits the modal before calling `removeDiagram()`.
- `ScenarioBar.tsx`: scenario delete button now awaits the modal before calling `deleteCurrentScenario()`.
- `index.css`: added `.confirm-overlay`, `.confirm-box`, `.confirm-message`, `.confirm-actions`, `.confirm-ok` styles, matching existing `--panel2`/`--border2`/`--text` theme vars.
- Rebuilt and redeployed `intelgraph-src/dist` → `static/intelgraph`.
- Out of scope, left as-is: `alert()` on failed JSON import (not a delete/CRUD confirm); node/edge/zone delete via Delete/Backspace key in `Canvas.tsx` has no confirmation at all today.

## [3.14.0] - 2026-07-10

### New Features

#### IntelGraph — 32 New Node Icons, Palette Recategorized

Node palette was missing icons for the attack-flow/TTP concepts used in pentest diagrams (Google Dorking, Shodan, leaked creds, lateral movement, AD compromise, etc.) — 3 reference diagrams surfaced ~30 concepts with no matching `NodeTypeId`.

- **`src/types.ts`**: 32 new `NodeTypeId` variants added.
- **`src/constants/nodeTypes.ts`**: 32 new `NodeTypeDef` entries (id/label/accent) — Google Dorking, GitHub Search, Mobile APK, Shodan Search, Leaked Credential, Web Vulnerability Assessment, File Upload Vulnerability, Exploitation, Sensitive Document, Enumeration, Exfiltrate Data, AI Agent, Prompt Injection, 3rd Party File Sharing, Decrypt, Storage Device, Domain Controller, SMB Share, Config File, Lateral Movement, Privileged Account, Privilege Escalation, Active Directory, Defense Impairment, LAN Network, Default Credential, Physical Access, Masquerading, Server Room Access, Cloning, Employee ID Card, Network Sniffing.
- **`src/components/NodeIcon.tsx`**: matching hand-drawn glyphs added for all 32, same stroke style as the existing 51 (no dup SVG bodies, verified by script).
- **`PALETTE_GROUPS`** recategorized from 9 groups down to 5 — Network & Security, Infrastructure, Endpoints, People & Places, Threats & TTPs — merging the old Network/Security & Edge/Servers/Storage & Data/People & Misc/Places & Orgs/Threats/Attack Techniques split.
- Rebuilt (`npm run build`) and redeployed `intelgraph-src/dist` → `static/intelgraph` (the actual serving path — build output doesn't land there automatically).

## [3.13.0] - 2026-07-10

### New Features

#### Per-Client Newsletters, Manual TP CVE Section, News Room CVE Tagging

Newsletter was a single global broadcast — one design, one recipient list (`CVE_EMAIL_SENDER`/`CVE_EMAIL_CC` from env), one CVE correlation pass against the entire `cve_tracker` collection with no `client_id` scoping. Now built and sent per client.

- Client record (`app/services/client_service.py`, `app/routers/clients.py`) gains `recipients`, `newsletter_css`, `newsletter_intro`, `newsletter_footer` — editable in Client Tenants admin (`templates/partials/tab_usermgmt.html`, edit modal in `templates/newsroom.html`).
- `templates/newsletter.html` builder gets a client selector: auto-fills that client's saved design, drives which recipients `draft-email` sends to (falls back to global sender if a client has none set), and persists on the saved newsletter doc (`client_id`/`client_name`) for history filtering.
- **"Outstanding TP CVEs" section is manual, not auto-fill** — a picker panel lists the selected client's tracked CVEs (`GET /api/cve/tp-ids`, new endpoint backed by new `cve_service.get_tp_cve_ids()`) as checkboxes; only checked ones render in the email (`get_newsletter_cve_summary()` returns `[]` with no explicit picks — no silent "dump all TP CVEs" behavior). CVE correlation against article text (`_find_cve_mentions`) is now also client-scoped instead of matching against every client's CVEs.
- **News Room article cards now tag tracked TP CVEs.** `render.js` regex-matches article titles against the active client's TP CVE set (same `/api/cve/tp-ids` endpoint) and shows a `⚠ CVE-XXXX-XXXX` badge; refreshes on client switch.
- **Tech Stack News panel** now also surfaces articles whose `iocs.cves` (already populated at ingest by ScraperNewsRevamp's `iocSyncer`) intersect the client's TP CVE set, OR'd with the existing tech-name title match (`article_service.get_articles(cve_ids=...)`, `GET /api/articles?cve_id=...`) — no longer requires a tech-stack name to be configured to show CVE-relevant news.

### Bug Fixes

#### Newsletter Builder — Assigned Articles Lost on Navigation

`state` (highlight/apac/global/indonesia picks, analyst notes) lived only in a JS variable, never persisted — unlike the article queue, which already used `localStorage`. Navigating to Newsroom and back wiped every assignment. Now saved to `localStorage` on every assign/remove/note-edit and reloaded on page init.

#### Newsletter Builder — Expanded Panels Couldn't Scroll

"Customize Template" and "Outstanding TP CVEs" panels sat outside the `#sections` scroll container, directly under `.builder` (`overflow:hidden`) — expanding them just got clipped with no reachable scrollbar. Moved both inside `#sections`. Also added a `@media (max-width: 900px)` breakpoint (stacks to one column instead of squeezing a fixed 420px sidebar) and made the history drawer's card list height scale with viewport (`min(200px, 35vh)` instead of a fixed 200px).

#### News Room — Local News Tweet/Article Card Width Mismatch

Tweet cards in the Local News (Indonesia) panel spanned the full 3-column grid width while article cards sat in one narrow column, producing very long unreadable text lines. `.indonesia-grid` is now a fixed 2-column grid — tweet and article cards both occupy one equal-width cell, no spanning tricks, no blank gaps when filtering to articles-only.

## [3.12.1] - 2026-07-10

### Bug Fixes

#### Newsletter — Brand Name Desync, Missing Back Link

Newsletter page showed "CTI Platform" instead of "CTI Nexus" — hardcoded in three spots (`<title>`, auth-gate screen, header title) with no shared brand source across templates, each page just duplicating its own header markup. All three now read "CTI Nexus", matching Newsroom/Login.

Added `← CTI Nexus` back link to `templates/newsletter.html` header, same pattern as IntelGraph's `TopBar.tsx` `#backLink` (arrow-prefixed link to `/newsroom`) — previously only the existing "Newsroom" nav tab served that purpose.

## [3.12.0] - 2026-07-10

### New Features

#### IntelGraph — Native Scenario Mode, Mongo Persistence, Real Icons

**Scenario Flow removed, rebuilt as a native IntelGraph mode.** The standalone `/scenario-flow` page (Mongo-backed ordered "steps" with its own disconnected mini node/edge schema) is gone. Scenario storytelling is now a first-class mode inside IntelGraph itself — a `Diagram | Scenario` toggle in the toolbar switches into Builder (step list, note per step, "Capture selection" pulls the canvas's current multi-select into a step) or Player (Prev/Play/Pause/Next, cumulative-reveal toggle, playback interval), with dim/highlight rendering on the canvas showing what's already revealed vs. new in the current step, a note bubble anchored above the newly-revealed node, and smooth camera pan/zoom between steps.

- `templates/scenario_flow.html` deleted; `/scenario-flow` route removed from `app/main.py`; nav link removed from `templates/newsroom.html`.
- Scenario steps now reference real diagram node/edge ids (`node_ids`/`edge_ids`) instead of duplicating a separate mini graph — `app/models/scenario.py`, `app/services/scenario_service.py`.
- New frontend: `intelgraph-src/src/state/scenarioStore.ts`, `components/ScenarioBar.tsx`, `ScenarioBuilder.tsx`, `ScenarioPlayerControls.tsx`, `lib/scenarioApi.ts`.

**Real node icons.** `components/NodeIcon.tsx` previously shipped a "best-effort recreation" icon set (the original was lost to an earlier external rewrite). 48 of 51 node types now use the original hand-drawn glyphs recovered from the upstream `net_draw` source; the 3 IntelGraph-only types (`ids`/`siem`/`vpn`) keep hand-drawn stand-ins in the same style.

**New "Places & Orgs" palette group.** Organisation, Building, City, Location/Site, Place of Interest — with `Address`/`Coordinates` fields (placeholder text "Address"/"Coordinate") in place of the IP/Hostname/Owner fields shown for technical node types. `constants/nodeTypes.ts`, `components/Inspector.tsx`, `types.ts`.

**Diagrams now persist to MongoDB**, not just the visiting browser's IndexedDB. Mongo is primary; IndexedDB is kept as an offline cache — edits still save locally (flagged `syncPending`) if the backend is briefly unreachable, and auto-retry/migrate to a real id on the next edit. Same offline-cache treatment now applies to Scenario steps and scenario creation.

- New `app/models/diagram.py`, `app/services/diagram_service.py`, `app/routers/diagrams.py` (`/api/diagrams`), `DIAGRAMS_COLLECTION` in `app/config.py`.
- `intelgraph-src/src/state/store.ts` reworked for Mongo-first save/boot/list/open with IndexedDB fallback; new `lib/diagramApi.ts`.

**Delete permissions.** Deleting a diagram or scenario is now owner-or-admin gated: an `analyst` can only delete their own; `admin`/`superadmin` can delete anyone's within their client scope. Previously neither resource had any ownership check on delete at all.

- `delete_diagram`/`delete_scenario` fold the check into the Mongo filter itself (owner-or-privileged), rather than a separate fetch-then-check — a non-owner's delete simply matches nothing and 404s, same as today's cross-client "not found" semantics.
- `intelgraph-src/src/lib/authToken.ts` decodes the JWT payload client-side (UI hint only, not a trust boundary) so the TopBar can grey out delete for diagrams you don't own.

**UI polish:** toolbar and scenario bar now wrap instead of overflowing off-screen on narrow windows; palette/inspector panels shrink at responsive breakpoints; themed scrollbars (matching dark/light theme) across IntelGraph and the main Newsroom/Login pages, which previously fell back to the browser default; native `<select>` elements themed; `← CTI Nexus` back link added to the IntelGraph toolbar (previously no way back to the Newsroom without editing the URL by hand).

---

## [3.11.1] - 2026-07-09

### Bug Fixes

#### Newsroom — APAC/Global Misclassification

Articles were being routed to the wrong region panel (APAC news showing under Global, and vice versa). Two independent root causes, both fixed:

**Cause 1 — merged country list lost region origin.** Scraper's `global-country` seed list intentionally duplicates APAC countries (Japan, China, India, Singapore, Australia, etc.) "for completeness." The classifier merged `apac-country` + `global-country` into one flat list before matching, so any country hit — regardless of which list it actually came from — counted as an APAC signal. A globally-themed article mentioning "Japan" in passing got tagged APAC; an APAC article with a threat-group match but no direct country/people hit fell through to the Global branch.

- `ScraperNewsRevamp/modules/nlp.py` — region-routing conditions now check membership in `apac_country_list` specifically (`mentioned_apac_countries`), not the merged list.

**Cause 2 — `news_type` field overloaded for two purposes.** The same Mongo field held both the region tag (`apac`/`global`) and article-category labels (`OT Article`, `Zero Day Article`, `Data Breach Article`, `Vendor Report Article`, `Tech Stack Article`). When an article matched both a region signal and a category keyword, the category label silently overwrote the region tag. The web's Global panel had a hardcoded whitelist that happened to catch these category strings, so overwritten APAC articles leaked into the Global panel; the APAC panel had no equivalent catch-all, so they vanished from APAC.

- `ScraperNewsRevamp/modules/nlp.py` — `_sendAlert` now stashes the true region into a separate `region` field before any category label can overwrite `news_type`.
- `app/services/article_service.py`, `app/routers/articles.py` — new `region` query filter, with `$or` fallback to `news_type` for older documents saved before this fix.
- `static/js/newsroom/api.js`, `static/js/newsroom/cve.js` — APAC/Global panels now filter by `region` instead of the old `news_type` whitelist hack.

Articles saved before this fix that already lost their region tag to a category overwrite are not backfilled — the original signal is unrecoverable from the stored data.

---

## [3.11.0] - 2026-07-09

### New Features

#### IntelGraph — Network Diagram Editor

New **🗺 IntelGraph** tab: a full-screen, offline-first network/threat diagram editor for mapping infrastructure, actors, and incidents. Built as a standalone React SPA, embedded as static assets and served from this app — no separate process or port.

- Infinite pan/zoom SVG canvas. ~45 hand-drawn device icons across Network, Security & Edge, Servers, Storage, Endpoints, People, and Threats palette groups.
- Nodes support **Disposition** (Friendly/Partner/Neutral/Unknown/Suspicious/Adversary/Victim, single-select pill) and **Status** (Issue/Vulnerable/Suspicious Activity/Outage/DDoS/Exploited/Malware Infection/Data Exfiltration/Data Breach/Compromised, multi-select pill with icon badges + animated flicker ring on the node border), plus IP/hostname/owner metadata shown inline on the card (auto-hidden for non-technical or non-owned node types like Internet, threat actors, people).
- Edges support line style (solid/dashed/dotted/sneakernet), arrow direction (none/one-way/two-way), labels, and an animated "marching ants" footstep flow indicator (one-way or both-way).
- Zones (labeled translucent grouping rectangles), full undo/redo, multi-diagram management via IndexedDB, JSON save/open, PNG/SVG export, shareable gzip-compressed URL links, light/dark theme.
- All diagram data stays client-side in the visiting browser's IndexedDB — nothing is sent to or stored on this server.

**Backend**

- `app/main.py` — `GET /intelgraph` gated with the same `cti_auth` cookie check used by `/` and `/newsroom`; unauthenticated requests redirect to `/login`. Static bundle mounted at `/intelgraph` via `StaticFiles(directory="static/intelgraph")` (assets themselves are unauthenticated — they carry no data, only app code).
- `static/intelgraph/` — built output of the IntelGraph SPA (source maintained in a separate `net_draw` project; rebuild with `npm run build:embed` there, then copy `dist/` into this path).

**Frontend**

- `templates/newsroom.html` — Added **🗺 IntelGraph** nav tab (real page link, not a JS tab-switch, since IntelGraph is a separate SPA).

---

## [3.10.1] - 2026-05-25

### New Features

#### User Management — Client Tenant Editing

Superadmins can now edit existing client tenants. Previously, clients could only be created or deleted — name and country metadata were immutable after creation.

**Backend**

- `app/services/client_service.py` — Added `update_client(client_id, name, countries)` using MongoDB `find_one_and_update`.
- `app/routers/clients.py` — Added `ClientUpdate` Pydantic model and `PUT /api/clients/{client_id}` endpoint (superadmin-only). Change is audited via `write_audit`.

**Frontend**

- `templates/partials/tab_usermgmt.html` — Client Tenants table now has a **Countries** column (badge pills). Table colspan updated 4→5. Add Client form restructured to two rows: ID/Name/buttons row + full-width Countries picker row.
- `templates/newsroom.html` — Added **Edit Client Tenant** modal (`#ect-overlay`) with Display Name input and country picker. Follows existing modal pattern (`modal-card`, `modal-head`, `modal-foot`).
- `static/js/newsroom/usermgmt.js` — `loadUMClients` renders country badges and per-row **Edit** button. Added `umOpenEditClient`, `umCloseEditClient`, `umSaveEditClient` functions calling `PUT /api/clients/{id}`.

#### User Management — Client Tenant Country Picker

Country name free-text inputs replaced with a searchable checkbox list in both the Add Client form and the Edit Client Tenant modal. Prevents typos and ensures consistent country name values stored in the database.

- `static/js/newsroom/usermgmt.js` — Added `_COUNTRIES` array (195 ISO 3166-1 country names). Added helpers: `_buildCountryPicker(containerId, selected)` renders search input + scrollable checkbox list pre-checked from saved data; `_filterCountryPicker` provides live search; `_getCheckedCountries(containerId)` collects selections. `umSaveClient` and `umSaveEditClient` use `_getCheckedCountries` instead of parsing free text.

#### User Management — Edit Client Access via Checkbox List

The **Edit Client Access** modal (assigning tenants to a user) replaced its free-text client ID input with a checkbox list loaded from `/api/clients`. Each client shows display name + ID. Current assignments are pre-checked on open.

- `templates/newsroom.html` — Replaced `#ec-clients-input` text field with `#ec-clients-list` scrollable checkbox container.
- `static/js/newsroom/usermgmt.js` — `openEditClientsModal` is now `async`; fetches `/api/clients` on open and renders labelled checkboxes. `saveEditClients` collects checked values instead of parsing text input.

---

## [3.10.0] - 2026-05-23

### New Features

#### Daily Recap & Forecast (News Room + 𝕏 Intel)

New analyst-facing brief that summarises yesterday's cyber activity across both News Room articles and 𝕏 Intel tweets, plus a short forecast for the next 1–3 days. Each recap is persisted to MongoDB so analysts can revisit any prior day.

**Backend**

- `app/services/recap_service.py` — Pulls articles, tweets, IOCs, CVEs, and active campaign clusters for the target date, then prompts the LLM (`json_object` response format) for a structured recap + forecast. Forecast items are required to cite a concrete input signal. Results saved to the `daily_recaps` collection (one doc per date, upserted).
- `app/routers/recap.py` — `GET /api/recap/list`, `GET /api/recap/latest`, `GET /api/recap/{date}`, `POST /api/recap/generate?date=&force=`. All require auth; generation is audited.
- `app/main.py` — `_daily_recap_loop()` runs daily at 06:00 UTC (after the 04:00 IOC decay sweep) and idempotently generates the prior-day recap. Added to the `lifespan` task list with cancellation on shutdown.

**Frontend**

- New top-level **📰 Daily Recap** tab (`templates/partials/tab_recap.html`) with a date picker, GENERATE / FORCE REGEN buttons, a history sidebar (last 60 days), and a rendered recap card showing headline, summary, top stories, top tweets, active actors, notable CVEs, active campaigns, APAC signals, and a Forecast block with confidence-tagged likely events.
- `static/js/newsroom/recap.js` handles loading, history, generation, and rendering.

**No change to ScraperNewsRevamp** — the recap reads data already produced by the existing news + tweet ingestion pipelines.

---

## [3.9.1] - 2026-05-23

### Bug Fixes

#### IOC Extraction — Version Number False Positives

Software version numbers in four-octet notation (e.g. `12.5.1.0`, `12.6.1.0`) were being extracted as IP addresses. Fixed in all three extraction paths.

- `app/services/newsletter_service.py` — Added `_RE_VERSION_PREFIX` pattern. `extract_iocs()` now pre-scans text for version-context strings (`version`, `ver`, `firmware`, `software`, `release`, `patch`, `build`, `update`, `v`) and excludes matching four-octet values from the IP candidate list.
- `wisemap_cti.py` — Same `_VERSION_PREFIX_RE` added as class attribute on `IOCExtractor`; applied in `extract()` when processing `"IPs"`.
- `ScraperNewsRevamp/modules/iocExtractor.py` — Identical fix applied.

#### IOC Extraction — URL+Path False Positives (Space in Separator)

Prose fragments like `like .vscode/tasks.json` and `hidden .claude/settings.json` were matching as `url_with_path` IOCs because `_RE_URL_PATH` allowed `\s*` around the dot separator. Removed `\s*` from around `_SEP` in `_RE_URL_PATH` — spaces adjacent to dots are not valid in real or defanged domain notation.

- `app/services/newsletter_service.py` and `ScraperNewsRevamp/modules/iocExtractor.py` updated.

#### IOC Extraction — URL+Path False Positives (Fake TLD)

Patterns like `File.claude/settings.json` matched because the TLD slot used `[a-zA-Z]{2,6}` — too broad. Replaced with an explicit `_TLD` allowlist of recognised top-level domains. `claude`, `vscode`, and other non-TLD words no longer qualify.

- `_TLD` constant added to both `newsletter_service.py` and `iocExtractor.py`; `_RE_URL_PATH` updated to use it.

### New Features

#### IOC Management — API Integration Docs Button

Added a `⟨/⟩ API` button to the far-right of the IOC Management toolbar. Opens an in-page modal with the full IOC REST API reference:

- `GET /api/iocs` with all query parameters (type filter, search, pagination, sort)
- `GET /api/iocs/stats`, `GET /api/iocs/{type}/{value}` detail
- `POST` endpoints for feedback (tp/fp), tags, and threat-actor linking — with JSON body examples
- `DELETE` for single and bulk IOC removal (admin-only noted)
- `GET /api/stix/iocs` STIX 2.1 bundle export with type and limit params
- Auth header requirement (`Authorization: Bearer <token>`) shown at top

### Scripts

#### `scripts/purge_false_positive_iocs.py`

One-shot cleanup script targeting IOCs already in the database that match the false-positive patterns above. Dry-run by default; pass `--execute` to delete.

- Removes **IP** records where all four octets ≤ 30 and last octet = 0 (version-number heuristic).
- Removes **URL+PATH** records containing whitespace.
- Removes **URL+PATH** records whose TLD is not in the recognised list.

---

## [3.9.0] - 2026-05-20

### New Features

#### TA Evolution Timeline & Dormancy/Resurgence Detector (B2)

Every tracked threat actor now surfaces a 24-month activity sparkline and a state flag — **ACTIVE**, **DORMANT**, or **RESURGENT** — computed from articles, tweets, and ransomware victim records.

**Backend**

- `app/services/ta_profile_service.py` — `get_ta_timeline(actor_name, months=24)` aggregates monthly counts from three collections (`COLLECTION_NAME`, `tweets`, `ransomware_victims`) and returns the full sparkline payload, dormancy state, state transitions, and linked campaigns. `get_dormancy_states(actor_names)` batch-computes states for the watchlist with a single pipeline. Helper `_build_month_list` generates the YYYY-MM grid without external deps.
- `app/routers/ta_groups.py` — `GET /api/ta/{actor}/timeline?months=24` wired to `get_ta_timeline`; audit-logged as `ta_timeline_view`. Watchlist endpoint extended: each item now carries `dormancy_state` via `get_dormancy_states` batch call — no extra per-item round-trips.

**Frontend**

- `static/js/newsroom/ta.js` — Profile modal injects a timeline strip above Capability Assessment: stacked-area Chart.js chart (articles blue, tweets cyan, ransom red), dormancy badge (🟢/🟡/🔴), state-transition log below. Watchlist cards gain an inline state badge next to actor name. Timeline chart destroyed on modal close to prevent canvas leaks.

#### Role-Based Dashboard Variants: Exec / Analyst / SOC (C2)

The Exec Dashboard now serves three audience variants from the same tab. The server returns a `view_config` block with per-section visibility flags; the frontend hides sections the current role cannot see and renders role-specific data panels.

**Backend**

- `app/services/exec_dashboard_v2_service.py` — `build_view_config(role)` returns the full sections map keyed to role strings. `get_exec_dashboard_v2` gains `client_id` and `role` parameters; conditionally fetches `critical_cves` (EPSS ≥ 50% or CISA KEV, client_id scoped), `recent_clusters_summary` (via `cluster_service.get_recent_campaigns`, soft-gated), `pending_fp_queue` (confidence 40–75%, client_id scoped, soft-gated), and `source_reliability_spread` (Admiralty A–F distribution). All new fetches fail soft — return `[]` or `{}` on error.
- `app/routers/exec_dashboard.py` — `GET /api/exec/dashboard-v2` now requires auth; reads user role and client_id from token. Admin/superadmin may pass `?role=` to preview another role's view (audit-logged as `exec_dashboard_role_preview`).

**Frontend**

- `templates/partials/tab_exec.html` — Existing sections wrapped in `data-section` divs matching the `view_config.sections` keys. New placeholder sections added for `source_reliability_spread`, `cluster_list`, `fp_feedback_queue`, `critical_cve_feed`, `ioc_enrichment_hits`, `sigma_export_quick`. Role indicator badge + admin role-switcher dropdown added to controls bar.
- `static/js/newsroom/exec.js` — `_execApplyViewConfig(vc)` iterates `data-section` divs and toggles visibility. New panel renderers for critical CVE feed (EPSS% / CVE / CVSS / KEV), cluster list (Summary / Size / Actors / last seen), FP queue (IOC / type / confidence chip / 👍👎), and source reliability doughnut. Admin role preview persisted in `localStorage`. Sections not yet backed by deployed features show "No data yet — feature pending."

---

## [3.8.5] - 2026-05-20

### New Features

#### Tech Stack Hosting Type Field & Composite Risk Score Refinement

Each tech stack entry now carries a **hosting type** classification (`on_prem` / `cloud` / `saas`) that feeds into the adjusted risk score alongside exposure and EPSS. The exposure dropdown was also changed from a click-to-cycle button to a direct `<select>` dropdown.

**Backend**

- `app/models/techstack.py` — `TechStack` and `TechStackAdd` gain `hosting_type: str = "on_prem"`. New `TechStackHostingUpdate` request model. `HOSTING_MULTIPLIER` dict added (`on_prem`→1.0, `cloud`→1.0, `saas`→0.8). Rationale: SaaS platform CVEs are vendor-patched; on-prem and cloud remain full-ownership.
- `app/services/techstack_service.py` — `add_techstack()` accepts and persists `hosting_type`. New `update_techstack_hosting(tech_id, hosting_type, client_id)`. `get_exposure_map()` replaced by `get_tech_risk_context(client_id)` which returns `{name_lower: {exposure, hosting_type}}` in a single DB call; `get_exposure_map()` kept as thin backwards-compat wrapper.
- `app/services/cve_service.py` — `get_cves()` now calls `get_tech_risk_context()` (single call instead of two) and extends the formula to:
  ```
  adjusted_risk = min(10.0, cve_score × exposure_mult × epss_mult × hosting_mult)
  ```
  Fields `hosting_type` and `hosting_multiplier` added to each CVE response doc.
- `app/models/cve_tracker.py` — `CveOut` gains `hosting_type: str` and `hosting_multiplier: float`.
- `app/routers/techstack.py` — new `PATCH /api/techstack/{tech_id}/hosting` endpoint; validates value, writes audit log entry `update_techstack_hosting`. `POST /api/techstack` passes `hosting_type` through to service.

**Frontend**

- `templates/partials/tab_cvetracker.html` — Tech Stack table gains **Hosting** column (with multiplier tooltip). Add form gains hosting dropdown (`On-Prem` / `Cloud` / `SaaS`) beside the exposure dropdown.
- `static/js/newsroom/techstack.js` — Exposure column changed from click-to-cycle button to `<select>` dropdown (direct selection). Hosting column renders matching `<select>` dropdown. Both fire their respective `PATCH` endpoints on `change`, update colors in-place, revert on failure. `tsAddTech()` sends both `exposure` and `hosting_type` on add.
- `static/js/newsroom/cve.js` — Score cell tooltip and modal formula now include hosting factor when SaaS reduces score: `6.5 × 1.5× (public) × EPSS≥50% 1.3× × saas 0.8× = 10.0`.

---

## [3.8.4] - 2026-05-20

### New Features

#### Tech Stack Exposure Field & Adjusted Risk Score

Each tech stack entry now carries an **exposure** classification (`internal` / `public` / `both`) that feeds a composite adjusted risk score for every associated CVE, incorporating both internet exposure and EPSS exploitation probability.

**Backend**

- `app/models/techstack.py` — `TechStack` and `TechStackAdd` gain `exposure: str = "internal"`. New `TechStackExposureUpdate` request model. `EXPOSURE_MULTIPLIER` dict (`public`→1.5, `both`→1.25, `internal`→1.0) exported for use in CVE scoring.
- `app/services/techstack_service.py` — `add_techstack()` accepts and persists `exposure`. Two new helpers:
  - `update_techstack_exposure(tech_id, exposure, client_id)` — validates against `_VALID_EXPOSURE`, issues `$set` update, returns `{"success": bool}`.
  - `get_exposure_map(client_id)` — returns `{name_lower: exposure}` for all client tech stacks; used by CVE service at query time.
- `app/services/cve_service.py` — `get_cves()` now calls `get_exposure_map()` and computes per-CVE:
  ```
  epss_mult     = 1.3 if epss ≥ 0.5 else (1.15 if epss ≥ 0.1 else 1.0)
  adjusted_risk = min(10.0, cve_score × exposure_mult × epss_mult)
  ```
  Fields `tech_exposure`, `adjusted_risk_score`, and `epss_multiplier` added to each CVE response doc. Not stored to DB — recomputed on every query from live exposure map.
- `app/models/cve_tracker.py` — `CveOut` gains `tech_exposure: str`, `adjusted_risk_score: float`, `epss_multiplier: float`.
- `app/routers/techstack.py` — new `PATCH /api/techstack/{tech_id}/exposure` endpoint; validates exposure value, writes audit log entry `update_techstack_exposure`. `POST /api/techstack` passes `exposure` through to service.

**Frontend**

- `templates/partials/tab_cvetracker.html` — Tech Stack table gains **Exposure** column (with multiplier tooltip). Add form gains exposure dropdown (`Internal` / `Public` / `Both`) beside the name input.
- `static/js/newsroom/techstack.js` — Exposure column renders a clickable badge per row. Click cycles `Internal 1×` → `Public 1.5×` → `Both 1.25×` in-place via `PATCH` with no page reload. `tsAddTech()` sends selected exposure on add.
- `static/js/newsroom/cve.js` — CVE table score cell: when adjusted ≠ raw, shows `~~raw~~ **adjusted**` with strikethrough; tooltip gives full formula (`6.5 × 1.5× (public) × EPSS≥50% 1.3× = 10.0`). CVE detail modal: same strikethrough + ▲ marker; exposure tag badge shown in meta bar. Adjusted score triggers when exposure ≠ `internal` **or** EPSS multiplier > 1.0.

---

## [3.9.0] - 2026-05-20

### New Features

#### IOC Confidence Decay + Analyst TP/FP Feedback (A3)

Every IOC now carries a decaying confidence score (0–100) reflecting recency, source count, and analyst verdicts. Analysts can mark IOCs as True Positive or False Positive directly from the IOC Management table; each vote is audited and immediately recomputes the score.

**Backend**

- `app/services/confidence_service.py` — new `compute_ioc_confidence(ioc_doc, now) -> int`. Formula: base 50 + recency bonus (30 if last_seen ≤ 7d) + source bonus (10 per source, capped at 30) + verdict bonus (20 × tp/(tp+fp+1)), then exponential decay by IOC-type half-life (IP/URL: 30d, domain: 60d, hash: 90d). Result clamped 0–100.
- `app/services/ioc_service.py` — `upsert_ioc()` now writes `confidence_score` and `confidence_decayed_at` on every insert/update. New `submit_feedback(ioc_id, user_id, client_id, verdict, note)` pushes a scoped `feedback_log` entry (carrying `client_id`), increments `tp_count`/`fp_count`, recomputes score, and calls `audit_service.write_audit`. New `decay_sweep()` finds stale IOCs (decayed >24 h ago or missing), recomputes in batches of 500 via `bulk_write`, returns `{scanned, updated}`. `get_iocs()` accepts `sort_by="confidence"` → sorts by `confidence_score` descending.
- `app/routers/iocs.py` — `POST /api/iocs/{ioc_id}/feedback` (body: `{verdict:"tp"|"fp", note?:str}`), returns updated IOC doc. `GET /api/iocs` forwards new `sort_by` param.
- `app/main.py` — `_ioc_decay_loop` background task runs daily at 04:00 UTC, mirrors `_cve_enrichment_loop` pattern.

**Frontend**

- `templates/partials/tab_intelligence.html` — IOC Management table gains **Confidence** column and **Feedback** column (👍 TP / 👎 FP buttons); Sort dropdown adds "Sort: Confidence" option.
- `static/js/newsroom/ioc_mgmt.js` — confidence chip rendered green ≥75, amber 40–74, grey <40. Feedback buttons call `POST /api/iocs/{id}/feedback` with optimistic chip update. `iocmgmtSetSort()` wires the sort dropdown.

**Multi-tenant note:** `feedback_log` entries are scoped with `client_id`. Global `tp_count`, `fp_count`, and `confidence_score` are shared across all tenants — IOC reputation is cross-org.

#### Campaign Clusters Surface (A4)

Activates the existing semantic clustering engine as a user-facing "Campaign Clusters" sub-tab under Intelligence, exposing recent threat campaigns with enriched metadata.

**Backend**

- `app/services/cluster_service.py` — new `get_recent_campaigns(days, client_id, min_size)`. Fetches recent articles, runs TF-IDF + Union-Find at cosine threshold 0.75, keeps clusters of `size ≥ min_size`. Each cluster returned with: `cluster_id, size, first_seen, last_seen, member_article_ids[], titles[], summary_title` (title of highest-reliability source member), `dominant_tas[], dominant_industries[], dominant_countries[], attack_techniques[], iocs[], cve_ids[]`.
- `app/routers/intelligence.py` — `GET /api/clusters/recent?days=7&min_size=3`. Defaults to caller's active `client_id`. Audit-logs reads via `audit_service`.

**Frontend**

- `templates/partials/tab_intelligence.html` — new **Campaign Clusters** sub-tab button in the Intelligence sub-menu.
- `static/js/newsroom/clusters.js` (new) — table with columns: Summary Title | Size | First Seen | Last Seen | TAs | Industries | Countries | ATT&CK chips | Actions. Row expand shows member articles (linked to article modal), IOC chips (deep-link to IOC detail modal), CVE chips. "⬇ Hunt Pack" button stubs A2 export with informational alert.
- `templates/newsroom.html` — includes new `clusters.js`.

---

## [3.8.3] - 2026-05-20

### New Features

#### CVE Historical Backfill — NVD 180-Day Lookback per Tech Stack

New per-tech backfill pipeline fetches CVEs from NVD for the past 180 days and enriches each with MITRE data. Closes the gap where assets added after a CVE was published would never receive that CVE automatically.

**Backend**

- `app/services/techstack_service.py` — three new async helpers:
  - `_fetch_nvd_cves(tech, days=180)` — pages NVD API v2.0 (`pubStartDate`/`pubEndDate`, +07:00 timezone); respects rate limit with `asyncio.sleep(6)` between pages; supports optional `NVD_API_KEY` for elevated rate limit (5 → 50 req/30s).
  - `_fetch_mitre_details(cve_id, client)` — enriches a CVE ID from `cveawg.mitre.org`: references, CVSS score/vector/severity, affected versions, solutions, published/modified dates.
  - `backfill_nvd_for_tech(tech_name, client_id, days=180)` — orchestrates fetch + enrichment + bulk upsert to `cve_tracker` (same schema as daily scraper); `asyncio.sleep(2)` between MITRE calls.
  - `get_tech_by_id(tech_id, client_id)` — helper for router to resolve tech name from ObjectId.
- `add_techstack()` — now fires `asyncio.create_task(backfill_nvd_for_tech(...))` immediately after new tech insert. Non-blocking; runs in background without delaying the add response.
- `app/routers/techstack.py` — `POST /api/techstack/{tech_id}/backfill-historical`: looks up tech by ID, creates background task, returns `{"started": true, "tech": ..., "days": 180}` immediately. Writes audit log entry `backfill_historical`.
- `app/config.py` — new `NVD_API_KEY` env var (optional).

**Frontend**

- `static/js/newsroom/techstack.js` — per-row `↺ Historical` button in the Action column of the Tech Stack table. Calls `tsBackfillHistorical(techId, techName, btn)` which hits the new endpoint and shows a status toast; button returns immediately since backfill is background.

---

## [3.8.2] - 2026-05-20

### Improvements

#### Audit Trail Coverage — Monitored Accounts & ATT&CK Sync

Extended audit logging to three previously untracked admin operations.

**Backend**

- `app/routers/monitored_accounts.py` — `POST /api/monitored-accounts` logs `add_monitored_account` (target: username); `DELETE /api/monitored-accounts/{username}` logs `delete_monitored_account`; `PATCH /api/monitored-accounts/{username}/toggle` logs `toggle_monitored_account` (detail includes `active` bool). All three capture IP.
- `app/routers/attack.py` — `POST /api/attack/sync` and `GET /api/attack/sync/{domain_key}` now log `attack_sync` with domains list and IP. Both endpoints changed from discarding (`_`) to capturing the admin user dict for the audit entry.

---

## [3.8.1] - 2026-05-18

### New Features

#### EPSS Integration (FIRST.org Exploit Prediction Scoring System)

CVE Tracker now fetches and displays EPSS scores for all CVEs in the org's tech stack. EPSS estimates the probability a CVE will be exploited in the wild within 30 days, sourced from [api.first.org](https://api.first.org/data/v1/epss).

**Backend**

- `app/services/epss_service.py` (new) — batch-fetches EPSS scores from FIRST.org API (100 CVEs/request), persists `epss_score`, `epss_percentile`, `epss_date`, `epss_checked_at` per CVE doc in `cve_tracker`.
- `POST /api/cve/epss-lookup` — manual trigger; fetches scores for all true-positive CVEs, writes audit log entry.
- `app/models/cve_tracker.py` — `CveOut` gains four new optional fields: `epss_score` (float), `epss_percentile` (float), `epss_date` (str), `epss_checked_at` (str).
- `app/services/cve_service.py` — `_SORT_FIELD_MAP` extended with `"epss" → "epss_score"`.
- `app/routers/cve.py` — `sort_by` query param pattern extended to accept `epss`.
- `app/main.py` — `_cve_enrichment_loop` now runs EPSS lookup alongside CISA KEV and Exploit-DB on every 3h UTC boundary. No new background task required.

**Frontend**

- **EPSS column** in CVE table — shows `X.XX%` probability badge; color-coded by risk tier (≥ 50% red, ≥ 10% orange, < 10% teal); `—` when not yet fetched. Column is sortable (click header, defaults to descending).
- **EPSS badge** in CVE detail modal meta bar — shows `📊 EPSS X.XX%` alongside CVSS score and CISA KEV badges.
- **EPSS detail section** in CVE modal body — displays probability percentage, percentile rank, score date, and brief explanatory note.
- **`📊 EPSS Lookup` button** in CVE Tracker filter bar — manual on-demand fetch for all true-positive CVEs; reloads table on completion.

---

## [3.8.0] - 2026-05-15

### New Features

#### Multi-Client (Multi-Tenant) Support

Full multi-client isolation. Every client gets its own scoped view of PIRs, RFIs, IOCs, CVE Tracker, Techstack, and CVE Tickets. Shared/global data (TA groups, ATT&CK DB, article feed, source scores) remains unscoped.

---

**Data Model**

- New `clients` collection in `news_db`. Seeded with `"default"` client on startup.
- New role: `superadmin` — cross-client visibility; created by `/api/auth/init` bootstrap endpoint (replaces plain `admin` first-user creation).
- Users gain `client_ids: list[str]` (replaces single `client_id`). One user can belong to multiple clients. `_resolve_client_ids()` migrates old single-`client_id` docs at login — no DB migration required for existing users.
- JWT payload now carries `client_ids: list[str]`. Old tokens carrying `client_id: str` are read backward-compatibly.
- All scoped collections use `_client_filter(client_id)` helper: for `"default"` matches docs with `client_id="default"` OR missing `client_id` field (backward compat for legacy data).

**Scoped Collections**

| Collection | DB |
|---|---|
| `pirs`, `pir_notes` | `news_db` |
| `rfis` | `threatintel` |
| `iocs` | `news_db` |
| `cve_tracker`, `cve_false_positives`, `cve_tickets` | `news_db` |
| `techstack` | `threatintel` |

**Backend**

- `app/services/client_service.py` (new) — `list_clients`, `create_client`, `delete_client`, `ensure_default_client`.
- `app/routers/clients.py` (new) — `GET /api/clients` (admin+), `POST /api/clients` (superadmin), `DELETE /api/clients/{id}` (superadmin).
- `app/auth.py` — `get_current_user` returns `client_ids`; `require_superadmin` dependency; `effective_client_id(user, x_client_id_header)` — superadmin can override via `X-Client-ID` request header; non-superadmin validated against their allowed list.
- All scoped routers (`pir`, `iocs`, `rfi`, `cve`, `techstack`) accept `X-Client-ID` header and pass resolved `client_id` into service layer.
- `PUT /api/auth/users/{username}/clients` — update user's `client_ids` list (admin+).
- `PUT /api/auth/users/{username}/role` — change user role (admin+; only superadmin can grant superadmin).
- `app/main.py` — registers `clients_router`; calls `ensure_default_client()` at startup; adds `X-Client-ID` to CORS allowed headers.

**Frontend**

- **Client switcher dropdown** in header — visible to superadmin always; visible to any user assigned to 2+ clients. Superadmin fetches full client list from `/api/clients`; regular multi-client users see only their assigned IDs. Switching client triggers reload of all active scoped tabs.
- **User Management tab** — new "Client" column; "Add User" form accepts comma-separated `client_ids`; superadmin ⋮ action menu on each user row (Reset PW / Edit Clients / Change Role); "Client Tenants" section for superadmin to create/delete clients.
- **Edit Clients modal** — input comma-separated list; calls `PUT /api/auth/users/{username}/clients`.
- **Change Role modal** — select new role; calls `PUT /api/auth/users/{username}/role`.
- All PIR, RFI, IOC, CVE, Techstack fetch calls send `X-Client-ID` header via `_authAndClientHeaders()`.

**ScraperNewsRevamp — `newCveThreat.py`**

- Imports `get_tech_list_by_client()` from `modules/techstackStore.py`.
- Builds `_tech_to_clients` reverse map (`{tech → [client_ids]}`). Scrapes union of all clients' tech stacks (one NVD/Tenable call per unique tech). Writes one `cve_tracker` doc per `(cve_id, client_id)` pair.
- DB index changed from single-field `unique("cve_id")` to compound `unique([("cve_id",1),("client_id",1)])`. Old `cve_id_1` index is dropped on each run to prevent resurrection.
- `modules/techstackStore.py` — new `get_tech_list_by_client()` function returning `{client_id: [tech_names]}` with 5-minute cache.

---

#### Techstack — Per-Client Isolation Improvements

- **CVE backfill on tech add** — when a client adds a tech stack entry that another client already has, existing CVEs for that tech are automatically copied into the new client's scope. Uses `$setOnInsert` upsert, non-fatal on BulkWriteError.
- **Bulk backfill endpoint** — `POST /api/techstack/backfill-cves` copies CVEs for all of the client's current tech stacks from other clients. "↺ Backfill CVEs" button in Tech Stack sub-tab.
- **Cascade delete** — removing a tech stack entry also deletes all `cve_tracker`, `cve_false_positives`, and `cve_tickets` docs for that tech+client. CVE panel auto-refreshes. Other clients' data unaffected.
- **Cross-client duplicate fix** — old `unique("name")` MongoDB index on `techstack` blocked adding a tech already used by another client. Replaced with compound `unique([("name",1),("client_id",1)])`. `DuplicateKeyError` caught gracefully; returns HTTP 409 with migration hint.

**Migration scripts** (run once after upgrade):

- `scripts/fix_techstack_index.py` — drops old single-field `name_1` unique index on `techstack`, creates compound `(name, client_id)` unique index.
- `scripts/fix_cve_tracker_index.py` — drops old `cve_id_1` unique index on `cve_tracker`, creates compound `(cve_id, client_id)` unique index.
- `scripts/migrate_client_data.py` — migrates all scoped collections from one client to another. Supports `--dry-run`, `--copy` (default), `--move`. Example: `python scripts/migrate_client_data.py --from default --to mil_command`.

---

#### User Management — ⋮ Action Menu

Single "⋮" button per user row replaces separate "Reset PW" and "Edit" buttons. Click opens floating dropdown with three actions:

- 🔑 **Reset Password** — existing modal, available to all admins.
- 🏢 **Edit Clients** — modal with comma-separated client IDs input; calls `PUT /api/auth/users/{username}/clients`.
- 👤 **Change Role** — modal with role `<select>`; calls `PUT /api/auth/users/{username}/role`. Only superadmin can grant superadmin role.

---

#### CVE Tracker — Pagination

CVE table now paginates. Default 20 per page; options 20 / 50 / 100. Prev/Next buttons with `X–Y of N` counter. Filter/sort changes reset to page 1. Pager hidden when all CVEs fit on one page.

---

### Bug Fixes

- **News Room — "Not Related to Cyber" tab** hidden for `analyst` role (visible to `admin` and `superadmin` only). Two-layer guard: button hidden in `_updateHeaderAuth`; `newsroomSwitchView` bounces analyst attempts back to `"cyber"` view.
- **CVE Tracker row** — removed ⚡ Exploit-DB button from table row (was crowding Mark FP button). Exploit-DB lookup still accessible inside CVE detail modal.
- **Techstack duplicate check** scoped per-client; previously a tech used by any client blocked all other clients from adding the same tech.

---

## [3.7.2] - 2026-05-15

### New Features

#### Threat Actor Watchlist — ATT&CK Navigator TTP Export

Watched threat actors' TTPs can now be opened directly in the MITRE ATT&CK Navigator as a heatmap layer with one click.

**Backend**

- `GET /api/ta/watchlist/navigator-layer` (new endpoint in `app/routers/ta_groups.py`) — aggregates TTPs across all watched actors that have generated profiles. For each actor, extracts technique IDs from `capability_assessment.attack_techniques` (all tactic buckets) using regex `T\d{4}(?:\.\d{3})?`. Scores each technique by actor coverage: `score = (actor_count / max_actor_count) × 100`. Each technique entry includes a `comment` field listing which actors use it (e.g. `"Used by: APT28, Lazarus Group"`). Returns a Navigator v4.5-compatible JSON layer. Actors with no profile are skipped silently.

**Frontend**

- `⧉ Navigator` button added to the Watchlist toolbar in `templates/partials/tab_intelligence.html`.
- `tawOpenNavigator()` added to `static/js/newsroom/ta.js` — opens `https://mitre-attack.github.io/attack-navigator/#layerURL=<origin>/api/ta/watchlist/navigator-layer` in a new tab. Identical pattern to the existing ATT&CK DB Navigator integration.

---

## [3.7.1] - 2026-05-12

### New Features

#### X Intel — Monitored Accounts Management

New **Monitored Accounts** sub-tab added to the 𝕏 Intel tab. Accounts are stored in `news_db.monitored_accounts` and managed entirely through the UI. `monitorX.py` now reads from the database instead of a static text file.

**ScraperNewsRevamp — `monitorX.py`**

`main()` now fetches monitored accounts from `news_db.monitored_accounts` (active only) via the new `list_monitored_accounts()` function in `modules/dbMongo.py`. Falls back to `supportFile/twitterAccounts.txt` if the collection is empty, and exits cleanly with a message if neither source has accounts.

**ScraperNewsWeb — Backend**

- `app/services/monitored_accounts_service.py` (new) — async CRUD against `news_db.monitored_accounts`:
  - `list_accounts()` — all accounts sorted by username
  - `add_account(username, display_name, notes)` — normalises handle (strips `@`, lowercases), checks for duplicate before insert, raises `ValueError` on conflict
  - `remove_account(username)` — hard delete by username
  - `toggle_account(username, active)` — flip active flag
- `app/routers/monitored_accounts.py` (new) — REST API at `/api/monitored-accounts`:
  - `GET /api/monitored-accounts` — list all accounts
  - `POST /api/monitored-accounts` — add account; returns `409 Conflict` with message if username already exists
  - `DELETE /api/monitored-accounts/{username}` — remove account
  - `PATCH /api/monitored-accounts/{username}/toggle` — toggle active state
- `app/config.py` — added `MONITORED_ACCOUNTS_COLLECTION` env var (default `monitored_accounts`)

**ScraperNewsWeb — Frontend**

The X Intel tab now has a sub-tab bar: **Tweets** (existing) | **Monitored Accounts** (new). Sub-tab state managed by `xiSwitchSubTab()`.

Monitored Accounts panel:

- **Add Account form** — handle (required), display name, notes fields. On submit, validates handle non-empty client-side; on duplicate, shows server's `"@foo already monitored"` error message inline. Clears fields and refreshes table on success.
- **Accounts table** — columns: Handle, Display Name, Notes, Added date, Active toggle, Remove button. Active toggle fires `PATCH /{username}/toggle` immediately. Remove button confirms before `DELETE`.
- Lazy-loaded on first sub-tab switch (no request until tab is opened).

JS functions added to `static/js/newsroom/xintel.js`: `xiSwitchSubTab`, `loadMonitoredAccounts`, `xiAddAccount`, `xiRemoveAccount`, `xiToggleAccount`, `_renderAccountsTable`.

---

## [3.7.0] - 2026-05-12

### New Features

#### Twitter/X Intel Integration

End-to-end pipeline ingesting Twitter/X feeds from curated security accounts into the CTI platform — scraping, TI validation, enrichment, persistent storage, and a dedicated UI tab.

**ScraperNewsRevamp — `monitorX.py` (new)**

Pulls tweets from twitterapi.io for accounts listed in `supportFile/twitterAccounts.txt`. Replaces the legacy `since_time` window approach with `since_id`-based offset tracking (one state entry per account stored in `supportFile/twitterLastSeen.json`) — no overlapping windows, no duplicate pulls. First run falls back to `since_time: 3h ago` to avoid pulling entire history.

Each tweet goes through two validation layers before saving:

1. **Regex scan (`_scan_tweet`)** — adapted from `twitter.py`. Extracts: mentioned threat groups (from DB `groups` collection), APAC countries/people (from DB + flag emoji matching), CVE IDs, zero-day signals, data breach keywords, OT keywords, report keywords. Funding-related tweets (`venture capital`, `seed funding`, etc.) are rejected outright (`tweet_indicator = False`).
2. **LLM gate (`articleValidator`)** — same module used by article scrapers. Tweets classified `related_cyber: false` are skipped. On LLM error, tweet is saved with a warning (no silent drops).

Tweets accepted by both layers are upserted directly into `news_db.tweets` via `modules/dbMongo.upsert_tweet()` (idempotent on `tweet_id`). Config keys added to `config/config.yml` under `twitter:` section (`api_key`, `accounts_file`, `state_file`).

Fields saved per tweet:

| Field | Source |
|---|---|
| `tweet_id`, `url`, `text`, `posted_on`, `lang` | twitterapi.io raw |
| `author_username`, `author_name`, `author_avatar`, `author_followers` | author object |
| `media_urls` | `extendedEntities.media[].media_url_https` |
| `fetched_at` | server timestamp |
| `apac_indicator`, `mentioned_group`, `mentioned_apac_country`, `mentioned_apac_people`, `cve_list`, `zero_day_list`, `databreach_list`, `ot_status`, `report_status` | regex scan |
| `related_cyber`, `confidence`, `industries_impacted`, `victim_countries`, `actor_countries`, `confirmed_incident`, `incident_confidence`, `incident_indicators`, `victim_name` | LLM validation |

**ScraperNewsWeb — Backend**

- `app/models/tweet.py` — `TweetOut` Pydantic model with all base and enrichment fields. `TweetListResponse` for paginated responses.
- `app/services/tweet_service.py` — `get_tweets()` with filter params: `search`, `author`, `lang`, `posted_on_start/end`, `apac_only`, `ot_only`, `confirmed_only`. `get_tweet_stats()` returns total count and top-10 authors by volume.
- `app/routers/tweets.py` — read-only API:
  - `GET /api/tweets` — paginated tweet list with all filter params
  - `GET /api/tweets/stats` — total count + top authors
- `app/config.py` — added `TWEETS_COLLECTION` env var (default `tweets`).

**ScraperNewsWeb — Frontend**

New **𝕏 Intel** tab added to the main navigation bar.

- **Filter bar** — search text, `@handle`, date range, APAC toggle, OT toggle, Confirmed Incident toggle. Checkboxes auto-apply on change; Apply / Reset buttons.
- **Stats row** — total tweet count, top-5 authors with per-author counts.
- **Tweet cards** — avatar, author name/handle, age, tweet text (t.co links stripped, 4-line clamp), media thumbnails (click → open tweet), TI signal badges (APAC / OT / CONFIRMED / REPORT / 0-DAY / CVE-XXXX / group names), top-2 industries. Card click opens modal.
- **Tweet detail modal** (`xi-modal-overlay`) — full metadata view:
  - Author header: avatar, display name, handle, follower count, datetime (UTC), language
  - Full untruncated tweet text
  - All media images (click → full size)
  - All TI signal badges (no limit)
  - Sections: Threat Groups, APAC Countries/People, CVEs, Zero-Day Signals, Data Breach Signals, Industries Impacted, Country Roles (victim/actor with LLM attribution), Confirmed Incident block (victim name, incident indicators, confidence %), LLM cyber relevance confidence, raw `fetched_at` + `tweet_id`
- Global filter bar hidden when 𝕏 Intel tab is active (tab has its own filter bar).

Files added: `templates/partials/tab_xintel.html`, `static/js/newsroom/xintel.js`

---

## [3.6.5] - 2026-05-12

### New Features

#### ATT&CK Navigator Integration

MITRE ATT&CK heatmap tab now opens the hosted Navigator pre-loaded with the current layer — no manual JSON download required.

- `GET /api/mitre/navigator-layer` — new endpoint returns plain JSON (no `Content-Disposition` attachment header), allowing Navigator to fetch cross-origin. Existing `GET /api/mitre/navigator-export` (download) unchanged.
- **⧉ Open Navigator** button added to MITRE ATT&CK toolbar. Builds `https://mitre-attack.github.io/attack-navigator/#layerURL=<origin>/api/mitre/navigator-layer?view=&days=` and opens in new tab.

---

#### ATT&CK Database

Full local mirror of MITRE ATT&CK (Enterprise, ICS, Mobile) synced from MITRE's public CTI GitHub repository into MongoDB. Enables offline browsing, filtering, cross-referencing, and Navigator layer export without hitting mitre.org.

**Backend — `app/services/attack_sync_service.py` (new)**

Fetches STIX bundles from `raw.githubusercontent.com/mitre/cti/master/{domain}/{domain}.json`. All upserts use `bulk_write` in batches of 500 (not individual `update_one`) for performance. Streams download with progress updates to DB every ~5 MB.

Collections populated:

| Collection | Contents |
|---|---|
| `attack_techniques` | Techniques + sub-techniques. Fields: `attack_id`, `name`, `description`, `tactics`, `is_subtechnique`, `parent_id`, `platforms`, `domains`, `version` |
| `attack_tactics` | x-mitre-tactic objects (shortname, name, description) |
| `attack_mitigations` | course-of-action (M-prefixed IDs only) |
| `attack_groups` | intrusion-set objects with aliases |
| `attack_software` | malware + tool objects with type flag |
| `attack_relationships` | Relationships (uses, mitigates, subtechnique-of) with source/target type |
| `attack_sync_log` | Per-domain sync state: version, MITRE modified date, object counts, delta vs. previous sync, download progress |

Sync loop (`_attack_sync_loop` in `main.py`): starts 3 min after boot, checks daily, syncs if any domain is older than `ATTACK_SYNC_INTERVAL_DAYS` (default `7`).

**Backend — `app/routers/attack.py` (new)**

| Endpoint | Description |
|---|---|
| `GET /api/attack/status` | Sync status per domain |
| `POST /api/attack/sync` | Trigger full or partial sync (background) |
| `GET /api/attack/sync/{domain}` | Trigger single-domain sync (background) |
| `GET /api/attack/techniques` | Paginated technique list (filter: domain, tactic, search, is_subtechnique) |
| `GET /api/attack/techniques/{id}` | Technique detail with mitigations, groups, software, sub-techniques |
| `GET /api/attack/tactics` | Tactic list |
| `GET /api/attack/tactics/distinct` | Distinct tactic shortnames from synced techniques (used by filter dropdown) |
| `GET /api/attack/mitigations` | Mitigation list |
| `GET /api/attack/groups` | Group list |
| `GET /api/attack/groups/{id}` | Group detail with techniques and software |
| `GET /api/attack/software` | Software list (filter by type: malware/tool) |
| `GET /api/attack/software/{id}` | Software detail with groups and techniques |
| `GET /api/attack/navigator-layer` | Navigator v4.5 layer from DB (filter: domain, tactic, group_id, search) |

**UI — Intelligence tab → ATT&CK DB sub-tab**

- **Sync status cards** per domain: ATT&CK version, MITRE published date, last sync, object counts with `+N`/`-N` delta vs. previous sync, live download progress (`↓ 35.2MB / 97MB 36%` → `⟳ parsing & writing`). Cards poll every 5 s while any domain is `SYNCING`.
- **Technique browser**: search, domain filter, tactic filter (populated via `distinct` from DB), parent/sub-technique select. Clickable rows open detail modal.
- **Groups / Software / Mitigations browsers**: search + domain filter, paginated.
- **Detail modals**: cross-linked — technique shows mitigations/groups/software/sub-techniques; group shows techniques/software with Navigator button; software shows groups/techniques. All IDs clickable to navigate between modals.
- **⧉ Open Navigator** button in technique browser and group modal: opens hosted Navigator with current filter or group's techniques highlighted.

---

### Bug Fixes

- **ICS/Mobile tactics empty** — `kill_chain_name` filter was `== "mitre-attack"`, which excludes `"mitre-ics-attack"` and `"mitre-mobile-attack"`. Changed to `startswith("mitre")`. Re-sync required to backfill existing documents.
- **Tactic dropdown not populating** — was reading from `attack_tactics` collection (x-mitre-tactic objects, not always present). Now uses `distinct("tactics")` on `attack_techniques` — always reflects actual synced data.
- **Duplicate tactic options** — `_loadTacticOptions` appended without clearing first. Now resets all options (except default) before each load.
- **Tactic dropdown never called on first load** — `attackdbSwitchBrowse('techniques')` inside `loadAttackDB` set `_attackdbLoaded = true` before the `if (!_attackdbLoaded)` guard, causing `_loadTacticOptions()` to be skipped. Separated visual state (`_attackdbSetActiveTab`) from data loading.
- **Browse tab button whitespace** — `btn-apply` global CSS has `margin-left:auto`. Four consecutive `btn-apply` buttons spread across full row width. Fixed by wrapping tabs in `margin-left:auto` container div with `margin-left:0` per button.
- **Navigator buttons wrong color** — inline `style` on ⬇ Navigator and ⧉ Open Navigator overrode `btn-apply` background. Removed inline overrides.
- **Sync shows NEVER after trigger** — status only updated after sync completed (minutes for Enterprise). Now writes `{status:"syncing"}` to DB at sync start. UI shows amber `● SYNCING` immediately; poll continues indefinitely while any domain is syncing.

---

## [3.6.4] - 2026-05-08

### Security / Audit

#### Audit Trail Gap Fixes

Six mutating endpoints lacked `write_audit` coverage. All now emit audit log entries with user, action, IP, and relevant detail.

| Router | Action recorded |
|--------|----------------|
| `iocs.py` | `tag_ioc` — IOC type, value, and applied tags |
| `newsletter.py` | `resend_newsletter` — newsletter ID, week/year, send method |
| `newsletter.py` | `draft_newsletter_email` — newsletter ID, week/year, send method |
| `exec_dashboard.py` | `generate_exec_brief` — query parameters (days, filters) |
| `articles.py` | `compute_confidence` — article ID and resulting score |
| `articles.py` | `recompute_confidence_all` — updated and total counts |

`POST /api/exec/brief` also gained `require_auth` (was previously unauthenticated).

---

## [3.6.3] - 2026-05-07

### New Features

#### STIX 2.1 Article Export

Individual articles now exportable as STIX 2.1 bundles — closes the gap between news ingestion and standard dissemination formats. Each bundle represents the article as a `report` object with linked attack-pattern and threat-actor objects, preserving full TTP and actor context for MISP sharing or downstream tooling.

- `app/services/stix_service.py` — added `build_article_stix_bundle(article_id)`:
  - `report` object (title, published date, source URL as external ref, `news_type` as label)
  - `threat-actor` stubs per `threat_actors` field (deterministic `uuid5` IDs — consistent with TA profile bundles)
  - `attack-pattern` objects per TTP (`id` + `name` mapped to MITRE external refs where pattern matches `T\d{4}`)
  - `uses` relationships linking each actor to each technique
  - `confidence_score` propagated to `report.confidence` if computed
  - Returns `None` on missing ID; router surfaces as 404
- `app/routers/stix.py` — added `GET /api/stix/article/{article_id}`, same `application/json` attachment response as other STIX endpoints

---

#### Article Confidence Score

Articles now carry a 0–100 confidence score derived from source reliability, source credibility, TTP richness, and threat actor presence. Surfaces in the article API and is available as a weight for PIR matching prioritization.

Scoring formula:
- **Source reliability** (Admiralty A–F): A=100, B=80, C=60, D=40, E=20, F=50 (unjudged → neutral)
- **Source credibility** (Admiralty 1–6): 1=100, 2=80, 3=60, 4=40, 5=20, 6=50
- **Base** = (reliability + credibility) / 2
- **TTP bonus** = `min(ttp_count × 5, 20)`
- **TA bonus** = `min(ta_count × 10, 10)`
- **Final** = `clamp(base + ttp_bonus + ta_bonus, 0, 100)`
- Sources with no rating default to 50 (neutral) for both components

Implementation:
- `app/services/confidence_service.py` *(new)* — `compute_score()`, `compute_article_confidence(article)`, `compute_and_store(article_id)`, `recompute_all_confidence()` (bulk: loads all source ratings into memory, streams article cursor)
- `app/models/article.py` — `confidence_score: int | None = None` added to `ArticleOut` — auto-surfaces in all article list and detail responses
- `app/routers/articles.py`:
  - `POST /api/articles/{article_id}/confidence` — compute and store score for one article (auth required)
  - `POST /api/articles/confidence/recompute` — batch recompute all articles (auth required)

---

#### RFI (Request for Intelligence) Tracker

Closes the consumer-analyst planning loop. Analysts can now receive, track, and respond to intelligence requests linked to PIRs. Modeled after the PIR collection with full CRUD, audit logging, and status lifecycle.

- `app/models/rfi.py` *(new)* — `RFICreate`, `RFIUpdate`, `RFIOut`: fields `requester`, `question`, `due_date`, `status` (open / in_progress / closed), `linked_pir` (PIR `_id` reference), `response`, `created_at`, `updated_at`
- `app/services/rfi_service.py` *(new)* — full async CRUD against `rfis` collection (TA DB; configurable via `RFI_COLLECTION` env var); `list_rfis` supports status filter + pagination; `update_rfi` uses `find_one_and_update` for atomic return
- `app/routers/rfi.py` *(new)* — `GET/POST /api/rfi`, `GET/PUT/DELETE /api/rfi/{rfi_id}`; all endpoints auth-gated; write ops emit audit log entries
- `app/config.py` — `RFI_COLLECTION = os.getenv("RFI_COLLECTION", "rfis")`
- `app/main.py` — registered `rfi_router`
- `templates/newsroom.html` — RFI panel added to Intelligence tab:
  - **RFI tab** in intel submenu (after PIR) with live count badge
  - Status filter chips: All / Open / In Progress / Closed
  - Card list — status badge (yellow=open, blue=in_progress, dim=closed), question, requester, due date, response preview, created date
  - Create/Edit modal: requester, question, due date, status, linked PIR dropdown (populated from `/api/pir`), response textarea
  - Auth-gated write ops via `requireTAAuth` + confirm modal on delete
  - Unauthenticated view shows "Sign in to view RFIs" instead of empty/error state

### Bug Fixes

- `app/main.py` — restored `ta_connect` / `ta_disconnect` calls in lifespan after linter removal; without these, TA DB (source scores, PIR, RFI) all fail at startup
- `app/services/rfi_service.py` — rewrote after silent Write tool failure left file empty on disk

---

## [3.6.2] - 2026-05-07

### New Features

#### STIX 2.1 Export

TA profiles, IOCs, and PIRs now exportable as STIX 2.1 bundles. No external STIX library — built as pure JSON following the spec. Deterministic `uuid5` IDs on object names ensure the same TA always gets the same STIX ID across exports.

- `app/services/stix_service.py` *(new)* — three async builders:
  - `build_ta_stix_bundle(actor_name)` — produces `ThreatActor` + `AttackPattern` (per TTP tactic bucket with MITRE external refs) + `Malware` (per known malware entry) + `Indicator` (per infrastructure IOC) + `Relationship` objects
  - `build_ioc_stix_bundle(ioc_type, limit)` — all 9 IOC types (ip, domain, url, url_with_path, email, sha256, sha1, md5, cve) converted to STIX `indicator` patterns
  - `build_pir_stix_bundle()` — active PIRs exported as `course-of-action` with custom `x_` fields; `derived-from` relationship to platform identity
- `app/routers/stix.py` *(new)* — endpoints, all return `application/json` with `Content-Disposition: attachment` download header:
  - `GET /api/stix/ta/{actor_name}`
  - `GET /api/stix/iocs?type=&limit=500`
  - `GET /api/stix/pirs`
- `app/main.py` — registered `stix_router`

---

#### Executive Intelligence Brief (AI Narrative)

"Generate Brief" button in exec dashboard toolbar. LLM synthesizes live dashboard v2 metrics into a 1-page executive briefing (Markdown, 5 sections). No page reload — renders in modal overlay with clipboard copy.

- `app/services/exec_brief_service.py` *(new)* — `generate_exec_brief(days, incident_only, confirmed_only)`: calls `get_exec_dashboard_v2`, builds structured user message (top sector risk scores, industry spikes with z-scores, TA velocity top 5, CVE exposure per tech, top TTPs, confirmed incident rate), calls LLM via `get_llm_client`
- `app/routers/exec_dashboard.py` — added `POST /api/exec/brief`
- `templates/newsroom.html`:
  - `✦ GENERATE BRIEF` button added to exec toolbar (purple accent, after Export CSV)
  - `#exec-brief-modal` fixed overlay: content area, generated-at metadata, close button, clipboard copy
  - `generateExecBrief()` / `copyExecBrief()` JS functions

---

#### TA Profile → CVE Tracker Cross-Reference

LLM-generated `exploited_vulnerabilities` in TA profiles now validated against actual `cve_tracker` DB entries. Hallucinated or untracked CVEs are flagged; confirmed entries are enriched with live tracker fields. Also surfaces CVEs found in TA-tagged articles that the LLM missed.

- `app/services/ta_profile_service.py` — added `_enrich_profile_cves(profile)` async function:
  - Extracts CVE IDs from `capability_assessment.exploited_vulnerabilities`
  - Scans article titles for CVE-YYYY-NNNNN patterns in articles tagged with this TA
  - Bulk-fetches matched CVEs from `cve_tracker` in one query
  - Annotates each `exploited_vulnerabilities` entry: `_confirmed`, `_cve_score`, `_cve_severity`, `_cisa_kev`, `_poc_available`, `_tech`, `_link`, `_active_exploitation`
  - Adds `_article_cves`: CVEs from articles not present in LLM profile, with full tracker data
  - Enrichment computed fresh on every fetch — never written back to MongoDB, so tracker updates propagate automatically
- Called from both `get_ta_profile()` and `generate_ta_profile()`

---

#### Semantic Deduplication

Same incident reported by multiple sources no longer floods panels. TF-IDF + cosine similarity groups near-duplicate articles; one canonical shown per group. Available as inspection endpoint and optional query parameter on article listing.

- `app/services/dedup_service.py` *(new)*:
  - `find_dedup_groups(articles, threshold=0.75)` — TF-IDF on titles (`ngram_range=(1,2)`), cosine similarity matrix, Union-Find grouping (transitive: A≈B, B≈C → one group); canonical = most-recent-first; canonicals annotated with `_dup_count`, `_dup_sources`, `_dup_urls`; untitled articles pass through as singletons
  - `get_dedup_groups(days, threshold, limit)` — fetches recent articles from MongoDB, runs dedup, returns only groups with `_dup_count > 1` plus stats (`total_articles`, `total_groups`, `duplicates_suppressed`)
- `app/routers/articles.py`:
  - `GET /api/articles/dedup-groups?days=7&threshold=0.75&limit=500` *(new endpoint)* — inspection view of current duplicate groups
  - `GET /api/articles?dedup=true&dedup_threshold=0.75` — optional dedup pass on article listing results

---

## [3.6.1] - 2026-05-07

### New Features

#### D3FEND Countermeasure Integration

MITRE D3FEND defensive technique lookup integrated directly into TTP views. For any ATT&CK technique ID surfaced in the platform, analysts can now see mapped D3FEND countermeasures without leaving the UI.

- `app/services/d3fend_service.py` *(new)* — `get_d3fend_countermeasures(technique_id)`: async fetch from `d3fend.mitre.org/api/offensive-technique/attack/{id}.json`, parses `off_to_def.results.bindings`, deduplicates by technique name, returns `[{id, name, tactic, artifact, url}]`; in-memory cache per technique ID
- `app/routers/mitre.py` — added `GET /api/mitre/d3fend/{technique_id}` endpoint
- `templates/newsroom.html`:
  - **Article modal** — TTP table gains a `D3FEND` column; **🛡 Defenses** button per row expands inline panel with countermeasure pills (each links to `d3fend.mitre.org`)
  - **Heatmap TTP drill-down** — subtitle bar gains **🛡 D3FEND** toggle button; opens countermeasures panel above article list
  - `_fetchD3fend()` / `_renderD3fend()` / `toggleD3fend()` / `loadD3fendDrill()` JS helpers; shared `_d3fCache` dict avoids redundant fetches within session

---

## [3.6.0] - 2026-05-07

### New Features

#### IOC Persistent Database

Extracted IOCs now persisted to a dedicated `iocs` MongoDB collection instead of staying buried in newsletter documents.

- `app/services/ioc_service.py` *(new)* — `upsert_ioc()`, `persist_iocs_from_extraction()`, `get_iocs()`, `get_ioc_detail()`, `get_ioc_stats()`, `tag_ioc()`
- `app/routers/iocs.py` *(new)* — REST endpoints: `GET /api/iocs`, `GET /api/iocs/stats`, `GET /api/iocs/{type}/{value}`, `POST /api/iocs/{type}/{value}/tags`
- `app/services/newsletter_service.py` — after `extract_iocs()`, calls `persist_iocs_from_extraction()` to write IPs, domains, URLs, hashes, CVEs to `iocs` collection (deduplicated by type+value, source-tracked)
- `app/config.py` — added `IOC_COLLECTION` env var (default `iocs`)

**IOC schema:** `{ type, value, sources: [{url, source_name, feature_type, doc_id, first_seen}], first_seen, last_seen, seen_count, tags }`

---

#### CVE ↔ PIR ↔ Threat Actor Cross-Reference

Unified cross-reference service linking CVEs, PIRs, and TA profiles. Eliminates manual analyst correlation across three separate modules.

- `app/services/cross_reference_service.py` *(new)* — three functions:
  - `get_cve_crossrefs(cve_id)` — finds active PIRs with overlapping TA/TTP criteria, TA profiles for actors in CVE context, and news articles mentioning the CVE
  - `get_pir_crossrefs(pir_id)` — finds CVEs matching PIR's TA/TTP/industry criteria, TA profiles for tracked actors (with `has_profile` flag for unproiled actors)
  - `get_ta_crossrefs(actor_name)` — finds CVEs attributed to actor, active PIRs tracking actor, recent news articles
- `app/routers/crossref.py` *(new)* — endpoints: `GET /api/crossref/cve/{cve_id}`, `GET /api/crossref/pir/{pir_id}`, `GET /api/crossref/ta/{actor_name}`

---

#### MITRE ATT&CK Navigator Export

Observed TTPs exportable as ATT&CK Navigator layer JSON (v4.5 format). Respects current view (TA/industry) and day-window settings.

- `app/services/mitre_heatmap_service.py` — added `get_navigator_layer(view, days)`: builds Navigator layer from TTP frequency aggregation, scores techniques 0–100 relative to max observed count
- `app/routers/mitre.py` — added `GET /api/mitre/navigator-export?view=ta|industry&days=N` — returns JSON with `Content-Disposition: attachment` header
- `templates/newsroom.html` — added **⬇ Navigator** button in MITRE controls; `downloadNavigatorLayer()` JS function triggers download using current view/days settings

---

#### PIR Escalation by Priority

P1 PIRs now alert at a faster interval (default 5 min) independently of the main P2+ interval (default 15 min).

- `app/main.py` — `_pir_alert_loop()` refactored to dual-tick system: `p1_tick` (fires every `PIR_P1_INTERVAL_MIN`) and `all_tick` (fires every `PIR_ALERT_INTERVAL_MIN`); P2+ matches only send on `all_tick`; base poll every 60 s
- `_format_pir_alert()` extracted — P1 alerts prefixed with `🚨` and `⚡ CRITICAL — Immediate action required`; P2+ use `🔔`
- New env var: `PIR_P1_INTERVAL_MIN` (default `5`)

---

#### PIR Keyword Search — Body Text

PIR keyword criteria now searches `title`, `description`, `body`, and `content` fields (OR match). Improves recall for scrapers that store article body text.

- `app/services/pir_service.py` — `_build_query()` replaces single `title` regex with `$or` across four fields

---

#### Source Reliability Badge on Article Cards

Admiralty code badge now shown inline on article cards in all Newsroom panels (not just the article modal).

- `templates/newsroom.html` — `renderNewsItem()` reads `_srScoreMap` (already loaded) and appends `<span class="sr-inline-badge">` with Admiralty code + tooltip
- Added `.sr-inline-badge` CSS class — small monospace badge using accent color

---

## [3.5.6] - 2026-05-07

### New Features

#### News Room — Tech Stack News Panel

New **Tech Stack News** panel added to the News Room, below TA Watchlist News. Matches articles by keyword-searching the title against all configured tech stack entries. Catches both correctly-labelled `Tech Stack Article` entries and misclassified ones (e.g. `Unrelated Tech Stack Article`) that still mention a monitored technology. Respects global date, industry, actor, and search filters. Pagination and refresh button included.

**Backend — `title_keyword` filter added to `/api/articles`**
- `get_articles()` accepts new `title_keywords: list[str]` param; builds a MongoDB `$or` of per-keyword case-insensitive title regex matches
- When combined with the existing `search` param, both are enforced via `$and`

**Files changed**
- `app/services/article_service.py` — added `title_keywords` param and `$or`/`$and` query logic
- `app/routers/articles.py` — exposed `title_keyword` as a multi-value query param, passed through to service
- `templates/newsroom.html` — added Tech Stack News panel HTML, `state.techstack`, `loadTechStackPanel()`, wired into `loadAllPanels`, `refreshPanel`, `goPage`

---

## [3.5.4] - 2026-05-05

### Bug Fixes & Improvements

#### News Room — Not Related Cyber tab now populated

The **Not Related Cyber** sub-tab was always empty because the service queried `nlp_jobs` for `{"status": "filtered"}`, a status value the NLP pipeline never actually writes. Fixed by switching the data source to the `scraper_runs` collection (queried via `{"accepted": false}`), which is where the scraper logs all rejected articles.

Ransomware victim alert entries (`"NEW RANSOMWARE VICTIM"`, `"NEW RANSOMWARE VICTIM (INDONESIA)"`) are excluded from the list as they are not relevant in this context.

Article titles are now clickable links that open the original source URL.

**Restore to News Room**

The **↺ Restore** button now works end-to-end:
- Fixed 401 Unauthorized error — the frontend fetch was missing the `Authorization: Bearer <token>` header
- Clicking Restore inserts the article directly into the main news collection (`COLLECTION_NAME`) with `news_type: "Manually Restored"` and `manually_restored: true`, bypassing the NLP pipeline entirely
- Duplicate-safe: if the URL already exists in the news collection, the insert is skipped
- Article appears in News Room immediately after restore; `month`/`week`/`year` fields are derived from the original scrape timestamp

**Files changed**
- `app/services/filtered_articles_service.py` — rewrote data source (`nlp_jobs` → `scraper_runs`), implemented `restore_filtered_article` with direct insert to `COLLECTION_NAME`
- `app/routers/filtered_articles.py` — updated field mapping to match `scraper_runs` schema (`script` → `script_name`, `run_at` → `created_at`)
- `templates/newsroom.html` — added `Authorization` header to restore fetch; updated button tooltip

---

## [3.5.3] - 2026-05-05

### Improvements

#### Threat Actor Profile — Live News Context Injection

Profile generation now queries the scraped news database for recent articles mentioning the actor before calling the LLM. The actor name is split on `/` and `,` to match common alias formats (e.g. `APT29 / Cozy Bear`). Up to 10 articles from the last 90 days are retrieved, sorted newest-first, and injected into the user message as a structured bullet list (date, title, source, URL). The LLM receives this grounded context alongside the standard Senior CTI Analyst system prompt, enabling the generated profile to reference post-training-cutoff reporting. Falls back to actor-name-only input when no recent articles are found.

**Files changed**
- `app/services/ta_profile_service.py` — added `_fetch_recent_news(actor_name)`, `_build_user_message(actor_name, news)`; updated `_call_llm` and `generate_ta_profile` to pass news context through

---

## [3.5.2] - 2026-05-05

### New Features

#### CVE Tracker — Excel Export with Date Range Filter

True-positive CVEs can now be exported to a pre-formatted Excel file matching the company CVE Tracker template. Only CVEs that are **not** false-positives and fall within the selected date range are included.

**Export behavior**
- Filters on `detected_on` field; falls back to `published` when `detected_on` is empty
- Joins each CVE with its `cve_tickets` document to populate all ticket fields (owner, remediation status, risk acceptance, etc.)
- Ticket fields fall back to CVE document values when ticket data is absent (e.g. `affected_asset` → `tech`, `fixed_version` → `solutions`, `active_exploitation` → CVE-level field)
- Loads a user-supplied Excel template, clears existing data rows (row 16+), writes filtered rows with style copied from the original first data row
- Returns file as a streaming download; filename includes the selected date range
- Template path defaults to `app/templates/CVE_Tracker_template.xlsx`; overridable via `CVE_TRACKER_TEMPLATE` env var
- Export action logged to audit trail

**Column mapping (B–U, row 16+)**

| Col | Field |
|-----|-------|
| B | Ticket ID |
| C | CVE ID |
| D | CVE Reported Date |
| E | Severity |
| F | CVSS Score |
| G | Affected Asset/Product |
| H | Affected Version |
| I | Fixed Version |
| J | Asset Owner |
| K | Owner Email |
| L | Owner Team |
| M | Active Exploitation |
| N | Date Acknowledged by CTI Team |
| O | Remediation Date Plan |
| P | Remediation Status |
| Q | Actual Remediation Date |
| R | Escalation Required |
| S | Comments/Notes |
| T | Risk Acceptance |
| U | Closure Date |

**Backend — new/modified:**
- `app/services/cve_export_service.py` *(new)* — `export_cves_to_excel(date_start, date_end)`: fetches TP CVEs, joins tickets, fills Excel template, returns bytes
- `app/routers/cve.py` — added `GET /api/cve/export?date_start=YYYY-MM-DD&date_end=YYYY-MM-DD` (auth required)
- `requirements.txt` — added `openpyxl>=3.1.0`

**Frontend — modified:**
- `templates/newsroom.html` — added **⬇ Export Excel** button in CVE toolbar (below CISA KEV Lookup); picks `date_start`/`date_end` from existing date filter inputs, downloads resulting `.xlsx`

---

## [3.5.1] - 2026-05-05

### New Features

#### Newsletter — CVE Correlation & IOC Extraction from Article Bodies

Newsletter enrichment now cross-references fetched article bodies against tracked true-positive CVEs and extracts IOCs via regex.

**CVE Correlation**
- `_get_tp_cve_ids()` — fetches all `cve_tracker` docs and `cve_false_positives` concurrently; returns set of confirmed true-positive CVE IDs
- `_find_cve_mentions(title, body, tp_cve_set)` — regex-scans article title + body for CVE IDs, intersects with TP set
- Each enriched article now includes:
  - `cve_mentions: list[str]` — TP CVE IDs found in this article
  - `possibly_exploited_wild: bool` — `True` when any TP CVE is mentioned (signals potential in-the-wild exploitation)
- TP CVE set fetched once before parallel article processing (not per-article) for efficiency

**IOC Extraction**
- `extract_iocs(text) -> dict` — runs after trafilatura body extraction; returns dict of non-empty IOC type lists
- IOC types extracted: `ips`, `urls` (with protocol), `urls_with_path` (no protocol, has path), `domains` (defanged only), `emails`, `sha256`, `sha1`, `md5`, `cves`
- URL-with-protocol matches stripped from text before URL-with-path matching; both stripped before domain matching — avoids double-counting
- `domains` pattern requires a defanged separator (`[.]`, `[dot]`, `(dot)`, `{.}`, `(.)`) immediately before the TLD — eliminates prose false positives (`normal.com` excluded, `evil[.]com` included)

**Backend — modified:**
- `app/services/newsletter_service.py`:
  - Added `import re` and all IOC/CVE regex constants at module level (compiled once)
  - Added `extract_iocs(text)`, `_get_tp_cve_ids()`, `_find_cve_mentions()`
  - `_enrich_articles()` — fetches TP CVE set once, inner `_process()` now calls IOC extraction + CVE correlation per article
  - `_strip_article()` — persists `iocs`, `cve_mentions`, `possibly_exploited_wild` to newsletter DB document

---

## [3.5.0] - 2026-05-04

### New Features

#### PIR Date Range — Start Date, End Date, and Auto-Expiry

PIRs can now be scoped to a specific article timeframe via optional `start_date` and `end_date` fields (format: `YYYY-MM-DD`). Article queries, coverage counts, and alert scanning all respect the configured window. PIRs with a past `end_date` are silently skipped during alert checks without modifying their `status` in the database.

**Backend — modified:**
- `app/models/pir.py` — added `start_date: Optional[str]` and `end_date: Optional[str]` to `PIRCreate`, `PIRUpdate`, and `PIROut`
- `app/services/pir_service.py`:
  - Added `_apply_date_range(q, start_date, end_date)` — injects `posted_on` range filter into a MongoDB query dict
  - `_compute_coverage(criteria, start_date, end_date)` — total count and recent-14d count both scoped to date range; recent lower bound is `max(cutoff_14d, start_date)` so the window is always honoured
  - `_to_out()` — includes `start_date` and `end_date` in serialized output
  - `list_pirs()` — passes per-PIR dates to coverage computation
  - `get_pir_articles()` — date range applied before querying articles
  - `get_pir_export()` — date range applied to article fetch
  - `check_new_articles_vs_pirs()` — skips PIR if `today > end_date` or `today < start_date`; alert scan uses `max(since_str, start_date)` as effective lower bound
  - `create_pir()` / `update_pir()` — persist `start_date` / `end_date`; `update_pir` uses `if key in data` (not `is not None`) so explicit `null` clears existing dates

**Frontend — modified:**
- `templates/newsroom.html` — PIR create/edit modal now shows `START DATE` and `END DATE` date pickers in a two-column row below Keywords
  - `openPirModal(pir)` — populates both fields from `pir.start_date` / `pir.end_date`; clears to empty on new PIR
  - `savePir()` — on create: sends dates only when non-empty; on edit: always sends both fields (passing `null` to clear)
  - PIR card meta row — shows `From: YYYY-MM-DD` and `Until: YYYY-MM-DD` when dates are set

---

## [3.4.0] - 2026-05-04

### New Features

#### Not Related Cyber — Filtered Article Review & Restore

Articles rejected by GPT as not cyber-related are now tracked, visible in the UI, and restoreable to the NLP queue — instead of silently disappearing with `status: completed`.

**Root cause fixed:** `nlp_worker.py` previously marked every job `completed` regardless of outcome. Jobs where `nlp_scan` returned `None` (GPT rejection) were indistinguishable from successfully stored articles.

**ScraperNewsRevamp — modified:**
- `nlp_worker.py` — capture return value of `nlp_scan()`; set `status: "filtered"` when `None` (rejected), `"completed"` only when article was stored

**Backend — new files:**
- `app/services/filtered_articles_service.py` — `get_filtered_articles(page, page_size, search)` queries `nlp_jobs` collection for `status: "filtered"` sorted by `completed_at` desc; `restore_filtered_article(id)` sets `status: "pending"` so the NLP worker re-processes it
- `app/routers/filtered_articles.py` — REST endpoints:
  - `GET /api/filtered-articles` — paginated list with optional `search` filter; public
  - `POST /api/filtered-articles/{id}/restore` — re-queue article; requires auth

**Backend — modified:**
- `app/config.py` — added `NLP_JOBS_COLLECTION` env var (default `"nlp_jobs"`)
- `app/main.py` — registered `filtered_articles_router`

**Frontend — modified:**
- `templates/newsroom.html` — News Room tab now has a sub-menu ("Cyber News" / "Not Related Cyber"), matching the pattern used by CVE Tracker and Intelligence tabs
  - **Cyber News** — existing APAC / Global / Ransomware / Indonesia / TA Watchlist panels (unchanged)
  - **Not Related Cyber** — new panel: paginated list of filtered articles with search bar; each item shows title (linked), date, source, and a **↺ Restore** button
  - Restore fades the card, re-queues it via `POST /api/filtered-articles/{id}/restore`, then reloads the list after 1.2 s
  - "Not Related Cyber" badge counter updates when view loads; "Cyber News" badge mirrors existing `newsroom-count`

---

## [3.3.0] - 2026-05-03

### New Features

#### Newsletter Mind Map Button (History Cards)

Added "Mind Map" button to each saved newsletter card in the history drawer, positioned alongside the existing Preview and Resend buttons.

**Frontend — modified:**
- `templates/newsletter.html` — added `<button class="hc-btn" onclick="generateMindmap('${n._id}')">Mind Map</button>` to every history card's `.hc-actions` row
- `templates/newsletter.html` — added `generateMindmap(id)` async function:
  - Calls `GET /api/mindmap/newsletter/{id}`
  - If `wisemap_url` is non-empty → opens WiseMapping editor in new tab
  - If `wisemap_url` is empty → fetches `/download`, triggers browser file save as `{title}.wxml`
  - Toast feedback on all states (generating, success, error)

**Why history cards only:** The newsletter composer has no saved `doc_id` until after the newsletter is sent; the mindmap endpoint requires a persisted document ID.

### Changed

#### Newsletter Mind Map — Section-Based Structure

Replaced CTI-style mindmap structure (IOCs, TTPs, CVEs extracted from text) with a section-hierarchy layout matching the actual newsletter structure.

**New map structure:**
```
Newsletter Week X/Y  (root)
├── ⭐ Highlight (N)     [gold]
│   └── Article title    [with summary note + url link]
├── 🌏 APAC (N)          [teal]
│   ├── Article title
│   └── ...
├── 🌐 Global News (N)   [dark blue]
│   └── ...
└── 🇮🇩 Indonesia (N)    [purple — omitted if no articles]
    └── ...
```

**Backend — modified:**
- `app/services/wisemap_service.py`:
  - `build_newsletter_report()` — rewritten; now builds `MapNode` tree directly from `sections.highlight / apac / global_news / indonesia`; skips empty sections; each article node carries `summary` as note and `url` as link; returns `(title, wxml)` tuple instead of `CTIReport`
  - `generate_mindmap()` — updated signature to `generate_mindmap(report_or_raw, ...)`: accepts both `CTIReport` (all other feature types, unchanged) and `(title, wxml)` tuple (newsletter path); creates a stub `CTIReport(title, summary)` for the WiseMapping push call when given raw tuple
  - Added `_NEWSLETTER_SECTION_META` constant — ordered list of `(key, label, color)` for the four sections
  - Added `MapNode`, `COLORS` to imports from `wisemap_cti`
- `wisemap_cti.py — WiseMappingXMLBuilder`:
  - Extracted shared XML serialization into private `_serialize(title, branches)` method
  - `build(report)` now delegates to `_serialize()`
  - Added `build_from_nodes(title, branches)` — public method that builds WXML from a pre-constructed `MapNode` list, bypassing `CTIReport` entirely

**All other feature types** (`threat_actor`, `cve`, `pir`, `cluster`, `ransomware`) — no changes; still use `CTIReport` path.

---

## [3.2.0] - 2026-05-03

### New Features

#### WiseMapping Mind Map Integration

Mind map generation added across 6 CTI feature types. All maps stored in MongoDB (`mindmaps` collection) so users can re-download without regenerating. Behavior determined by config: if WiseMapping server credentials are set, maps are auto-pushed and an editor URL is returned; otherwise the map is saved as a `.wxml` file for manual download or import.

**Reference implementation:** `wisemap_cti.py` (repo root) — `WiseMappingXMLBuilder`, `WiseMappingClient`, `CTIReport`, `IOCExtractor`. Copied into `ScraperNewsWeb/` for direct import.

**Backend — new files:**
- `wisemap_cti.py` — copied to project root; handles WXML generation (Tango format), WiseMapping REST API client (login, create map, upload XML, download XML), IOC extraction, MITRE T-code extraction
- `app/services/wisemap_service.py` — central service: `get_or_generate()` (cache-first), `generate_mindmap()` (build → push/save), `get_cached_mindmap()` (DB lookup), 6 feature-specific `CTIReport` builders (see below)
- `app/routers/mindmap.py` — REST endpoints:
  - `GET /api/mindmap/{feature_type}/{doc_id}` — get or generate mind map; returns `{ wisemap_url, has_wxml, title, generated_at }`
  - `GET /api/mindmap/{feature_type}/{doc_id}/download` — stream `.wxml` file as `application/xml` download
  - `POST /api/mindmap/{feature_type}/{doc_id}/regenerate` — force-regenerate (bypass cache)

**Backend — modified:**
- `app/main.py` — registered `mindmap_router`
- `app/config.py` — added `WISEMAP_BASE_URL`, `WISEMAP_EMAIL`, `WISEMAP_PASSWORD`, `WISEMAP_ENABLED` (derived bool), `MINDMAPS_COLLECTION`
- `.env.template` — documented WiseMapping env vars

**MongoDB collection (auto-created):**
- `mindmaps` — `{ feature_type, doc_id, title, wxml, wisemap_url, generated_at }` — upserted on `{ feature_type, doc_id }` key

**Supported feature types and data sources:**

| `feature_type` | Source collection | Mind map content |
|---|---|---|
| `newsletter` | `newsletters` | Threat actors, IOCs, CVEs, TTPs extracted from all article summaries and key points |
| `threat_actor` | `ta_groups` + `ta_profiles` (TA DB) | Actor identity, aliases, TTPs by tactic, malware families, targeted sectors/regions, references |
| `cve` | `cve_tracker` | CVE ID, severity, CVSS vector, affected tech, associated TTPs, NVD link |
| `pir` | `PIR_COLLECTION` + matched articles | PIR title, coverage count, matched threat actors, targeted industries/countries, article references |
| `cluster` | Computed via `cluster_service.get_clusters()` | Cluster name, article count, source list, IOCs extracted from article titles, references |
| `ransomware` | `ransomware_victims` | Group name, victim count, targeted industries and countries, victim name list |

**Auto-push vs download logic:**
- `WISEMAP_ENABLED=True` (all three creds set) → `WiseMappingClient.push()` runs in thread via `asyncio.to_thread`; WiseMapping editor URL stored in `mindmaps.wisemap_url`; frontend opens URL in new tab
- `WISEMAP_ENABLED=False` (any cred missing) → WXML saved to DB only; frontend triggers `/download` endpoint to stream `.wxml` file

**Frontend pattern (add to any feature page):**
```javascript
async function openMindmap(featureType, docId) {
    const r = await fetch(`/api/mindmap/${featureType}/${docId}`);
    const d = await r.json();
    if (d.wisemap_url) window.open(d.wisemap_url, '_blank');
    else window.location.href = `/api/mindmap/${featureType}/${docId}/download`;
}
```

**Activation (env vars):**
```
WISEMAP_BASE_URL=https://wisemapping.yourcompany.com   # leave blank for download-only mode
WISEMAP_EMAIL=your@email.com
WISEMAP_PASSWORD=yourpassword
MINDMAPS_COLLECTION=mindmaps                           # optional, default: mindmaps
```

---

## [3.1.0] - 2026-05-02

### Bug Fixes

- **`templates/newsletter.html` — Queue items stayed after assignment**: `assignQueued()` added articles to sections but never removed them from the localStorage queue. Fixed — assignment now calls `removeFromQueue(articleId)` immediately. Articles disappear from queue list on assignment.
- **`templates/newsletter.html` — `_renderQueueBanner` created DOM node regardless of visibility**: `_renderQueueBanner(mapped)` unconditionally inserted `#queue-banner` into the DOM even when `_queueBannerVisible = false` (banner never opened by user). Fixed — banner DOM is only created/updated when `_queueBannerVisible` is true; otherwise only the badge count updates. Also added `_queueBannerVisible = false` inside `_renderQueueBanner([])` directly for consistency.

### New Features

#### Newsletter — Queue Browser (replaces full article browser)

Left panel of the newsletter builder replaced. Previously showed all DB articles with search/filter/pagination. Now shows only the localStorage queue from Newsroom.

- **`templates/newsletter.html`**: New `renderQueuedArticles()` function reads `newsletter_queue` from localStorage and renders article cards with `+` assign menu and `✕` per-item remove button. Empty state shows "No queued articles — go to Newsroom to queue articles." Header shows article count and "Clear All" button (hidden when empty).
- Removed: filter inputs, date pickers, country/type selects, pagination controls, `loadArticles()`, `loadFilterOptions()`, `updatePagination()`, `changePage()`, `debounceLoad()`, `clearFilters()`, `renderArticles()`.
- `assign()` updated — now calls `removeFromQueue(articleId)` after adding to section, so assigned articles auto-disappear from queue.
- `removeFromSection()` updated — calls `renderQueuedArticles()` instead of `loadArticles()`.
- `removeFromQueue()` and `clearQueue()` updated — both call `renderQueuedArticles()` instead of `_renderQueueBanner()`.
- `init()` updated — no longer calls `loadFilterOptions()`, `loadArticles()`, `loadNewsroomQueue()`; calls `renderQueuedArticles()` directly.

#### Newsletter — Per-item Queue Removal

- **`templates/newsletter.html`**: Each article row in queue now has a `✕` remove button calling `removeFromQueue(articleId)`. Previously only "Clear All" existed. "Clear" button renamed to "Clear All" for clarity.
- New `removeFromQueue(articleId)` function: filters item from localStorage, updates queue, re-renders article list.

#### Newsletter — Template Customization

Collapsible "🎨 Customize Template" section added to newsletter builder (below Indonesia section).

- **`templates/newsletter.html`**: Three textareas — Custom CSS (whole-email style overrides), Custom Intro (HTML injected at top of email body), Custom Footer (replaces default footer). Panel toggled via `toggleTemplatePanel()`. All three fields included in `buildPayload()` as `custom_css`, `custom_intro`, `custom_footer`.
- **`app/routers/newsletter.py`**: `POST /api/newsletter/preview` and `POST /api/newsletter/draft-email` now extract `custom_css`, `custom_intro`, `custom_footer` from request body and pass to `build_newsletter_context()`.
- **`app/services/newsletter_service.py`**: `build_newsletter_context()` accepts optional `custom_css`, `custom_intro`, `custom_footer` kwargs; includes all three in returned context dict.
- **`templates/newsletter_email.html`**: Injects `{% if custom_css %}<style>{{ custom_css | safe }}</style>{% endif %}` in `<head>`; `{% if custom_intro %}<div class="custom-intro">...</div>{% endif %}` at top of email body; footer block wrapped in `{% if custom_footer %}...{% else %}...{% endif %}` for full replacement. Added `.custom-intro` CSS class.

#### Newsletter — Newsroom Nav Closes Tab

- **`templates/newsletter.html`**: "Newsroom" nav link now calls `goToNewsroom(e)`. If newsletter was opened as a popup (`window.opener` exists and not closed), focuses the opener tab and closes the newsletter tab via `window.close()`. Falls back to `location.href = '/newsroom'` if opened directly.

---

## [3.0.0] - 2026-05-02

### New Features

#### Newsletter Builder — Full Pipeline

Weekly threat intelligence newsletter generated from curated article selections. Covers article selection UI, AI-powered summarization (with paywall fallback), HTML email draft dispatch via existing Graph/SMTP infrastructure, paywall source tracking, and saved newsletter history with resend.

**Architecture:**

```
Selected article IDs
  → MongoDB article fetch
  → Parallel: Playwright stealth → page.content() → trafilatura.extract()
  → Paywall detected? → upsert newsletter_paywall_hints collection
  → GPT-4o: body available → full summarization
            body unavailable → infer from title + metadata (countries, industries, TTPs, actors)
  → Jinja2 render → save to newsletters collection → Graph/SMTP email draft
```

**Sections per newsletter:**
- 1 Highlight of the Week (prominent, full-width card)
- 5 APAC Threats
- 5 Global Threats
- 5 Indonesia (optional)

**Backend — new files:**
- `app/services/newsletter_service.py` — body fetch (`fetch_article_body`), paywall detection, GPT-4o summarization (`_llm_summarize_with_body` / `_llm_summarize_from_metadata`), parallel article enrichment, Jinja2 render, newsletter persistence (`save_newsletter`, `list_newsletters`, `get_newsletter_html`, `get_newsletter_doc`), paywall hint storage (`upsert_paywall_hint`, `get_all_paywall_hints`)
- `app/routers/newsletter.py` — REST endpoints:
  - `GET /api/newsletter/source-hints` — paywall-flagged sources map
  - `GET /api/newsletter/history` — paginated saved newsletters (HTML excluded)
  - `GET /api/newsletter/{id}/html` — retrieve stored HTML (no regeneration)
  - `POST /api/newsletter/{id}/resend` — resend email from stored HTML (no GPT/Playwright)
  - `POST /api/newsletter/preview` — generate + save + return rendered HTML + `newsletter_id`
  - `POST /api/newsletter/draft-email` — generate + save + dispatch email draft

**Backend — modified:**
- `app/main.py` — registered `newsletter_router`; added `GET /newsletter` page route
- `requirements.txt` — added `trafilatura>=1.9.0`, `playwright>=1.44.0`, `playwright-stealth>=1.0.6`

**MongoDB collections (auto-created):**
- `newsletters` — saved newsletter docs: `{week, year, generated_at, created_by, html, sections}`
- `newsletter_paywall_hints` — per-source paywall flags: `{source, paywall_likely, last_seen}`

**Frontend — new files:**
- `templates/newsletter_email.html` — HTML email template; dark header, Highlight full-width card, section cards (APAC/Global/Indonesia) with key-point bullets, summary paragraph, country/industry/actor tags; Indonesia section rendered only if present
- `templates/newsletter.html` — selection UI:
  - Left panel: article browser with search, date-range, country, news-type filters + pagination
  - Paywall badge (⚠) on articles from known paywalled sources
  - Each article card: always-visible `+` button → click dropdown → assign to Highlight / APAC / Global / Indonesia
  - Right panel: newsletter builder — 4 sections with fill slots + per-slot remove button
  - "Preview" → `POST /api/newsletter/preview` → renders in iframe modal
  - "Send Draft Email" → `POST /api/newsletter/draft-email`
  - History drawer (bottom) — saved newsletters as horizontal scroll cards; each card: Preview + Resend without regeneration
  - Auth gate — redirects to `/newsroom` login if `localStorage.cti_jwt` absent

**Activation — new deps:**
```
pip install trafilatura playwright playwright-stealth
playwright install chromium
```

---

#### Newsroom → Newsletter Queue

Articles can be queued from the newsroom article modal and assigned to newsletter sections without re-browsing.

**Flow:**
1. Open any article in newsroom modal → click `+ Newsletter` button (modal footer, between Close and Open Article ↗)
2. Article stored in `localStorage.newsletter_queue`; button shows `✓ Queued (N)` / `✓ Already queued` on duplicate
3. Open `/newsletter` → `📋 Queue (N)` button appears in article browser header
4. Click → queue banner expands showing all queued articles with ⭐🌏🌐🇮🇩 one-click assign buttons
5. "Clear" wipes localStorage queue

**Changes to `templates/newsroom.html`:**
- Added `+ Newsletter` button in `#modal-card .modal-foot`; `queueForNewsletter()` serializes `window._modalArticle` to `localStorage.newsletter_queue`
- `openModal()` now sets `window._modalArticle = a` on each open
- `#header-username` span replaced with `#header-user-wrap` dropdown:
  - Click username → dropdown with **🔑 Change Password** (existing `openSelfPwModal()`) + **📋 Newsletter Queue (N)** (opens `/newsletter` in new tab, count refreshed live from localStorage)
  - Outside-click closes dropdown

---

### Improvements

- **Paywall source learning** — each newsletter generation records which sources blocked body fetch (`HTTP 4xx`, trafilatura < 150 chars, or paywall keywords detected). Flag stored in `newsletter_paywall_hints`; visible as `⚠ Paywall` badge in article browser on next visit. Summarization silently falls back to metadata-only; no user action needed.
- **Saved newsletters / no-regen resend** — every preview and send auto-saves full HTML + article summaries to MongoDB. History drawer lets users re-preview or re-send any past newsletter instantly (no Playwright, no GPT-4o cost).

---

### Bug Fixes

- **Newsroom header** — removed "LIVE FEED" text from `.header-status`
- **Newsletter auth** — `getToken()` previously read `cti_auth` cookie (set `HttpOnly` — JS-inaccessible). Fixed to read `localStorage.getItem('cti_jwt')`, matching the token key written by newsroom login flow. All newsletter API calls now authenticated correctly.
- **Article ID alias** — FastAPI serializes Pydantic `Field(alias="_id")` as `_id` in JSON. Newsletter JS used `a.id` throughout → always `undefined` → article map lookups silently failed → assign buttons did nothing. Fixed all occurrences to `a._id` (`renderArticles`, `allSelectedIds`, `assign`, `removeFromSection`, `buildPayload`, slot rendering).

---

## [2.5.0] - 2026-05-01

### New Features

#### Auth — OIDC / SSO Integration (Authorization Code + PKCE)

Generic OIDC SSO added alongside existing local username/password login. Both auth paths work simultaneously. After SSO, app issues a local JWT using the existing token format — all API code and frontend JS are unchanged.

**Flow:** Browser → `GET /auth/login` → redirect to provider → `GET /auth/callback` validates state/nonce/PKCE → provisions/looks up user → issues local JWT → redirects to `/#token=<jwt>` → JS stores token in `localStorage` and clears fragment.

**Security properties:**
- Authorization Code flow with PKCE (S256) — no implicit grant
- State + nonce + PKCE verifier stored in signed `SessionMiddleware` cookie (10-min TTL, `HttpOnly`, `Secure`, `SameSite=Lax`)
- Explicit `iss` and `aud` validation on ID token — rejects tokens issued for other clients on same provider
- JWKS cached with 1-hour TTL — not re-fetched per login
- `SESSION_SECRET_KEY` required at startup — app refuses to start if unset
- SSO-provisioned users (`hashed_password: null`) blocked from local login and password reset endpoints

**Backend:**
- `app/services/oidc_service.py` *(new)* — OIDC discovery fetch/cache, PKCE pair generation, authorization URL builder, code exchange, ID token validation, JWKS cache, user provisioning/lookup, logout URL builder
- `app/routers/oidc.py` *(new)* — `GET /auth/login` (redirect to provider), `GET /auth/callback` (code exchange → JWT), `GET /auth/logout` (clear session + provider RP-initiated logout if supported)
- `app/config.py` — added `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_DISCOVERY_URL`, `OIDC_REDIRECT_URI`, `SESSION_SECRET_KEY`, `OIDC_ENABLED` (bool, derived)
- `app/main.py` — added `SessionMiddleware` (wraps full app, before CORS), registered `oidc_router`, startup guard (`RuntimeError` if `SESSION_SECRET_KEY` empty), warms OIDC discovery cache on startup if `OIDC_ENABLED`, passes `oidc_enabled` to newsroom template context
- `app/routers/auth.py` — `POST /api/auth/login` guards SSO-only accounts (`hashed_password: null` → HTTP 400 with SSO redirect message); `POST /api/auth/users/{username}/reset-password` blocks password reset for SSO-provisioned accounts
- `requirements.txt` — added `authlib>=1.3.0`, `itsdangerous>=2.1.2`; bumped `httpx>=0.27.0`

**User provisioning:**
- First SSO login auto-creates user doc: `username` = email claim (fallback: `preferred_username`, `sub`), `role = analyst`, `hashed_password = null`, `auth_provider = "oidc"`, `sso_sub` stored for future matching
- Subsequent logins update `last_sign_in` and backfill `sso_sub` on pre-existing local accounts with matching username
- Role managed in-app by admin — never overwritten from OIDC claims
- `sso_provisioned` audit event written on first-time auto-create; `sso_login` on every SSO sign-in

**Frontend:**
- `templates/newsroom.html` — SSO button ("Sign in with SSO") added to auth modal with divider; only rendered when `oidc_enabled` is true (Jinja2 conditional)
- Fragment pickup inline script (runs before page render): reads `#token=<jwt>` from URL hash, writes to `localStorage`, clears fragment via `history.replaceState`; surfaces `?error=sso_failed` as inline auth modal error on callback failure
- `static/js/app.js` — no changes

**Activation (env vars required):**
```
SESSION_SECRET_KEY=<output of: python -c "import secrets; print(secrets.token_hex(32))">
OIDC_CLIENT_ID=<client-id>
OIDC_CLIENT_SECRET=<client-secret>
OIDC_DISCOVERY_URL=https://<provider>/.well-known/openid-configuration
OIDC_REDIRECT_URI=https://<app-host>/auth/callback
```
OIDC is opt-in — SSO button hidden and all `/auth/*` endpoints inert when `OIDC_CLIENT_ID` is unset.

---

## [2.4.0] - 2026-04-30

### New Features

#### User Management — Last Sign In Column

Users table now shows a "Last Sign In" column after "Created".

**Backend:**
- `app/services/auth_service.py` — `update_last_sign_in(username)` sets `last_sign_in` ISO timestamp on user document
- `app/routers/auth.py` — `POST /api/auth/login` calls `update_last_sign_in` on every successful login

**Frontend:**
- Added `Last Sign In` `<th>` after Created column in Users table header
- `loadUMUsers()` — renders `last_sign_in` (formatted `YYYY-MM-DD HH:MM:SS`); shows `—` for users who have never signed in
- All `colspan` references in user table updated from 5 → 6

---

#### User Management — Audit Log Pagination

Audit log now supports configurable per-page row count.

**Frontend:**
- Per-page `<select>` added in audit log section header: options 25 / 50 / 100, default 25
- `loadAuditLog()` reads selected value dynamically instead of hardcoded 50
- Pager total-page calculation uses dynamic `pageSize`
- Changing per-page selector resets to page 1 automatically

---

### Bug Fixes

- **Intelligence tab — sklearn `UserWarning`**: `TfidfVectorizer` in `cluster_service.py` emitted `"The parameter 'token_pattern' will not be used since 'tokenizer' is not None"` on every Intelligence tab load. Fixed by passing `token_pattern=None` explicitly to suppress the warning.
- **Intelligence tab — first-load UX**: Loading spinner showed generic "Clustering articles…" text, causing users to panic-refresh before cold compute finished. Updated to "Clustering articles… (first load may take a few seconds)" to set expectations and prevent unnecessary refreshes.

---

## [2.3.0] - 2026-04-30

### New Features

#### CVE Tracker — Bulk False Positive

Selected CVEs (acknowledged, non-FP only) can now be marked as False Positive in one action. Checkbox selection no longer locks to a single tech stack — tech restriction moved into Draft Email validation only.

**Backend:**
- `app/services/cve_service.py` — `bulk_mark_false_positive(cve_ids)` using `pymongo.UpdateOne` objects in `bulk_write` (upsert per CVE, deduplicates existing FP entries)
- `app/routers/cve.py` — `POST /api/cve/bulk-false-positive` (auth, audited) — accepts `{"cve_ids": [...]}`, max 100

**Frontend:**
- "⚑ Mark FP" button in CVE table toolbar — appears when ≥1 CVE selected, stacked above Draft Email
- Confirm modal shows affected CVE IDs (truncated after 10 with count)
- `toggleCveSelect` / `toggleAllCveSelect` — tech-lock removed from selection; `_updateCveBulkButtons()` replaces `_updateCveEmailBtn()` — Draft Email button shows disabled (not hidden) with tooltip when mixed tech selected

---

#### CVE Tracker — Authentication Bug Fix

Exploit-DB Lookup, CISA KEV Lookup, and per-row Exploit-DB buttons were logging users out on click. Root cause: callbacks used `({ pass })` destructuring without passing opts to `requireTAAuth` → `isNewStyle=false` → callback received raw JWT string → `pass = undefined` → `Authorization: Bearer undefined` → 401 → `_authFailed()` cleared JWT.

**Fix:** Changed all three callbacks from `async ({ pass }) =>` to `async (pass) =>` (old-style, matches how `requireTAAuth` calls them with no opts).

---

#### Auth — Bottom-Right Toast for Unauthenticated Actions

Any button that calls `requireTAAuth` when not signed in now shows a bottom-right toast notification ("Authentication required — please sign in to perform this action.") in addition to the login modal.

`_authFailed()` now also uses `_cveToast` (global) instead of `_taStatus` (TA-room only), so session-expired messages appear regardless of which tab triggered the failure.

---

#### Auth — User Management "Add User" Fix & Feedback

Add User button in User Management was silently failing in certain cases: if `_pwPolicy` was null/corrupt, `_validatePasswordClient` threw a `TypeError` that propagated up the async function and rejected silently with no visible feedback.

**Fixes:**
- `_validatePasswordClient` call wrapped in `try/catch` — corrupt policy degrades gracefully
- Explicit empty password check before validator
- Success `_cveToast("User X created as role", true)` after successful creation
- Pydantic 422 `detail` array joined to readable string instead of `[object Object]`
- Button shows "Adding…" + disabled during request, resets in `finally`
- `type="button"` added to prevent accidental form submission

---

#### Auth — Self Password Change (All Users)

Any logged-in user (admin or analyst) can change their own password by clicking their username in the header.

**Frontend:**
- `#header-username` span made clickable — `cursor:pointer`, dotted underline hover hint, `title` tooltip
- New `#self-pw-overlay` modal — dismissible (backdrop click or Cancel), shows current username, password field with policy tooltip, "Update Password" button
- `openSelfPwModal()` / `closeSelfPwModal()` / `doSelfPwChange()` — guards `_jwtValid()`, client-validates against `_pwPolicy`, calls `POST /api/auth/change-password`, shows success toast or inline error; array `detail` from Pydantic joined to readable string

**Backend:** No changes — `POST /api/auth/change-password` already uses `require_auth` (not `require_admin`), available to all roles.

---

### Bug Fixes

- **`app/services/cve_service.py` — Bulk FP `bulk_write` TypeError**: Raw dicts passed to Motor's `bulk_write` instead of `pymongo.UpdateOne` objects. Fixed to use proper `UpdateOne(filter, update, upsert=True)` instances.
- **CVE filter bar — "From" label + date input misalignment**: Wrapped each `From`/`To` label + date input pair in a `display:flex; white-space:nowrap` group so they stay inline when the filter bar wraps.
- **CVE filter bar — Exploit-DB/CISA buttons layout**: Wrapped in `flex-direction:column` container, pushed right via `margin-left:auto` — stacked vertically side by side.

---

## [2.2.0] - 2026-04-30

### New Features

#### Threat Actor Profile — AI Generate Content

"AI Generate Content" button added to Threat Actor Watchlist. Calls GPT-4o with a structured Senior CTI Analyst prompt and saves the resulting JSON profile to MongoDB `ta_profiles` collection (upsert by actor name).

Watchlist view converted from table to **card grid layout** — one card per actor, showing name, date added, `✓ PROFILE` / `NO PROFILE` badge, and action buttons.

Profile cards batch-check profile existence on load via `Promise.allSettled`. Generated profiles persist and can be regenerated on demand.

**Backend:**
- `app/config.py` — `TA_PROFILES_COLLECTION = "ta_profiles"` *(new)*
- `app/services/ta_profile_service.py` *(new)* — `generate_ta_profile(name)` calls GPT-4o with full CTI analyst schema prompt, `get_ta_profile(name)` retrieves from DB; uses `asyncio.to_thread` for sync OpenAI client
- `app/routers/ta_groups.py` — `POST /api/ta/profile/generate` (auth-gated, audited), `GET /api/ta/profile/{name}`

**Frontend:**
- Watchlist table → card grid (`.taw-card-grid`, `.taw-card`) — responsive auto-fill columns
- `⚡ AI Generate` button per card — triggers auth-gated generation with loading state
- `👁 View Profile` button appears after profile exists
- `↻ Regenerate` button in profile modal header
- Full-page scrollable profile modal (`.tap-*` CSS classes) with sections: Identity, Motivation, Targeting Profile, Capability Assessment (malware table, CVE table, MITRE ATT&CK techniques by phase), Infrastructure (IOCs), Campaign History, Detection & Defense, Organizational Relevance, Intelligence Gaps, References

---

#### CVE Tracker — Exploit-DB Integration

Lookup True Positive CVEs against the [Exploit-DB](https://www.exploit-db.com/) database. Found exploits are saved to the CVE document's `pocs[]` array and `poc_available` flag set to `true`.

**Backend:**
- `app/services/exploit_db_service.py` *(new)* — `lookup_exploitdb(cve_id)` async httpx GET to Exploit-DB search JSON API (`X-Requested-With: XMLHttpRequest`); `save_exploit_hits(cve_id, exploits)` upserts into `cve_tracker` doc with deduplication by URL; `lookup_all_true_positives()` batches all TP CVEs in groups of 5 with 1s rate-limit delay
- `app/routers/cve.py` — `POST /api/cve/exploit-lookup` (bulk, auth, audited), `POST /api/cve/{cve_id}/exploit-lookup` (single, auth, audited)
- `requirements.txt` — `httpx>=0.26.0` added explicitly

**Frontend:**
- "⚡ Exploit-DB Lookup" button in CVE filter bar — runs bulk lookup with result toast
- Per-row "⚡" button in action column — single-CVE lookup; shows `✓` tick with date tooltip if already checked

---

#### CVE Tracker — CISA Known Exploited Vulnerabilities Integration

Cross-reference True Positive CVEs against the full [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Matched CVEs are tagged **"Exploited in the Wild"** with full CISA metadata saved to the CVE document.

**Backend:**
- `app/services/cisa_kev_service.py` *(new)* — `fetch_cisa_kev()` downloads full catalog JSON (~1,200+ entries) into `{CVE_ID: vuln_dict}` dict; `lookup_all_true_positives()` does O(1) dict lookup per TP CVE, saves all matches concurrently; `save_cisa_kev_hit()` sets `cisa_kev=true`, `cisa_kev_date_added/due_date/vendor/product/name/description/action`, and `active_exploitation = "Active Exploitation — Confirmed widespread use by threat actors (high priority)"`
- `app/routers/cve.py` — `POST /api/cve/cisa-lookup` (auth, audited) — returns `{checked, matched, catalog_size, matched_cves[]}`
- `app/models/cve_tracker.py` — `CveOut` model extended with `cisa_kev`, `cisa_kev_*` fields, `active_exploitation`, `exploit_db_checked_at`, `exploit_db_hits`

**Frontend:**
- "🔴 CISA KEV Lookup" button in CVE filter bar
- `🔴 KEV` red badge in POC column — tooltip shows vuln name and date added
- "🔴 EXPLOITED IN THE WILD (CISA KEV)" badge in CVE detail modal meta bar
- CISA KEV detail section in CVE modal body: vendor, product, date added, due date, vulnerability name, description, required action

---

#### CVE Enrichment — Automated 3-Hour Schedule

CISA KEV and Exploit-DB lookups run automatically every 3 hours at UTC boundaries: **00:00, 03:00, 06:00, 09:00, 12:00, 15:00, 18:00, 21:00**.

**Backend:**
- `app/main.py` — `_seconds_until_next_3h()` calculates exact sleep duration to next 3h UTC boundary; `_cve_enrichment_loop()` background task (same pattern as PIR alert loop) — waits, runs CISA lookup, then Exploit-DB lookup, logs results; wired into `lifespan` as `enrichment_task`, cancelled on shutdown

---

## [2.1.0] - 2026-04-30

### New Features

#### Password Policy — Admin Configurable

Admin can now configure password rules from the User Management tab. Rules stored as singleton doc in `password_policy` MongoDB collection. Applied server-side on all password-accepting endpoints and client-side with live validation.

Rules: minimum length (4–128), require uppercase, require lowercase, require number, require symbol. Defaults: min 8, all requirements enabled.

Admin can trigger **Force All Users to Change Password** checkbox — sets `force_pw_change: true` on all non-admin users. On next login those users see a blocking modal requiring a compliant new password before any access is granted.

**Backend:**
- `app/services/policy_service.py` *(new)* — `get_policy()`, `save_policy()`, `validate_password(pw, policy)`, `policy_hint(policy)`
- `app/models/auth.py` — `PolicySettings` model, `ChangePasswordRequest`; removed hardcoded validators (policy-driven)
- `app/services/auth_service.py` — `flag_force_pw_change()`, `reset_password` now clears `force_pw_change` flag
- `app/routers/auth.py` — `GET /api/auth/policy` (public), `PUT /api/auth/policy` (admin, audited), `POST /api/auth/change-password`
- `POST /api/auth/login` now returns `force_pw_change: bool`

**Frontend:**
- Policy editor section in User Management tab: min_length input + 4 checkboxes + force-all trigger
- Force-change-password modal blocks all UI after login when `force_pw_change: true`
- `_validatePasswordClient` now uses live `_pwPolicy` loaded from `GET /api/auth/policy` on page init

---

#### Password Requirement Tooltip — Instant (No Delay)

Replaced native `title="..."` attribute on all `?` info buttons with custom CSS tooltip. Native browser `title` tooltip has hardcoded ~600ms delay. New implementation: `.pw-info-wrap:hover .pw-tooltip { display: block }` — shows instantly on hover.

Tooltip text is dynamically populated from current policy rules on page load and on each policy save.

---

#### CVE Tracker — Sortable Columns

Tech Stack, Severity, and Published Date columns are now sortable. Click column header to sort ascending; click again to toggle descending. Active sort column shows `↑`/`↓` indicator; inactive columns show `↕`.

Severity sorts by `cve_score` (numeric) not severity string. Default sort: Published descending (newest first).

**Backend:**
- `app/services/cve_service.py` — `get_cves()` accepts `sort_by` (`tech`|`severity`|`published`) and `sort_dir` (`asc`|`desc`). Maps `severity → cve_score` for meaningful numeric sort.
- `app/routers/cve.py` — exposes `sort_by` and `sort_dir` query params with pattern validation.

**Frontend:**
- `_cveSortBy`, `_cveSortDir` state vars; `cveSortBy(col)`, `_updateCveSortUI()` functions
- `.cve-th-sortable` CSS class; `.sort-active` highlights active column header in accent colour

---

## [2.0.0] - 2026-04-30

### New Features

#### JWT Authentication & User Management

Replaced single shared password (`X-Auth-Password` header) with per-user JWT auth. Users sign in once via top-right header button — token cached in `localStorage` (8-hour expiry). All subsequent write actions use the token silently with no per-action modal.

**Users:** stored in `users` MongoDB collection with bcrypt-hashed passwords. Roles: `admin`, `analyst`.

**Audit log:** every write action recorded to `audit_log` collection — user, action, target_id, detail, IP, timestamp.

**New API endpoints:**
- `POST /api/auth/init` — bootstrap first admin (fails if any user exists)
- `POST /api/auth/login` — returns JWT
- `GET /api/auth/me` — current user info
- `GET /api/auth/users` — list users (admin)
- `POST /api/auth/users` — create user (admin)
- `POST /api/auth/users/{username}/reset-password` — admin reset (audited)
- `GET /api/auth/audit-log` — paginated log with user/action filters (admin)

All existing write endpoints updated: CVE (false-positive, ticket, acknowledge, draft-email), techstack, TA groups, watchlist, whitelist, source reliability, PIR — all now require Bearer token, all write to audit log.

**Frontend:**
- `Sign In` / `Sign Out` buttons in header; username shown when logged in
- Login modal: username + password fields; JWT stored in `localStorage`
- `User Management` tab (admin only, hidden until admin login): user list, add user form, audit log table with filters and pagination
- `requireTAAuth` bypasses modal entirely when JWT valid — uses logged-in username as analyst name

**Bootstrap:**
```bash
curl -X POST http://your-server/api/auth/init \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YourStr0ng!Pass"}'
```

**Dependencies added:** `python-jose[cryptography]`, `bcrypt>=4.0.0` (passlib dropped — incompatible with bcrypt 4.x).

---

#### CVE Tracker — News Article Correlation

CVE table now shows a "News Mentions" count badge for each true-positive CVE. Clicking the CVE opens the detail modal where the matching article titles and URLs are listed.

Correlation: regex search on article `title` field in MongoDB for the CVE ID (case-insensitive). Single bulk query per page load — one DB round trip for all CVEs in view.

False positive CVEs are excluded from correlation.

**Backend:**
- `app/services/cve_service.py` — `get_article_mentions(cve_ids)`, enriches `get_cves()` response with `news_mentions` and `news_mentions_count`
- `app/models/cve_tracker.py` — `CveOut` gains `news_mentions_count: int`, `news_mentions: list[dict]`

**Frontend:**
- New "News Mentions" column in CVE table — green `📰 N` badge when articles found
- Modal detail section "News Mentions" with clickable article title links

---

#### GitHub POC Monitor — True Positive CVE Lookup (Phase 2)

`githubPOCMonitor.py` now runs a second phase after the existing broad Telegram alert sweep.

Phase 2 loads all true-positive CVEs from `cve_tracker` (excluding `cve_false_positives`), searches GitHub for each CVE ID specifically (`{CVE-ID} in:name,description`), and bulk-updates matched repos to the DB:

- Sets `poc_available: true`
- Appends to `pocs[]` array with `url`, `source` (repo owner), `type` (`exploit` or `poc`)
- Skips forks, whitelisted URLs, already-known POC URLs

Rate limit: 2s sleep per CVE query.

---

#### Audit Log Query Script

`scripts/query_audit_log.py` — standalone CLI to query the audit log API.

```bash
python scripts/query_audit_log.py --user admin --action mark_false_positive
python scripts/query_audit_log.py --export audit.json
```

Supports `--user`, `--action`, `--page`, `--page-size`, `--export` flags. Authenticates via `POST /api/auth/login` and prints a formatted table.

---

## [1.8.0] - 2026-04-29

### New Features

#### Ransomware Activity Panel — Full Rebuild (News Room)

Updated to ransomware.live v2 API (`/v2/victims/{year}/{month}`). Fixed broken field mappings (`group_name←group`, `victim←victim`, `published←attackdate`, `post_url←claim_url`). Added new fields to DB and display: `domain`, `description`, `discovered`, `data_size`, `ransom`, `screenshot`.

Redesigned victim table to fit 340px panel width — grid now `80px 1fr 76px 14px` (Group | Victim+Industry stacked | Published/Discovered stacked | link). Victim column no longer collapses to zero width.

Removed NLP job queue (`push_job`) from `ransomwareLiveThreat.py` — scraper now writes directly to DB, eliminating GPT processing delay per victim.

**Files:**
- `ScraperNewsRevamp/ransomwareLiveThreat.py` — v2 API field mapping, new fields saved, NLP removed
- `ScraperNewsWeb/templates/newsroom.html` — `renderRwVictimRow`, `renderRwVictimHeader` rebuilt

---

#### CVE Tracker — Email Draft Feature

Selected acknowledged CVEs can be emailed as a formatted security notification. Generates AI-enriched HTML email (risk context, remediation, timeline) via GPT-4o, then creates an Outlook draft via Microsoft Graph API or sends via SMTP.

**Gate rules:**
- Checkbox visible only for acknowledged CVEs
- Only CVEs of the same Tech Stack can be selected together (cross-tech blocked with toast)
- False Positive CVEs cannot be selected
- "Mark FP" button disabled until CVE is acknowledged
- Auto-refresh table after acknowledge / mark FP / unmark FP

**Backend:**
- `app/services/cve_email_service.py` *(new)* — LLM enrichment (`llmCveValidator`, `dedupMitigation`, `dedupRiskContext`), Jinja2 template render, Graph API draft + SMTP fallback
- `app/services/cve_ticket_service.py` — `get_ack_statuses()`, fixed ticket ID auto-increment (now saved on acknowledge), `acknowledge_cve` assigns ticket ID at ack time
- `app/routers/cve.py` — `GET /api/cve/ack-statuses`, `POST /api/cve/draft-email`
- `app/config.py` — Azure, OpenAI, SMTP env vars; `EMAIL_METHOD` toggle (`graph`|`smtp`)
- `scripts/cve_notification_email.html` — converted to Jinja2 template

**Frontend (`templates/newsroom.html`):**
- Checkbox column in CVE table with tech-lock and ack-gate logic
- `_cveAckMap`, `_cveSelected`, `_cveSelectedTech` state
- `toggleCveSelect`, `toggleAllCveSelect`, `draftCveEmail` functions
- `GET /api/cve/ack-statuses` fetched on panel load
- Auth modal closes immediately on submit; success/error toast shown after LLM completes

---

### Bug Fixes

- **CVE ticket ID always `001`**: `acknowledge_cve` now fetches next ticket ID and saves `ticket_id` field on first acknowledge. `get_next_ticket_id` queries existing `ticket_id` fields — no more collision.
- **Mark FP greyed after acknowledge**: replaced manual DOM checkbox patch with `loadCvePanel()` call after acknowledge — full row re-render with correct button states.

---

## [1.7.5] - 2026-04-28

### New Features

#### GPT-Verified Only Filter — Exec Dashboard

Adds a second filter toggle to the Executive Dashboard that restricts all data to articles where GPT-4o confirmed a specific named incident occurred.

**`ScraperNewsWeb/templates/newsroom.html`**
- Renamed existing "Confirmed Incidents Only" checkbox label to **"Incident Types Only"** to accurately reflect its function (news_type heuristic exclusion, not GPT classification).
- Added new **"GPT-Verified Only"** toggle (`id="exec-confirmed-only"`) in green accent, off by default. Tooltip explains old articles without the field are excluded.
- Fetch URL now passes `confirmed_only` param alongside `incident_only`.
- Watchlist save/restore (`saveExecWatchlist` / `restoreExecWatchlist`) persists `confirmedOnly` state to `localStorage`.

**`ScraperNewsWeb/app/routers/exec_dashboard.py`**
- `GET /api/exec/dashboard-v2` accepts new `confirmed_only: bool = False` query param.

**`ScraperNewsWeb/app/services/exec_dashboard_v2_service.py`**
- `get_exec_dashboard_v2()` accepts `confirmed_only`. When true, injects `{"confirmed_incident": True}` into both current-period and prev-period `base_filter`. Passes flag down to base `get_exec_dashboard()` call so all totals, sector trends, and TA leaderboard also reflect confirmed-only scope.

**`ScraperNewsWeb/app/services/exec_dashboard_service.py`**
- `get_exec_dashboard()` accepts `confirmed_only`. Same filter injection pattern as V2 service.

**Behavior note**: confirmed-only mode only covers articles ingested after the `articleValidator.py` prompt update (v1.7.0). Old articles with `confirmed_incident: null` are excluded. Data volume will be sparse initially and grow as the scraper processes new articles.

---

## [1.7.0] - 2026-04-28

### New Features

#### Incident Verification Signal — GPT-4o Classification at Ingest

Adds a first-class `confirmed_incident` signal to every scraped article, enabling the dashboard to distinguish verified security incidents from threat reports, vendor advisories, and general news — at zero extra API cost (piggybacks the existing `articleValidator` GPT-4o call).

**`ScraperNewsRevamp/modules/articleValidator.py`**
- Extended the GPT-4o classification prompt with **Section 5 — Incident Confirmation Classification**.
- New fields in JSON response schema:
  - `confirmed_incident` (bool): `true` only when the title indicates a **specific, confirmed** incident — named victim and/or explicitly stated impact (breach, encryption, disruption, financial loss).
  - `incident_confidence` (float 0.0–1.0): confidence in that classification. 0.9–1.0 = named victim + confirmed impact; 0.7–0.9 = one of the two; 0.4–0.7 = ambiguous; 0.0–0.4 = weak/predictive.
  - `incident_indicators` (list): signals found, from `["named_victim", "confirmed_breach", "ransomware_deployment", "data_exfiltration", "service_disruption", "financial_loss", "government_disclosure", "vendor_disclosure", "active_campaign", "zero_day_exploitation"]`. Empty list if `confirmed_incident` is false.
- No additional API call — fields are extracted from the same `gpt-4o` completion already made per article (~50–100 extra output tokens).

**`ScraperNewsRevamp/modules/nlp.py`**
- Extracts three new vars after existing GPT response parsing: `gpt_confirmed_incident`, `gpt_incident_confidence`, `gpt_incident_indicators`.
- All five `article_dict` branches (security_tech early-return + 4 main pipeline branches) now include these fields when writing to MongoDB.
- New articles store `confirmed_incident: true/false`. Old articles retain `confirmed_incident: null` — handled gracefully by the dashboard.

**`ScraperNewsWeb/app/services/exec_dashboard_v2_service.py`**
- **TA Confidence (T3-15)** upgraded: now uses `confirmed_incident` field directly when populated. Falls back to `news_type` proxy for older articles where field is `null`. Logic: if `has_field_count > 0`, use `confirmed_count / total`; else use `(total - non_incident_type) / total`.
- Added `confirmed_rate_pipeline`: computes the overall confirmed incident rate across all articles in the selected time window (articles where `confirmed_incident` is not null).
- Returns `confirmed_incident_rate` (int or null) in the V2 payload.

**`ScraperNewsWeb/templates/newsroom.html`**
- Added **7th KPI card** — "Confirmed Incident Rate" with green accent (`var(--green)`).
- JS renders `${confRate}%` from `d.confirmed_incident_rate`, or `N/A` if field not yet populated (graceful degradation for deployments before scraper update).

---

## [1.6.0] - 2026-04-28

### New Features

#### Executive Intelligence Dashboard V2 — Full Redesign

Complete replacement of the Exec Dashboard with a three-tier intelligence platform. Backend upgraded from `/api/exec/dashboard` to `/api/exec/dashboard-v2`.

**Tier 1 — Decision-Critical**
- **Sector Risk Matrix**: Each sector scored 0–100 using a weighted formula — Volume (0–50 pts): last-month count / max-sector × 50; Trend (0–20 pts): second-half vs first-half avg increase; Spike (0–30 pts): z-score of last month vs prior months. Hover any row or the "Highest Risk Sector" KPI for full formula breakdown.
- **Anomaly / Spike Alerts**: Yellow alert banner above KPIs. Reuses `spike_service.py` z-score engine (threshold 1.5). Shows entity name, z-score, count, date, and HIGH/MED severity badge.
- **New vs Recurring Threat Actors**: Each actor in leaderboard carries a `NEW` (green) or `REC` (grey) badge. Determined by comparing current-period TA set against previous-period TA set from DB.
- **Enhanced CVE Table**: Added CVSS base score (color-coded: red ≥9, orange ≥7, yellow ≥4) and PoC count (⚠ badge) columns. Sourced from `cve_score` and `poc_available` fields in `cve_tracker`.
- **CSV Export**: One-click export of full briefing — sector risk matrix, TA table with NEW/REC status, CVE exposure, spike alerts, KPI summary.

**Tier 2 — Intelligence Depth**
- **Incident Type Trend (stacked bar)**: Monthly stacked bar chart replacing the static donut. Top 6 incident types over the selected time window.
- **Top TTPs (MITRE ATT&CK)**: Bar list of top 15 techniques from `ttps.id/name` array, ranked by frequency.
- **Threat Actor Velocity**: Ramp rate per actor: `(last_month / avg_prev_months − 1) × 100%`. Sorted descending. ▲/▼/★ indicators for rising, falling, and new actors.
- **Victim Geography**: Separate monthly line chart using `victim_countries` field (distinct from general `mentioned_countries`). Gracefully degrades with message if field absent.
- **Sector × Threat Actor Matrix**: Heatmap of top-8-sectors × top-8-actors co-occurrence frequency (red intensity). Complements existing leaderboards with cross-dimension view.
- **Sector Co-Targeting (Supply Chain Signal)**: Python `itertools.combinations` over multi-sector articles → ranked list of sector pairs hit together. Surfaces supply chain cascade patterns.

**Tier 3 — Operational Convenience**
- **Heatmap Cell Drill-Down**: Click any non-zero sector × month cell → modal overlay → fetches `/api/articles?industry=X&posted_on_start=…&posted_on_end=…`. Shows title, date, source, news_type, threat actors per article.
- **Saved Watchlist / Personalized View**: `💾 SAVE VIEW` button persists `days` + `incident_only` settings to `localStorage` (`cti_exec_watchlist_v1`). Auto-restored on tab activate. `✕ CLEAR SAVED` removes saved state.
- **Peer Benchmark**: Each sector risk matrix row shows `+X.X% vs avg` or `−X.X% vs avg` incident share relative to average sector share. Red if >5% above avg.
- **Source Confidence Indicator**: Per-actor badge showing percentage of mentions classified as incident-type articles (vs vendor/unrelated content). Green ≥80%, yellow ≥50%, red <50%.

**Backend — `app/services/exec_dashboard_v2_service.py`** *(new)*
- Single `asyncio.gather` across 9 aggregation pipelines + base V1 call + spike service.
- New helpers: `_compute_sector_risk_scores`, `_compute_ta_velocity`, `_compute_sector_cooccurrence`, `_build_newstype_trend`, `_build_sector_actor_matrix`.

**Backend — `app/routers/exec_dashboard.py`**
- Added `GET /api/exec/dashboard-v2` route.

---

## [1.5.0] - 2026-04-28

### New Features

#### PIR — Word Document Export
- **Export button now downloads `.docx`** instead of `.json`. Backend generates the document server-side and streams it back.
- **`scripts/export_pir_docx.py`** *(new)*: Standalone baseline script. Connects to MongoDB directly (sync pymongo), fetches PIR + articles + notes, builds `.docx` via `python-docx`. Sections: title/metadata, Intelligence Requirement, Collection Criteria (bulleted), Coverage Summary, all articles with source/date/type/URL/tags and analyst notes. Run: `python export_pir_docx.py <pir_id> [output.docx]`. **Expand this file** to add cover pages, logos, charts, custom styles.
- **`app/services/pir_service.py`**: Added `_build_pir_docx(data)` (same structure as standalone script, for web use) and `export_pir_to_docx_bytes(pir_id) -> (bytes, filename)`.
- **`app/routers/pir.py`**: `GET /api/pir/{id}/export/docx` — streams `.docx` as `application/vnd.openxmlformats-officedocument.wordprocessingml.document`. Returns 501 if `python-docx` not installed.
- **Dependency**: `pip install python-docx` required on the server.

---

## [1.4.1] - 2026-04-27

### Bug Fixes

- **PIR analyst notes not appearing saved**: `savePirNote()` closed the modal but never called `_fetchPirArticles()` — articles list did not refresh, so `✓ NOTED` badge never appeared. User could not confirm save happened. Fixed by calling `_fetchPirArticles()` after `closePirNote()` inside the save callback.
- **No visual indicator for noted articles**: Articles with existing analyst notes showed no badge. Fixed by querying `pir_notes` collection in `get_pir_articles()` for current-page article URLs and setting `has_note: bool` on each article. Frontend renders green `✓ NOTED` badge next to "📝 Note" button.
- **Note modal orphaned when closing articles overlay**: `closePirArticles()` only hid the articles overlay, leaving note modal visible with no articles behind it. Fixed by calling `closePirNote()` inside `closePirArticles()`.
- **Articles overlay not closeable via Esc**: `closePirArticles()` missing from Esc key handler. Added. Esc now closes note modal (via `closePirArticles` chain) then the articles overlay.
- **Save Note auth modal invisible**: `.modal-overlay` CSS z-index was `2000`. PIR note modal is `z-index: 9600`. Auth overlay opened behind note modal — user saw nothing, button appeared broken. Fixed by raising `.modal-overlay` z-index to `9800` so auth dialog always renders above all content overlays.
- **Save Note button did nothing — `requireTAAuth` args reversed**: `savePirNote()` called `requireTAAuth(opts, fn)` but signature is `requireTAAuth(fn, opts)`. `fn` received the opts object (not callable) → `TypeError: fn is not a function` → silent failure. Fixed: callback first, `{ subtitle: 'Save analyst note' }` second.

---

## [1.4.0] - 2026-04-27

### New Features

#### Changelog Viewer
- **Clickable version badge** (top-right header): clicking `v1.8.0` opens a release history modal.
- **Version list view**: shows all versions with dates, newest first.
- **Version detail view**: renders full changelog for selected version with markdown formatting (headers, bullets, bold, inline code).
- **`app/routers/changelog.py`** *(new)*: Parses `CHANGELOG.md` at request time. Endpoints: `GET /api/changelog` (index list) and `GET /api/changelog/{version}` (full content). No DB dependency — reads flat file directly.
- **`app/main.py`**: Registered `changelog_router`.
- **`templates/newsroom.html`**: Changelog modal HTML + CSS (`.cl-version-row`, `.cl-content`). JS: `openChangelog()`, `clShowList()`, `clShowDetail(version)`, `_clRenderMd()`, `_clInline()`. Esc key closes modal.

#### PIR — Analyst Notes
- **📝 Note button on each PIR article**: clicking opens analyst note modal (z-index 9600, above articles overlay). Shows article title, existing note + analyst name if previously saved, last-saved timestamp.
- **Note saved per PIR-article pair** (keyed on `pir_id` + `url`). Auth-gated (`requireTAAuth` new-style).
- **`app/config.py`**: Added `PIR_NOTES_COLLECTION = "pir_notes"`.
- **`app/models/pir.py`**: Added `PIRNote(url, note, analyst)` Pydantic model.
- **`app/services/pir_service.py`**: Added `_notes_col()`, `get_pir_note()`, `save_pir_note()`. Notes stored in `news_db.pir_notes`, upserted on `{pir_id, url}`.
- **`app/routers/pir.py`**: `GET /api/pir/{id}/note?url=` (fetch note), `PUT /api/pir/{id}/note` (save, auth).
- **`templates/newsroom.html`**: Note modal HTML (`#pir-note-modal`). JS: `openPirNote(idx)`, `closePirNote()`, `savePirNote()`. `_pirArticleData[]` tracks current-page articles for index-based note lookup. Esc key closes modal.

#### PIR — JSON Export
- **Export button** on each PIR card → downloads `PIR_<title>_<date>.json` via `Blob` + `URL.createObjectURL`.
- **Export payload**: `{ pir, exported_at, total_articles, articles: [...] }`. Each article includes all metadata fields + `analyst_note: { note, analyst, updated_at }` (empty `{}` if no note).
- **`app/services/pir_service.py`**: Added `get_pir_export()` — fetches ALL matching articles (no pagination limit) + all notes for PIR, merges by URL.
- **`app/routers/pir.py`**: `GET /api/pir/{id}/export`.
- **`templates/newsroom.html`**: `exportPir(pirId, title)` function.

#### Navigation — Threat Actor Room moved into Intelligence
- **Threat Actor Room is now a sub-tab under Intelligence** (alongside News Clusters, Source Reliability, Early Warning, MITRE ATT&CK, PIR). Removed as a top-level tab.
- **`templates/newsroom.html`**: Added `Threat Actor Room` button to Intelligence sub-menu (`intel-threatroom-btn`) with group count badge (`#ta-count`). Added `<div id="intel-view-threatroom">` inside `#tab-intelligence` containing the TA sub-menu (Tracked / Whitelist / Watchlist) and all three views. Updated `intelSwitchView()` to include `'threatroom'`, `intelSwitchViewAndLoad()` to call `loadTAGroups()` on `'threatroom'`, and `switchTab()` to remove the old `threatroom` tab handling.
- **Bug fix — TA Room showed no data**: `loadTAGroups()` called `getElementById('ta-count')` and `getElementById('ta-submenu-count')` — both removed with the old top-level tab. Null access threw inside the try-catch → "Failed to load groups". Fixed by adding `#ta-count` span to the Intel sub-menu button and removing the dead `ta-submenu-count` update.

---

## [1.3.0] - 2026-04-27

### Bug Fixes
- **CVE False Positive auth always failing**: `markCveFP` / `unmarkCveFP` passed `{ subtitle: ... }` opts → `requireTAAuth` detected new-style → `_authSubmit` invoked callback with `{ pass, analyst }` object. Callbacks received it as plain `pwd` string, sending `[object Object]` as `X-Auth-Password` header → always 401. Fixed by changing callbacks to destructure `({ pass })` and call `closeAuthModal()` on success (new-style contract).
- **Threat actor filter case-insensitive**: `GET /api/articles?threat_actor=` used MongoDB `$in` (exact match). "Apt36" would not match "APT36" in articles. Fixed: compiles each name as `re.compile(f"^{re.escape(t)}$", re.IGNORECASE)` regex, allowing case-insensitive match across all threat actor filter usages.

### News Room — Search Enhancement
- **Source field added to search**: Article search previously matched only `title`. Now matches `title` OR `source` (both case-insensitive via `$options: "i"` regex). No API change required — same `search` query param.

### Auth Modal — PIR Actions
- **`savePir` migrated from `prompt()` to `requireTAAuth` modal**: Password cached after first use. Added 401 → `_authFailed()` handling.
- **`deletePir` migrated from `confirm()` + `prompt()` to `requireTAAuth` + `showConfirmModal`**: Matches `taDeleteGroup` pattern. Added 401 handling.

### Intelligence — MITRE ATT&CK Drill-Down
- **Click-to-articles on heatmap cells**: Non-zero heatmap cells are now clickable. Clicking opens a modal listing articles that mention the selected TTP AND the selected row (threat actor or industry).
- **New backend endpoint** `GET /api/mitre/articles?ttp_id=&row=&view=&days=&page=&page_size=`: Queries articles matching a specific TTP ID + row value within the time window. Returns paginated list with title, URL, date, source.
- **`app/services/mitre_heatmap_service.py`**: Added `get_ttp_articles()` function.
- **`app/routers/mitre.py`**: Added `mitre_ttp_articles` endpoint.
- **`templates/newsroom.html`**: Added TTP drill-down modal HTML + CSS. Cell click handler stores `ttpId`, `ttpName`, `rowName` in closure. `openTtpDrill()` / `closeTtpDrill()` / `_loadTtpDrillPage()` functions with pagination. Esc key closes modal.

### Threat Actor Room — Watchlist Feature
- **New "Watchlist" sub-tab** added beside Whitelist in Threat Actor Room.
- **⊕ WATCH / ◎ UNWATCH button** on each tracked TA row: toggles watchlist membership. Button state reflects live watchlist (fetched in parallel with TA group load). Auth modal required for both actions.
- **Watchlist management view**: Table of watched TAs with sortable columns, search, pagination. `✕ REMOVE` button (auth modal required) removes from watchlist.
- **New MongoDB collection** `ta_watchlist` (in `threatintel` DB). Stores `name`, `added_date`.
- **New backend endpoints** (`app/routers/ta_groups.py`):
  - `GET /api/ta/watchlist-names` — returns plain name list (used by news panel + row rendering)
  - `GET /api/ta/watchlist` — paginated, sortable, searchable list
  - `POST /api/ta/watchlist` — add TA (auth-gated)
  - `DELETE /api/ta/watchlist/{name}` — remove TA (auth-gated)
- **New service functions** (`app/services/ta_service.py`): `list_ta_watchlist`, `get_watchlist_names`, `add_to_ta_watchlist`, `remove_from_ta_watchlist`.
- **`app/config.py`**: Added `TA_WATCHLIST_COLLECTION = "ta_watchlist"`.

### News Room — TA Watchlist Panel
- **New "TA Watchlist News" panel** below Indonesia News section. Displays all historical articles mentioning any watched threat actor (no date filter applied — searches full article history).
- Fetches watchlist names from `/api/ta/watchlist-names`, then queries `/api/articles?threat_actor=...` for each. Shows empty state with instructions if watchlist is empty.
- Supports text search filter (global search bar) and pagination. Refreshes with `↻` button or global filter apply.
- **`templates/newsroom.html`**: Added panel HTML, `state.watchlist`, `loadWatchlistPanel()`, integrated into `loadAllPanels()`, `refreshPanel()`, `goPage()`.

---

## [1.2.0] - 2026-04-27

### Bug Fixes
- **`acknowledged_by` overwrite on ticket save**: `CveTicket` Pydantic model had `acknowledged_by: str = ""` and `acknowledge_time: str = ""` with empty defaults. `PUT /api/cve/{id}/ticket` called `model_dump()` which included both fields as `""`, causing `$set` to overwrite values written by `acknowledge_cve`. Fixed by removing `acknowledged_by` and `acknowledge_time` from `CveTicket` model entirely — those fields are exclusively owned by the acknowledge endpoint. Also removed `acknowledge_time` from the frontend ticket save payload.
- **Excel export — ISO datetime format**: `published` and `acknowledge_time` stored as ISO8601 (`2026-04-21T16:48:24.722Z`) were written raw to Excel. Added `_fmt_dt()` helper to normalize all datetime fields to `YYYY-MM-DD HH:MM:SS` before writing.
- **Excel export — missing CVE tracker fields**: `cve_lookup` projection only fetched 4 fields (`cve_id`, `cve_severity`, `cve_score`, `detected_on`, `published`). Unticketed CVEs had empty rows for all other columns. Changed to `find({}, {"_id": 0})` (full doc fetch).

### "Security Technology & Best Practices" News Type — Full Pipeline
- **`ScraperNewsRevamp/modules/nlp.py`**: After sending Telegram alert, now builds `article_dict` inline (using `message`, `source_name`, `industries_string`, `gpt_victim/actor_countries` — all available at that point), sets `news_type = "Security Technology & Best Practices"`, and calls `dbMongo.upsert_article()` + `dbMongo.log_scraper_run()` before returning. Articles now persist to DB.
- **`ScraperNewsWeb/app/services/exec_dashboard_service.py`**: Added `"Security Technology & Best Practices"` to `NON_INCIDENT_TYPES` — excluded from Exec Dashboard "Confirmed Incidents Only" view.
- **`ScraperNewsWeb/templates/newsroom.html`**: Global panel `PANEL_CONFIG` now fetches `news_type` array `['global', 'Security Technology & Best Practices']`. Updated `buildParams` to handle both string and array `newsType` (appends each as separate `news_type` query param). Articles appear in Global tab alongside regular global news, distinguished by `news_type` badge.

---

## [1.1.0] - 2026-04-27

### Ransomware Live Victims Integration
- **`ScraperNewsRevamp/ransomwareLiveThreat.py`**: Replaced `offset.txt` file-based dedup with MongoDB-based dedup. Pre-loads existing `offset_key` set via `dbMongo.get_existing_ransomware_keys()`. Saves each new victim to `news_db.ransomware_victims` via `dbMongo.upsert_ransomware_victim()`. Victim doc fields: `group_name`, `victim`, `country`, `country_code`, `industry`, `published`, `post_url`, `offset_key`, `saved_at`.
- **`ScraperNewsRevamp/modules/dbMongo.py`**: Added `upsert_ransomware_victim()` (upserts to `ransomware_victims` on `offset_key` unique index) and `get_existing_ransomware_keys()` (returns set of all stored keys for startup dedup).
- **`ScraperNewsWeb/app/services/ransomware_service.py`** *(new)*: Async service querying `ransomware_victims` collection. `get_victims()` supports filter by group (regex), country (regex), industry (regex), date range. `get_victim_filter_options()` returns distinct group/country/industry lists.
- **`ScraperNewsWeb/app/routers/ransomware.py`** *(new)*: `GET /api/ransomware/victims` (paginated, filterable) and `GET /api/ransomware/victims/filters`.
- **`ScraperNewsWeb/app/main.py`**: Registered `ransomware_router`.
- **`ScraperNewsWeb/templates/newsroom.html`**: Ransomware Activity panel now has two sections — **Live Victims table** (top, from `ransomware.live` via new API, group/country/industry filter inputs, pagination) and **Related Articles** (bottom, existing `news_type=ransomware` article cards). Victims load on panel init and on refresh.

---

## [1.0.0] - 2026-04-26

### Navigation
- Removed **PIR** and **MITRE ATT&CK** as top-level tabs
- Both now live as sub-tabs under **Intelligence** alongside News Clusters, Source Reliability, Early Warning
- PIR auto-loads when switching to its sub-view; MITRE remains on-demand (user clicks LOAD)

### Bug Fixes
- **PIR article overlay — links unclickable**: `onclick="viewPirArticles(..., ${JSON.stringify(title)})"` used double-quoted attribute; `JSON.stringify` injected its own double-quotes, breaking the handler. Fixed by switching to single-quoted attribute.
- **CVE Tracker — Pydantic validation error**: `reference[].tags` stored as `""` (empty string) in MongoDB instead of `[]`. Added `field_validator('tags', mode='before')` on `CveReference` to coerce `""` / `None` → `[]`.
- **Exec Dashboard — CVE exposure counts always zero**: `$eq` comparison used title-case (`"Critical"`) while DB stores uppercase (`"CRITICAL"`). Fixed with `$toUpper` in aggregation expression.

### CVE Tracker
- **False Positive flag**: New `cve_false_positives` MongoDB collection. Endpoints `POST /api/cve/{cve_id}/false-positive` and `DELETE` (auth-gated). FP CVEs excluded from list and stats by default.
- **Show False Positives toggle**: Checkbox in CVE filter bar (unchecked = hidden). FP rows shown at 45% opacity with red `FP` badge and Unmark button.
- **Effective severity escalation**: CVEs with `poc.type = "exploit"` or `"metasploit_module"` display severity bumped one tier (e.g. `MEDIUM → HIGH`) in the Severity column. Base severity preserved in DB. Score colour reflects effective tier.

### Executive Dashboard
- **CVE exposure fix**: Severity comparison now uses `$toUpper`; critical/high/medium counts were always 0, now correct.
- **CVE exposure excludes false positives**: Uses `cve_false_positives` collection as exclusion list.
- **True unique Threat Actor count**: KPI "Threat Actors" now shows distinct TA count via dedicated aggregation pipeline, not `ta_leaderboard.length` (was hardcoded ≤ 10).
- **Period-over-period KPI trends**: Total Incidents, Active Sectors, Threat Actors show `↑/↓ X% vs prev period`. Red = increase (worse), green = decrease (better).
- **TA leaderboard drill-down**: Clicking a threat actor row switches to News Room tab with actor filter pre-set.
- **Incident Type Breakdown chart**: New doughnut chart (Chart.js) rendering `news_type_breakdown` data that was computed but never displayed.
- **Confirmed Incidents Only toggle** (default ON): Excludes `Vendor Report Article` and `Unrelated Tech Stack Article` from all exec aggregations — incident count, sector/country trends, TA leaderboard, heatmap, prev-period. Countries and industries now reflect true attack/breach/zero-day events only. Toggle off to see unfiltered view.
- **Sector heatmap + news type chart**: Restructured bottom section into two-column layout.

### Models
- `CveOut`: added `false_positive: bool = False` field (runtime-injected by service, not stored in CVE doc).
- `CveReference`: added `coerce_tags` validator fixing `tags: ""` → `[]` deserialization error.

### CVE Ticket System
- **Auto-generated Ticket IDs**: Format `CTI-YYYY-MM-NNN` (e.g. `CTI-2026-04-062`). Sequential per month, padded to 3 digits. Generated server-side via `GET /api/cve/next-ticket-id`.
- **Active Exploitation dropdown**: Replaced free-text with 4 options — `Yes`, `No`, `Unknown/Under Investigation`, `Suspected`.
- **Risk Acceptance dropdown**: Replaced free-text with `Accepted`, `Not Accepted`, `Pending Review`.
- **Affected fields pre-filled from CVE DB**: `Affected Asset/Product` ← `cve_tracker.tech`, `Affected Version` ← first affected version string, `Fixed Version` ← `solutions` field.
- **Readonly datetime fields**: Ticket form shows `CVE Reported Date` (= published date), `Detection Time` (= `detected_on`), `Acknowledge Time` (= `acknowledge_time`). All formatted `YYYY-MM-DD HH:MM:SS`.
- **System / MTTD fields removed**: Dropped `system`, `mttd`, `date_acknowledged` from `CveTicket` model, service, DB writes, and frontend form entirely.
- **Acknowledge time UTC+7**: Backend `acknowledge_cve` now uses `datetime.now(timezone(timedelta(hours=7)))`. Frontend cache update no longer stores redundant `date_acknowledged`.

### CVE Auth Modal
- **Modal auth for all CVE actions**: Replaced `prompt()`/`alert()` with reusable modal (`requireTAAuth`). Covers Save Ticket, Acknowledge, Mark as FP, Unmark FP.
- **Auth modal supports analyst name**: `Acknowledge` flow shows analyst name input field inside modal. Other flows (Save, FP) use password-only.
- **Error shown inline**: Wrong password displays error message inside modal instead of closing it.
- **Old-style / new-style callback branching**: `_authNewStyle = Object.keys(opts).length > 0`. Old-style passes plain password string (TA room compatibility). New-style passes `{pass, analyst}` object.

### ScraperNewsRevamp — CVE Scraper (`newCveThreat.py`)
- **MongoDB-based dedup**: Replaced `offset.txt` with pre-loaded `_existing_cves = {cve_id: cve_modified_date}` dict. Skips alert if CVE exists and MITRE `dateUpdated` unchanged. Alerts `NEW` or `UPDATED` accordingly.
- **`detected_on` / `registered_date` fields**: Set on first insert via `$setOnInsert` with `YYYY-MM-DD HH:MM:SS` format. `last_updated` reflects each run; difference between fields shows CVE age.
- **`cve_modified_date` stored**: `cveMetadata.dateUpdated` (fallback `datePublished`) persisted; used as change fingerprint for dedup.

### ScraperNewsRevamp — Scripts
- **`scripts/export_cve_tracker_excel.py`**: Exports `cve_tickets` + `cve_tracker` to Excel using `supportFile/CVE_Tracker_template.xlsx` as base. 23 columns B–X. `CVE Detected Date` ← `detected_on`, `Date Acknowledged by CTI Team` ← `acknowledge_time`, `Time To Detect (Hour)` = `|detected_on − published|` hours, `Time To Acknowledge` = `|acknowledge_time − detected_on|` hours. All datetime fields normalized to `YYYY-MM-DD HH:MM:SS`.
- **`scripts/import_cve_tickets.py`**: Imports Excel back to `cve_tickets` (header row 15, data row 16, cols B–U), upserts on `ticket_id`.
- **`scripts/delete_cve.py`**: Deletes CVE by ID from `cve_tracker`, `cve_false_positives`, and `cve_tickets`. `--keep-ticket` flag to preserve ticket data.
- **`scripts/export_db.py` + `export_db.sh` + `import_db.py`**: Full DB migration scripts for `news_db` and `threatintel` collections. Gzipped NDJSON format.
