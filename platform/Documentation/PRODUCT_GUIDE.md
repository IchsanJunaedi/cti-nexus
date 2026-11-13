# ScraperNewsWeb — Product Guide

CTI (Cyber Threat Intelligence) platform supporting **strategic**, **tactical/operational**, and **technical** intelligence workflows for analysts, SOC, and leadership.

This guide documents every feature: what it does, **who it's for**, **how to actually run it day-to-day**, and where it lives in the codebase.

---

## How to read this guide

Each feature entry has:
- **Intel type** — strategic / tactical-operational / technical / cross-cutting
- **Who it's for** — primary user role
- **What it does** — plain-language description
- **How to use it** — operational steps, cadence, gotchas
- **Key files** — router / service / template, for engineering reference

---

## Daily/Weekly Operating Rhythm (cheat sheet)

Use this as the "what do I open, in what order" checklist. Full detail per item is in the numbered sections below.

| Cadence | Action | Who | Where |
|---|---|---|---|
| **06:00 UTC, daily** | Auto-generated Daily Recap + forecast lands | All analysts | Recap tab (1.3) |
| **Start of shift** | Scan News Room 3-panel feed, triage "Not Related Cyber" for false-drops | All analysts | Newsroom (2.1) |
| **Start of shift** | Check Scraper Health panel for dead/red scrapers before trusting feed completeness | Analysts/Admin | Dashboard (2.3 / 4.7) |
| **Continuous** | P1 PIR matches page via Telegram (~5 min) — action immediately | Analysts | PIR (1.6) |
| **Daily** | Clear CVE Tracker queue: mark FP / acknowledge / ticket true positives | SOC | CVE Tracker (3.1) |
| **Daily** | Review IOC feed for new extractions, tag/allowlist noise | Analysts/SOC | IOC Management (2.11) |
| **Weekly (or on-demand)** | Build & send client newsletter | Editors | Newsletter (1.5) |
| **Weekly, automatic** | ATT&CK KB re-syncs | — | ATT&CK Browser (2.8) |
| **On new campaign** | Check Campaign Clusters for auto-grouped activity, review Diamond Model + Kill Chain tags | Analysts | Clusters (2.4) |
| **On ad-hoc question** | Log it as an RFI, convert to PIR if it'll recur | Analysts | RFI (1.7) |
| **Monthly / on request** | Pull Exec Dashboard v2 + generate AI brief for leadership | Analysts | Exec Dashboard (1.1/1.2) |
| **On new package/dependency** | Import lockfile, triage new vulns, acknowledge | Security eng | Package Vuln (2.18) |
| **Incident mapping** | Build/update a network diagram in IntelGraph, attach scenario playback for briefing | Analysts | IntelGraph (2.20) |

---

## 1. Strategic Intelligence

Leadership-facing, trend-level, decision support.

### 1.1 Executive Dashboard (v1 + v2)
- **Who:** Leadership, senior analysts
- **What it does:** Threat-landscape summary over rolling window (90d default). V2 adds: KPI cards, spike-alert banner, sector risk-matrix (0–100 score), TA velocity leaderboard, sector/country trend charts, incident-type trend, sector×actor heatmap, ransomware group activity treemap (per-group victim counts, current vs. prior window, click-through group detail with trend/rankings and TA watchlist toggle), and role-gated widgets (source-reliability, FP queue, critical CVE feed, IOC hits, Sigma export). Widget visibility adapts per role.
- **How to use it:** Open the Exec tab, pick a lookback window (page-level days selector; ransomware treemap has its own independent 1D/1W/1M/3M/1Y toolbar). Click any treemap tile to open group detail (top country/industry, 12-month trend, recent victims) — use the WATCH button there to push a group straight onto the TA Watchlist without leaving the dashboard.
- **Key files:** `app/routers/exec_dashboard.py`, `app/services/exec_dashboard_service.py`, `app/services/exec_dashboard_v2_service.py`, `app/services/ransomware_service.py` (`get_group_treemap`, `get_group_detail`), `templates/partials/tab_exec.html`

### 1.2 AI-Generated Executive Brief
- **Who:** Leadership
- **What it does:** LLM turns live dashboard v2 metrics into a 5-section narrative brief (markdown) — grounded in real numbers, no fabrication.
- **How to use it:** From the Exec tab, click "Generate Brief." Re-run any time metrics change meaningfully — it's not cached long-term.
- **Key files:** `app/routers/exec_dashboard.py` (`/api/exec/brief`), `app/services/exec_brief_service.py`

### 1.3 Daily Recap & Forecast
- **Who:** All analysts (desk brief)
- **What it does:** Auto-generated daily summary (06:00 UTC) of prior day's News Room + X Intel activity, plus 1–3 day forecast with confidence-tagged predictions, each citing a real input signal. 60-day history browsable; force-regeneration available.
- **How to use it:** Read it first thing each shift as your desk brief. If new data lands late and the recap looks stale, use "Regenerate" rather than waiting for tomorrow's run. Use the 60-day history to spot-check forecast accuracy over time.
- **Key files:** `app/routers/recap.py`, `app/services/recap_service.py`, `templates/partials/tab_recap.html`

### 1.4 Geopolitical Overview
- **Who:** Strategic analysts
- **What it does:** Panel inside Campaign Clusters summarizing geopolitical/attribution context of active campaigns, from TA profile data.
- **How to use it:** Open a cluster in Campaign Clusters (2.4) — the geopolitical panel is embedded, not a separate tab.
- **Key files:** `app/services/geopolitical_service.py`

### 1.5 Newsletter Generation & Distribution
- **Who:** Editors / analysts publishing to stakeholders
- **What it does:** Hand-curated periodic newsletter — highlight article + up to 5 each for APAC/Global/Indonesia sections. **Per-client**: each client tenant has its own recipient list, CSS, intro/footer, and its own CVE correlation pass scoped to that client. **Preview** (save, no send) or **Draft & Send** (email via SMTP/MS Graph). History browsable, resendable. Warns on paywalled/unreliable sources during composition. Manual true-positive CVE section addable. News Room articles taggable as CVE-relevant to feed the pull.
- **How to use it:** Switch active client (header switcher) before composing — content, CVE correlation, and recipients are all client-scoped. Curate sections, preview first, then Draft & Send. If a source is flagged paywalled/unreliable, either swap it or accept the warning consciously. Configure per-client recipients/branding under Client Tenant Management (4.5) before the first send for a new client.
- **Key files:** `app/routers/newsletter.py`, `app/services/newsletter_service.py`, `app/services/client_service.py`, `templates/newsletter.html`

### 1.6 Priority Intelligence Requirements (PIR)
- **Who:** Analysts, intel managers
- **What it does:** Standing intelligence requirements (keyword/actor/industry/country/TTP criteria, P1/P2 priority). New articles auto-matched; P1 fires Telegram alert ~5min, P2 configurable. Per-PIR matched-article view with notes; export as JSON or `.docx`.
- **How to use it:** Create a PIR when a question is going to recur (vs. one-off — use RFI for that, see 1.7). Set criteria as tight as possible to avoid alert fatigue on P1. When a Telegram P1 alert fires, open the PIR's matched-article view, add analyst notes, export `.docx` if it needs to leave the platform.
- **Key files:** `app/routers/pir.py`, `app/services/pir_service.py`, `Documentation/How this application solve compliance.md`

### 1.7 RFI (Request for Intelligence) Tracker
- **Who:** Analysts + intel consumers (SOC, execs, hunt teams)
- **What it does:** Tracks ad-hoc intelligence questions end to end — requester, question, due date, status, response. Can link an RFI to a PIR to convert a one-off question into standing coverage. All writes audit-logged.
- **How to use it:** Log every incoming ad-hoc question here first, even if answered quickly — it's the audit trail. If the same question type shows up 2+ times, link/convert it into a PIR instead of re-answering manually each time.
- **Key files:** `app/routers/rfi.py`, `app/services/rfi_service.py`, `Documentation/How To Use RFI.md`

### 1.8 Source Reliability Database
- **Who:** Analysts (intel quality governance)
- **What it does:** NATO Admiralty Code rating (A–F reliability, 1–6 credibility) per source. Feeds article confidence scoring and cluster-anchoring quality filter. CRUD + aggregate grade-distribution stats.
- **How to use it:** Rate new sources as they're onboarded — unrated sources drag down downstream confidence scoring (2.2) and cluster quality. Review grade-distribution stats periodically to catch drift (e.g. too many unrated/low-grade sources feeding the pipeline).
- **Key files:** `app/routers/source_reliability.py`, `app/services/source_score_service.py`

**Note:** PIR/RFI are governance-level (Direction stage of intel cycle) but drive daily analyst workflow — see them as a tight pair, RFI often converts into a PIR.

---

## 2. Tactical / Operational Intelligence

Day-to-day analyst workflows: monitoring, actors, campaigns, IOCs.

### 2.1 Newsroom / Article Feed
- **Who:** All analysts (primary surface)
- **What it does:** Three-panel feed — APAC News, Global/Local News (client-scoped), Ransomware Activity. "Not Related Cyber" sub-view shows scraper-filtered articles with **Restore** action. Rich filters (industry, country, source, actor, date, keyword). Optional semantic dedup. Top filter bar (search/date/country/industry/actor) applies consistently across all sub-panels including Watchlist, TechStack, and Ransomware Activity/Victims.
- **How to use it:** This is the default landing surface each shift. Use the top filter bar to scope by client/region before triaging. Periodically check "Not Related Cyber" — the scraper filter isn't perfect; **Restore** anything mis-filtered so it doesn't silently disappear from coverage.
- **Key files:** `app/routers/articles.py`, `app/routers/filtered_articles.py`, `app/services/dedup_service.py`, `templates/newsroom.html`

### 2.2 Article Confidence Scoring
- **Who:** Analysts
- **What it does:** 0–100 score per article from source Admiralty grade + TTP count bonus (max 20) + TA count bonus (max 10). Single or bulk recompute. Surfaces in article cards and STIX exports.
- **How to use it:** Trust the score as a triage aid, not ground truth — it's only as good as the underlying source rating (1.8). Bulk-recompute after a source's Admiralty grade changes so historical articles reflect it.
- **Key files:** `app/services/confidence_service.py`

### 2.3 News Intelligence Dashboard
- **Who:** All analysts (default landing tab)
- **What it does:** Aggregate stats (counts by type/source/industry), top countries/actors/TTPs, timeline chart. Embeds Scraper Health panel inline.
- **How to use it:** Check the embedded Scraper Health panel first each shift — if scrapers are red/stale, the counts and trends below it are undercounting and shouldn't be treated as complete.
- **Key files:** `app/routers/articles.py` (`/api/dashboard`), `templates/partials/tab_dashboard.html`

### 2.4 Semantic Article Clustering / Campaign Clusters
- **Who:** Analysts
- **What it does:** TF-IDF + cosine similarity groups related articles into campaigns. Each cluster enriched with Diamond Model assessment, Kill Chain phase mapping, weighted severity score, trend/velocity analysis. Cross-matched against active PIRs.
- **How to use it:** Use this tab (not raw News Room search) when investigating "is this part of a bigger campaign." Check the PIR cross-match badge — if a cluster hits an active PIR, that's your cue to update the PIR's matched-article notes (1.6) rather than treating it as a fresh finding.
- **Key files:** `app/routers/intelligence.py`, `app/services/cluster_service.py`, `app/services/diamond_model_service.py`, `app/services/killchain_service.py`, `app/services/campaign_link_service.py`, `app/services/campaign_scoring_service.py`, `app/services/campaign_trend_service.py`

### 2.5 Spike / Early-Warning Detection
- **Who:** Analysts
- **What it does:** Z-score anomaly detection on article volume by source/topic vs. historical baseline. Feeds Exec Dashboard spike-alert banner.
- **How to use it:** Treat a spike-alert banner hit on the Exec Dashboard as a trigger to go check Campaign Clusters (2.4) for that topic/source — it's an early-warning pointer, not a finished analysis.
- **Key files:** `app/services/spike_service.py`

### 2.6 Risk Matrix
- **Who:** Analysts
- **What it does:** Likelihood×impact-style comparison of current vs. prior period, sector/threat trend visualization.
- **How to use it:** Pull this when leadership asks "is it getting worse" — it's built for period-over-period comparison, not point-in-time snapshots.
- **Key files:** `app/services/risk_matrix_service.py`

### 2.7 MITRE ATT&CK Heatmap & Navigator Export
- **Who:** Analysts
- **What it does:** TTP-frequency heatmap by actor or industry (7–365d lookback), drill-down to source articles, exports Navigator v4.5 JSON layer, shows D3FEND countermeasures per technique.
- **How to use it:** Pick actor or industry scope and a lookback window, drill into a hot cell to see the source articles behind it, and export the Navigator layer when you need to hand a defensible TTP-coverage view to a SOC/detection-engineering team. Check D3FEND suggestions per technique before recommending mitigations from scratch.
- **Key files:** `app/routers/mitre.py`, `app/services/mitre_heatmap_service.py`, `app/services/d3fend_service.py`

### 2.8 ATT&CK Knowledge Base Browser
- **Who:** Analysts
- **What it does:** Local synced copy of full MITRE ATT&CK dataset (Enterprise/Mobile/ICS) — browse techniques/tactics/groups/software/mitigations. Admin-triggered sync (full or per-domain); auto weekly sync.
- **How to use it:** Use as reference lookup while writing TA profiles or heatmap analysis. Admins: trigger a manual sync after MITRE publishes a mid-cycle update rather than waiting for the weekly auto-sync.
- **Key files:** `app/routers/attack.py`, `app/services/attack_sync_service.py`

### 2.9 Threat Actor (TA) Room
- **Who:** Analysts
- **What it does:** Three sub-views — **Tracked** (actors platform auto-tags), **Whitelist** (excluded name collisions), **Watchlist** (priority tracked subset). Aggregate TA stats.
- **How to use it:** If an actor auto-tag is a false positive (name collision with something non-threat-related), add it to Whitelist so it stops re-triggering. Promote actors you're actively following to Watchlist — it's what feeds the Exec Dashboard TA velocity leaderboard and the ransomware-group WATCH shortcut (1.1).
- **Key files:** `app/routers/ta_groups.py`, `app/services/ta_service.py`

### 2.10 Threat Actor Profile Generation
- **Who:** Analysts
- **What it does:** LLM synthesizes structured actor profile (aliases, TTPs, malware, exploited CVEs) auto cross-referenced from related articles. Cached, feeds relevance scoring/STIX/mindmap.
- **How to use it:** Generate/refresh a profile when a TA hits Watchlist or ahead of writing a TA-focused report — it's cached, so regenerate explicitly after a burst of new articles about that actor rather than assuming it's live.
- **Key files:** `app/services/ta_profile_service.py`, `app/services/ta_relevance_service.py`

### 2.11 IOC Management
- **Who:** Analysts, SOC
- **What it does:** Repository of IPs/domains/URLs/hashes/emails/CVEs auto-extracted from newsletters/articles. Filter, search, tag. FP Analytics sub-section; admin-only IOC Allowlist (suppress known-benign). Daily decay sweep ages stale IOCs.
- **How to use it:** Triage new extractions daily. Push known-benign recurring FPs (e.g. CDN IPs, sinkholes) to the Allowlist (admin) instead of re-marking them FP every time — that's what FP Analytics is tracking. Don't worry about manually pruning old IOCs — the daily decay sweep ages them out automatically.
- **Key files:** `app/routers/iocs.py`, `app/services/ioc_service.py`, `app/services/ioc_allowlist_service.py`, `app/services/fp_analytics_service.py`

### 2.12 Cross-Reference Explorer
- **Who:** Analysts
- **What it does:** Given a CVE/PIR/actor, returns connected entities (e.g. "which PIRs & actors relate to this CVE") — pivot without manual search.
- **How to use it:** Use this instead of manually cross-searching News Room/PIR/TA Room whenever you need "everything connected to X" for a report or investigation.
- **Key files:** `app/routers/crossref.py`, `app/services/cross_reference_service.py`

### 2.13 Ransomware Tracking
- **Who:** Analysts
- **What it does:** Ingests ransomware.live victim postings, filterable by group/country/industry/date. Live "Live Victims" table in Newsroom panel; per-group mindmap/report. Group activity also drives the Exec Dashboard treemap (1.1). Manual enrichment: analysts can edit blank/"Not Found" **country**/**industry** fields per victim (feed source often ships them empty) via the "⛶ Expand" full-list modal or the treemap group-detail modal — edit affordance is intentionally not in the compact News Room row.
- **How to use it:** Backfill missing country/industry on victims as you notice them (via Expand modal) — it directly improves the Exec Dashboard treemap's regional/sector breakdowns. Use per-group mindmap when writing up a specific group's activity.
- **Key files:** `app/routers/ransomware.py`, `app/services/ransomware_service.py`

### 2.14 X (Twitter) Intel — Tweets
- **Who:** Analysts
- **What it does:** Tweets from monitored security accounts, filterable/searchable, aggregate stats, live API-quota chip. Feeds Daily Recap "top tweets."
- **How to use it:** Watch the API-quota chip — if it's near limit, new tweets will lag until it resets; don't assume silence means no activity.
- **Key files:** `app/routers/tweets.py`, `app/services/tweet_service.py`

### 2.15 X Intel — Monitored Accounts
- **Who:** Admin
- **What it does:** Manage which X accounts are scraped — add/delete/toggle without losing history.
- **How to use it:** Toggle off (don't delete) an account if you want to pause monitoring but keep its historical tweets browsable.
- **Key files:** `app/routers/monitored_accounts.py`

### 2.16 Mind Map Generation (Wisemap / Mermaid)
- **Who:** Analysts (export utility, reused across 6 features)
- **What it does:** Visual mindmap for newsletter/TA/CVE/PIR/cluster/ransomware-group as `.wxml` download, with cache + force-regenerate. Parallel Mermaid-syntax generator for in-browser rendering.
- **How to use it:** Not a standalone tab — trigger it from within the feature you're documenting (TA profile, CVE detail, cluster, etc.). Force-regenerate if the underlying data changed since the map was cached.
- **Key files:** `app/routers/mindmap.py`, `app/services/wisemap_service.py`, `app/services/mermaid_service.py`

### 2.17 STIX 2.1 Export
- **Who:** Analysts (interoperability)
- **What it does:** Exports article reports, TA profiles, IOC sets, and PIRs as STIX 2.1 JSON bundles for use in other CTI tooling. TLP marking carried through.
- **How to use it:** Use when handing data to an external CTI tool/partner that consumes STIX — check the TLP marking carries the right sensitivity before sharing outward.
- **Key files:** `app/routers/stix.py`, `app/services/stix_service.py`

### 2.18 Package Vulnerability (Dependency) Monitoring
- **Who:** Analysts / security engineering
- **What it does:** Tracks org's open-source packages (npm/PyPI/Go/Maven/etc.), scans against osv.dev, CVSS/EPSS/KEV-adjusted severity. Dependency-tree graph (deps.dev), lockfile import for bulk population, per-vuln acknowledgement. Effectively a lightweight SCA tool bolted onto the CTI platform.
- **How to use it:** Bulk-import via lockfile when onboarding a new project rather than adding packages one by one. Triage by adjusted severity (KEV/EPSS-weighted, same multiplier logic as CVE Tracker — see 3.1), acknowledge what's accepted-risk, and use the dependency-tree graph to check if a vuln is direct or transitive before prioritizing a fix.
- **Key files:** `app/routers/pkg_vuln.py`, `app/services/pkg_vuln_service.py`, `templates/partials/tab_pkgvuln.html`

### 2.19 Sector/Country Filter & Regional Grouping
- **Who:** All analysts (platform-wide utility)
- **What it does:** Country-group definitions powering multi-country filters across Articles/Dashboard/Exec views, and drives "Local News" panel naming logic per client.
- **How to use it:** Configured once per deployment/client, not a daily-use screen — see `FIRST_RUN.md` if a client's regional grouping needs adjusting.
- **Key files:** `app/routers/articles.py`, `Documentation/FIRST_RUN.md`

### 2.20 IntelGraph — Network/Attack Diagram Editor & Scenario Playback
- **Who:** Analysts (incident mapping, briefing prep, red/blue-team storytelling)
- **What it does:** Full-screen, offline-first network/threat diagram editor for mapping infrastructure, actors, and incident/attack flows. Standalone React SPA, served from `/intelgraph` as a real page link (not a JS tab). Infinite pan/zoom canvas, 80+ hand-drawn device/TTP icons (Network, Security & Edge, Infrastructure, Endpoints, People & Places, Threats & TTPs groups). Nodes carry **Disposition** (Friendly/Partner/Neutral/Unknown/Suspicious/Adversary/Victim) and **Status** (Vulnerable/Compromised/Data Breach/etc., multi-select with animated flicker ring). Edges support line style, direction, labels, animated flow indicator. Zones for grouping, full undo/redo, JSON save/open, PNG/SVG export, shareable gzip-compressed URL links, light/dark theme.
  - **Scenario mode**: a `Diagram | Scenario` toggle switches into Builder (ordered step list, note per step, "Capture selection" pulls current canvas multi-select into a step) or Player (Prev/Play/Pause/Next, cumulative-reveal toggle, playback interval) — dim/highlight rendering shows what's revealed vs. new per step, with camera pan/zoom following the story.
  - **Persistence**: diagrams and scenarios persist to MongoDB (multi-tenant, client-scoped), with IndexedDB as an offline cache — edits save locally if the backend is briefly unreachable and auto-sync on reconnect.
- **How to use it:** Build a diagram to map an incident/infrastructure, then switch to Scenario mode to turn it into a step-by-step walkthrough for briefings — Capture Selection as you build each step, then use Player mode live in front of stakeholders instead of a static screenshot. Use gzip-compressed share links to hand a diagram to someone without giving them edit access to your account.
- **Key files:** `intelgraph-src/` (source SPA — rebuild with `npm run build`, redeploy `dist/` → `static/intelgraph/`), `app/routers/diagrams.py`, `app/routers/scenarios.py`, `app/services/diagram_service.py`, `app/services/scenario_service.py`, `app/models/diagram.py`, `app/models/scenario.py`

---

## 3. Technical Intelligence

Vulnerability/exploit-specific, feeds security engineering.

### 3.1 CVE Tracker
- **Who:** SOC, vuln management
- **What it does:** Lists CVEs — filter by tracked tech/severity/date, include/exclude FPs. Stats by severity, exploit availability, CISA KEV membership. Mark FP (single/bulk to 100), acknowledge, export true-positives to Excel. **Adjusted Risk Score** multiplies the base exposure/hosting/EPSS score by a `kev_mult` (1.5x if CISA KEV-listed) and `poc_mult` (1.2x if a public PoC exists), stacked multiplicatively, capped at 10.0 — so a KEV+PoC CVE will visibly outrank a same-severity CVE with neither signal. See `Documentation/CVE Scoring.md` for the full formula and worked examples.
- **How to use it:** Sort/triage by Adjusted Risk Score, not raw CVSS — it already folds in KEV and exploit-availability signal. Clear the queue daily: mark FP, acknowledge accepted-risk, ticket (3.3) anything actionable, export true-positives when a batch needs to leave the platform.
- **Key files:** `app/routers/cve.py`, `app/services/cve_service.py`, `app/services/cve_priority_service.py`, `app/services/cve_export_service.py`, `templates/partials/tab_cvetracker.html`, `Documentation/CVE Scoring.md`

### 3.2 CVE Enrichment — CISA KEV & Exploit-DB
- **Who:** SOC
- **What it does:** Cross-references tracked CVEs against CISA KEV catalog and Exploit-DB (public exploit exists?). Feeds Exec Dashboard critical-CVE feed and severity stats. EPSS exploitation-probability also feeds package-vuln severity.
- **How to use it:** This is the enrichment feeding the badges you see in CVE Tracker (3.1) — no separate screen to operate, it runs automatically against tracked CVEs.
- **Key files:** `app/services/cisa_kev_service.py`, `app/services/exploit_db_service.py`, `app/services/epss_service.py`

### 3.3 CVE Ticketing & Analyst Workflow
- **Who:** SOC
- **What it does:** Attach ticket (status/notes/assignee) per CVE for remediation tracking, sequential ticket-ID reservation.
- **How to use it:** Open a ticket from a CVE Tracker row once it's past FP/acknowledge triage and needs actual remediation tracking. Ticket IDs reserve sequentially — don't hand-assign your own numbering.
- **Key files:** `app/services/cve_ticket_service.py`

### 3.4 CVE Notification Email
- **Who:** SOC
- **What it does:** Drafts stakeholder-notification email for selected CVE(s) tied to an internal ticket ID, sent via SMTP/MS Graph.
- **How to use it:** Select the CVE(s), attach the ticket ID from 3.3, review the draft, send. Use this instead of hand-writing stakeholder emails so ticket linkage stays consistent.
- **Key files:** `app/routers/cve.py` (`/draft-email`), `app/services/cve_email_service.py`

### 3.5 Tech Stack Tracking
- **Who:** SOC
- **What it does:** Maintains org's technology/product list; CVE tracker matches incoming CVE tech tags against it to determine relevance/priority.
- **How to use it:** Keep this current when onboarding new tech into the org — a stale list means CVE Tracker under-flags relevant CVEs against products you actually run.
- **Key files:** `app/routers/techstack.py`, `app/services/techstack_service.py`

### 3.6 CVE Mind Map
- **Who:** SOC
- **What it does:** Per-CVE mindmap (`.wxml`) summarizing affected tech, severity, related TTPs/exploits.
- **How to use it:** Generate from a CVE's detail view when writing up remediation guidance or a stakeholder report.
- **Key files:** `app/routers/cve.py` (`/{cve_id}/mindmap`)

### 3.7 CISA KEV Catalog Browser
- **Who:** SOC, vuln management
- **What it does:** Full browsable CISA Known Exploited Vulnerabilities catalog (independent of what's in your own CVE Tracker) — paginated, searchable, filterable by ransomware-association and by whether it's already matched against your tracked CVEs, sortable by CVE ID/date-added/due-date/vendor/product. Stats view alongside the list.
- **How to use it:** Use this to check the *entire* KEV catalog for entries relevant to your tech stack that haven't yet surfaced in CVE Tracker (i.e. `matched=false`) — that's a coverage gap, not a false negative, since KEV entries only cross-reference CVEs you're already tracking (3.2). Filter `ransomware_only` when scoping ransomware-specific patch priorities.
- **Key files:** `app/routers/cisa_kev.py`, `app/services/cisa_kev_catalog_service.py`, `templates/partials/tab_cisakev.html`

---

## 4. Cross-Cutting (Auth, Admin, Platform)

### 4.1 Authentication (JWT / local accounts)
- **What it does:** Username/password login → JWT + HttpOnly cookie, bcrypt hashing. First-run bootstrap (one-time). Self-service password change. Configurable password policy, admin can force onto all users.
- **How to use it:** First-run bootstrap only happens once per deployment — see `FIRST_RUN.md`. Admins: use "force password policy" sparingly, it invalidates existing passwords platform-wide on next login.
- **Key files:** `app/routers/auth.py`, `app/services/auth_service.py`

### 4.2 OIDC / SSO Login
- **What it does:** Enterprise SSO — redirect to IdP, OAuth2 callback mints platform JWT, SSO logout flow. Disabled unless `OIDC_ENABLED` set. SSO accounts exempt from admin password reset.
- **How to use it:** Set `OIDC_ENABLED` + IdP config in `.env` to turn this on. Don't try to reset an SSO account's password from User Management — it's exempt by design, reset happens at the IdP.
- **Key files:** `app/routers/oidc.py`, `app/services/oidc_service.py`

### 4.3 User Management
- **Who:** Admin/superadmin
- **What it does:** List/create users, assign role, reset password (blocked for SSO accounts).
- **How to use it:** Assign the least-privileged role that covers the user's job (see RBAC, 4.4) rather than defaulting to admin.
- **Key files:** `app/routers/auth.py` (`/users*`)

### 4.4 Roles & Permissions (RBAC)
- **Who:** Superadmin
- **What it does:** Built-in roles — `superadmin` (all 26 perms), `admin` (all except role/client management), `analyst` (view/export/RFI/PIR-scoped). Superadmin can create custom roles from full permissions catalog.
- **How to use it:** Use built-in roles by default. Only build a custom role when a real user needs a permission set that doesn't fit `admin`/`analyst` — check `FIRST_RUN.md` for the full permission catalog before assembling one.
- **Key files:** `app/routers/roles.py`, `app/services/role_service.py`, `Documentation/FIRST_RUN.md`

### 4.5 Client Tenant Management (Multi-tenancy)
- **Who:** Superadmin
- **What it does:** Manage client tenants (ID, name, assigned countries via checkbox picker) — drives "Local News" panel scoping and other client-scoped resources (e.g. packages, newsletters). Assign user→client access same way.
- **How to use it:** Set up a new client's country assignment and newsletter branding (recipients/CSS/intro/footer, see 1.5) here before their first newsletter send or dashboard access. Assign analyst→client access to scope what they see.
- **Key files:** `app/routers/clients.py`, `app/services/client_service.py`

### 4.6 Audit Log
- **Who:** Admin (compliance)
- **What it does:** Every mutating action platform-wide recorded (user, action, target, IP, UTC timestamp). Evidentiary backbone for ISO 27001 / SOC 2 / CIS Control 8 alignment (see `How this application solve compliance.md`).
- **How to use it:** Pull this for compliance audits or to investigate "who changed X" — don't rely on memory/Slack history for that, it's all here with IP + timestamp.
- **Key files:** `app/routers/auth.py` (`/audit-log`), `app/services/audit_service.py`

### 4.7 Scraper Health Monitoring
- **What it does:** Per-scraper (60+) last-run, article counts, accept/reject rate over configurable lookback. Drill-down to recent articles per scraper. Embedded in Dashboard tab.
- **How to use it:** Check this before trusting any coverage-based conclusion (Dashboard stats, Exec Dashboard trends) — a red/stale scraper silently means missing articles, not zero activity. Drill down per-scraper if accept/reject rate looks off to catch a source that started producing garbage.
- **Key files:** `app/routers/scraper_health.py`, `app/services/scraper_health_service.py`

### 4.8 Changelog Viewer
- **What it does:** Parses `CHANGELOG.md` into browsable version list, in-app release notes.
- **How to use it:** Point users here instead of a separate release-notes doc — it's always in sync with `CHANGELOG.md`.
- **Key files:** `app/routers/changelog.py`, `CHANGELOG.md`

### 4.9 API Documentation Tab
- **What it does:** In-app browsable REST endpoint reference, organized by section, mirrors `Documentation/API_DOCUMENTATION.md`.
- **How to use it:** Use for quick endpoint lookup while integrating something externally; `API_DOCUMENTATION.md` is the source of truth if the two ever drift.
- **Key files:** `templates/partials/tab_apidocs.html`

### 4.10 Login Page
- **What it does:** Entry point — local login + optional SSO button.
- **Key files:** `templates/login.html`

---

## Appendix: Shared export utilities

**Mind Map (2.16)** and **STIX Export (2.17)** aren't standalone tabs — they attach to Newsletter, TA, CVE, PIR, Cluster, and Ransomware features as reusable "export" actions. Treat as platform capabilities, not separate menu items, when scoping roadmap work.

**Package Vulnerability Monitoring (2.18)** is effectively a lightweight SCA (software composition analysis) tool bolted onto the CTI platform — easy to under-scope from tab name alone.

**IntelGraph (2.20)** is a separate React SPA served at `/intelgraph`, not a JS tab inside the main Newsroom app — engineering changes require a rebuild (`npm run build` in `intelgraph-src/`) and manual redeploy of `dist/` into `static/intelgraph/`; it does not happen automatically on backend deploy.
