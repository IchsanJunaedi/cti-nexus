# Task: Extend the daily CTI recap pipeline

  Repo: `.`
  Sibling scraper repo (read-only reference for data shapes): `./ScraperNewsRevamp`

  Two files own this feature:
  - `app/services/recap_service.py` — collects data, calls the LLM, persists to the `daily_recaps` Mongo collection.
  - `scripts/get_daily_recap_html.py` — reads a saved recap doc and renders standalone HTML.

  Read both fully before editing. Also read `app/config.py` for collection names, and skim the services referenced below for their function signatures. Do not guess at field names — open the service
  that owns each collection and confirm.

  Work in three phases, in order. Do not start a phase until the previous one is done. Do not touch anything listed under "Out of scope".

  ---

  ## Phase 1 — Fix existing bugs                                                                     
  
  **1a. Inverted reliability sort.** `recap_service.py:94` does `.sort("source_reliability", -1)`. `source_reliability` is an Admiralty letter grade string (`A`–`F`; confirm in
  `app/services/campaign_scoring_service.py:112` and `app/services/source_score_service.py`). Descending lexicographic sort puts `F` first, so the 200-doc cap and the 60-article prompt slice feed the
  LLM the *least* reliable articles. Sort ascending so `A` comes first. Articles with a missing/empty grade must not sort ahead of `A` — handle that explicitly (Mongo sorts missing fields first on
  ascending), e.g. sort in Python after fetch, or use an aggregation with a computed rank.

  **1b. Wrong date field.** `_collect_articles` filters on `posted_on`, which is the article's *publication* date. An article published three days ago but scraped yesterday never appears in
  yesterday's recap, so the recap's "yesterday's activity" claim is wrong. Find the ingest/scrape timestamp field actually written by the scrapers (check `ScraperNewsRevamp` writers and existing
  article docs) and widen the filter to match on either publication date or ingest date within the target day. If no ingest timestamp exists on the documents, stop and report that back rather than
  inventing one.

  **1c. Missing links.** `url` is already in the `_collect_articles` projection but is never passed to the LLM and never rendered. Include the URL in the prompt's article lines, add a `url` field to
  the `top_stories` schema in `SYSTEM_PROMPT`, instruct the model to copy URLs verbatim from the input and never invent one, and render each story title as an `<a href>` in the HTML. Do the same for
  tweets (`url` is already projected in `_collect_tweets`).

  **1d. Silent LLM parse failure.** When `_extract_json` fails it returns `{"_raw": ...}`, so `yesterday` and `forecast` are saved empty and the HTML renders every section as "(none)" with no
  indication anything broke. Persist an explicit `parse_error: true` flag on the doc, and have the renderer emit a visible banner when that flag is set or when `headline` is empty.

  ---

  ## Phase 2 — Add missing data feeds                                                                
  
  For each feed: add an `async def _collect_*` function following the existing style, add it to the `asyncio.gather(...)` in `generate_daily_recap`, add a section to `_build_user_message`, extend
  `SYSTEM_PROMPT`'s JSON schema, add the count to `doc["counts"]`, and render a section in the HTML. Each collector must be individually fault-tolerant — one failing feed must not kill the whole recap
  (mirror the `try/except` in `_collect_campaigns`).

  **2a. Ransomware victims.** Collection `ransomware_victims` (see `app/services/ransomware_service.py:9`), date field `published`. Pull victims published on the target date. Include group name,
  victim, country, industry. Add a `ransomware` block to the schema with the day's new victims and a one-line "which groups were most active" note.
  **2b. CISA KEV additions.** See `app/services/cisa_kev_service.py` and `app/services/cisa_kev_catalog_service.py`, plus `ScraperNewsRevamp/cisaKevIngestion.py` for the ingest shape. Pull CVEs newly
  added to KEV on the target date. Include CVE ID, vendor/product, and the remediation due date. These carry a patch deadline, so surface them as their own section, not as a boolean flag inside the
  existing CVE list.

  **2c. Spikes / anomalies.** Call `app/services/spike_service.get_spikes(...)` — read its signature and pick sane defaults for a daily run. This is z-score-based entity and volume anomaly detection,
  and it is the strongest available grounding for the forecast section. Feed the detected spikes into the prompt and explicitly instruct the model to prefer spike data as the `basis` for
  `likely_events` when a relevant spike exists.

  **2d. Domain watch hits.** `app/services/domain_watch_service.list_results(...)` supports `newly_registered_only=True`. Pull newly registered lookalike domains for the target date (check whether the
  result field is `timestamp` or similar and filter accordingly). Newly registered typosquats are phishing pre-staging, so give them their own section.

  **2e. Package vulnerabilities.** `app/services/pkg_vuln_service.list_vulns(...)` supports `kev_only` and sorts on `adjusted_score`. Pull advisories newly published/modified on the target date
  against tracked packages. Include advisory ID, package, ecosystem, severity, and fixed version.

  **2f. MITRE TTP roll-up.** `ttps` is already in the `_collect_articles` projection (`recap_service.py:91`) and thrown away. Aggregate technique IDs and names across the day's articles in Python,
  take the top ~10 by frequency, and add them to both the prompt and the rendered output. No new query needed.

  **2g. IOC detail.** `_collect_iocs` currently reduces everything to type counts. Keep the counts, and additionally surface the top ~15 IOCs by `confidence_score` (type, value, score) so the output
  is directly usable by a defender. Render them in a monospace block.

  **2h. Scraper health.** Call `app/services/scraper_health_service.get_health_summary(days=...)`. If a batch of scrapers failed, low article counts mean an outage, not a quiet day, and the recap
  currently cannot tell those apart. Add the summary to the prompt with an explicit instruction: if scraper health is degraded, say so in the headline and do not characterize low volume as a calm day.
  Render a health line near the counts.

  ---

  ## Phase 3 — Deltas and forecast accountability                                                    
  
  **3a. Day-over-day deltas.** Before generating, load the previous day's doc from `daily_recaps`. Compute the delta for every field in `counts` and store it as `counts_delta` on the new doc. Render
  each count as `value (+N)` / `(-N)` with color. Handle a missing previous day gracefully (no delta shown, no crash).

  **3b. Forecast scoring.** The pipeline currently never checks whether its forecasts came true. Take the previous day's `forecast.likely_events`, include them in the prompt alongside today's actual
  collected signals, and have the model judge each one as `hit`, `miss`, or `unclear` with a one-line justification. Store the result as `forecast_review` on the new doc and render it as its own
  section. Add a `forecast_review` block to the JSON schema. This must degrade cleanly when no prior forecast exists.

  ---

  ## Renderer refactor (do this as part of Phase 2, before adding sections)

  `render_html` is a single giant f-string and will not survive eight more sections. Refactor it before adding them:

  - Split into one small function per section, each returning an HTML string, composed by a thin top-level function. Alternatively use Jinja2 — the project already ships `app/templates/` and
  `templates/` and has Jinja available — but only if it does not pull in new dependencies.
  - Keep the existing `_e()` escaping discipline. Every value interpolated into HTML must go through it. URLs must be escaped and must be validated as `http`/`https` before being placed in an `href`.
  - Add severity/priority badges rather than rendering everything as flat equal-weight `<li>`: CVSS score, `KEV`, `PoC`, and EPSS on CVEs; severity on package vulns.
  - Sections with no data must render a compact "(none)" line, not a large empty heading block.
  - Preserve the current CLI contract exactly: `--date`, `--out`, and the same default output path.

  ---
  
  ## Out of scope — do not implement

  - Client scoping / `client_id` on recaps, and the techstack↔CVE exposure join.
  - Email/Teams delivery, a `--send` flag, or email-safe inline-style HTML.
  - Email/Teams delivery, a `--send` flag, or email-safe inline-style HTML.
  - PDF/DOCX export, multi-day/weekly modes.
  - PIR mapping, RFI status, false-positive queue, cross-reference corroboration, dark web feeds, EPSS movers, exploit-availability deltas.
  - Any change to scrapers in `ScraperNewsRevamp`.
  - Any change to the nightly loop in `app/main.py` beyond what is strictly required.
  
  ---
  
  ## Constraints
  
  - Python 3.10+ syntax, async Motor (not sync pymongo) inside `recap_service.py`. Note that `scripts/get_daily_recap_html.py` intentionally uses sync pymongo — leave that as-is.
  - Match the surrounding code's style, comment density, and naming. The existing comments explaining Mongo date-format quirks are load-bearing; write comments in that register for any new date-range
  logic.
  - Every new collector needs a `.limit()` cap and its own exception guard.
  - The LLM prompt is already long. Keep new sections terse, cap list lengths, and reuse `_truncate`.
  - Do not add new third-party dependencies.
  - `generate_daily_recap`'s cache/`force` semantics and the shape of the persisted doc's existing keys must keep working. Only add keys; do not rename or remove.
  
  ## Verification
  
  After each phase, run the renderer against a real recent date and confirm the HTML output. Report which dates you tested and paste any errors verbatim. If a collection turns out to be empty or a
  field name does not match what this prompt assumed, say so explicitly rather than silently working around it.
  
  Two things worth knowing before you paste: Phase 2 is ~8 new collectors plus a renderer refactor — if Sonnet start drifting, run phases as separate messages. And 1b may dead-end if articles carry no
  ingest timestamp; prompt tell it to report back instead of inventing one.