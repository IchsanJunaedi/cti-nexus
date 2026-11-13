# CTI Nexus Ingestion Engine (OSINT Threat Harvester & NLP Pipeline)

Part of **CTI Nexus** by **Aegis Nexus** (Kartika Cyber Hackathon 2026).

Autonomous CTI ingestion pipeline: 60+ OSINT & Ransomware crawlers collect threat articles and telemetry → push to MongoDB job queue → NLP Worker enriches (spaCy NER, TTP tagging, CVE extraction) and stores in threat database → iocSyncer extracts and correlates IOCs.

## Architecture

```
[scraper_*.py]  →  jobQueue (MongoDB)  →  nlp_worker.py  →  news_db / threatintel
      ↑                                                             ↑
  cron / scheduler                                          iocSyncer.py (daemon)
```

- **Scrapers** (`*Threat.py`, `*Github.py`, etc.) — fetch articles, dedup via `offsetStore`, push raw jobs
- **`nlp_worker.py`** — long-running daemon, polls queue, runs NLP pipeline per article (spaCy NER, TTP tagging, CVE extraction, DB write)
- **`modules/nlp.py`** — the actual enrichment logic called by the worker
- **`iocSyncer.py`** — long-running daemon, polls `news_db.articles` for unsynced IOCs, extracts and writes to `news_db.iocs`. Offloaded from ScraperNewsWeb so the web server is not burdened by heavy Playwright/body-fetch work

## Setup

### 1. Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m spacy download en_core_web_sm
python3 -m playwright install
```

NLTK punkt (required by sumy):
```python
import nltk; nltk.download('punkt_tab')
```

Sumy timeout fix — edit `/usr/local/lib/<python>/dist-packages/sumy/utils.py`, add `timeout=7` to the `fetch_url` call.

### 2. Config

Copy and fill:
```bash
cp config/config.yml.example config/config.yml   # if example exists
# else edit config/config.yml directly
```

Fields: MongoDB credentials under `mongodb`, plus API keys (see `config/config.yml.template`).

### 3. Run NLP worker

```bash
python3 nlp_worker.py
```

Stays alive, polls queue every 2 s, processes one job at a time. Restart-safe — stale `processing` jobs are reset to `pending` on startup.

## Running as a systemd service

### NLP worker

See [`supportFile/nlp_worker.service`](supportFile/nlp_worker.service) — copy to `/etc/systemd/system/`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable nlp_worker
sudo systemctl start nlp_worker
sudo systemctl status nlp_worker
```

Logs: `journalctl -u nlp_worker -f`

### IOC sync daemon

Extracts IOCs from article bodies and writes to `news_db.iocs`. Must run alongside ScraperNewsWeb — web server no longer handles IOC extraction.

Edit `supportFile/iocSyncer.service` — replace `YOUR_USER` and `WorkingDirectory` with actual values, then:

```bash
sudo cp supportFile/iocSyncer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ioc_syncer
sudo systemctl start ioc_syncer
sudo systemctl status ioc_syncer
```

Logs: `journalctl -u ioc_syncer -f`

**How it works:**
- **Path A** — article already has `iocs` field (set by scraper): syncs directly to `news_db.iocs`
- **Path B** — article has no `iocs` field: fetches body via httpx → trafilatura, falls back to Playwright if empty, then extracts and syncs
- Runs one batch of 20 articles per hour, sleeps 2 s between Path B articles to avoid Playwright OOM
- Marks each article `iocs_synced: true` when done — idempotent, safe to restart

## Scraper scheduling

Individual scrapers are short-lived scripts — schedule via cron or a task runner. Example crontab:

```cron
*/15 * * * * cd /opt/ScraperNewsRevamp && /opt/ScraperNewsRevamp/venv/bin/python3 bleepcompThreat.py
*/30 * * * * cd /opt/ScraperNewsRevamp && /opt/ScraperNewsRevamp/venv/bin/python3 hackernewsThreat.py
```

The NLP worker must be running continuously to drain the queue these scrapers produce.

## Scripts

Utility scripts live in `scripts/`:

| Script | Purpose |
|---|---|
| `export_db.py` | Export articles collection to JSON |
| `export_cve_tracker_excel.py` | Export CVE tracker to Excel |
| `dedup_articles.py` | Remove duplicate articles from DB |
| `update_cve_poc.py` | Refresh PoC links on CVE records |

## Template files

Start new scrapers from these:

| Template | Use when |
|---|---|
| `requestsTemplate.py` | Simple HTTP + lxml/XPath |
| `xmlTemplate.py` | RSS / Atom feeds |
| `seleniumTemplate.py` | JS-rendered pages (Selenium) |
| `playwrightTemplate.py` | JS-rendered pages (Playwright) |
| `undetectedChromeTemplate.py` | Bot-detection bypass needed |
| `seleniumTorTemplate.py` | Tor-routed requests |
