# FIRST_RUN — IOC Pipeline Deploy

How to bring the IOC pipeline up in production. Covers the full-schema IOC writers,
enrichment, liveness, and the rate-limit behavior of the API-using scripts.

All scripts write to `news_db.iocs` (shared with the CTI Nexus platform). Writes are
**additive** — `insert_one` / `$addToSet` / `$set`, no deletes.

---

## 1. Components

| Component | Subsystem | Type | Cadence | Writes |
|---|---|---|---|---|
| `iocSyncer.py` | `ingestion/` | **daemon** | continuous (1h batch) | article IOCs, full schema |
| `otxIngestion.py` | `ingestion/` | cron | every 6h | OTX IOCs + `pulse_ids` |
| `otxEnrichment.py` | `ingestion/` | cron | every 6h (+15m) | `enrichment.providers[]` verdict/score |
| `iocLiveness.py` | `ingestion/` | cron | every 12h | `liveness` field |
| `decay_sweep` | `platform/` | web-app background loop | auto | recomputes old docs |

**`decay_sweep` is NOT a cron job.** It already runs inside the web app
(`app/main.py`). Old thin IOCs (pre-schema-change) auto-upgrade — confidence and
actionability recompute on the sweep. Nothing to schedule.

---

## 2. Pre-flight checklist

- [ ] `config/config.yml` → `news_db` points at **PROD** Mongo.
- [ ] `config/config.yml` → `otx.api_key` set.
- [ ] `config/config.yml` → `abuseipdb.api_key` set (optional; IP enrichment skipped if blank).
- [ ] Web app `.env` → `IOC_FEED_TOKEN=<long-random-string>` set (for the pull feed).
- [ ] Mongo index on `news_db.iocs` `{type:1, value:1}` exists (web app creates on startup).

---

## 3. First run — manual, in order

Run each once by hand, verify exit 0, eyeball one written doc, THEN enable cron/daemon.

```bash
cd /opt/ScraperNewsRevamp

python3 otxIngestion.py      # 1. new OTX IOCs (full schema + pulse_ids)
python3 iocSyncer.py         # 2. Ctrl-C after first batch — confirms article IOC writes
python3 otxEnrichment.py     # 3. adds enrichment.providers[] (run AFTER ingestion)
python3 iocLiveness.py       # 4. liveness probe
```

Verify a new IOC has the full schema (mongo shell):

```js
use news_db
db.iocs.findOne({confidence_score: {$exists: false}})   // expect null — none missing
db.iocs.countDocuments({actionability_label: {$exists: false}})  // expect 0
db.iocs.findOne({"enrichment.providers.0": {$exists: true}})     // enrichment present
db.iocs.findOne({liveness: {$exists: true}})                     // liveness ran
db.iocs.findOne({"pulse_ids.0": {$exists: true}})                // OTX pulse linkage
```

---

## 4. Enable for steady state

**Daemon (iocSyncer — loops forever, do NOT cron it):**
```bash
sudo cp supportFile/iocSyncer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now iocSyncer
sudo systemctl status iocSyncer        # confirm active (running)
journalctl -u iocSyncer -f             # watch logs
```

**Cron (3 jobs — staggered so enrichment runs after ingestion lands IOCs):**
```cron
0  */6  * * *  cd /opt/ScraperNewsRevamp && python3 otxIngestion.py   >> log/otxIngest.log 2>&1
15 */6  * * *  cd /opt/ScraperNewsRevamp && python3 otxEnrichment.py  >> log/otxEnrich.log 2>&1
0  */12 * * *  cd /opt/ScraperNewsRevamp && python3 iocLiveness.py    >> log/iocLive.log 2>&1
```

---

## 5. Rate-limit / graceful-exit behavior

All API-calling scripts handle HTTP **429** without crashing:

| Script | API | On 429 |
|--------|-----|--------|
| `otxIngestion.py` | OTX | Raises `_RateLimited`, exits 0. **`otx_last_run.txt` is NOT advanced** → next cron resumes the same window. No pulses lost. |
| `otxEnrichment.py` | OTX, AbuseIPDB | Stops the batch (`break`), exits 0. Unenriched docs keep `enrichment:$exists:false` → next cron retries them. Already-enriched docs in the batch are kept. |
| `iocLiveness.py` | none (DNS/TCP/HTTP probes) | No API quota. Per-host timeouts only. |

What to expect in logs on a rate limit:
```
[OTX] OTX rate limit 429 (Retry-After=60s) — stopping gracefully, progress preserved for next run.
[Enrichment] OTX rate limit 429 (Retry-After=?s) — stopping batch gracefully, 14 done. Resume next cron.
```

Both exit code **0** (clean) — cron will not alert, work resumes automatically next cycle.
Lower `BATCH_SIZE` in the script if you hit limits every run.

---

## 6. Schema notes

- **New IOCs** → full schema at insert via `modules/iocSchema.enrich_new_ioc`
  (confidence_score, actionability_label/score, recommended_action, auto_suppressed,
  tp_count, fp_count, feedback_log, tags, threat_actors).
- **Existing IOCs re-touched** (new sighting) → confidence + actionability recomputed.
- **Existing untouched thin IOCs** → upgraded by the web app `decay_sweep` loop.
- **Enrichment** (`enrichment.providers[]`) is added only by `otxEnrichment.py`, never by
  the ingest/sync writers.
- `auto_suppress_check` may set `auto_suppressed=true` on benign IOCs (CDN/private-IP/
  email-provider) at insert. Flag only, reversible — review after first run.

---

## 7. Smoke test (web side)

```bash
cd /opt/ScraperNewsWeb
<py3.11> -c "import app.main" && echo OK   # import smoke
<py3.11> test_ioc_logic.py                 # pure-function unit checks (no DB)
IOC_USER=u IOC_PASS=p FEED_TOKEN=$IOC_FEED_TOKEN <py3.11> test_ioc_api.py   # e2e API
```
