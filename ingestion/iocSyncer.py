#!/usr/bin/env python3
"""IOC sync daemon.

Reads articles from news_db, extracts IOCs, writes to news_db.iocs.
Runs continuously — polls for unsynced articles, sleeps between batches.

Usage:
    python3 iocSyncer.py

Deploy as a systemd service using supportFile/iocSyncer.service.
"""
import gc
import signal
import time
import yaml
import trafilatura
from datetime import datetime, timezone
from pymongo import MongoClient

from modules.iocExtractor import extract_iocs
from modules.dbMongo import get_ioc_allowlist
from modules.iocSchema import enrich_new_ioc, compute_ioc_confidence, compute_ioc_actionability

BATCH_SIZE = 20
SLEEP_BETWEEN_ARTICLES = 2   # seconds — throttles httpx/Playwright pressure
SLEEP_BETWEEN_BATCHES = 3600  # seconds — 1 hour between full batch runs
IOC_COLLECTION = "iocs"
ARTICLES_COLLECTION = "articles"

with open("config/config.yml") as f:
    cfg = yaml.safe_load(f)

_NEWS_DB_URI = (
    f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
    f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}

_TYPE_MAP = {
    "ips": "ip",
    "domains": "domain",
    "urls": "url",
    "urls_with_path": "url_with_path",
    "emails": "email",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "cves": "cve",
}

_running = True


def _handle_signal(sig, frame):
    global _running
    print(f"[IOC sync] Shutting down (signal {sig})...")
    _running = False


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


def _fetch_body_httpx(url: str) -> str | None:
    try:
        import httpx
        r = httpx.get(url, headers=_HEADERS, timeout=15, follow_redirects=True)
        if r.status_code == 200:
            return trafilatura.extract(r.text, include_comments=False, include_tables=False)
    except Exception:
        pass
    return None


def _fetch_body_playwright(url: str) -> str | None:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                page = browser.new_page(user_agent=_HEADERS["User-Agent"])
                page.goto(url, wait_until="domcontentloaded", timeout=20000)
                html = page.content()
            finally:
                browser.close()
        return trafilatura.extract(html, include_comments=False, include_tables=False)
    except Exception:
        return None


def _fetch_body(url: str) -> str | None:
    body = _fetch_body_httpx(url)
    if body:
        return body
    return _fetch_body_playwright(url)


def _upsert_ioc(col, ioc_type: str, value: str, source_url: str, source_name: str, doc_id: str) -> None:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    source_entry = {
        "url": source_url,
        "source_name": source_name,
        "feature_type": "article",
        "doc_id": doc_id,
        "first_seen": today,
        "context": "",
    }
    existing = col.find_one({"type": ioc_type, "value": value})
    if existing:
        url_set = {s.get("url") for s in existing.get("sources", [])}
        if source_url not in url_set:
            now = datetime.now(timezone.utc)
            updated = dict(existing)
            updated["sources"] = existing.get("sources", []) + [source_entry]
            updated["last_seen"] = today
            updated["seen_count"] = existing.get("seen_count", 1) + 1
            score = compute_ioc_confidence(updated, now)
            updated["confidence_score"] = score
            act = compute_ioc_actionability(updated, now)
            col.update_one(
                {"type": ioc_type, "value": value},
                {
                    "$push": {"sources": source_entry},
                    "$inc": {"seen_count": 1},
                    "$set": {
                        "last_seen": today,
                        "confidence_score": score,
                        "confidence_decayed_at": now,
                        **act,
                    },
                },
            )
    else:
        new_doc = {
            "type": ioc_type,
            "value": value,
            "sources": [source_entry],
            "first_seen": today,
            "last_seen": today,
            "seen_count": 1,
        }
        col.insert_one(enrich_new_ioc(new_doc))


def _persist_iocs(ioc_col, ioc_dict: dict, source_url: str, source_name: str, doc_id: str) -> int:
    count = 0
    for field_key, ioc_type in _TYPE_MAP.items():
        for value in ioc_dict.get(field_key, []):
            _upsert_ioc(ioc_col, ioc_type, value, source_url, source_name, doc_id)
            count += 1
    return count


def _run_batch(articles_col, ioc_col, allowlist: dict) -> None:
    # Path A: scraper already extracted iocs into article.iocs — just sync to iocs collection
    path_a = list(articles_col.find(
        {"iocs": {"$exists": True, "$ne": {}}, "iocs_synced": {"$ne": True}},
        {"_id": 1, "url": 1, "source": 1, "iocs": 1},
    ).limit(BATCH_SIZE))

    # Path B: iocs field missing — fetch body, extract, then sync
    path_b = list(articles_col.find(
        {"iocs": {"$exists": False}},
        {"_id": 1, "url": 1, "source": 1},
    ).limit(BATCH_SIZE))

    total = len(path_a) + len(path_b)
    if total:
        print(f"[IOC sync] Path A (sync): {len(path_a)}, Path B (fetch+extract): {len(path_b)}")

    for article in path_a:
        url = article.get("url", "")
        try:
            _persist_iocs(ioc_col, article.get("iocs", {}), url, article.get("source", ""), str(article["_id"]))
            articles_col.update_one({"_id": article["_id"]}, {"$set": {"iocs_synced": True}})
        except Exception as e:
            print(f"[IOC sync] Path A failed {url}: {e}")

    for article in path_b:
        if not _running:
            break
        url = article.get("url", "")
        try:
            body = _fetch_body(url)
            iocs = extract_iocs(body, source_url=url, allowlist=allowlist) if body else {}
            if iocs:
                _persist_iocs(ioc_col, iocs, url, article.get("source", ""), str(article["_id"]))
            articles_col.update_one({"_id": article["_id"]}, {"$set": {"iocs": iocs, "iocs_synced": True}})
        except Exception as e:
            print(f"[IOC sync] Path B failed {url}: {e}")
            articles_col.update_one({"_id": article["_id"]}, {"$set": {"iocs": {}, "iocs_synced": True}})
        time.sleep(SLEEP_BETWEEN_ARTICLES)

    if total:
        print(f"[IOC sync] Done batch of {total}")


def main() -> None:
    client = MongoClient(_NEWS_DB_URI)
    db = client[cfg['news_db']['db']]
    articles_col = db[ARTICLES_COLLECTION]
    ioc_col = db[IOC_COLLECTION]

    print("[IOC sync] Daemon started.")

    try:
        while _running:
            try:
                allowlist = get_ioc_allowlist()
                _run_batch(articles_col, ioc_col, allowlist)
            except Exception as e:
                print(f"[IOC sync] Batch error: {e}")
            finally:
                gc.collect()

            if _running:
                print(f"[IOC sync] Sleeping {SLEEP_BETWEEN_BATCHES // 60} min until next batch...")
                time.sleep(SLEEP_BETWEEN_BATCHES)
    finally:
        client.close()
        print("[IOC sync] Daemon stopped.")


if __name__ == "__main__":
    main()
