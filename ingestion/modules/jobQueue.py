from pymongo import MongoClient
from datetime import datetime
import re
import yaml

with open("config/config.yml", 'r') as f:
    cfg = yaml.safe_load(f)

_CVE_TITLE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# script_name values whose feed is a raw exploit/PoC or vendor-advisory dump —
# titled per-CVE with no threat-actor narrative, already covered by the
# separate cveQueue/cveValidator pipeline. Narrative feeds (where a CVE
# mention can carry actor/campaign context) are intentionally NOT listed here.
_CVE_DUMP_SOURCES = {
    "NEW ARTICLE FROM EXPLOITDB",
    "NEW ARTICLE FROM ZEROPATH",

}

_CONNECTION_STRING = (
    f"mongodb://{cfg['mongodb']['user']}:{cfg['mongodb']['pass']}"
    f"@{cfg['mongodb']['ip']}/?authSource={cfg['mongodb']['cluster']}"
    f"&authMechanism=SCRAM-SHA-256"
)
_DB_NAME = cfg['mongodb']['collection']

def _get_col():
    client = MongoClient(_CONNECTION_STRING)
    col = client[_DB_NAME]['nlp_jobs']
    col.create_index([("status", 1), ("created_at", 1)], background=True)
    return client, col

def push_job(article_data: dict, script_name: str) -> None:
    """Push a scraping result onto the NLP processing queue."""
    title = str(article_data.get("title", ""))
    if script_name in _CVE_DUMP_SOURCES and _CVE_TITLE_RE.search(title):
        print(f"[jobQueue] skip CVE-dump article from {script_name}: {title}")
        return

    client, col = _get_col()
    try:
        col.insert_one({
            "status": "pending",
            "article": {
                "title": str(article_data.get("title", "")),
                "url": str(article_data.get("url", "")),
                "posted_on": str(article_data.get("posted_on", "")),
            },
            "script_name": script_name,
            "created_at": datetime.utcnow(),
        })
    finally:
        client.close()

def claim_job(col):
    """Atomically claim the next pending job. Returns job doc or None."""
    return col.find_one_and_update(
        {"status": "pending"},
        {"$set": {"status": "processing", "started_at": datetime.utcnow()}},
        sort=[("created_at", 1)],
        return_document=True,
    )
