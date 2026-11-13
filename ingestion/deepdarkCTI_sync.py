"""Sync fastfire/deepdarkCTI markdown threat data into MongoDB.

Run via cron or manually: python3 deepdarkCTI_sync.py

Parses all .md table files from the repo and syncs:
  - Threat actor names → threatintel.groups
  - Infrastructure URLs → news_db.threat_feeds  (for article URL correlation)
  - CVE IDs from cve_most_exploited.md → news_db.iocs with type=cve
"""

import re
import requests
import yaml
from modules import dbMongo

with open("config/config.yml") as f:
    cfg = yaml.safe_load(f)

RAW_BASE = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main"

_LINK_RE = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
_BARE_URL_RE = re.compile(r'https?://[^\s|]+')
_CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

# filename → {feed_name, tags, actor_col}
# actor_col: column name whose text becomes a groups entry (None = skip groups)
FILE_CONFIG: dict[str, dict] = {
    "ransomware_gang.md":        {"feed": "deepdarkCTI_ransomware", "tags": ["ransomware"],     "actor_col": "Name"},
    "telegram_threat_actors.md": {"feed": "deepdarkCTI_telegram",   "tags": ["telegram"],       "actor_col": "Threat Actor Name"},
    "twitter_threat_actors.md":  {"feed": "deepdarkCTI_twitter",    "tags": ["twitter"],        "actor_col": "Description"},
    "rat.md":                    {"feed": "deepdarkCTI_rat",        "tags": ["rat", "malware"], "actor_col": "Name"},
    "maas.md":                   {"feed": "deepdarkCTI_maas",       "tags": ["maas", "malware"],"actor_col": "Name"},
    "forum.md":                  {"feed": "deepdarkCTI_forum",      "tags": ["forum"],          "actor_col": None},
    "markets.md":                {"feed": "deepdarkCTI_markets",    "tags": ["market"],         "actor_col": None},
    "discord.md":                {"feed": "deepdarkCTI_discord",    "tags": ["discord"],        "actor_col": None},
    "phishing.md":               {"feed": "deepdarkCTI_phishing",   "tags": ["phishing"],       "actor_col": None},
    "exploits.md":               {"feed": "deepdarkCTI_exploits",   "tags": ["exploit"],        "actor_col": None},
    "search_engines.md":         {"feed": "deepdarkCTI_search",     "tags": ["darkweb"],        "actor_col": None},
    "defacement.md":             {"feed": "deepdarkCTI_defacement", "tags": ["defacement"],     "actor_col": None},
    "malware_samples.md":        {"feed": "deepdarkCTI_malware",    "tags": ["malware"],        "actor_col": None},
    "cve_most_exploited.md":     {"feed": "deepdarkCTI_cve",        "tags": ["cve", "exploit"], "actor_col": None},
    "others.md":                 {"feed": "deepdarkCTI_others",     "tags": ["darkweb"],        "actor_col": None},
}


def _fetch_raw(filename: str) -> str:
    r = requests.get(f"{RAW_BASE}/{filename}", timeout=30)
    r.raise_for_status()
    return r.text


def _parse_md_table(text: str) -> list[dict]:
    """Parse markdown pipe table → list of row dicts keyed by header."""
    headers: list[str] = []
    rows: list[dict] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if all(re.fullmatch(r'[-: ]+', c) for c in cells if c):
            continue  # separator row
        if not headers:
            headers = cells
            continue
        if len(cells) < len(headers):
            cells += [""] * (len(headers) - len(cells))
        rows.append(dict(zip(headers, cells[:len(headers)])))
    return rows


def _extract_link(cell: str) -> tuple[str, str | None]:
    """Return (display_text, url) from [text](url), or (bare_url, bare_url), or (text, None)."""
    m = _LINK_RE.search(cell)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    m2 = _BARE_URL_RE.search(cell)
    if m2:
        return m2.group(0), m2.group(0)
    return cell.strip(), None


def _all_urls_from_row(row: dict) -> list[str]:
    """Extract every URL from every cell in a row."""
    seen: set[str] = set()
    urls: list[str] = []
    for val in row.values():
        for m in _LINK_RE.finditer(val):
            u = m.group(2).strip()
            if u not in seen:
                seen.add(u)
                urls.append(u)
        for m in _BARE_URL_RE.finditer(val):
            u = m.group(0)
            if u not in seen:
                seen.add(u)
                urls.append(u)
    return urls


def sync_file(filename: str, conf: dict) -> tuple[int, int]:
    """Sync one .md file. Returns (new_groups, new_feeds)."""
    try:
        text = _fetch_raw(filename)
    except Exception as e:
        print(f"[sync] SKIP {filename}: {e}")
        return 0, 0

    rows = _parse_md_table(text)
    if not rows:
        print(f"[sync] {filename}: no rows parsed")
        return 0, 0

    feed_name = conf["feed"]
    tags = conf["tags"]
    actor_col = conf["actor_col"]
    new_groups = new_feeds = 0

    for row in rows:
        # Threat actor name → groups
        if actor_col and actor_col in row:
            name, _ = _extract_link(row[actor_col])
            if name and len(name) > 1:
                extra = {"tags": tags, "source_file": filename}
                if dbMongo.upsert_ta_group_from_feed(name, extra):
                    new_groups += 1

        # All URLs → threat_feeds
        for url in _all_urls_from_row(row):
            dbMongo.upsert_threat_feed(feed_name, "url", url)
            new_feeds += 1

        # CVE IDs (cve_most_exploited.md) → iocs
        if "CVE" in row:
            cve_id = row["CVE"].strip()
            if _CVE_RE.match(cve_id):
                dbMongo.upsert_ioc_from_feed("cve", cve_id, source_name="deepdarkCTI", tags=tags)

    print(f"[sync] {filename}: {new_groups} new groups, {new_feeds} feed entries")
    return new_groups, new_feeds


if __name__ == "__main__":
    print("=== deepdarkCTI sync ===")
    total_groups = total_feeds = 0
    for fname, conf in FILE_CONFIG.items():
        g, f = sync_file(fname, conf)
        total_groups += g
        total_feeds += f
    print(f"=== done — {total_groups} new groups, {total_feeds} feed entries ===")
