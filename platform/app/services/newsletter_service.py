import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bson import ObjectId
from jinja2 import Environment, FileSystemLoader
from app.config import COLLECTION_NAME, TWEETS_COLLECTION, LLM_PROVIDER, LLM_API_KEY, LLM_MODEL
from app.services.llm_client import get_llm_client, store_param
from app.database import get_database

_TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"
_NEWSLETTER_EMAIL_TEMPLATE = "newsletter_email.html"

# ── IOC regex patterns ────────────────────────────────────────────────────────
# Mirror of ScraperNewsRevamp/modules/iocExtractor.py (source-of-truth).
# Do not diverge from iocExtractor.py without syncing both files.

# Any separator (normal dot or defanged variants)
_SEP = r'(?:\.|\.|\[\.\]|\[\.|\.  \]|\(\.\)|\{\.\}|\[dot\]|\(dot\))'

# Defanged-only separator — presence signals intentional IOC defanging
_DEFANG_SEP = r'(?:\[\.\]|\[\.|\.  \]|\(\.\)|\{\.\}|\[dot\]|\(dot\))'

# Label: alphanumeric word optionally with hyphens inside
_LABEL = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?'

# Label that must contain at least one letter (prevents pure-digit labels in URL paths)
_ALPHA_LABEL = r'(?:[a-zA-Z0-9]*[a-zA-Z][a-zA-Z0-9]*)'

_TLD = (
    r'(?:com|net|org|io|gov|edu|mil|int|info|biz|xyz|ru|cn|de|uk|co|top|site|'
    r'online|tech|app|dev|cloud|red|pw|cc|tv|me|mobi|ly|to|sh|gg|is|am|fm|ac|'
    r'in|jp|fr|eu|au|nz|ca|br|pl|nl|se|no|fi|dk|ch|at|be|il|sg|hk|tw|kr|th|'
    r'id|my|ph|vn|ua|tr|sa|ae|za|ng|ke|gh)'
)

_RE_IP = re.compile(
    r'\b(?:\d{1,3})(?:\s*' + _SEP + r'\s*(?:\d{1,3})){3}\b'
)
_RE_VERSION_PREFIX = re.compile(
    r'(?:version|ver|firmware|software|release|patch|build|update|v)\s*[:\s]*'
    r'(\d{1,3}(?:\.\d{1,3}){3})',
    re.IGNORECASE
)
_RE_URL_PROTO = re.compile(
    r'(?:hxxps?|https?|fxp|ftp)://(?:' + _LABEL + r'(?:\s*' + _SEP + r'\s*))+[a-zA-Z]{2,}(?:/[^\s]*)?'
)
# Require at least one label with alpha chars before the TLD, preventing "user.3.6.Something/path"
_RE_URL_PATH = re.compile(
    r'(?:' + _ALPHA_LABEL + r'(?:' + _SEP + r'))'
    + r'(?:' + _LABEL + r'(?:' + _SEP + r'))*'
    + _TLD + r'/[^\s]+'
)
_RE_EMAIL = re.compile(
    r'[a-zA-Z0-9._%+-]+(?:\s*(?:\[@\]|\[at\]|@|\(@\))\s*)' + _LABEL
    + r'(?:\s*' + _SEP + r'\s*)+[a-zA-Z]{2,}'
)
# Bare domain: any labels separated by any seps, but TLD separator MUST be defanged.
# Require defanged sep immediately before TLD → "evil[.]com" yes, "normal.com" no.
_RE_DOMAIN_DEFANGED = re.compile(
    _LABEL
    + r'(?:\s*' + _SEP + r'\s*' + _LABEL + r')*'   # optional subdomains (any sep)
    + r'\s*' + _DEFANG_SEP + r'\s*'                  # last sep before TLD must be defanged
    + r'[a-zA-Z]{2,}'
)
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_CVE    = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

import ipaddress as _ipaddress

_RE_EXTRACT_DOMAIN = re.compile(r'^(?:https?://)?([^/:?\s]+)')

_PRIVATE_NETWORKS = [
    _ipaddress.ip_network("0.0.0.0/8"),
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("100.64.0.0/10"),
    _ipaddress.ip_network("127.0.0.0/8"),
    _ipaddress.ip_network("169.254.0.0/16"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.0.0.0/24"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("198.18.0.0/15"),
    _ipaddress.ip_network("255.255.255.255/32"),
]


def _is_private_ip(raw: str) -> bool:
    clean = _RE_DEFANG_DOT.sub('.', raw)
    try:
        addr = _ipaddress.ip_address(clean)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _url_domain(url: str) -> str:
    m = _RE_EXTRACT_DOMAIN.match(url.lower())
    return m.group(1) if m else ""


def _email_domain(email: str) -> str:
    parts = re.split(r'[@\[\(]at[\)\]]', email.lower())
    if len(parts) == 2:
        return parts[1].strip().lstrip('[').rstrip(']').strip()
    if '@' in email:
        return email.split('@', 1)[1].lower()
    return ""


def _filter_iocs(ioc_dict: dict, source_url: str = "", allowlist: dict | None = None) -> dict:
    domains: set = (allowlist or {}).get("domains", set())
    allowlisted_ips: set = (allowlist or {}).get("ips", set())
    source_domain = _url_domain(source_url) if source_url else ""

    def _ok_ip(v: str) -> bool:
        if _is_private_ip(v):
            return False
        clean = _RE_DEFANG_DOT.sub('.', v)
        return clean not in allowlisted_ips

    def _ok_domain(v: str) -> bool:
        d = v.lower().strip()
        return d not in domains

    def _ok_url(v: str) -> bool:
        d = _url_domain(v)
        if source_domain and (d == source_domain or d.endswith("." + source_domain)):
            return False
        return d not in domains

    def _ok_email(v: str) -> bool:
        return _email_domain(v) not in domains

    filters: dict[str, object] = {
        "ips":            _ok_ip,
        "domains":        _ok_domain,
        "urls":           _ok_url,
        "urls_with_path": _ok_url,
        "emails":         _ok_email,
    }
    result = {}
    for key, values in ioc_dict.items():
        fn = filters.get(key)
        result[key] = [v for v in values if fn is None or fn(v)]
    return {k: v for k, v in result.items() if v}


_RE_DEFANG_DOT = re.compile(r'\s*(?:\[\.\]|\[\.|\.  \]|\(\.\)|\{\.\}|\[dot\]|\(dot\))\s*')
_RE_DEFANG_PROTO = re.compile(r'^hxx(ps?)://', re.IGNORECASE)
_RE_DEFANG_FXP = re.compile(r'^fxp://', re.IGNORECASE)


def _refang(value: str) -> str:
    v = _RE_DEFANG_DOT.sub('.', value)
    v = _RE_DEFANG_PROTO.sub(r'htt\1://', v)
    v = _RE_DEFANG_FXP.sub('ftp://', v)
    return v.strip()


def extract_iocs(text: str, source_url: str = "", allowlist: dict | None = None) -> dict:
    if not text:
        return {}
    version_numbers = {m.group(1) for m in _RE_VERSION_PREFIX.finditer(text)}
    urls = list(dict.fromkeys(_refang(u) for u in _RE_URL_PROTO.findall(text)))
    text_no_urls = _RE_URL_PROTO.sub(" ", text)
    urls_with_path = list(dict.fromkeys(_refang(u) for u in _RE_URL_PATH.findall(text_no_urls)))
    text_no_urls_or_paths = _RE_URL_PATH.sub(" ", text_no_urls)
    raw = {
        "ips":            [ip for ip in dict.fromkeys(_RE_IP.findall(text)) if ip not in version_numbers],
        "urls":           urls,
        "urls_with_path": urls_with_path,
        "domains":        list(dict.fromkeys(_RE_DOMAIN_DEFANGED.findall(text_no_urls_or_paths))),
        "emails":         list(dict.fromkeys(_RE_EMAIL.findall(text))),
        "sha256":         list(dict.fromkeys(_RE_SHA256.findall(text))),
        "sha1":           list(dict.fromkeys(_RE_SHA1.findall(text))),
        "md5":            list(dict.fromkeys(_RE_MD5.findall(text))),
        "cves":           list(dict.fromkeys(m.upper() for m in _RE_CVE.findall(text))),
    }
    return _filter_iocs({k: v for k, v in raw.items() if v}, source_url=source_url, allowlist=allowlist)


# ── CVE correlation helpers ───────────────────────────────────────────────────

async def _get_tp_cve_ids(client_id: str = "default") -> set[str]:
    """Return set of true-positive CVE IDs for this client (cve_tracker minus false positives)."""
    from app.services.cve_service import get_tp_cve_ids
    return set(await get_tp_cve_ids(client_id))


def _find_cve_mentions(title: str, body: str | None, tp_cve_set: set[str]) -> list[str]:
    """Return TP CVE IDs mentioned in article title or body."""
    text = title + " " + (body or "")
    found = {m.upper() for m in _RE_CVE.findall(text)}
    return sorted(found & tp_cve_set)


_PAYWALL_KEYWORDS = [
    "subscribe to read", "sign in to read", "premium content",
    "create an account to continue", "subscribe now to continue",
    "this content is for subscribers", "to continue reading",
    "already a subscriber", "login to read", "register to read",
]
_PAYWALL_MIN_BODY_LEN = 150

try:
    from playwright_stealth import stealth_async as _stealth_async
    _STEALTH_AVAILABLE = True
except ImportError:
    _STEALTH_AVAILABLE = False


# ── Paywall hint persistence ──────────────────────────────────────────────────

def _hints_col():
    return get_database()["newsletter_paywall_hints"]


async def upsert_paywall_hint(source: str) -> None:
    await _hints_col().update_one(
        {"source": source},
        {"$set": {"paywall_likely": True, "last_seen": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )


async def get_all_paywall_hints() -> dict[str, dict]:
    docs = await _hints_col().find({"paywall_likely": True}).to_list(None)
    return {d["source"]: {"paywall_likely": True, "last_seen": d.get("last_seen")} for d in docs}


# ── Article body fetching ─────────────────────────────────────────────────────

def _is_paywall(html: str, body: str | None) -> bool:
    if not body or len(body) < _PAYWALL_MIN_BODY_LEN:
        html_lower = html.lower()
        return any(kw in html_lower for kw in _PAYWALL_KEYWORDS)
    return False


async def fetch_article_body(url: str, source: str) -> tuple[str | None, bool]:
    """Returns (body_text | None, paywall_detected)."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None, False

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1280, "height": 800},
            )
            page = await context.new_page()
            if _STEALTH_AVAILABLE:
                await _stealth_async(page)

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=20000)
                html = await page.content()
            finally:
                await browser.close()

        import trafilatura
        loop = asyncio.get_event_loop()
        body = await loop.run_in_executor(
            None, lambda: trafilatura.extract(html, include_comments=False, include_tables=False)
        )
        paywall = _is_paywall(html, body)

        if paywall:
            await upsert_paywall_hint(source)
            return None, True

        return body, False

    except Exception:
        return None, False


# ── LLM summarization ─────────────────────────────────────────────────────────

def _llm_summarize_with_body(title: str, body: str) -> dict:
    prompt = """You are a Cyber Threat Intelligence analyst writing a weekly newsletter.
Summarize this threat article concisely for a security leadership audience.

Return ONLY valid JSON (no markdown, no code blocks):
{
  "key_points": ["point 1 (max 20 words)", "point 2 (max 20 words)", "point 3 (max 20 words)"],
  "summary": "2-3 sentence paragraph covering what happened, who is affected, and the threat significance. Max 80 words."
}"""

    client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"Title: {title}\n\nArticle body:\n{body[:4000]}"},
        ],
        temperature=0,
        n=1,
        **store_param(LLM_PROVIDER),
    )
    return json.loads(completion.choices[0].message.content)


def _llm_summarize_from_metadata(article: dict) -> dict:
    prompt = """You are a Cyber Threat Intelligence analyst writing a weekly newsletter.
Based on available metadata, generate plausible key points and a summary for this threat news item.
Note: full article text is unavailable (possible paywall).

Return ONLY valid JSON (no markdown, no code blocks):
{
  "key_points": ["point 1 (max 20 words)", "point 2 (max 20 words)", "point 3 (max 20 words)"],
  "summary": "2-3 sentence paragraph covering the likely threat context based on metadata. Max 80 words. Do not mention that the article was paywalled."
}"""

    meta = {
        "title": article.get("title", ""),
        "source": article.get("source", ""),
        "news_type": article.get("news_type", ""),
        "mentioned_countries": article.get("mentioned_countries", []),
        "victim_countries": article.get("victim_countries", []),
        "impacted_industries": article.get("impacted_industries", []),
        "threat_actors": article.get("threat_actors", []),
        "ttps": [t.get("name", "") if isinstance(t, dict) else t for t in article.get("ttps", [])],
    }

    client, model_name = get_llm_client(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(meta)},
        ],
        temperature=0,
        n=1,
        **store_param(LLM_PROVIDER),
    )
    return json.loads(completion.choices[0].message.content)


async def generate_article_summary(article: dict, body: str | None) -> dict:
    loop = asyncio.get_event_loop()
    if body:
        result = await loop.run_in_executor(
            None, _llm_summarize_with_body, article.get("title", ""), body
        )
        result["body_source"] = "fetched"
    else:
        result = await loop.run_in_executor(None, _llm_summarize_from_metadata, article)
        result["body_source"] = "metadata"
    return result


# ── Newsletter assembly ───────────────────────────────────────────────────────

async def _enrich_articles(articles: list[dict], client_id: str = "default") -> list[dict]:
    """Fetch body + generate summary + IOC extraction + CVE correlation per article."""
    from app.services.ioc_allowlist_service import get_allowlist_sets
    tp_cve_set, allowlist = await asyncio.gather(_get_tp_cve_ids(client_id), get_allowlist_sets())

    async def _process(article: dict) -> dict:
        from app.services.cve_service import upsert_newsletter_mention
        if article.get("_is_tweet"):
            body = article.get("_tweet_text") or None  # X blocks headless fetch; tweet text is the body
        else:
            body, _ = await fetch_article_body(article.get("url", ""), article.get("source", ""))
        summary = await generate_article_summary(article, body)
        if body:
            loop = asyncio.get_event_loop()
            article_url = article.get("url", "")
            iocs = await loop.run_in_executor(None, extract_iocs, body, article_url, allowlist)
        else:
            iocs = {}
        cve_hits = _find_cve_mentions(article.get("title", ""), body, tp_cve_set)
        if cve_hits:
            await asyncio.gather(*[upsert_newsletter_mention(cid, article) for cid in cve_hits])
        if iocs:
            from app.services.ioc_service import persist_iocs_from_extraction
            from app.config import COLLECTION_NAME
            try:
                writes = [
                    persist_iocs_from_extraction(
                        ioc_dict=iocs,
                        source_url=article.get("url", ""),
                        source_name=article.get("source", ""),
                        feature_type="newsletter",
                    ),
                ]
                if not article.get("_is_tweet"):
                    writes.append(get_database()[COLLECTION_NAME].update_one(
                        {"url": article.get("url", "")},
                        {"$set": {"iocs": iocs}},
                    ))
                await asyncio.gather(*writes)
            except Exception:
                pass
        return {
            **article,
            **summary,
            "iocs": iocs,
            "cve_mentions": cve_hits,
            "possibly_exploited_wild": bool(cve_hits),
        }

    return list(await asyncio.gather(*[_process(a) for a in articles]))


def _inject_analyst_note(article: dict, notes: dict) -> dict:
    note = notes.get(str(article.get("_id", "")), "").strip()
    if note:
        return {**article, "analyst_note": note}
    return article


async def build_newsletter_context(
    highlight: dict,
    apac: list[dict],
    global_news: list[dict],
    indonesia: list[dict],
    custom_css: str = "",
    custom_intro: str = "",
    custom_footer: str = "",
    notes: dict | None = None,
    include_clusters: bool = False,
    cluster_days: int = 7,
    client_id: str = "default",
    cve_ids: list[str] | None = None,
) -> dict:
    from app.services.cluster_service import get_recent_campaigns
    from app.services.client_service import get_client
    from app.services.cve_service import get_newsletter_cve_summary

    notes = notes or {}
    all_articles = [highlight] + apac + global_news + indonesia

    tasks: list = [_enrich_articles(all_articles, client_id), get_client(client_id), get_newsletter_cve_summary(client_id, cve_ids)]
    if include_clusters:
        tasks.append(get_recent_campaigns(days=cluster_days, min_size=3))

    results = await asyncio.gather(*tasks)
    enriched = results[0]
    client = results[1] or {}
    client_cves = results[2]
    raw_clusters: list[dict] = results[3][:5] if include_clusters else []

    custom_css = custom_css or client.get("newsletter_css", "")
    custom_intro = custom_intro or client.get("newsletter_intro", "")
    custom_footer = custom_footer or client.get("newsletter_footer", "")

    highlight_enriched = _inject_analyst_note(enriched[0], notes)
    apac_count = len(apac)
    global_count = len(global_news)

    n = 1
    apac_enriched = [_inject_analyst_note(a, notes) for a in enriched[n : n + apac_count]]
    n += apac_count
    global_enriched = [_inject_analyst_note(a, notes) for a in enriched[n : n + global_count]]
    n += global_count
    indonesia_enriched = [_inject_analyst_note(a, notes) for a in enriched[n:]]

    now = datetime.now(timezone.utc)
    iso_cal = now.isocalendar()

    campaign_clusters = [
        {
            "name":       c.get("summary_title") or c.get("cluster_id", ""),
            "size":       c.get("size", 0),
            "first_seen": c.get("first_seen", ""),
            "last_seen":  c.get("last_seen", ""),
            "dominant_tas":        c.get("dominant_tas", [])[:5],
            "dominant_industries": c.get("dominant_industries", [])[:3],
            "dominant_countries":  c.get("dominant_countries", [])[:3],
            "attack_techniques":   c.get("attack_techniques", [])[:5],
            "cve_ids":             c.get("cve_ids", [])[:5],
        }
        for c in raw_clusters
    ]

    return {
        "week": iso_cal[1],
        "year": iso_cal[0],
        "generated_at": now.strftime("%Y-%m-%d %H:%M UTC"),
        "highlight": highlight_enriched,
        "apac": apac_enriched,
        "global_news": global_enriched,
        "indonesia": indonesia_enriched,
        "custom_css": custom_css,
        "custom_intro": custom_intro,
        "custom_footer": custom_footer,
        "campaign_clusters": campaign_clusters,
        "client_id": client_id,
        "client_name": client.get("name", ""),
        "client_cves": client_cves,
    }


def render_newsletter_html(context: dict) -> str:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)))
    return env.get_template(_NEWSLETTER_EMAIL_TEMPLATE).render(**context)


# ── Newsletter persistence ────────────────────────────────────────────────────

def _newsletters_col():
    return get_database()["newsletters"]


async def save_newsletter(context: dict, html: str, created_by: str) -> str:
    doc = {
        "week": context["week"],
        "year": context["year"],
        "generated_at": context["generated_at"],
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "client_id": context.get("client_id", "default"),
        "client_name": context.get("client_name", ""),
        "html": html,
        "sections": {
            "highlight": _strip_article(context["highlight"]),
            "apac": [_strip_article(a) for a in context["apac"]],
            "global_news": [_strip_article(a) for a in context["global_news"]],
            "indonesia": [_strip_article(a) for a in context["indonesia"]],
        },
    }
    result = await _newsletters_col().insert_one(doc)
    return str(result.inserted_id)


def _strip_article(a: dict) -> dict:
    """Keep only fields needed to reconstruct history cards."""
    return {
        "_id": a.get("_id", ""),
        "title": a.get("title", ""),
        "url": a.get("url", ""),
        "source": a.get("source", ""),
        "posted_on": a.get("posted_on", ""),
        "news_type": a.get("news_type", ""),
        "key_points": a.get("key_points", []),
        "summary": a.get("summary", ""),
        "body_source": a.get("body_source", ""),
        "iocs": a.get("iocs", {}),
        "cve_mentions": a.get("cve_mentions", []),
        "possibly_exploited_wild": a.get("possibly_exploited_wild", False),
        "is_tweet": a.get("_is_tweet", False),
    }


async def list_newsletters(
    page: int = 1,
    page_size: int = 20,
    client_id: str | None = None,
    client_ids: list[str] | None = None,
) -> tuple[list[dict], int]:
    col = _newsletters_col()
    skip = (page - 1) * page_size
    if client_id:
        query = {"client_id": client_id}
    elif client_ids is not None:
        query = {"client_id": {"$in": client_ids}}
    else:
        query = {}
    cursor = col.find(query, {"html": 0}).sort("created_at", -1).skip(skip).limit(page_size)
    docs, total = await asyncio.gather(cursor.to_list(page_size), col.count_documents(query))
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs, total


async def get_newsletter_html(newsletter_id: str) -> str | None:
    if not ObjectId.is_valid(newsletter_id):
        return None
    doc = await _newsletters_col().find_one({"_id": ObjectId(newsletter_id)}, {"html": 1})
    return doc["html"] if doc else None


async def get_newsletter_doc(newsletter_id: str) -> dict | None:
    if not ObjectId.is_valid(newsletter_id):
        return None
    doc = await _newsletters_col().find_one({"_id": ObjectId(newsletter_id)})
    if doc:
        doc["_id"] = str(doc["_id"])
    return doc


async def delete_newsletter(newsletter_id: str) -> bool:
    if not ObjectId.is_valid(newsletter_id):
        return False
    result = await _newsletters_col().delete_one({"_id": ObjectId(newsletter_id)})
    return result.deleted_count == 1


# ── MongoDB helpers ───────────────────────────────────────────────────────────

async def fetch_articles_by_ids(ids: list[str]) -> dict[str, dict]:
    col = get_database()[COLLECTION_NAME]
    object_ids = [ObjectId(i) for i in ids if ObjectId.is_valid(i)]
    docs = await col.find({"_id": {"$in": object_ids}}).to_list(None)
    result = {}
    for doc in docs:
        doc["_id"] = str(doc["_id"])
        result[doc["_id"]] = doc

    # IDs not in articles may be tweets queued from X Intel
    remaining = [o for o in object_ids if str(o) not in result]
    if remaining:
        tweets = await get_database()[TWEETS_COLLECTION].find({"_id": {"$in": remaining}}).to_list(None)
        for t in tweets:
            result[str(t["_id"])] = _tweet_as_article(t)
    return result


def _tweet_as_article(t: dict) -> dict:
    """Shape a tweet doc like an article so the newsletter pipeline can render it."""
    text = re.sub(r"https://t\.co/\S+", "", t.get("text", "")).strip()
    first_line = text.split("\n", 1)[0].strip()
    return {
        "_id": str(t["_id"]),
        "title": first_line[:120] or "(tweet)",
        "url": t.get("url", ""),
        "source": f"@{t['author_username']}" if t.get("author_username") else "X Intel",
        "posted_on": t.get("posted_on", ""),
        "news_type": "Tweet",
        "mentioned_countries": t.get("victim_countries", []),
        "victim_countries": t.get("victim_countries", []),
        "impacted_industries": t.get("industries_impacted", []),
        "threat_actors": t.get("mentioned_group", []),
        "ttps": [],
        "_is_tweet": True,
        "_tweet_text": text,
    }
