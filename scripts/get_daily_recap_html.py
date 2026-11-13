#!/usr/bin/env python3
"""
get_daily_recap_html.py — Fetch saved daily recap and render it as HTML.

Reads the already-generated `daily_recaps` doc (auto-created nightly at
06:00 UTC by app/main.py's _daily_recap_loop) and renders it to a standalone
HTML file. Does NOT generate a new recap and does NOT send anywhere (e.g.
Teams) — that's a separate step.

Usage:
  python scripts/get_daily_recap_html.py                  # yesterday's recap (default target)
  python scripts/get_daily_recap_html.py --date 2026-07-07
  python scripts/get_daily_recap_html.py --out /tmp/recap.html
"""

import argparse
import html
import os
import re
from datetime import datetime, timedelta, timezone

from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = (
    f"mongodb://{os.getenv('MONGO_USER')}:{os.getenv('MONGO_PASS')}"
    f"@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/"
    f"?authSource={os.getenv('DB_NAME')}"
)
DB_NAME = os.getenv("DB_NAME", "news_db")
RECAP_COLLECTION = "daily_recaps"


# ── escaping helpers ────────────────────────────────────────────────────────

def _e(s) -> str:
    return html.escape(str(s)) if s is not None and s != "" else ""


def _safe_url(u) -> str:
    """Escaped href value, or '' if u isn't a plausible http(s) URL."""
    u = str(u or "").strip()
    if not re.match(r"^https?://", u, re.I):
        return ""
    return html.escape(u, quote=True)


def _link(text, url) -> str:
    text_e = _e(text)
    href = _safe_url(url)
    return f'<a href="{href}" target="_blank" rel="noopener">{text_e}</a>' if href else text_e


def _list_or_none(items: str) -> str:
    return items or "<li>(none)</li>"


def _badge(label: str, kind: str = "default") -> str:
    return f'<span class="badge badge-{_e(kind)}">{_e(label)}</span>'


def _default_date() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")


def fetch_recap(date: str, client_id: str = "default") -> dict | None:
    client = MongoClient(MONGO_URI)
    try:
        if client_id == "default":
            query = {"date": date, "$or": [{"client_id": "default"}, {"client_id": {"$exists": False}}]}
        else:
            query = {"date": date, "client_id": client_id}
        return client[DB_NAME][RECAP_COLLECTION].find_one(query)
    finally:
        client.close()


# ── per-section renderers ───────────────────────────────────────────────────

def _render_error_banner(doc: dict) -> str:
    if not (doc.get("parse_error") or not doc.get("headline")):
        return ""
    return (
        '<div class="error-banner">⚠ The LLM response for this recap could not be parsed '
        "(or returned no headline). Sections below may be empty or incomplete.</div>"
    )


def _render_counts(counts: dict, deltas: dict) -> str:
    def _span(label, key):
        val = counts.get(key)
        d = deltas.get(key) if deltas else None
        delta_html = ""
        if d is not None:
            sign = "+" if d >= 0 else ""
            color = "#1a7f37" if d > 0 else ("#cf222e" if d < 0 else "#666")
            delta_html = f' <span style="color:{color}">({sign}{_e(d)})</span>'
        return f"<span>{label}: {_e(val)}{delta_html}</span>"

    fields = [
        ("Articles", "articles"), ("Tweets", "tweets"), ("CVEs", "cves"),
        ("IOCs", "iocs"), ("Campaigns", "campaigns"), ("New TAs", "new_threat_actors"),
        ("Ransomware victims", "ransomware_victims"), ("KEV additions", "kev_additions"),
        ("Domain watch hits", "domain_watch_hits"), ("Package vulns", "package_vulns"),
    ]
    return "\n".join(_span(label, key) for label, key in fields)


def _render_summary(recap: dict) -> str:
    return f"<p>{_e(recap.get('summary'))}</p>"


def _render_top_stories(recap: dict) -> str:
    items = "".join(
        f"<li><b>{_link(s.get('title'), s.get('url'))}</b> ({_e(s.get('source'))}) — {_e(s.get('why_it_matters'))}</li>"
        for s in recap.get("top_stories", [])
    )
    return f"<ul>{_list_or_none(items)}</ul>"


def _render_top_tweets(recap: dict) -> str:
    items = "".join(
        f"<li><b>{_link('@' + str(t.get('author', '')).lstrip('@'), t.get('url'))}</b> "
        f"[{_e(t.get('signal'))}] — {_e(t.get('summary'))}</li>"
        for t in recap.get("top_tweets", [])
    )
    return f"<ul>{_list_or_none(items)}</ul>"


def _render_threat_actors(recap: dict) -> str:
    actors = ", ".join(_e(a) for a in recap.get("active_threat_actors", []))
    return f"<p>{actors or 'none'}</p>"


def _render_notable_cves(recap: dict, cve_details: dict) -> str:
    cve_ids = recap.get("notable_cves", [])
    if not cve_ids:
        return "<p>none</p>"
    parts = []
    for cve_id in cve_ids:
        detail = (cve_details or {}).get(cve_id, {})
        badges = []
        score = detail.get("cve_score")
        if score is not None:
            kind = "critical" if score >= 9 else ("high" if score >= 7 else "default")
            badges.append(_badge(f"CVSS {score}", kind))
        if detail.get("cisa_kev"):
            badges.append(_badge("KEV", "critical"))
        if detail.get("poc_available"):
            badges.append(_badge("PoC", "high"))
        if detail.get("epss_score") is not None:
            badges.append(_badge(f"EPSS {detail['epss_score']}", "default"))
        badge_html = " " + "".join(badges) if badges else ""
        parts.append(f"<span class='cve-chip'>{_e(cve_id)}{badge_html}</span>")
    return "<p>" + " ".join(parts) + "</p>"


def _render_campaigns(recap: dict) -> str:
    items = "".join(
        f"<li><b>{_e(c.get('theme'))}</b> ({_e(c.get('article_count'))} articles) — {_e(c.get('why_it_matters'))}</li>"
        for c in recap.get("active_campaigns", [])
    )
    return f"<ul>{_list_or_none(items)}</ul>"


def _render_apac(recap: dict) -> str:
    items = "".join(f"<li>{_e(a)}</li>" for a in recap.get("apac_signals", []))
    return f"<ul>{_list_or_none(items)}</ul>"


def _render_ransomware(recap: dict) -> str:
    rw = recap.get("ransomware") or {}
    victims = rw.get("victims") or []
    items = "".join(
        f"<li><b>{_e(v.get('group'))}</b> — {_e(v.get('victim'))} "
        f"({_e(v.get('country'))}, {_e(v.get('industry'))})</li>"
        for v in victims
    )
    note = f"<p><i>{_e(rw.get('most_active_note'))}</i></p>" if rw.get("most_active_note") else ""
    return f"<ul>{_list_or_none(items)}</ul>{note}"


def _render_kev_additions(recap: dict) -> str:
    items = "".join(
        f"<li>{_badge(_e(k.get('cve_id')), 'critical')} {_e(k.get('vendor_product'))} "
        f"— remediation due <b>{_e(k.get('due_date'))}</b></li>"
        for k in recap.get("kev_additions", [])
    )
    return f"<ul>{_list_or_none(items)}</ul>"


def _render_ttps(recap: dict) -> str:
    items = "".join(
        f"<li>{_e(t.get('id'))} — {_e(t.get('name'))} (x{_e(t.get('count'))})</li>"
        for t in recap.get("mitre_ttps", [])
    )
    return f"<ul>{_list_or_none(items)}</ul>"


def _render_domain_watch(recap: dict) -> str:
    items = "".join(
        f"<li>{_e(d.get('domain'))}" + (f" — {_e(d.get('note'))}" if d.get("note") else "") + "</li>"
        for d in recap.get("domain_watch", [])
    )
    return f"<ul>{_list_or_none(items)}</ul>"


_SEV_KIND = {"CRITICAL": "critical", "HIGH": "high"}


def _render_package_vulns(recap: dict) -> str:
    items = "".join(
        f"<li>{_e(p.get('advisory_id'))} — {_e(p.get('package'))} ({_e(p.get('ecosystem'))}) "
        f"{_badge(str(p.get('severity') or '?'), _SEV_KIND.get(str(p.get('severity') or '').upper(), 'default'))} "
        f"fixed in: {_e(p.get('fixed_version') or 'none')}</li>"
        for p in recap.get("package_vulns", [])
    )
    return f"<ul>{_list_or_none(items)}</ul>"


def _render_iocs(doc: dict) -> str:
    ioc_detail = doc.get("ioc_detail") or []
    if not ioc_detail:
        return "<p>(none)</p>"
    lines = "\n".join(
        f"[{_e(i.get('type'))}] {_e(i.get('value'))} (confidence: {_e(i.get('confidence_score'))})"
        for i in ioc_detail
    )
    return f"<pre class='mono-block'>{lines}</pre>"


def _render_forecast_summary(forecast: dict) -> str:
    return f"<p>{_e(forecast.get('summary'))}</p>"


def _render_likely_events(forecast: dict) -> str:
    items = "".join(
        f"<li>{_e(ev.get('event'))} — <i>{_e(ev.get('basis'))}</i> (confidence: {_e(ev.get('confidence'))})</li>"
        for ev in forecast.get("likely_events", [])
    )
    return f"<ul>{_list_or_none(items)}</ul>"


def _render_watch_items(forecast: dict) -> str:
    items = "".join(f"<li>{_e(w)}</li>" for w in forecast.get("watch_items", []))
    return f"<ul>{_list_or_none(items)}</ul>"


_VERDICT_KIND = {"hit": "high", "miss": "default", "unclear": "default"}


def _render_forecast_review(doc: dict) -> str:
    review = doc.get("forecast_review") or []
    if not review:
        return "<p>(no prior-day forecast to score)</p>"
    items = "".join(
        f"<li>{_badge(str(r.get('verdict') or '?'), _VERDICT_KIND.get(str(r.get('verdict') or ''), 'default'))} "
        f"{_e(r.get('event'))} — {_e(r.get('justification'))}</li>"
        for r in review
    )
    return f"<ul>{items}</ul>"


def _render_scraper_health(doc: dict) -> str:
    health = doc.get("scraper_health") or {}
    if not health:
        return ""
    rate = health.get("accept_rate")
    degraded = rate is not None and rate < 70
    cls = "health-degraded" if degraded else "health-ok"
    label = "⚠ DEGRADED" if degraded else "OK"
    return (
        f'<p class="{cls}">Scraper health (24h): {label} — '
        f"accept rate {_e(rate)}%, {_e(health.get('total_accepted'))} accepted / "
        f"{_e(health.get('total_rejected'))} rejected</p>"
    )


_SECTIONS = [
    ("Summary", lambda doc, recap, forecast: _render_summary(recap)),
    ("Top Stories", lambda doc, recap, forecast: _render_top_stories(recap)),
    ("Top Tweets", lambda doc, recap, forecast: _render_top_tweets(recap)),
    ("Active Threat Actors", lambda doc, recap, forecast: _render_threat_actors(recap)),
    ("Notable CVEs", lambda doc, recap, forecast: _render_notable_cves(recap, doc.get("cve_details"))),
    ("Active Campaigns", lambda doc, recap, forecast: _render_campaigns(recap)),
    (lambda doc: "APAC Signals" if doc.get("client_id", "default") == "default" else "Regional Signals",
     lambda doc, recap, forecast: _render_apac(recap)),
    ("Ransomware Victims", lambda doc, recap, forecast: _render_ransomware(recap)),
    ("CISA KEV Additions", lambda doc, recap, forecast: _render_kev_additions(recap)),
    ("MITRE TTPs", lambda doc, recap, forecast: _render_ttps(recap)),
    ("Domain Watch — Newly Registered Lookalikes", lambda doc, recap, forecast: _render_domain_watch(recap)),
    ("Package Vulnerabilities", lambda doc, recap, forecast: _render_package_vulns(recap)),
    ("Top IOCs", lambda doc, recap, forecast: _render_iocs(doc)),
    ("Forecast", lambda doc, recap, forecast: _render_forecast_summary(forecast)),
    ("Likely Events", lambda doc, recap, forecast: _render_likely_events(forecast)),
    ("Watch Items", lambda doc, recap, forecast: _render_watch_items(forecast)),
    ("Forecast Review (previous day)", lambda doc, recap, forecast: _render_forecast_review(doc)),
]


_STYLE = """
body { font-family: Segoe UI, Arial, sans-serif; max-width: 800px; margin: 2rem auto; color: #1a1a1a; }
h1 { font-size: 1.4rem; }
h2 { font-size: 1.1rem; margin-top: 1.5rem; border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
.counts span { margin-right: 1rem; color: #555; font-size: .9rem; }
li { margin-bottom: .4rem; }
.error-banner { background: #fff3cd; border: 1px solid #ffdf7e; color: #7a5b00; padding: .75rem 1rem; border-radius: 4px; margin-bottom: 1rem; }
.badge { display: inline-block; font-size: .72rem; font-weight: 600; padding: .05rem .4rem; border-radius: 3px; margin-left: .3rem; color: #fff; background: #6b7280; }
.badge-critical { background: #b91c1c; }
.badge-high { background: #c2410c; }
.badge-default { background: #6b7280; }
.cve-chip { display: inline-block; margin: 0 .6rem .4rem 0; }
.mono-block { background: #f6f8fa; border: 1px solid #ddd; border-radius: 4px; padding: .6rem .8rem; font-size: .85rem; overflow-x: auto; white-space: pre; }
.health-ok { color: #1a7f37; font-size: .9rem; }
.health-degraded { color: #b91c1c; font-weight: 600; font-size: .9rem; }
"""


def render_html(doc: dict) -> str:
    recap = doc.get("yesterday", {}) or {}
    forecast = doc.get("forecast", {}) or {}
    counts = doc.get("counts", {}) or {}
    deltas = doc.get("counts_delta") or {}
    client_id = doc.get("client_id", "default")
    title_suffix = f" — {_e(doc.get('client_name'))}" if client_id != "default" else ""

    sections_html = "\n".join(
        f"<h2>{_e(title(doc) if callable(title) else title)}</h2>\n{fn(doc, recap, forecast)}"
        for title, fn in _SECTIONS
    )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Daily CTI Recap — {_e(doc.get('date'))}{title_suffix}</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>Daily CTI Recap — {_e(doc.get('date'))}{title_suffix}</h1>
{_render_error_banner(doc)}
<p><b>{_e(doc.get('headline'))}</b></p>
{_render_scraper_health(doc)}
<div class="counts">
{_render_counts(counts, deltas)}
</div>

{sections_html}

</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Fetch saved daily recap and render as HTML")
    parser.add_argument("--date", default=None, help="YYYY-MM-DD (default: yesterday, UTC)")
    parser.add_argument("--out", default=None, help="Output HTML path (default: scripts/output/recap_<date>.html)")
    parser.add_argument("--client-id", default="default", help="Client to render (default: org-wide recap)")
    args = parser.parse_args()

    date = args.date or _default_date()
    doc = fetch_recap(date, client_id=args.client_id)
    if not doc:
        raise SystemExit(f"No saved recap found for {date} (client_id={args.client_id}) in '{RECAP_COLLECTION}'.")

    default_name = f"recap_{date}.html" if args.client_id == "default" else f"recap_{date}_{args.client_id}.html"
    out_path = args.out or os.path.join(os.path.dirname(__file__), "output", default_name)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render_html(doc))

    print(f"Saved recap for {date} (client_id={args.client_id}) -> {out_path}")


if __name__ == "__main__":
    main()
