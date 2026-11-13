import asyncio
import json
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Cookie
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from app.database import connect, disconnect
from app.ta_database import ta_connect, ta_disconnect
from app.routers.articles import router as articles_router
from app.routers.ta_groups import router as ta_router
from app.routers.cve import router as cve_router
from app.routers.techstack import router as techstack_router
from app.routers.intelligence import router as intelligence_router
from app.routers.source_reliability import router as sr_router
from app.routers.mitre import router as mitre_router
from app.routers.exec_dashboard import router as exec_router
from app.routers.pir import router as pir_router
from app.routers.scraper_health import router as health_router
from app.routers.ransomware import router as ransomware_router
from app.routers.changelog import router as changelog_router
from app.routers.auth import router as auth_router
from app.routers.oidc import router as oidc_router
from app.routers.newsletter import router as newsletter_router
from app.routers.mindmap import router as mindmap_router
from app.routers.filtered_articles import router as filtered_articles_router
from app.routers.iocs import router as iocs_router
from app.routers.crossref import router as crossref_router
from app.routers.stix import router as stix_router
from app.routers.rfi import router as rfi_router
from app.routers.attack import router as attack_router
from app.routers.notifications import router as notifications_router
from app.routers.tweets import router as tweets_router
from app.routers.monitored_accounts import router as monitored_accounts_router
from app.routers.clients import router as clients_router
from app.routers.roles import router as roles_router
from app.routers.recap import router as recap_router
from app.routers.pkg_vuln import router as pkg_vuln_router
from app.routers.domain_watch import router as domain_watch_router
from app.routers.brand_watch import router as brand_watch_router
from app.routers.cisa_kev import router as cisa_kev_router
from app.routers.scenarios import router as scenarios_router
from app.routers.diagrams import router as diagrams_router
from app.config import (
    APP_VERSION, TELEGRAM_BOT_TOKEN, TELEGRAM_PIR_CHAT_ID,
    TELEGRAM_PIR_THREAD_ID, PIR_ALERT_INTERVAL_MIN,
    SESSION_SECRET_KEY, OIDC_ENABLED, JWT_SECRET, CORS_ORIGINS,
)
import os
_PIR_P1_INTERVAL_MIN = int(os.getenv("PIR_P1_INTERVAL_MIN", "5"))
_RECAP_HOUR_UTC = int(os.getenv("RECAP_HOUR_UTC", "23"))  # default 06:00 UTC+7
from app.services.auth_service import decode_token

_pir_check_since: datetime = datetime.utcnow()


async def _send_telegram(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_PIR_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_PIR_CHAT_ID, "text": text, "parse_mode": "HTML"}
    if TELEGRAM_PIR_THREAD_ID:
        payload["message_thread_id"] = TELEGRAM_PIR_THREAD_ID

    def _post():
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)

    try:
        await asyncio.to_thread(_post)
    except Exception as e:
        print(f"[PIR alert] Telegram send failed: {e}")


def _format_pir_alert(pir: dict, articles: list[dict]) -> str:
    priority = pir.get("priority", "P2")
    icon = "🚨" if priority == "P1" else "🔔"
    urgency = " ⚡ CRITICAL — Immediate action required" if priority == "P1" else ""
    msg = f"{icon} <b>PIR MATCH — {priority}{urgency}</b>\n<b>{pir.get('title', '')}</b>"
    if pir.get("owner"):
        msg += f"  |  {pir['owner']}"
    msg += "\n\n"
    for a in articles:
        msg += (
            f"• <a href=\"{a.get('url', '#')}\">{a.get('title', 'Untitled')}</a>\n"
            f"  {a.get('source', '')} · {a.get('posted_on', '')} · {a.get('news_type', '')}\n\n"
        )
    return msg.strip()


async def _pir_alert_loop() -> None:
    global _pir_check_since
    from app.services.pir_service import check_new_articles_vs_pirs
    await asyncio.sleep(120)  # let DB connections settle

    p1_tick = 0.0
    all_tick = 0.0
    poll_sec = 60.0  # base poll: 1 min, evaluate thresholds inside

    while True:
        await asyncio.sleep(poll_sec)
        now = datetime.utcnow().timestamp()

        run_p1  = (now - p1_tick)  >= (_PIR_P1_INTERVAL_MIN * 60)
        run_all = (now - all_tick) >= (PIR_ALERT_INTERVAL_MIN * 60)

        if not run_p1 and not run_all:
            continue

        try:
            since = _pir_check_since
            _pir_check_since = datetime.utcnow()
            matches = await check_new_articles_vs_pirs(since)

            for m in matches:
                pir = m["pir"]
                priority = pir.get("priority", "P2")
                is_p1 = priority == "P1"

                # P1 fires on any tick; P2+ only when all-PIR interval has elapsed
                if not is_p1 and not run_all:
                    continue

                msg = _format_pir_alert(pir, m["articles"])
                await _send_telegram(msg)
                print(f"[PIR alert] Sent {priority} for: {pir.get('title')}")

            if run_p1:
                p1_tick = now
            if run_all:
                all_tick = now

        except Exception as e:
            print(f"[PIR alert] Loop error: {e}")


def _seconds_until_next_3h() -> float:
    now = datetime.now(timezone.utc)
    blocks_elapsed = now.hour // 3
    next_hour = (blocks_elapsed + 1) * 3
    if next_hour >= 24:
        target = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        target = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
    return max((target - now).total_seconds(), 1)


_ATTACK_SYNC_INTERVAL_DAYS = int(os.getenv("ATTACK_SYNC_INTERVAL_DAYS", "7"))


async def _attack_sync_loop() -> None:
    from app.services.attack_sync_service import sync_all_domains, get_sync_status, upstream_is_newer
    await asyncio.sleep(180)  # let DB settle

    while True:
        try:
            status = await get_sync_status()
            never_synced = any(s.get("status") == "never" for s in status)
            oldest_sync = None
            for s in status:
                ls = s.get("last_sync")
                if ls:
                    dt = datetime.fromisoformat(ls)
                    if oldest_sync is None or dt < oldest_sync:
                        oldest_sync = dt

            needs_sync = never_synced or (
                oldest_sync is not None and
                (datetime.now(timezone.utc) - oldest_sync).days >= _ATTACK_SYNC_INTERVAL_DAYS
            )

            if not needs_sync and await upstream_is_newer():
                print("[ATT&CK sync] New upstream release detected")
                needs_sync = True

            if needs_sync:
                print(f"[ATT&CK sync] Starting scheduled sync — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
                results = await sync_all_domains()
                for r in results:
                    label = r.get("label", r.get("domain_key", "?"))
                    ver = r.get("version", "?")
                    status_str = r.get("status", "?")
                    techs = r.get("technique_count", 0)
                    print(f"[ATT&CK sync] {label} v{ver} — {status_str} ({techs} techniques)")
            else:
                print(f"[ATT&CK sync] Up to date (next sync in {_ATTACK_SYNC_INTERVAL_DAYS}d)")
        except Exception as e:
            print(f"[ATT&CK sync] Loop error: {e}")

        await asyncio.sleep(86400)  # check daily


def _seconds_until_04h_utc() -> float:
    now = datetime.now(timezone.utc)
    target = now.replace(hour=4, minute=0, second=0, microsecond=0)
    if target <= now:
        target = target + timedelta(days=1)
    return max((target - now).total_seconds(), 1)


def _seconds_until_recap_hour_utc() -> float:
    now = datetime.now(timezone.utc)
    target = now.replace(hour=_RECAP_HOUR_UTC, minute=0, second=0, microsecond=0)
    if target <= now:
        target = target + timedelta(days=1)
    return max((target - now).total_seconds(), 1)


async def _ioc_decay_loop() -> None:
    from app.services.ioc_service import decay_sweep
    await asyncio.sleep(120)
    while True:
        wait = _seconds_until_04h_utc()
        print(f"[IOC decay] Next sweep in {wait/3600:.1f}h (04:00 UTC)")
        await asyncio.sleep(wait)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        print(f"[IOC decay] Starting decay sweep — {now_str}")
        try:
            result = await decay_sweep()
            print(f"[IOC decay] scanned={result['scanned']} updated={result['updated']}")
        except Exception as e:
            print(f"[IOC decay] Error: {e}")



async def _generate_all_recaps() -> None:
    """Generate the org-wide recap, then every client's personalized recap.

    Each generation is independently guarded — one client failing (bad profile,
    LLM hiccup) must not block the org-wide recap or any other client.
    """
    from app.services.recap_service import generate_daily_recap
    from app.services.client_service import list_clients

    try:
        doc = await generate_daily_recap(date=None, force=False)
        status = "cached" if doc.get("cached") else "generated"
        print(f"[Daily Recap] default — {doc.get('date')} — {status}")
    except Exception as e:
        print(f"[Daily Recap] default — error: {e}")
        return  # per-client recaps lean on the default doc for context — skip them if it failed

    try:
        clients = await list_clients()
    except Exception as e:
        print(f"[Daily Recap] could not list clients, skipping per-client recaps: {e}")
        return

    for c in clients:
        client_id = c.get("client_id")
        if not client_id or client_id == "default":
            continue
        try:
            doc = await generate_daily_recap(date=None, force=False, client_id=client_id)
            status = "cached" if doc.get("cached") else "generated"
            print(f"[Daily Recap] {client_id} — {doc.get('date')} — {status}")
        except Exception as e:
            print(f"[Daily Recap] {client_id} — error: {e}")


async def _daily_recap_loop() -> None:
    """Generate yesterday's recap (org-wide + every client) once per day at _RECAP_HOUR_UTC (UTC)."""
    await asyncio.sleep(180)  # let DB + IOC decay loops settle

    # Catch-up: process may have been down through the last _RECAP_HOUR_UTC
    # boundary (deploy/crash/restart). generate_daily_recap() no-ops if
    # yesterday's recap already exists, so this is safe to call blind.
    await _generate_all_recaps()

    while True:
        wait = _seconds_until_recap_hour_utc()
        print(f"[Daily Recap] Next gen in {wait/3600:.1f}h ({_RECAP_HOUR_UTC:02d}:00 UTC)")
        await asyncio.sleep(wait)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        print(f"[Daily Recap] Generating recaps for yesterday — {now_str}")
        await _generate_all_recaps()


async def _cve_enrichment_loop() -> None:
    from app.services.cisa_kev_service import lookup_all_true_positives as cisa_lookup
    from app.services.exploit_db_service import lookup_all_true_positives as edb_lookup
    from app.services.epss_service import lookup_all_true_positives as epss_lookup

    await asyncio.sleep(60)  # let DB connections settle
    while True:
        wait = _seconds_until_next_3h()
        print(f"[CVE enrichment] Next run in {wait/60:.1f} min (next 3h boundary UTC)")
        await asyncio.sleep(wait)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        print(f"[CVE enrichment] Starting CISA KEV lookup — {now_str}")
        try:
            cisa = await cisa_lookup()
            print(f"[CVE enrichment] CISA KEV: checked={cisa['checked']} matched={cisa['matched']}")
        except Exception as e:
            print(f"[CVE enrichment] CISA KEV error: {e}")

        print(f"[CVE enrichment] Starting Exploit-DB lookup — {now_str}")
        try:
            edb = await edb_lookup()
            print(f"[CVE enrichment] Exploit-DB: checked={edb['checked']} with_exploits={edb['with_exploits']} found={edb['total_found']}")
        except Exception as e:
            print(f"[CVE enrichment] Exploit-DB error: {e}")

        print(f"[CVE enrichment] Starting EPSS lookup — {now_str}")
        try:
            epss = await epss_lookup()
            print(f"[CVE enrichment] EPSS: checked={epss['checked']} scored={epss['scored']} no_data={epss['no_data']}")
        except Exception as e:
            print(f"[CVE enrichment] EPSS error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not SESSION_SECRET_KEY:
        raise RuntimeError("SESSION_SECRET_KEY env var must be set before starting the app")
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET env var must be set before starting the app")
    if not CORS_ORIGINS:
        print("[WARNING] CORS_ORIGINS env var not set — all origins blocked. Set CORS_ORIGINS to allow browser access.")
    await connect()
    await ta_connect()
    from app.services.client_service import ensure_default_client
    await ensure_default_client()
    from app.services.pkg_vuln_service import ensure_indexes as _pkg_vuln_ensure_indexes
    await _pkg_vuln_ensure_indexes()
    from app.services.domain_watch_service import ensure_indexes as _domain_watch_ensure_indexes
    await _domain_watch_ensure_indexes()
    from app.services.brand_watch_service import ensure_indexes as _brand_watch_ensure_indexes
    await _brand_watch_ensure_indexes()
    from app.services.scenario_service import ensure_indexes as _scenario_ensure_indexes
    await _scenario_ensure_indexes()
    from app.services.diagram_service import ensure_indexes as _diagram_ensure_indexes
    await _diagram_ensure_indexes()
    from app.services.dls_service import ensure_indexes as _dls_ensure_indexes
    await _dls_ensure_indexes()
    from app.services.cisa_kev_catalog_service import ensure_indexes as _cisa_kev_ensure_indexes
    await _cisa_kev_ensure_indexes()
    from app.services.role_service import ensure_system_roles
    await ensure_system_roles()
    if OIDC_ENABLED:
        from app.services.oidc_service import get_provider_metadata
        await get_provider_metadata()
    pir_task        = asyncio.create_task(_pir_alert_loop())
    enrichment_task = asyncio.create_task(_cve_enrichment_loop())
    attack_sync_task = asyncio.create_task(_attack_sync_loop())
    ioc_decay_task  = asyncio.create_task(_ioc_decay_loop())
    recap_task      = asyncio.create_task(_daily_recap_loop())
    yield
    pir_task.cancel()
    enrichment_task.cancel()
    attack_sync_task.cancel()
    ioc_decay_task.cancel()
    recap_task.cancel()
    await disconnect()
    await ta_disconnect()


app = FastAPI(title="Cyber Threat News", lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY or "startup-will-reject-empty-key",
    session_cookie="oidc_session",
    max_age=600,
    same_site="lax",
    https_only=True,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Client-ID"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.include_router(articles_router)
app.include_router(ta_router)
app.include_router(cve_router)
app.include_router(techstack_router)
app.include_router(intelligence_router)
app.include_router(sr_router)
app.include_router(mitre_router)
app.include_router(exec_router)
app.include_router(pir_router)
app.include_router(health_router)
app.include_router(ransomware_router)
app.include_router(changelog_router)
app.include_router(auth_router)
app.include_router(oidc_router)
app.include_router(newsletter_router)
app.include_router(mindmap_router)
app.include_router(filtered_articles_router)
app.include_router(iocs_router)
app.include_router(crossref_router)
app.include_router(stix_router)
app.include_router(rfi_router)
app.include_router(attack_router)
app.include_router(notifications_router)
app.include_router(clients_router)
app.include_router(roles_router)
app.include_router(tweets_router)
app.include_router(monitored_accounts_router)
app.include_router(recap_router)
app.include_router(pkg_vuln_router)
app.include_router(domain_watch_router)
app.include_router(brand_watch_router)
app.include_router(cisa_kev_router)
app.include_router(scenarios_router)
app.include_router(diagrams_router)


@app.get("/newsletter")
async def newsletter_page(request: Request):
    return templates.TemplateResponse(request=request, name="newsletter.html", context={})


@app.get("/login")
async def login_page(request: Request, cti_auth: str | None = Cookie(default=None)):
    if cti_auth:
        try:
            decode_token(cti_auth)
            return RedirectResponse(url="/", status_code=302)
        except Exception:
            pass
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"oidc_enabled": OIDC_ENABLED},
    )


@app.get("/")
@app.get("/newsroom")
async def newsroom(request: Request, cti_auth: str | None = Cookie(default=None)):
    if not cti_auth:
        return RedirectResponse(url="/login", status_code=302)
    try:
        decode_token(cti_auth)
    except Exception:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="newsroom.html",
        context={"version": APP_VERSION, "oidc_enabled": OIDC_ENABLED, "auth_required": False},
    )


@app.get("/intelgraph")
async def intelgraph_page(cti_auth: str | None = Cookie(default=None), sso: str | None = None):
    if not cti_auth:
        return RedirectResponse(url="/login", status_code=302)
    try:
        decode_token(cti_auth)
    except Exception:
        return RedirectResponse(url="/login", status_code=302)
    if not sso:
        # hand the JWT to the SPA via hash fragment so it can call /api/scenarios
        # with Bearer auth
        return RedirectResponse(url=f"/intelgraph?sso=1#token={cti_auth}", status_code=302)
    return FileResponse("static/intelgraph/index.html")


app.mount("/intelgraph", StaticFiles(directory="static/intelgraph"), name="intelgraph-assets")
