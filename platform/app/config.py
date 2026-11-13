import os
import re
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def _latest_changelog_version() -> str:
    path = Path(__file__).parent.parent / "CHANGELOG.md"
    try:
        text = path.read_text(encoding="utf-8")
        m = re.search(r"^## \[([^\]]+)\]", text, re.MULTILINE)
        if m:
            return m.group(1).strip()
    except OSError:
        pass
    return "0.0.0"


APP_VERSION = _latest_changelog_version()

# ── JWT / Auth ────────────────────────────────────────────────
JWT_SECRET         = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM      = os.getenv("JWT_ALGORITHM", "HS256")

JWT_EXPIRE_MIN     = int(os.getenv("JWT_EXPIRE_MIN", "480"))   # 8 hours
USERS_COLLECTION   = os.getenv("USERS_COLLECTION", "users")
AUDIT_COLLECTION   = os.getenv("AUDIT_COLLECTION", "audit_log")


TELEGRAM_BOT_TOKEN      = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_PIR_CHAT_ID    = os.getenv("TELEGRAM_PIR_CHAT_ID", "")
TELEGRAM_PIR_THREAD_ID  = os.getenv("TELEGRAM_PIR_THREAD_ID", "")
PIR_ALERT_INTERVAL_MIN  = int(os.getenv("PIR_ALERT_INTERVAL_MIN", "15"))

MONGO_USER = os.getenv("MONGO_USER", "")
MONGO_PASS = os.getenv("MONGO_PASS", "")
MONGO_HOST = os.getenv("MONGO_HOST", "")
MONGO_PORT = os.getenv("MONGO_PORT", "")
DB_NAME = os.getenv("DB_NAME", "")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "")
NLP_JOBS_COLLECTION = os.getenv("NLP_JOBS_COLLECTION", "nlp_jobs")

MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/?authSource={DB_NAME}"

# ── Threat Actor Room authentication ─────────────────────
# Change this to a strong password before deploying
TA_AUTH_PASSWORD = os.getenv("TA_AUTH_PASSWORD", "")

# ── Threat Actor Groups DB (threatintel) ──────────────────
TA_MONGO_USER = os.getenv("TA_MONGO_USER", "")
TA_MONGO_PASS = os.getenv("TA_MONGO_PASS", "")
TA_DB_NAME = os.getenv("TA_DB_NAME", "")
TA_GROUPS_COLLECTION    = os.getenv("TA_GROUPS_COLLECTION", "")
TA_WHITELIST_COLLECTION = os.getenv("TA_WHITELIST_COLLECTION", "")
TA_WATCHLIST_COLLECTION = os.getenv("TA_WATCHLIST_COLLECTION", "")
TA_PROFILES_COLLECTION  = os.getenv("TA_PROFILES_COLLECTION", "")
TECHSTACK_COLLECTION     = os.getenv("TECHSTACK_COLLECTION", "")
SOURCE_SCORES_COLLECTION = os.getenv("SOURCE_SCORES_COLLECTION", "")
CLUSTERS_COLLECTION      = os.getenv("CLUSTERS_COLLECTION", "")
PIR_COLLECTION           = os.getenv("PIR_COLLECTION", "")
PIR_NOTES_COLLECTION     = os.getenv("PIR_NOTES_COLLECTION", "")
RFI_COLLECTION           = os.getenv("RFI_COLLECTION", "rfis")
SCENARIOS_COLLECTION     = os.getenv("SCENARIOS_COLLECTION", "scenarios")
DIAGRAMS_COLLECTION      = os.getenv("DIAGRAMS_COLLECTION", "diagrams")
TA_MONGO_URI = (
    f"mongodb://{TA_MONGO_USER}:{TA_MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}"
    f"/?authSource={TA_DB_NAME}&authMechanism=SCRAM-SHA-256"
)

# ── CVE Email (Microsoft Graph + OpenAI) ─────────────────────
AZURE_CLIENT_ID     = os.getenv("AZURE_CLIENT_ID", '')
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", '')
AZURE_TENANT_ID     = os.getenv("AZURE_TENANT_ID", '')
CVE_EMAIL_SENDER      = os.getenv("CVE_EMAIL_SENDER", "")
CVE_EMAIL_SENDER_NAME = os.getenv("CVE_EMAIL_SENDER_NAME", "")   # display name, e.g. "Threat Intelligence Team"
CVE_EMAIL_CC          = os.getenv("CVE_EMAIL_CC", "")

# LLM provider config — set these to switch away from OpenAI.
# provider: openai | deepseek | gemini
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "")
LLM_API_KEY  = os.getenv("LLM_API_KEY", "")
LLM_MODEL    = os.getenv("LLM_MODEL", "")   # empty = use provider default

# ── CVE Email method: "graph" (Outlook draft) or "smtp" (send via SMTP) ──────
EMAIL_METHOD  = os.getenv("EMAIL_METHOD", "graph")   # "graph" | "smtp"
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASS     = os.getenv("SMTP_PASS", "")
SMTP_USE_TLS  = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

# ── OIDC / SSO ────────────────────────────────────────────────
OIDC_CLIENT_ID     = os.getenv("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_DISCOVERY_URL = os.getenv("OIDC_DISCOVERY_URL", "")
OIDC_REDIRECT_URI  = os.getenv("OIDC_REDIRECT_URI", "")
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "")
OIDC_ENABLED       = bool(OIDC_CLIENT_ID and OIDC_DISCOVERY_URL)
OIDC_VERIFY_SSL    = os.getenv("OIDC_VERIFY_SSL", "true").lower() != "false"

# ── WiseMapping ───────────────────────────────────────────────
WISEMAP_BASE_URL  = os.getenv("WISEMAP_BASE_URL", "")
WISEMAP_EMAIL     = os.getenv("WISEMAP_EMAIL", "")
WISEMAP_PASSWORD  = os.getenv("WISEMAP_PASSWORD", "")
WISEMAP_ENABLED   = bool(WISEMAP_BASE_URL and WISEMAP_EMAIL and WISEMAP_PASSWORD)
MINDMAPS_COLLECTION = os.getenv("MINDMAPS_COLLECTION", "mindmaps")

# ── IOC Database ───────────────────────────────────────────
IOC_COLLECTION           = os.getenv("IOC_COLLECTION", "iocs")
IOC_ALLOWLIST_COLLECTION = os.getenv("IOC_ALLOWLIST_COLLECTION", "ioc_allowlist")
IOC_FEED_TOKEN           = os.getenv("IOC_FEED_TOKEN", "")

# ── NVD API (optional — raises rate limit from 5→50 req/30s) ─
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# ── CVE Enrichment template ────────────────────────────────
CVE_TRACKER_TEMPLATE = os.getenv("CVE_TRACKER_TEMPLATE", "app/templates/CVE_Tracker_template.xlsx")

# ── Twitter/X Intel ───────────────────────────────────────
TWITTER_API_KEY = os.getenv("TWITTER_API_KEY", "")
TWEETS_COLLECTION = os.getenv("TWEETS_COLLECTION", "tweets")
MONITORED_ACCOUNTS_COLLECTION = os.getenv("MONITORED_ACCOUNTS_COLLECTION", "monitored_accounts")
CLIENTS_COLLECTION = os.getenv("CLIENTS_COLLECTION", "clients")
ROLES_COLLECTION   = os.getenv("ROLES_COLLECTION", "roles")

# ── CORS ───────────────────────────────────────────────────
# Comma-separated list of allowed origins. Required in production.
# Example: "https://cti.example.com,https://cti-dev.example.com"
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
