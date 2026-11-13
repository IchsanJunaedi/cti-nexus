import json
import os
import re
import time
import requests
import yaml
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
from modules.dbMongo import upsert_tweet, tweet_exists, list_existing, list_monitored_accounts
from modules.articleValidator import articleValidator

with open("config/config.yml", "r") as f:
    cfg = yaml.safe_load(f)

_tw = cfg["twitter"]
API_KEY       = _tw["api_key"]
ACCOUNTS_FILE = _tw["accounts_file"]
STATE_FILE    = _tw["state_file"]

# ── Load reference data from DB (same as twitter.py) ─────────────────────────

group_list_raw = list_existing("groups")
group_list = []
for group in group_list_raw:
    escaped = re.sub(r'[^a-zA-Z0-9\s]', r'\\\g<0>', group['name'])
    group_list.append(escaped)

_apac_country_list   = [c['name'] for c in list_existing("apac-country")]
_global_country_list = [c['name'] for c in list_existing("global-country")]
country_list     = list(dict.fromkeys(_global_country_list + _apac_country_list))
apac_people_list = [p['name'] for p in list_existing("apac-people")]

flags_list = [
    # Asia-Pacific
    ("🇦🇫", "Afghanistan"), ("🇦🇺", "Australia"), ("🇧🇩", "Bangladesh"),
    ("🇧🇹", "Bhutan"), ("🇧🇳", "Brunei"), ("🇰🇭", "Cambodia"),
    ("🇨🇳", "China"), ("🇫🇯", "Fiji"), ("🇮🇩", "Indonesia"),
    ("🇮🇳", "India"), ("🇯🇵", "Japan"), ("🇰🇿", "Kazakhstan"),
    ("🇰🇮", "Kiribati"), ("🇰🇵", "North Korea"), ("🇰🇷", "South Korea"),
    ("🇱🇦", "Laos"), ("🇲🇾", "Malaysia"), ("🇲🇻", "Maldives"),
    ("🇲🇳", "Mongolia"), ("🇲🇲", "Myanmar"), ("🇳🇵", "Nepal"),
    ("🇳🇿", "New Zealand"), ("🇵🇰", "Pakistan"), ("🇵🇬", "Papua New Guinea"),
    ("🇵🇭", "Philippines"), ("🇸🇧", "Solomon Islands"), ("🇸🇬", "Singapore"),
    ("🇱🇰", "Sri Lanka"), ("🇹🇭", "Thailand"), ("🇹🇱", "Timor-Leste"),
    ("🇹🇴", "Tonga"), ("🇹🇻", "Tuvalu"), ("🇻🇺", "Vanuatu"), ("🇻🇳", "Vietnam"),
    # Americas
    ("🇺🇸", "United States"), ("🇨🇦", "Canada"), ("🇲🇽", "Mexico"),
    ("🇧🇷", "Brazil"), ("🇦🇷", "Argentina"), ("🇨🇴", "Colombia"),
    ("🇨🇱", "Chile"), ("🇵🇪", "Peru"), ("🇻🇪", "Venezuela"),
    ("🇪🇨", "Ecuador"), ("🇧🇴", "Bolivia"), ("🇵🇾", "Paraguay"),
    ("🇺🇾", "Uruguay"), ("🇨🇺", "Cuba"), ("🇩🇴", "Dominican Republic"),
    ("🇬🇹", "Guatemala"), ("🇭🇳", "Honduras"), ("🇸🇻", "El Salvador"),
    ("🇨🇷", "Costa Rica"), ("🇵🇦", "Panama"), ("🇯🇲", "Jamaica"),
    ("🇹🇹", "Trinidad and Tobago"), ("🇭🇹", "Haiti"), ("🇬🇾", "Guyana"),
    # Europe
    ("🇬🇧", "United Kingdom"), ("🇩🇪", "Germany"), ("🇫🇷", "France"),
    ("🇮🇹", "Italy"), ("🇪🇸", "Spain"), ("🇳🇱", "Netherlands"),
    ("🇧🇪", "Belgium"), ("🇸🇪", "Sweden"), ("🇳🇴", "Norway"),
    ("🇩🇰", "Denmark"), ("🇫🇮", "Finland"), ("🇵🇱", "Poland"),
    ("🇺🇦", "Ukraine"), ("🇷🇺", "Russia"), ("🇨🇭", "Switzerland"),
    ("🇦🇹", "Austria"), ("🇵🇹", "Portugal"), ("🇨🇿", "Czech Republic"),
    ("🇷🇴", "Romania"), ("🇭🇺", "Hungary"), ("🇬🇷", "Greece"),
    ("🇹🇷", "Turkey"), ("🇸🇰", "Slovakia"), ("🇧🇬", "Bulgaria"),
    ("🇭🇷", "Croatia"), ("🇷🇸", "Serbia"), ("🇮🇪", "Ireland"),
    ("🇱🇹", "Lithuania"), ("🇱🇻", "Latvia"), ("🇪🇪", "Estonia"),
    ("🇧🇾", "Belarus"), ("🇲🇩", "Moldova"), ("🇦🇱", "Albania"),
    ("🇲🇰", "North Macedonia"), ("🇧🇦", "Bosnia and Herzegovina"),
    ("🇲🇪", "Montenegro"), ("🇮🇸", "Iceland"), ("🇱🇺", "Luxembourg"),
    # Middle East
    ("🇦🇪", "United Arab Emirates"), ("🇸🇦", "Saudi Arabia"),
    ("🇮🇱", "Israel"), ("🇮🇷", "Iran"), ("🇮🇶", "Iraq"),
    ("🇶🇦", "Qatar"), ("🇰🇼", "Kuwait"), ("🇧🇭", "Bahrain"),
    ("🇯🇴", "Jordan"), ("🇱🇧", "Lebanon"), ("🇴🇲", "Oman"),
    ("🇾🇪", "Yemen"), ("🇸🇾", "Syria"), ("🇵🇸", "Palestine"),
    ("🇨🇾", "Cyprus"), ("🇬🇪", "Georgia"), ("🇦🇲", "Armenia"),
    ("🇦🇿", "Azerbaijan"),
    # Africa
    ("🇿🇦", "South Africa"), ("🇳🇬", "Nigeria"), ("🇰🇪", "Kenya"),
    ("🇪🇹", "Ethiopia"), ("🇪🇬", "Egypt"), ("🇬🇭", "Ghana"),
    ("🇲🇦", "Morocco"), ("🇹🇳", "Tunisia"), ("🇩🇿", "Algeria"),
    ("🇱🇾", "Libya"), ("🇹🇿", "Tanzania"), ("🇸🇩", "Sudan"),
    ("🇺🇬", "Uganda"), ("🇷🇼", "Rwanda"), ("🇦🇴", "Angola"),
    ("🇲🇿", "Mozambique"), ("🇸🇳", "Senegal"), ("🇿🇼", "Zimbabwe"),
    ("🇨🇲", "Cameroon"), ("🇨🇮", "Ivory Coast"), ("🇿🇲", "Zambia"),
    ("🇲🇱", "Mali"), ("🇧🇫", "Burkina Faso"), ("🇲🇬", "Madagascar"),
    ("🇸🇴", "Somalia"), ("🇸🇸", "South Sudan"), ("🇳🇪", "Niger"),
    ("🇲🇼", "Malawi"), ("🇹🇩", "Chad"), ("🇬🇳", "Guinea"),
    # Central Asia
    ("🇺🇿", "Uzbekistan"), ("🇹🇲", "Turkmenistan"),
    ("🇰🇬", "Kyrgyzstan"), ("🇹🇯", "Tajikistan"),
    # Taiwan
    ("🇹🇼", "Taiwan"),
]

ot_list = [
    "ics vulnerabilities", "industrial espionage", "scada",
    "supervisory control and data acquisitions?", "plc",
    "programmable logic controller", "dcs", "distributed control systems?",
    "mes", "manufacturing execution systems?", "iiot",
    "industrial internet of things?", "mcc", "Motor Control Center",
    "sis", "esd", "pneumatics?", "hydraulics?", "safety instrumented",
    "emergency shutdown systems?", "ot resilience", "ot security standards?",
    "ot environments?", "ot infrastructures?", "industrial attacks?",
    "industrial networks?", "industrial automations?",
    "industrial safety regulation updates?", "ics", "industrial control systems?",
]

funding_list = [
    "funding round", "venture capital", "seed funding", "serie[s] a",
    "serie[s] b", "serie[s] c", "equity financing", "fundraising",
    "capital raise", "private equity", "crowdfunding", "startup funding",
    "acquisition funding", "strategic investment",
]

keyword_list = [
    "report[s]?", "trend[s]?", "landscape", "Q[1-4]", "threat[s]?",
    "prediction[s]?", "threatscape", "roundup", "whitepaper[s]?", "analysis",
    "case study", "insight[s]?", "overview", "annual report", "quarterly report",
    "forecast[s]?", "security bulletin", "cybersecurity report",
    "research paper[s]?", "executive summary", "write-up", "publication",
    "threat report", "threat intelligence report", "security update",
]

databreach_keyword = [
    r"(?:data|security) breach", r"data leaks?", r"customer data exposed",
    r"alleged(?:ly)? (?:breach(?:ed|es)|leak(?:ed|s)|sale|leak)",
]


# ── Scan tweet text for TI signals ───────────────────────────────────────────

def _scan_tweet(text: str) -> dict:
    tweet_indicator = True
    apac_indicator = False
    report_status_count = 0
    ot_status_count = 0
    mentioned_group = []
    mentioned_apac_country = []
    mentioned_apac_people = []
    databreach_list = []
    cve_list = []
    zero_day_list = []
    ot_status = False
    report_status = False
    funding_status = False

    ltext = text.lower()

    for group in group_list:
        if str(group).startswith("[") or len(group) == 0:
            continue
        if re.search(f"\\b{group.lower()}\\b", ltext):
            mentioned_group.append(group.replace("\\-", "-"))

    for country in country_list:
        if re.search(f"\\b{country.lower()}\\b", ltext):
            mentioned_apac_country.append(country)

    for flag, country in flags_list:
        if flag in text:
            mentioned_apac_country.append(country)

    for people in apac_people_list:
        if re.search(f"\\b{people.lower()}\\b", ltext):
            mentioned_apac_people.append(people)

    cve_list = re.findall(r"cve-\d{4}-\d{4,}", ltext)
    zero_day_list = re.findall(r"(zero|0).day", ltext)

    for kw in databreach_keyword:
        if re.search(f"\\b{kw}\\b", ltext):
            databreach_list.append(kw)

    for kw in keyword_list:
        if re.search(f"\\b{kw.lower()}\\b", ltext):
            report_status_count += 1
        if report_status_count >= 5:
            report_status = True

    for kw in funding_list:
        if re.search(f"\\b{kw.lower()}\\b", ltext):
            funding_status = True
            tweet_indicator = False

    for kw in ot_list:
        if re.search(f"\\b{kw.lower()}\\b", ltext):
            ot_status_count += 1
        if ot_status_count >= 1:
            ot_status = True

    mentioned_group         = list(OrderedDict.fromkeys(mentioned_group))
    mentioned_apac_country  = list(OrderedDict.fromkeys(mentioned_apac_country))
    mentioned_apac_people   = list(OrderedDict.fromkeys(mentioned_apac_people))

    if mentioned_apac_country or mentioned_apac_people:
        apac_indicator = True

    return {
        "tweet_indicator":      tweet_indicator,
        "apac_indicator":       apac_indicator,
        "mentioned_group":      mentioned_group,
        "mentioned_apac_country": mentioned_apac_country,
        "mentioned_apac_people":  mentioned_apac_people,
        "cve_list":             cve_list,
        "zero_day_list":        zero_day_list,
        "databreach_list":      databreach_list,
        "ot_status":            ot_status,
        "report_status":        report_status,
        "funding_status":       funding_status,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def parse_created_at(raw: str) -> str:
    # "Mon May 11 13:00:57 +0000 2026" → ISO 8601
    try:
        dt = datetime.strptime(raw, "%a %b %d %H:%M:%S +0000 %Y")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return raw


def fetch_tweets_for_account(account: str, last_seen_id: str | None) -> list[dict]:
    query = f"from:{account} -is:retweet -filter:replies"
    if last_seen_id:
        # since_id is precise — no time window needed
        query += f" since_id:{last_seen_id}"
    else:
        # First run: limit to last 3 hours to avoid pulling entire history
        since_time = datetime.now(timezone.utc) - timedelta(hours=3)
        query += f" since_time:{int(since_time.timestamp())}"

    url = "https://api.twitterapi.io/twitter/tweet/advanced_search"
    params = {"query": query, "queryType": "Latest"}
    headers = {"X-API-Key": API_KEY}

    all_tweets = []
    next_cursor = None

    running_time = 0

    while True:
        if running_time >= 3:
            break

        time.sleep(5)
        if next_cursor:
            params["cursor"] = next_cursor

        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
        except requests.exceptions.RequestException as e:
            print(f"[{account}] request failed: {e}")
            break

        if response.status_code == 200:
            data = response.json()
            tweets = data.get("tweets", [])
            if tweets:
                all_tweets.extend(tweets)

            if data.get("has_next_page") and data.get("next_cursor"):
                next_cursor = data["next_cursor"]
            else:
                break
        else:
            print(f"[{account}] API error {response.status_code}: {response.text}")
            break

        running_time += 1

    return all_tweets


def build_tweet_doc(tweet: dict, scan: dict, llm: dict) -> dict:
    author = tweet.get("author", {})
    media_urls = [
        m["media_url_https"]
        for m in tweet.get("extendedEntities", {}).get("media", [])
        if m.get("media_url_https")
    ]
    return {
        "tweet_id":         tweet["id"],
        "url":              tweet.get("url", ""),
        "text":             tweet.get("text", ""),
        "author_username":  author.get("userName", ""),
        "author_name":      author.get("name", ""),
        "author_avatar":    author.get("profilePicture", ""),
        "author_followers": int(author.get("followers", 0) or 0),
        "posted_on":        parse_created_at(tweet.get("createdAt", "")),
        "lang":             tweet.get("lang", "en"),
        "media_urls":       media_urls,
        "fetched_at":       datetime.now(timezone.utc).isoformat(),
        # regex scan fields
        "apac_indicator":       scan["apac_indicator"],
        "mentioned_group":      scan["mentioned_group"],
        "mentioned_apac_country": scan["mentioned_apac_country"],
        "mentioned_apac_people":  scan["mentioned_apac_people"],
        "cve_list":             scan["cve_list"],
        "zero_day_list":        scan["zero_day_list"],
        "databreach_list":      scan["databreach_list"],
        "ot_status":            scan["ot_status"],
        "report_status":        scan["report_status"],
        # LLM validation fields
        "related_cyber":        llm.get("related_cyber", True),
        "confidence":           llm.get("confidence", None),
        "industries_impacted":  llm.get("industries_impacted", []),
        "victim_countries":     llm.get("victim_countries", []),
        "actor_countries":      llm.get("actor_countries", []),
        "confirmed_incident":   llm.get("confirmed_incident", False),
        "incident_confidence":  llm.get("incident_confidence", None),
        "incident_indicators":  llm.get("incident_indicators", []),
        "victim_name":          llm.get("victim_name", None),
    }


# ── Main ──────────────────────────────────────────────────────────────────────

LOCK_FILE = "/tmp/monitorX.lock"

def main():
    # Prevent concurrent cron runs — if a previous run is still active, skip.
    if os.path.exists(LOCK_FILE):
        print("[monitorX] already running (lockfile exists), exiting")
        return
    open(LOCK_FILE, "w").close()

    try:
        _main()
    finally:
        os.remove(LOCK_FILE)


def _main():
    accounts = list_monitored_accounts()
    if not accounts:
        # fallback to file if DB is empty
        if os.path.exists(ACCOUNTS_FILE):
            with open(ACCOUNTS_FILE) as f:
                accounts = [line.strip() for line in f if line.strip()]
        if not accounts:
            print("[monitorX] no accounts to monitor — add via ScraperNewsWeb X Intel > Monitored Accounts")
            return

    state = load_state()
    total_tweet_session = 0

    for account in accounts:
        last_seen_id = state.get(account)
        print(f"[{account}] fetching (last_seen_id={last_seen_id})")

        raw_tweets = fetch_tweets_for_account(account, last_seen_id)

        if not raw_tweets:
            print(f"[{account}] no new tweets")
            continue

        # Sort ascending by id — max id = newest tweet
        raw_tweets.sort(key=lambda t: int(t["id"]))
        new_max_id = raw_tweets[-1]["id"]

        inserted = skipped_dup = skipped_filter = 0

        for tweet in raw_tweets:
            text = tweet.get("text", "")

            # ── Regex scan ──
            scan = _scan_tweet(text)

            # Skip funding noise
            if scan["funding_status"]:
                print(f"  [skip] funding content: {text[:60]}")
                skipped_filter += 1
                continue

            # ── Duplicate check (before LLM to save cost) ──
            if tweet_exists(tweet["id"]):
                print(f"{tweet['id']} is duplicated tweet")
                skipped_dup += 1
                continue

            # ── LLM validation ──
            try:
                llm_result = articleValidator(text)
            except Exception as e:
                print(f"  [warn] articleValidator error: {e} — saving without LLM")
                llm_result = {}

            if isinstance(llm_result, dict) and llm_result.get("related_cyber") is False:
                print(f"  [skip] not cyber-related (confidence={llm_result.get('confidence')}): {text[:60]}")
                skipped_filter += 1
                continue

            # ── Build doc + upsert ──
            doc = build_tweet_doc(tweet, scan, llm_result if isinstance(llm_result, dict) else {})
            if upsert_tweet(doc):
                inserted += 1
            else:
                skipped_dup += 1

        print(f"[{account}] inserted={inserted} skipped_dup={skipped_dup} skipped_filter={skipped_filter}")
        
        total_tweet_session += inserted
        print(total_tweet_session)

        state[account] = new_max_id
        save_state(state)

        time.sleep(1)  # rate-limit courtesy


if __name__ == "__main__":
    main()
