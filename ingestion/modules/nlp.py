import time
import en_core_web_sm
from modules import dbMongo
from modules import cveValidator
from modules import articleValidator
from modules import ttpValidator
from modules import iocExtractor
from modules.techstackStore import get_tech_list
from sumy.parsers.html import HtmlParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.lsa import LsaSummarizer
from sumy.nlp.stemmers import Stemmer
from sumy.utils import get_stop_words
from collections import OrderedDict
import requests.exceptions
import requests, yaml, re, lxml
from datetime import datetime

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

# Loaded once at module import — shared across all articles processed by this worker
NLP = en_core_web_sm.load()


def _sendAlert(related_tech_cve_status, related_tech_status, cve_list, report_status,
               ot_status, msg_data, databreach_list, zero_day_list, group_string, news_type, news_dict):

    # news_type gets overwritten below by category labels (OT/Zero Day/etc.) whenever
    # those keyword checks also match, clobbering the apac/global region classify
    # result. Stash it here, untouched, so region is always recoverable downstream
    # regardless of which category branch fires.
    news_dict['region'] = news_type

    ot_keyword_list = [
        "critical infrastructure", "energy & utilities", "manufacturing & industrial",
        "transportation & logistics", "aerospace & defense contractors",
    ]
    for keyword in ot_keyword_list:
        if re.search(f"\\b{str(keyword).lower()}\\b", str(msg_data).lower()):
            news_dict['news_type'] = "OT Article"
            break

    if len(zero_day_list) != 0:
        news_dict['news_type'] = "Zero Day Article"
    elif len(databreach_list) != 0:
        news_dict['news_type'] = "Data Breach Article"
    elif report_status == True:
        news_dict['news_type'] = "Vendor Report Article"
    elif ot_status == True:
        news_dict['news_type'] = "OT Article"
    elif related_tech_status == True or related_tech_cve_status == True:
        news_dict['news_type'] = "Tech Stack Article"
    elif related_tech_status == False and len(cve_list) != 0:
        news_dict['news_type'] = "Unrelated Tech Stack Article"
    else:
        alert_sent = False
        vuln_keyword_list = [
            "flaws? (.+)?(enables?|expose|lets?|allows?)",
            "critical (.+)?(flaws?|vulnerability|vulnerabilities)",
            "(vulnerability|vulnerabilities) (.+)?(allows?|exposes?|enables?|lets?)",
        ]
        for keyword in vuln_keyword_list:
            if re.search(f"\\b{str(keyword).lower()}\\b", str(msg_data).lower()):
                alert_sent = True
                news_dict['news_type'] = "Unrelated Tech Stack Article"
                break
        if not alert_sent:
            news_dict['news_type'] = news_type

    # Persist article to MongoDB (replaces threat_info_recap.json)
    dbMongo.upsert_article(news_dict)


def _trackingNews(filename, title):
    try:
        with open(filename, 'r') as indata:
            indata.readlines()
    except FileNotFoundError:
        open(filename, 'w+')

    with open(filename, 'a') as f:
        f.write(str(title) + "\n")


_allowlist_cache: dict | None = None
_allowlist_cache_ts: float = 0.0
_ALLOWLIST_TTL = 300.0

_c2_feed_cache: dict | None = None
_c2_feed_cache_ts: float = 0.0
_C2_FEED_TTL = 3600.0


def _get_allowlist() -> dict:
    global _allowlist_cache, _allowlist_cache_ts
    now = time.monotonic()
    if _allowlist_cache is None or (now - _allowlist_cache_ts) > _ALLOWLIST_TTL:
        try:
            _allowlist_cache = dbMongo.get_ioc_allowlist()
        except Exception:
            _allowlist_cache = {"url_domains": set(), "email_domains": set()}
        _allowlist_cache_ts = now
    return _allowlist_cache


def _get_c2_feed() -> dict:
    global _c2_feed_cache, _c2_feed_cache_ts
    now = time.monotonic()
    if _c2_feed_cache is None or (now - _c2_feed_cache_ts) > _C2_FEED_TTL:
        try:
            _c2_feed_cache = dbMongo.get_c2_feed_set()
        except Exception:
            _c2_feed_cache = {"ips": set(), "domains": set()}
        _c2_feed_cache_ts = now
    return _c2_feed_cache


def _check_c2_hit(ioc_data: dict) -> bool:
    feed = _get_c2_feed()
    if not feed["ips"] and not feed["domains"]:
        return False
    article_ips = set(ioc_data.get("ips", []))
    article_domains = set(ioc_data.get("domains", []))
    return bool(article_ips & feed["ips"] or article_domains & feed["domains"])


def nlp_scan(article_data, script_name):
    cve_list_body = []
    cve_list_title = []
    databreach_list = []
    zero_day_list = []
    tech_stack_list = []

    report_status = False
    report_status_count = 0
    ot_status = False
    ot_status_count = 0
    related_tech_cve_status = False
    related_tech_status = False

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
        "industrial safety regulation updates?", "ics",
        "industrial control systems?", "ot networks?",
    ]

    funding_list = [
        "funding round", "venture capital", "seed funding", "serie[s] a",
        "serie[s] b", "serie[s] c", "equity financing", "fundraising",
        "capital raise", "private equity", "crowdfunding", "startup funding",
        "acquisition funding", "strategic investment",
    ]

    keyword_list = [
        "report[s]?", "trend[s]?", "landscape", "Q[1-4]", "threat[s]?",
        "prediction[s]?", "threatscape", "roundup", "whitepaper[s]?",
        "analysis", "case study", "insight[s]?", "overview", "annual report",
        "quarterly report", "forecast[s]?", "security bulletin",
        "cybersecurity report", "research paper[s]?", "executive summary",
        "write-up", "publication", "threat report", "threat intelligence report",
        "case study", "security update",
    ]

    databreach_keyword = [
        "(?:data|security) breach", "data leaks?", "customer data exposed",
        "alleged(?:ly)? (?:breach(?:ed|es)|leak(?:ed|s)|sale|leak)",
        "records leak(?:ed|s)",
    ]

    flags_list = [
        # Asia-Pacific
        ("🇦🇫", "Afghanistan"), ("🇦🇺", "Australia"), ("🇧🇩", "Bangladesh"),
        ("🇧🇹", "Bhutan"), ("🇧🇳", "Brunei"), ("🇰🇭", "Cambodia"),
        ("🇨🇳", "China"), ("🇫🇯", "Fiji"), ("🇮🇩", "Indonesia"),
        ("🇮🇳", "India"), ("🇯🇵", "Japan"), ("🇰🇿", "Kazakhstan"),
        ("🇰🇮", "Kiribati"), ("🇰🇵", "North Korea"), ("🇰🇷", "South Korea"),
        ("🇱🇦", "Laos"), ("🇲🇾", "Malaysia"), ("🇲🇻", "Maldives"),
        ("🇲🇳", "Mongolia"), ("🇲🇲", "Myanmar"), ("🇳🇵", "Nepal"),
        ("🇳🇿", "New Zealand"), ("🇵🇰", "Pakistan"),
        ("🇵🇬", "Papua New Guinea"), ("🇵🇭", "Philippines"),
        ("🇸🇧", "Solomon Islands"), ("🇸🇬", "Singapore"),
        ("🇱🇰", "Sri Lanka"), ("🇹🇭", "Thailand"), ("🇹🇱", "Timor-Leste"),
        ("🇹🇴", "Tonga"), ("🇹🇻", "Tuvalu"), ("🇻🇺", "Vanuatu"),
        ("🇻🇳", "Vietnam"),
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

    tech_stack_list.extend(get_tech_list())

    message = article_data

    ### GPT call 1: title-only classification (cheap — no body fetch yet) ###
    _url = message.get('url', '')
    _cache = dbMongo.get_openai_cache(_url) if _url else None
    if _cache and 'validator_result' in _cache:
        open_ai_status = _cache['validator_result']
        print(f"[openai cache hit] validator: {_url}")
    else:
        open_ai_status = articleValidator.articleValidator(message['title'])
        if open_ai_status and _url:
            dbMongo.set_openai_cache(_url, open_ai_status)

    # Extract country roles returned by GPT (empty lists if not determined)
    gpt_victim_countries = open_ai_status.get('victim_countries', []) if open_ai_status else []
    gpt_actor_countries  = open_ai_status.get('actor_countries', []) if open_ai_status else []

    if open_ai_status['related_cyber'] == False or open_ai_status['related_cyber'] is None:
        _trackingNews(
            f"supportFile/UNRELATED_{datetime.now().strftime('%d_%m_%Y')}.txt",
            message['title'],
        )
        print(f"'{message['title']}' is not related to cyber security trend")
        dbMongo.log_scraper_run(script_name, accepted=False,
                                title=message.get('title', ''), url=message.get('url', ''))
        return
    #########################################################################

    ### Fetch + summarize article body (only for cyber-relevant articles) ###
    LANGUAGE = "english"
    result = ""
    _full_article_text = ""
    try:
        _headers = {"User-Agent": "Mozilla/5.0"}
        _resp = requests.get(message['url'], timeout=30, headers=_headers)
        _resp.raise_for_status()
        parser = HtmlParser.from_string(_resp.text, message['url'], Tokenizer(LANGUAGE))
        stemmer = Stemmer(LANGUAGE)
        summarizer_lsa = LsaSummarizer(stemmer)
        summarizer_lsa.stop_words = get_stop_words(LANGUAGE)
        SENTENCES_COUNT = min(int(
            str(parser.document).replace("<DOM with ", "").replace(" paragraphs>", "")
        ), 15)
        for sentence in summarizer_lsa(parser.document, SENTENCES_COUNT):
            result += str(sentence) + " "
        _full_article_text = " ".join(str(s) for s in parser.document.sentences)
    except Exception:
        result = ttpValidator.fetch_article_text(message['url'])
    #########################################################################

    ioc_data = iocExtractor.extract_iocs(_full_article_text or result, source_url=message.get('url', ''), allowlist=_get_allowlist()) if (_full_article_text or result) else {}
    c2_indicator = _check_c2_hit(ioc_data)

    _trackingNews(
        f"supportFile/RELATED_{datetime.now().strftime('%d_%m_%Y')}.txt",
        message['title'],
    )
    industries_string = ""
    if "General" in open_ai_status['industries_impacted'] and len(open_ai_status['industries_impacted']) >= 1:
        industries_string = "General"
    else:
        for tag in open_ai_status['industries_impacted']:
            if tag == "General":
                continue
            industries_string += str(tag) + " || "
        industries_string = industries_string[:-4]

    msg_data = f"""
        === <b>{str(script_name).upper()}</b> ===
<b>Title</b>: {message['title']}
<b>Posted On</b>: {message['posted_on']}
<b>Link</b>: <a href="{message['url']}">Read Now</a>
<b>Impacted Industries</b>: {industries_string}
"""

    upper_script_name = str(script_name).upper()
    source_name = upper_script_name.split("FROM")[1].title() if "FROM" in upper_script_name else upper_script_name.title()

    if open_ai_status['security_tech_best_practice'] == True:
        article_dict = {
            "title": message.get('title', 'No Title Found'),
            "url": message.get('url', ''),
            "posted_on": str(message.get('posted_on', '')),
            "source": source_name.lstrip(),
            "impacted_industries": industries_string.split(" || ") if industries_string else [],
            "mentioned_countries": list(dict.fromkeys(gpt_victim_countries + gpt_actor_countries)),
            "victim_countries": gpt_victim_countries,
            "actor_countries": gpt_actor_countries,
            "threat_actors": [],
            "ttps": [],
            "confidence": open_ai_status.get('confidence', 0),
            "confirmed_incident": open_ai_status.get('confirmed_incident'),
            "incident_confidence": open_ai_status.get('incident_confidence'),
            "incident_indicators": open_ai_status.get('incident_indicators', []),
            "victim_name": open_ai_status.get('victim_name'),
            "news_type": "Security Technology & Best Practices",
            "iocs": ioc_data,
            "c2_indicator": c2_indicator,
        }
        dbMongo.log_scraper_run(script_name, accepted=True, title=article_dict["title"], url=article_dict["url"])
        dbMongo.upsert_article(article_dict)
        return

    ### Get reference lists from MongoDB ###
    group_list_raw = dbMongo.list_existing("groups")
    # (canonical_name, escaped_variant_pattern) — variant is name + any alias, so
    # "Everest", "Everest Group", "Everest Ransomware Group" all still match in text,
    # but every match reports the single canonical name (dedup happens here, not after).
    group_list = []
    for group in group_list_raw:
        canonical = group['name']
        if str(canonical).startswith("[") or len(canonical) == 0:
            continue
        for variant in [canonical] + list(group.get('aliases', [])):
            if not variant:
                continue
            escaped = re.sub(r'[^a-zA-Z0-9\s]', r'\\\g<0>', variant)
            group_list.append((canonical, escaped))

    apac_country_list_raw   = dbMongo.list_existing("apac-country")
    global_country_list_raw = dbMongo.list_existing("global-country")
    apac_country_list = [c['name'] for c in apac_country_list_raw]
    global_country_list = [c['name'] for c in global_country_list_raw]
    # Merge: global superset + any APAC-specific entries not already covered
    country_list = list(dict.fromkeys(global_country_list + apac_country_list))

    apac_people_list_raw = dbMongo.list_existing("apac-people")
    apac_people_list = [p['name'] for p in apac_people_list_raw]
    ########################################

    mentioned_group = []
    mentioned_countries = []
    mentioned_apac_people = []

    ### Regex matching on title ###
    for canonical, variant in group_list:
        if re.search(f"\\b{str(variant).lower()}\\b", str(message['title']).lower()):
            mentioned_group.append(canonical)

    for country in country_list:
        if re.search(f"\\b{str(country).lower()}\\b", str(message['title']).lower()):
            mentioned_countries.append(country)

    for flag, country in flags_list:
        if re.search(f"{flag}", str(message['title']).lower()):
            mentioned_countries.append(country)

    for people in apac_people_list:
        if re.search(f"\\b{str(people).lower()}\\b", str(message['title']).lower()):
            mentioned_apac_people.append(people)

    cve_list_title = re.findall(r"cve-\d{4}-\d{4,}", str(message['title']).lower())

    for keyword in tech_stack_list:
        if re.search(f"\\b{str(keyword).lower()}\\b", str(message['title']).lower()):
            related_tech_status = True

    for keyword in databreach_keyword:
        if re.search(f"\\b{str(keyword).lower()}\\b", str(message['title']).lower()):
            databreach_list.append(keyword)

    zero_day_list = re.findall(r"\\b(zero|0)[-.]day\\b", str(message['title']).lower())

    for keyword in keyword_list:
        if re.search(f"\\b{str(keyword).lower()}\\b", str(message['title']).lower()):
            report_status_count += 1
        if report_status_count >= 5:
            report_status = True

    for keyword in funding_list:
        if re.search(f"\\b{str(keyword).lower()}\\b", str(message['title']).lower()):
            msg_data += f"<b>Funding Related Article</b>: True ({keyword})\n"
            break

    for keyword in ot_list:
        if re.search(f"\\b{str(keyword).lower()}\\b", str(message['title']).lower()):
            ot_status_count += 1
        if ot_status_count >= 1:
            ot_status = True

    ### NER + regex matching on body (uses module-level spaCy) ###
    if result:
        for canonical, variant in group_list:
            if re.search(f"\\b{str(variant).lower()}\\b", str(result).lower()):
                mentioned_group.append(canonical)

        for country in country_list:
            if re.search(f"\\b{str(country).lower()}\\b", str(result).lower()):
                mentioned_countries.append(country)

        for flag, country in flags_list:
            if re.search(f"{flag}", str(result).lower()):
                mentioned_countries.append(country)

        for people in apac_people_list:
            if re.search(f"\\b{str(people).lower()}\\b", str(result).lower()):
                mentioned_apac_people.append(people)

        cve_list_body = re.findall(r"cve-\d{4}-\d{4,}", str(result).lower())

        for keyword in keyword_list:
            if re.search(f"\\b{str(keyword).lower()}\\b", str(result).lower()):
                report_status_count += 1
            if report_status_count >= 5:
                report_status = True

        for keyword in ot_list:
            if re.search(f"\\b{str(keyword).lower()}\\b", str(result).lower()):
                ot_status_count += 1
            if ot_status_count >= 1:
                ot_status = True

        output = NLP(result[:1_000_000])
        for item in output.ents:
            if item.label_ in ("ORG", "PERSON", "GPE"):
                for canonical, variant in group_list:
                    if re.search(f"\\b{str(variant).lower()}\\b", str(item).lower()):
                        mentioned_group.append(canonical)

            if item.label_ in ("NORP", "GPE"):
                for country in country_list:
                    if re.search(f"\\b{str(country).lower()}\\b", str(item).lower()):
                        mentioned_countries.append(country)
                for flag, country in flags_list:
                    if re.search(f"{flag}", str(item).lower()):
                        mentioned_countries.append(country)
                for people in apac_people_list:
                    if re.search(f"\\b{str(people).lower()}\\b", str(item).lower()):
                        mentioned_apac_people.append(people)
    ###############################################################

    mentioned_group = list(OrderedDict.fromkeys(mentioned_group))
    mentioned_apac_people = list(OrderedDict.fromkeys(mentioned_apac_people))
    mentioned_countries = list(OrderedDict.fromkeys(mentioned_countries))
    # global-country collection intentionally re-lists APAC countries "for completeness"
    # (see scripts/seed_global_countries.py), so country_list membership alone can't
    # tell APAC from global. Use apac_country_list as the single source of truth for
    # region routing; mentioned_countries stays as-is for display purposes.
    _apac_country_set = {str(c).lower() for c in apac_country_list}
    mentioned_apac_countries = [c for c in mentioned_countries if str(c).lower() in _apac_country_set]
    cve_list = cve_list_title

    gpt_confidence           = open_ai_status.get('confidence')           if open_ai_status else None
    gpt_confirmed_incident   = open_ai_status.get('confirmed_incident')   if open_ai_status else None
    gpt_incident_confidence  = open_ai_status.get('incident_confidence')  if open_ai_status else None
    gpt_incident_indicators  = open_ai_status.get('incident_indicators', []) if open_ai_status else []
    gpt_victim_name          = open_ai_status.get('victim_name')          if open_ai_status else None

    ttp_list = []
    ttp_string = ""
    apac_string = ""
    group_string = ""

    # ── #1 TTP extraction for ALL cyber-relevant articles ─────────────────
    if result:
        try:
            _cached_ttp = _cache.get('ttp_result') if _cache else None
            if _cached_ttp:
                ttp_data = _cached_ttp
                print(f"[openai cache hit] ttp: {_url}")
            else:
                ttp_data = articleValidator.extractTTPs(result[:2000])
                if _url and open_ai_status:
                    dbMongo.set_openai_cache(_url, open_ai_status, ttp_result=ttp_data)
            if ttp_data.get('has_techniques'):
                for technique in ttp_data.get('techniques', []):
                    ttp_list.append({"id": technique['technique_id'], "name": technique['technique_name']})
                    ttp_string += f"{technique['technique_name']} ({technique['technique_id']}), "
                if ttp_string:
                    ttp_string = ttp_string[:-2]
        except Exception:
            pass
    # ──────────────────────────────────────────────────────────────────────

    if len(mentioned_group) == 0 and (len(mentioned_apac_people) == 0 and len(mentioned_apac_countries) == 0):
        print("Global Article")
        title = message.get('title', 'No Title Found')
        link = message.get('url', 'No url Found')

        with open("supportFile/GLOBAL.txt", "a", encoding="utf-8") as f:
            f.write(title + " || " + link + "\n")
        dbMongo.insert_logbook_entry("GLOBAL", message['title'], message['url'], str(message['posted_on']))

        if ttp_string:
            msg_data += f"<b>Related TTP</b>: {ttp_string}\n"

        article_dict = {
            "title": message.get('title', 'No Title Found'),
            "url": message.get('url', 'No url Found'),
            "posted_on": str(message.get('posted_on', '')),
            "source": source_name.lstrip(),
            "impacted_industries": industries_string.split(" || ") if industries_string else [],
            "mentioned_countries": list(dict.fromkeys(gpt_victim_countries + gpt_actor_countries)),
            "victim_countries": gpt_victim_countries,
            "actor_countries": gpt_actor_countries,
            "threat_actors": [],
            "ttps": ttp_list,
            "confidence": gpt_confidence,
            "confirmed_incident": gpt_confirmed_incident,
            "incident_confidence": gpt_incident_confidence,
            "incident_indicators": gpt_incident_indicators,
            "victim_name": gpt_victim_name,
            "iocs": ioc_data,
            "c2_indicator": c2_indicator,
        }

        for cve_id in cve_list:
            related_tech_cve_status = cveValidator.checkCVE(str(cve_id).upper())
            if related_tech_cve_status:
                break

        dbMongo.log_scraper_run(script_name, accepted=True, title=article_dict["title"], url=article_dict["url"])
        _sendAlert(related_tech_cve_status, related_tech_status, cve_list, report_status,
                   ot_status, msg_data, databreach_list, zero_day_list,
                   group_string="", news_type="global", news_dict=article_dict)

    elif len(mentioned_group) != 0 and (len(mentioned_apac_people) != 0 or len(mentioned_apac_countries) != 0):
        print("Regional and TA Group Article")
        for group in mentioned_group:
            if group in str(group_string).lower():
                continue
            group_string += str(group).capitalize().replace("\-", "-") + " || "

        for country in mentioned_countries:
            apac_string += str(country).capitalize() + " || "
        for apac in mentioned_apac_people:
            apac_string += str(apac).capitalize() + " || "

        group_string = group_string[:-4]
        apac_string = apac_string[:-4]

        msg_data += f"<b>Related Threat Actor</b>: {group_string}\n"
        msg_data += f"<b>Mentioned Country/People</b>: {apac_string}\n"
        if ttp_string:
            msg_data += f"<b>Related TTP</b>: {ttp_string}\n"

        title = message.get('title', 'No Title Found')
        link = message.get('url', 'No url Found')

        with open("supportFile/ThreatActorName.txt", "a", encoding="utf-8") as f:
            f.write(group_string + "\n")
        with open("supportFile/APAC.txt", "a", encoding="utf-8") as f:
            f.write(title + " || " + link + "\n")
        dbMongo.insert_logbook_entry("APAC", message['title'], message['url'], str(message['posted_on']))

        regex_countries = apac_string.split(" || ") if apac_string else []
        article_dict = {
            "title": message.get('title', 'No Title Found'),
            "url": message.get('url', 'No url Found'),
            "posted_on": str(message.get('posted_on', '')),
            "source": source_name.lstrip(),
            "impacted_industries": industries_string.split(" || ") if industries_string else [],
            "mentioned_countries": list(dict.fromkeys(regex_countries + gpt_victim_countries + gpt_actor_countries)),
            "victim_countries": gpt_victim_countries if gpt_victim_countries else regex_countries,
            "actor_countries": gpt_actor_countries,
            "threat_actors": group_string.split(" || ") if group_string else [],
            "ttps": ttp_list,
            "confidence": gpt_confidence,
            "confirmed_incident": gpt_confirmed_incident,
            "incident_confidence": gpt_incident_confidence,
            "incident_indicators": gpt_incident_indicators,
            "victim_name": gpt_victim_name,
            "iocs": ioc_data,
            "c2_indicator": c2_indicator,
        }

        dbMongo.log_scraper_run(script_name, accepted=True, title=article_dict["title"], url=article_dict["url"])
        _sendAlert(related_tech_cve_status, related_tech_status, cve_list, report_status,
                   ot_status, msg_data, databreach_list, zero_day_list,
                   group_string, news_type="apac", news_dict=article_dict)

    elif len(mentioned_group) == 0 and (len(mentioned_apac_people) != 0 or len(mentioned_apac_countries) != 0):
        print("Regional Article")
        for country in mentioned_countries:
            apac_string += str(country).capitalize() + " || "
        for apac in mentioned_apac_people:
            apac_string += str(apac).capitalize() + " || "
        apac_string = apac_string[:-4]

        msg_data += f"<b>Mentioned Country/People</b>: {apac_string}\n"
        if ttp_string:
            msg_data += f"<b>Related TTP</b>: {ttp_string}\n"

        title = message.get('title', 'No Title Found')
        link = message.get('url', 'No url Found')

        with open("supportFile/APAC.txt", "a", encoding="utf-8") as f:
            f.write(title + " || " + link + "\n")
        dbMongo.insert_logbook_entry("APAC", message['title'], message['url'], str(message['posted_on']))

        regex_countries = apac_string.split(" || ") if apac_string else []
        article_dict = {
            "title": message.get('title', 'No Title Found'),
            "url": message.get('url', 'No url Found'),
            "posted_on": str(message.get('posted_on', '')),
            "source": source_name.lstrip(),
            "impacted_industries": industries_string.split(" || ") if industries_string else [],
            "mentioned_countries": list(dict.fromkeys(regex_countries + gpt_victim_countries + gpt_actor_countries)),
            "victim_countries": gpt_victim_countries if gpt_victim_countries else regex_countries,
            "actor_countries": gpt_actor_countries,
            "threat_actors": [],
            "ttps": ttp_list,
            "confidence": gpt_confidence,
            "confirmed_incident": gpt_confirmed_incident,
            "incident_confidence": gpt_incident_confidence,
            "incident_indicators": gpt_incident_indicators,
            "victim_name": gpt_victim_name,
            "iocs": ioc_data,
            "c2_indicator": c2_indicator,
        }

        dbMongo.log_scraper_run(script_name, accepted=True, title=article_dict["title"], url=article_dict["url"])
        _sendAlert(related_tech_cve_status, related_tech_status, cve_list, report_status,
                   ot_status, msg_data, databreach_list, zero_day_list,
                   group_string="", news_type="apac", news_dict=article_dict)

    elif len(mentioned_group) != 0 and (len(mentioned_apac_people) == 0 or len(mentioned_apac_countries) == 0):
        print("TA Group Article")
        for group in mentioned_group:
            if group in str(group_string).lower():
                continue
            group_string += str(group).capitalize().replace("\-", "-") + " || "
        group_string = group_string[:-4]

        msg_data += f"<b>Related Threat Actor</b>: {group_string}\n"
        if ttp_string:
            msg_data += f"<b>Related TTP</b>: {ttp_string}\n"

        title = message.get('title', 'No Title Found')
        link = message.get('url', 'No url Found')

        with open("supportFile/GLOBAL.txt", "a", encoding="utf-8") as f:
            f.write(title + " || " + link + "\n")
        dbMongo.insert_logbook_entry("APT", message['title'], message['url'], str(message['posted_on']))
        with open("supportFile/ThreatActorName.txt", "a", encoding="utf-8") as f:
            f.write(group_string + "\n")

        article_dict = {
            "title": message.get('title', 'No Title Found'),
            "url": message.get('url', 'No url Found'),
            "posted_on": str(message.get('posted_on', '')),
            "source": source_name.lstrip(),
            "impacted_industries": industries_string.split(" || ") if industries_string else [],
            "mentioned_countries": list(dict.fromkeys(gpt_victim_countries + gpt_actor_countries)),
            "victim_countries": gpt_victim_countries,
            "actor_countries": gpt_actor_countries,
            "threat_actors": group_string.split(" || ") if group_string else [],
            "ttps": ttp_list,
            "confidence": gpt_confidence,
            "confirmed_incident": gpt_confirmed_incident,
            "incident_confidence": gpt_incident_confidence,
            "incident_indicators": gpt_incident_indicators,
            "victim_name": gpt_victim_name,
            "iocs": ioc_data,
            "c2_indicator": c2_indicator,
        }

        dbMongo.log_scraper_run(script_name, accepted=True, title=article_dict["title"], url=article_dict["url"])
        _sendAlert(related_tech_cve_status, related_tech_status, cve_list, report_status,
                   ot_status, msg_data, databreach_list, zero_day_list,
                   group_string, news_type="global", news_dict=article_dict)

    ### CVE mention tracking → MongoDB (replaces cve.json) ###
    if len(cve_list_body) != 0 or len(cve_list_title) != 0:
        curr_month = datetime.today().strftime("%Y-%m")
        for cve_id in cve_list_title + cve_list_body:
            dbMongo.update_cve_mention(curr_month, cve_id)
    ###########################################################

    return mentioned_group, mentioned_apac_people, mentioned_countries
