from pymongo import MongoClient
from pymongo.operations import UpdateOne
from pymongo.errors import DuplicateKeyError, OperationFailure
from datetime import datetime
import sys, yaml, re

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

CONNECTION_STRING = f"mongodb://{cfg['mongodb']['user']}:{cfg['mongodb']['pass']}@{cfg['mongodb']['ip']}/?authSource={cfg['mongodb']['cluster']}&authMechanism=SCRAM-SHA-256"
_NEWS_DB_URI = (
    f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
    f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
)

client = MongoClient(CONNECTION_STRING)

# Use db named testing-ti
mydb = client[f"{cfg['mongodb']['collection']}"]

def insert_database(list_data, type_data):
    # Provide the mongodb atlas url to connect python to mongodb using pymongo
    mycol = mydb[type_data]
    x = mycol.insert_many(list_data)

    return "OK"

def list_existing(type_data):
    mycol = mydb[type_data]
    list_existing_data = mycol.find()

    return list_existing_data

def delete_existing(type_data):
    mycol = mydb[type_data]
    for x in mycol.find():
        mycol.delete_one({"_id" : x['_id']})

    return

def count_existing(type_data):
    start_time = datetime.now()
    mycol = mydb[type_data]
    counter = 0

    print("collection name: threatintel-" + str(type_data))
    print("total data: " + str(mydb.command('collstats', type_data)['count']))
    print("total size: " + str(mydb.command('collstats', type_data)['size']/1000000) + " Mb")
    print("total execution time : " + str(datetime.now() - start_time))

    return

def upsert_article(article_dict: dict) -> None:
    """Upsert an article into news_db.articles (deduplicates on url)."""
    now = datetime.now()
    doc = {
        "year": now.year,
        "month": now.strftime("%B").lower(),
        "week": f"W{(now.day - 1) // 7 + 1}",
        **article_dict,
    }
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['articles']
        col.update_one({"url": doc["url"]}, {"$setOnInsert": doc}, upsert=True)
    except DuplicateKeyError:
        pass  # already exists — safe to skip
    finally:
        news_client.close()

def update_cve_mention(year_month: str, cve_id: str) -> None:
    """Increment the mention counter for a CVE in news_db.cve_mentions."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['cve_mentions']
        col.update_one(
            {"year_month": year_month, "cve_id": cve_id},
            {
                "$set": {"update_time": datetime.today().strftime("%Y-%m-%d")},
                "$inc": {"counter": 1},
                "$setOnInsert": {"created_at": datetime.utcnow()},
            },
            upsert=True,
        )
    finally:
        news_client.close()

def get_cve_mentions(year_month: str) -> list:
    """Return all CVE mention docs for the given year_month string (e.g. '2026-04')."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['cve_mentions']
        return list(col.find({"year_month": year_month}))
    finally:
        news_client.close()

def get_ioc_allowlist() -> dict:
    """Load ioc_allowlist from news_db. Returns {url_domains: set, email_domains: set}."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['ioc_allowlist']
        url_domains: set = set()
        email_domains: set = set()
        ips: set = set()
        for doc in col.find({}):
            if doc.get("type") == "url_domain":
                url_domains.add(doc["value"].lower())
            elif doc.get("type") == "email_domain":
                email_domains.add(doc["value"].lower())
            elif doc.get("type") == "ip":
                ips.add(doc["value"])
        return {"url_domains": url_domains, "email_domains": email_domains, "ips": ips}
    finally:
        news_client.close()


def upsert_alert(kind: str, key: str, message: str, source: str | None = None, **extra) -> bool:
    """Store a feed item in news_db.alerts (replaces the old Telegram notifications).

    Dedupes on (kind, key). `message` is the HTML-formatted text the alert used to carry;
    extra fields (title, url, ...) are stored alongside it. Returns True if new."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['alerts']
        col.create_index([("kind", 1), ("key", 1)], unique=True, background=True)
        now = datetime.utcnow()
        result = col.update_one(
            {"kind": kind, "key": str(key)},
            {"$setOnInsert": {
                "kind": kind,
                "key": str(key),
                "source": source,
                "message": message,
                "created_at": now,
                **extra,
            }},
            upsert=True,
        )
        return result.upserted_id is not None
    except DuplicateKeyError:
        return False
    finally:
        news_client.close()


def log_scraper_run(script_name: str, accepted: bool, title: str, url: str) -> None:
    """Write one row per processed article to news_db.scraper_runs for health monitoring."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['scraper_runs']
        col.insert_one({
            "script": script_name,
            "accepted": accepted,
            "title": title,
            "url": url,
            "run_at": datetime.utcnow(),
        })
    except Exception:
        pass  # health logging must never crash the scraper
    finally:
        news_client.close()


def upsert_ransomware_victim(victim_dict: dict) -> bool:
    """Upsert a ransomware victim into news_db.ransomware_victims. Returns True if new."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['ransomware_victims']
        col.create_index("offset_key", unique=True, background=True)
        result = col.update_one(
            {"offset_key": victim_dict["offset_key"]},
            {"$setOnInsert": victim_dict},
            upsert=True,
        )
        return result.upserted_id is not None
    except DuplicateKeyError:
        return False
    finally:
        news_client.close()


def add_ta_aliases(name: str, aliases: list[str]) -> None:
    """Add aliases to the existing threatintel.groups doc matching name (by core name). No-op if none."""
    core = _normalize_actor_core(name)
    if not core or not aliases:
        return
    try:
        for existing in mydb["groups"].find({}, {"name": 1, "aliases": 1}):
            variants = [existing["name"]] + existing.get("aliases", [])
            if any(_normalize_actor_core(v) == core for v in variants):
                mydb["groups"].update_one(
                    {"_id": existing["_id"]},
                    {"$addToSet": {"aliases": {"$each": aliases}}},
                )
                return
    except Exception:
        pass


def upsert_dls_group(group_dict: dict) -> bool:
    """Upsert a leak-site group into news_db.dls_groups keyed on name_norm.

    Uses $set (not $setOnInsert): host availability / lastscrape change upstream.
    Returns True if new.
    """
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['dls_groups']
        try:
            col.create_index("name_norm", unique=True, background=True)
        except OperationFailure as e:
            if e.code != 86:  # IndexKeySpecsConflict: non-unique index made by web app
                raise
            col.drop_index("name_norm_1")
            col.create_index("name_norm", unique=True, background=True)
        col.create_index("aliases_norm", background=True)
        result = col.update_one(
            {"name_norm": group_dict["name_norm"]},
            {"$set": group_dict},
            upsert=True,
        )
        return result.upserted_id is not None
    except DuplicateKeyError:
        return False
    finally:
        news_client.close()


def get_existing_ransomware_keys() -> set:
    """Return set of offset_key strings already in ransomware_victims."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['ransomware_victims']
        return {doc['offset_key'] for doc in col.find({}, {'offset_key': 1, '_id': 0})}
    finally:
        news_client.close()


def get_openai_cache(url: str) -> dict | None:
    """Return cached OpenAI results for url, or None on miss."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['openai_cache']
        return col.find_one({"url": url}, {"_id": 0})
    finally:
        news_client.close()


def set_openai_cache(url: str, validator_result: dict, ttp_result: dict | None = None) -> None:
    """Upsert OpenAI results for url. TTL index auto-expires docs after 30 days."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['openai_cache']
        col.create_index("cached_at", expireAfterSeconds=30 * 24 * 3600, background=True)
        update: dict = {"$set": {"validator_result": validator_result, "cached_at": datetime.utcnow()}}
        if ttp_result is not None:
            update["$set"]["ttp_result"] = ttp_result
        col.update_one({"url": url}, update, upsert=True)
    except Exception:
        pass  # cache write must never crash the scraper
    finally:
        news_client.close()


def reset_cve_counter(year_month: str, cve_id: str) -> None:
    """Reset the mention counter to 0 after weekly report is sent."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['cve_mentions']
        col.update_one(
            {"year_month": year_month, "cve_id": cve_id},
            {"$set": {"counter": 0, "update_time": datetime.today().strftime("%Y-%m-%d")}},
        )
    finally:
        news_client.close()


def list_monitored_accounts() -> list[str]:
    """Return active monitored X/Twitter usernames from news_db.monitored_accounts."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['monitored_accounts']
        return [doc['username'] for doc in col.find({'active': True}, {'username': 1, '_id': 0})]
    finally:
        news_client.close()


def tweet_exists(tweet_id: str) -> bool:
    """Return True if tweet_id already in news_db.tweets."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['tweets']
        return col.find_one({"tweet_id": tweet_id}, {"_id": 1}) is not None
    finally:
        news_client.close()


def upsert_tweet(tweet_dict: dict) -> bool:
    """Upsert a tweet into news_db.tweets (deduplicates on tweet_id). Returns True if new."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['tweets']
        result = col.update_one(
            {"tweet_id": tweet_dict["tweet_id"]},
            {"$setOnInsert": tweet_dict},
            upsert=True,
        )
        return result.upserted_id is not None
    except DuplicateKeyError:
        return False
    finally:
        news_client.close()


def insert_logbook_entry(category: str, title: str, url: str, posted_on: str) -> None:
    """Upsert a logbook entry into news_db.logbook_entries (deduplicates on url)."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['logbook_entries']
        col.update_one(
            {"url": url},
            {"$setOnInsert": {
                "category": category,
                "title": title,
                "url": url,
                "posted_on": posted_on,
                "reported": False,
                "created_at": datetime.utcnow(),
            }},
            upsert=True,
        )
    except Exception:
        pass
    finally:
        news_client.close()


def get_pending_logbook_entries() -> list:
    """Return all logbook entries not yet reported."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['logbook_entries']
        return list(col.find({"reported": False}, {"_id": 0}))
    finally:
        news_client.close()


def get_all_article_entries_in_period(start_date: datetime, end_date: datetime) -> list:
    """Return all articles entries (reported or not) with posted_on within [start_date, end_date]."""
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['articles']
        return list(col.find(
            {"posted_on": {"$gte": start_str, "$lte": end_str}},
            {"_id": 0},
        ).sort("posted_on", 1))
    finally:
        news_client.close()


def mark_logbook_entries_reported() -> None:
    """Mark all pending logbook entries as reported."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['logbook_entries']
        col.update_many({"reported": False}, {"$set": {"reported": True}})
    finally:
        news_client.close()


def get_logbook_last_date() -> str | None:
    """Return the last logbook report date string (e.g. '04-May-2026'), or None."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['logbook_meta']
        doc = col.find_one({"key": "last_report_date"})
        return doc["value"] if doc else None
    finally:
        news_client.close()


def set_logbook_last_date(date_str: str) -> None:
    """Upsert the last logbook report date."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['logbook_meta']
        col.update_one(
            {"key": "last_report_date"},
            {"$set": {"value": date_str}},
            upsert=True,
        )
    finally:
        news_client.close()

def upsert_ioc_from_feed(ioc_type: str, value: str, source_name: str = "deepdarkCTI", tags: list | None = None) -> bool:
    """Upsert IOC from threat feed into news_db.iocs. Returns True if new."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['iocs']
        now = datetime.utcnow()
        source_entry = {
            "url": "https://github.com/fastfire/deepdarkCTI",
            "source_name": source_name,
            "added_at": now,
        }
        existing = col.find_one({"type": ioc_type, "value": value})
        if existing:
            known_sources = {s.get("source_name") for s in existing.get("sources", [])}
            if source_name not in known_sources:
                col.update_one(
                    {"type": ioc_type, "value": value},
                    {"$push": {"sources": source_entry}, "$set": {"last_seen": now}},
                )
            return False
        col.insert_one({
            "type": ioc_type,
            "value": value,
            "sources": [source_entry],
            "tags": (tags or []) + ["deepdarkCTI"],
            "first_seen": now,
            "last_seen": now,
            "confidence_score": 50.0,
            "confidence_decayed_at": now,
            "feedback_log": [],
        })
        return True
    except Exception:
        return False
    finally:
        news_client.close()


def upsert_threat_feed(feed_name: str, ioc_type: str, value: str) -> None:
    """Upsert an entry in news_db.threat_feeds (used for C2/blocklist cross-reference)."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['threat_feeds']
        col.update_one(
            {"feed": feed_name, "type": ioc_type, "value": value},
            {"$setOnInsert": {
                "feed": feed_name,
                "type": ioc_type,
                "value": value,
                "added_at": datetime.utcnow(),
            }},
            upsert=True,
        )
    except Exception:
        pass
    finally:
        news_client.close()


def get_c2_feed_set() -> dict:
    """Load C2 IPs and domains from news_db.threat_feeds. Returns {ips: set, domains: set}."""
    news_client = MongoClient(_NEWS_DB_URI)
    try:
        col = news_client[cfg['news_db']['db']]['threat_feeds']
        ips: set = set()
        domains: set = set()
        for doc in col.find({"feed": "deepdarkCTI_c2"}, {"type": 1, "value": 1, "_id": 0}):
            if doc["type"] == "ip":
                ips.add(doc["value"])
            else:
                domains.add(doc["value"].lower())
        return {"ips": ips, "domains": domains}
    finally:
        news_client.close()


_GENERIC_NAME_TOKENS = {
    "ransomware", "group", "gang", "team", "the", "cybercrime", "criminal",
    "collective", "organization", "org", "actor", "apt",
}


def _normalize_actor_core(name: str) -> str:
    tokens = re.findall(r"[a-z0-9]+", str(name).lower())
    core = [t for t in tokens if t not in _GENERIC_NAME_TOKENS]
    return " ".join(core) if core else " ".join(tokens)


def upsert_ta_group_from_feed(name: str, extra: dict | None = None) -> bool:
    """Upsert threat actor group into threatintel.groups. Returns True if new.

    Folds near-duplicate names (e.g. "Everest" vs "Everest Ransomware Group")
    into the existing doc's aliases instead of creating a second top-level entry.
    """
    try:
        exact = mydb["groups"].find_one({"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}})
        if exact:
            return False

        core = _normalize_actor_core(name)
        if core:
            for existing in mydb["groups"].find({}, {"name": 1, "aliases": 1}):
                variants = [existing["name"]] + existing.get("aliases", [])
                if any(_normalize_actor_core(v) == core for v in variants):
                    mydb["groups"].update_one(
                        {"_id": existing["_id"]},
                        {"$addToSet": {"aliases": name}},
                    )
                    return False

        result = mydb["groups"].update_one(
            {"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}},
            {"$setOnInsert": {"name": name, "aliases": [], **(extra or {}), "source": "deepdarkCTI"}},
            upsert=True,
        )
        return result.upserted_id is not None
    except Exception:
        return False


# for ioc in list_existing('apac-country'):
#     print(ioc)
# count_existing("apac-country")