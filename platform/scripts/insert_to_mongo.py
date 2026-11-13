import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from pymongo import MongoClient
from pymongo.operations import UpdateOne

_TRACKING_PARAMS = frozenset({
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'utm_id', 'utm_source_platform', 'utm_creative_format', 'utm_marketing_tactic',
    'fbclid', 'gclid', 'gclsrc', 'dclid', 'msclkid', 'twclid', 'li_fat_id',
    'mc_cid', 'mc_eid', 'igshid', '_ga', '_gl',
})


def normalize_url(url: str) -> str:
    """Strip tracking query parameters from a URL."""
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        params = parse_qs(parsed.query, keep_blank_values=True)
        cleaned = {k: v for k, v in params.items() if k.lower() not in _TRACKING_PARAMS}
        return urlunparse(parsed._replace(query=urlencode(cleaned, doseq=True)))
    except Exception:
        return url

# MONGO_URI = "mongodb://localhost:27017"

MONGO_USER = "ti-news"
MONGO_PASS = "ElbiRxywfCcolEI"
MONGO_HOST = "10.8.20.78"
MONGO_PORT = "27017"
DB_NAME = "news_db"
COLLECTION_NAME = "articles"

MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/?authSource={DB_NAME}"

def load_and_insert():
    with open("dbSchema.json", "r") as f:
        data = json.load(f)

    documents = []
    for year, months in data.items():
        for month, weeks in months.items():
            for week, articles in weeks.items():
                for article in articles:
                    doc = {
                        "year": int(year),
                        "month": month,
                        "week": week,
                        **article,
                    }
                    documents.append(doc)

    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    # Ensure a unique index on `url` so the DB itself enforces no duplicates
    collection.create_index("url", unique=True, background=True)

    # Build bulk upsert operations — insert only if url not already present
    for doc in documents:
        doc["url"] = normalize_url(doc["url"])

    ops = [
        UpdateOne({"url": doc["url"]}, {"$setOnInsert": doc}, upsert=True)
        for doc in documents
    ]

    result = collection.bulk_write(ops, ordered=False)
    inserted  = result.upserted_count
    skipped   = len(documents) - inserted

    print(f"Processed {len(documents)} articles from dbSchema.json")
    print(f"  Inserted : {inserted}")
    print(f"  Skipped  : {skipped} (already in DB)")

    client.close()

if __name__ == "__main__":
    load_and_insert()
