"""
One-time script: remove duplicate URL entries from news_db.articles,
then build the unique index so future writes are protected.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pymongo import MongoClient
import yaml

with open("config/config.yml", 'r') as f:
    cfg = yaml.safe_load(f)

nc  = cfg['news_db']
uri = f"mongodb://{nc['user']}:{nc['pass']}@{nc['ip']}/?authSource={nc['db']}"
client = MongoClient(uri)
col    = client[nc['db']]['articles']

# Drop the broken unique index if it exists in a partial/failed state
for idx in col.list_indexes():
    if idx.get("key") == {"url": 1} and idx.get("unique"):
        print(f"Dropping existing unique index on url...")
        col.drop_index("url_1")
        break

# Find all URLs with more than one document
pipeline = [
    {"$group": {"_id": "$url", "ids": {"$push": "$_id"}, "count": {"$sum": 1}}},
    {"$match": {"count": {"$gt": 1}}},
]

duplicate_groups = list(col.aggregate(pipeline))
print(f"Found {len(duplicate_groups)} URL(s) with duplicates.")

total_deleted = 0
for group in duplicate_groups:
    # Keep the first inserted (_id is ObjectId, so first = smallest)
    ids_to_delete = sorted(group["ids"])[1:]
    result = col.delete_many({"_id": {"$in": ids_to_delete}})
    total_deleted += result.deleted_count
    print(f"  {group['_id'][:80]}… — kept 1, deleted {result.deleted_count}")

print(f"\nTotal deleted: {total_deleted}")

# Now it's safe to build the unique index
print("Building unique index on url...")
col.create_index("url", unique=True, background=False)
print("Done.")

client.close()
