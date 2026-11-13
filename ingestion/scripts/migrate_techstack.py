"""One-time migration: import supportFile/techstack.txt into MongoDB threatintel.techstack"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from datetime import date
import yaml

with open("config/config.yml", 'r') as f:
    cfg = yaml.safe_load(f)

mc  = cfg['mongodb']
uri = (
    f"mongodb://{mc['user']}:{mc['pass']}@{mc['ip']}"
    f"/?authSource={mc['cluster']}&authMechanism=SCRAM-SHA-256"
)
client = MongoClient(uri)
col    = client[mc['cluster']]['techstack']
col.create_index("name", unique=True)

with open("supportFile/techstack.txt", 'r') as f:
    entries = [line.strip() for line in f if line.strip()]

inserted = 0
for name in entries:
    try:
        col.insert_one({"name": name, "added_date": str(date.today()), "source": "migration"})
        inserted += 1
        print(f"  + {name}")
    except DuplicateKeyError:
        print(f"  = {name} (already exists)")

client.close()
print(f"\nDone: {inserted}/{len(entries)} entries inserted.")
