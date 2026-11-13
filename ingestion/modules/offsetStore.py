from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from datetime import datetime
import yaml

with open("config/config.yml", 'r') as f:
    cfg = yaml.safe_load(f)

_CONNECTION_STRING = (
    f"mongodb://{cfg['mongodb']['user']}:{cfg['mongodb']['pass']}"
    f"@{cfg['mongodb']['ip']}/?authSource={cfg['mongodb']['cluster']}"
    f"&authMechanism=SCRAM-SHA-256"
)
_DB_NAME = cfg['mongodb']['collection']

_client = None
_col = None

def _get_col():
    global _client, _col
    if _col is None:
        _client = MongoClient(_CONNECTION_STRING)
        _col = _client[_DB_NAME]['offsets']
        _col.create_index([("script", 1), ("key", 1)], unique=True, background=True)
    return _col

def is_new_and_mark(script_name: str, key: str) -> bool:
    """Return True and record the key if it has never been seen; False if duplicate."""
    col = _get_col()
    try:
        col.insert_one({
            "script": script_name,
            "key": key,
            "seen_at": datetime.utcnow(),
        })
        return True
    except DuplicateKeyError:
        return False
