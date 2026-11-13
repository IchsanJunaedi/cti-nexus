from pymongo import MongoClient
from datetime import datetime
import yaml

with open("config/config.yml", 'r') as _f:
    _cfg = yaml.safe_load(_f)

_mc = _cfg['mongodb']
_URI = (
    f"mongodb://{_mc['user']}:{_mc['pass']}@{_mc['ip']}"
    f"/?authSource={_mc['cluster']}&authMechanism=SCRAM-SHA-256"
)
_DB   = _mc['cluster']   # "threatintel"
_COL  = "techstack"

_CACHE_TTL_SECONDS = 300
_cache: list[str] = []
_cache_at: datetime | None = None
_cache_by_client: dict[str, list[str]] = {}
_cache_by_client_at: datetime | None = None


def _get_col():
    client = MongoClient(_URI)
    return client, client[_DB][_COL]


def get_tech_list() -> list[str]:
    """Backward-compat: return ALL techs across all clients (for single-tenant usage)."""
    global _cache, _cache_at
    now = datetime.utcnow()
    if _cache and _cache_at and (now - _cache_at).total_seconds() < _CACHE_TTL_SECONDS:
        return _cache

    client, col = _get_col()
    try:
        _cache = sorted([t['name'] for t in col.find({}, {"name": 1}) if t.get('name')])
        _cache_at = now
        return _cache
    finally:
        client.close()


def get_tech_list_by_client() -> dict[str, list[str]]:
    """Return {client_id: [tech_names]} for all clients. Docs without client_id → 'default'."""
    global _cache_by_client, _cache_by_client_at
    now = datetime.utcnow()
    if _cache_by_client and _cache_by_client_at and (now - _cache_by_client_at).total_seconds() < _CACHE_TTL_SECONDS:
        return _cache_by_client

    client, col = _get_col()
    try:
        result: dict[str, list[str]] = {}
        for doc in col.find({}, {"name": 1, "client_id": 1}):
            name = doc.get('name')
            if not name:
                continue
            cid = doc.get('client_id') or 'default'
            result.setdefault(cid, []).append(name)
        for cid in result:
            result[cid] = sorted(result[cid])
        _cache_by_client = result
        _cache_by_client_at = now
        return result
    finally:
        client.close()
