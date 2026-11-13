from collections import defaultdict
from datetime import datetime, timedelta
import asyncio

_buckets: dict[str, list[datetime]] = defaultdict(list)
_lock = asyncio.Lock()


async def is_rate_limited(key: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
    async with _lock:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        _buckets[key] = [t for t in _buckets[key] if t > cutoff]
        if len(_buckets[key]) >= max_requests:
            return True
        _buckets[key].append(now)
        return False
