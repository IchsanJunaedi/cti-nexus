#!/usr/bin/env python3
"""Count all news processed on a given day, straight from MongoDB.

Replaces the old file-based supportFile/counterAllNews_DD_MM_YYYY.txt counter,
which nlp_scan() used to bump on every article it picked up. Every scraped
article already becomes one row in nlp_jobs (see modules/jobQueue.py),
stamped with created_at when it enters the pipeline — counting those rows
per day is equivalent to (and more reliable than, since it also captures
failed jobs) the old increment-per-file counter.

Usage:
    python3 supportFile/countAllNewsDB.py               # today
    python3 supportFile/countAllNewsDB.py 03_06_2026    # specific day (DD_MM_YYYY)
"""
import sys
from datetime import datetime, timedelta

from modules.jobQueue import _get_col


def count_all_news(date_str: str = None) -> dict:
    """Return job counts by status for given local day (DD_MM_YYYY, default today)."""
    day = datetime.strptime(date_str, "%d_%m_%Y") if date_str else datetime.now()
    start_local = day.replace(hour=0, minute=0, second=0, microsecond=0)
    end_local = start_local + timedelta(days=1)

    # nlp_jobs.created_at is stored in UTC (datetime.utcnow()); convert local day bounds to UTC
    utc_offset = datetime.now() - datetime.utcnow()
    start_utc = start_local - utc_offset
    end_utc = end_local - utc_offset

    client, col = _get_col()
    try:
        query = {"created_at": {"$gte": start_utc, "$lt": end_utc}}
        total = col.count_documents(query)
        by_status = {
            status: col.count_documents({**query, "status": status})
            for status in ("completed", "filtered", "failed", "pending", "processing")
        }
    finally:
        client.close()

    return {"total": total, **by_status}


if __name__ == '__main__':
    date_arg = sys.argv[1] if len(sys.argv) > 1 else None
    counts = count_all_news(date_arg)
    label = date_arg or datetime.now().strftime('%d_%m_%Y')
    print(f"=== ALL NEWS COUNT FOR {label} ===")
    for key, value in counts.items():
        print(f"{key:<12}: {value}")
