"""Standalone unit checks for IOC technical-intel logic. No DB, no server.
Run: python test_ioc_logic.py
"""
import asyncio
from datetime import datetime, timezone, timedelta
from app.services.confidence_service import (
    compute_ioc_confidence, compute_ioc_actionability, _enrichment_signal,
)
from app.services.newsletter_service import extract_iocs

now = datetime.now(timezone.utc)
today = now.strftime("%Y-%m-%d")
old = (now - timedelta(days=120)).strftime("%Y-%m-%d")
fails = []


def check(name, cond):
    print(f"{'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails.append(name)


# P1-A: enrichment lifts confidence
base = {"type": "ip", "value": "1.2.3.4", "last_seen": today, "seen_count": 1, "sources": []}
mal = {**base, "enrichment": {"providers": [
    {"verdict": "malicious", "score": 90}, {"verdict": "malicious", "score": 80}]}}
clean = {**base, "enrichment": {"providers": [{"verdict": "clean", "score": 5}]}}
check("malicious confidence > plain", compute_ioc_confidence(mal, now) > compute_ioc_confidence(base, now))
check("clean confidence < plain", compute_ioc_confidence(clean, now) < compute_ioc_confidence(base, now))
check("_enrichment_signal counts", _enrichment_signal(mal)["malicious"] == 2)

# P1-A: 2 malicious -> block_now regardless of recency (old IOC)
old_mal = {**mal, "last_seen": old}
act = asyncio.run(compute_ioc_actionability(old_mal, now))
check("2x malicious -> block_now even when old", act["actionability_label"] == "block_now")

# P3: dead liveness downgrades block_now
dead = {**mal, "liveness": "dead"}
act_dead = asyncio.run(compute_ioc_actionability(dead, now))
check("dead -> not block_now", act_dead["actionability_label"] != "block_now")
sink = {**mal, "liveness": "sinkholed"}
act_sink = asyncio.run(compute_ioc_actionability(sink, now))
check("sinkholed -> archive", act_sink["actionability_label"] == "archive")

# Extraction still works (regression)
iocs = extract_iocs("contact evil[.]com from 8.8.8.8 hash d41d8cd98f00b204e9800998ecf8427e CVE-2024-1234")
check("extract domain", "evil.com" in iocs.get("domains", []) or "evil[.]com" in str(iocs))
check("extract cve", "CVE-2024-1234" in iocs.get("cves", []))

print(f"\n{len(fails)} failures" if fails else "\nALL PASS")
