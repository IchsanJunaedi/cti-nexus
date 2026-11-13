#!/usr/bin/env python3
"""
Standalone CVE query per client, for manual alert scripting.
Reads same env vars as app/config.py (MONGO_USER, MONGO_PASS, MONGO_HOST,
MONGO_PORT, DB_NAME, TA_MONGO_USER, TA_MONGO_PASS, TA_DB_NAME).

Usage:
  python scripts/query_cve_per_client.py --client <client_id> [--severity CRITICAL,HIGH] [--kev-only] [--min-epss 0.5] [--json]
  python scripts/query_cve_per_client.py --all-clients
"""
import argparse
import json
import os
import sys

from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_USER = os.getenv("MONGO_USER", "")
MONGO_PASS = os.getenv("MONGO_PASS", "")
MONGO_HOST = os.getenv("MONGO_HOST", "")
MONGO_PORT = os.getenv("MONGO_PORT", "")
DB_NAME = os.getenv("DB_NAME", "")
MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/?authSource={DB_NAME}"

TA_MONGO_USER = os.getenv("TA_MONGO_USER", "")
TA_MONGO_PASS = os.getenv("TA_MONGO_PASS", "")
TA_DB_NAME = os.getenv("TA_DB_NAME", "")
TA_MONGO_URI = (
    f"mongodb://{TA_MONGO_USER}:{TA_MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}"
    f"/?authSource={TA_DB_NAME}&authMechanism=SCRAM-SHA-256"
)

CLIENTS_COLLECTION = os.getenv("CLIENTS_COLLECTION", "clients")
TECHSTACK_COLLECTION = os.getenv("TECHSTACK_COLLECTION", "techstack")
CVE_COLLECTION = "cve_tracker"


def get_dbs():
    db = MongoClient(MONGO_URI)[DB_NAME]
    ta_db = MongoClient(TA_MONGO_URI)[TA_DB_NAME]
    return db, ta_db


def active_tech_names(ta_db, client_id):
    docs = ta_db[TECHSTACK_COLLECTION].find(
        {"client_id": client_id, "active": {"$ne": False}}, {"name": 1}
    )
    return [d["name"] for d in docs if d.get("name")]


def query_cves_for_client(db, ta_db, client_id, severities=None, kev_only=False, min_epss=None, tech=None):
    query = {"client_id": client_id}

    techs = tech or active_tech_names(ta_db, client_id)
    if techs:
        query["tech"] = {"$in": techs}

    if severities:
        query["cve_severity"] = {"$in": [s.upper() for s in severities]}

    if kev_only:
        query["cisa_kev"] = True

    if min_epss is not None:
        query["epss_score"] = {"$gte": min_epss}

    return list(db[CVE_COLLECTION].find(query).sort("cve_score", -1))


def list_client_ids(db):
    return [c["_id"] if "_id" in c else c.get("client_id") for c in db[CLIENTS_COLLECTION].find({}, {"_id": 1})]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", help="client_id to query")
    ap.add_argument("--all-clients", action="store_true", help="run for every client in CLIENTS_COLLECTION")
    ap.add_argument("--severity", help="comma-separated: CRITICAL,HIGH,MEDIUM,LOW")
    ap.add_argument("--kev-only", action="store_true", help="only CISA KEV-listed CVEs")
    ap.add_argument("--min-epss", type=float, help="minimum EPSS score, e.g. 0.5")
    ap.add_argument("--tech", help="comma-separated tech names to filter, overrides active techstack lookup")
    ap.add_argument("--json", action="store_true", help="output raw JSON instead of table")
    args = ap.parse_args()

    if not args.client and not args.all_clients:
        ap.error("need --client <id> or --all-clients")

    db, ta_db = get_dbs()
    severities = args.severity.split(",") if args.severity else None
    tech = args.tech.split(",") if args.tech else None

    client_ids = list_client_ids(db) if args.all_clients else [args.client]

    results = {}
    for cid in client_ids:
        cves = query_cves_for_client(db, ta_db, cid, severities, args.kev_only, args.min_epss, tech)
        results[cid] = cves

    if args.json:
        print(json.dumps(results, default=str, indent=2))
        return

    for cid, cves in results.items():
        print(f"\n=== client: {cid} ({len(cves)} cve) ===")
        for c in cves:
            print(
                f"  {c.get('cve_id'):18} sev={c.get('cve_severity'):8} "
                f"score={c.get('cve_score')}  kev={c.get('cisa_kev')}  "
                f"epss={c.get('epss_score')}  tech={c.get('tech')}"
            )


if __name__ == "__main__":
    sys.exit(main())
