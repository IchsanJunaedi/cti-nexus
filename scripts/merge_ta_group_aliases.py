#!/usr/bin/env python3
"""
Dedup near-duplicate threat actor group entries (e.g. "Everest", "Everest Group",
"Everest Ransomware Group" all being the same actor as 3 separate docs).

Clusters groups.<collection> docs by a normalized "core" name — lowercase,
tokenized, with generic filler words (ransomware/group/gang/team/apt/...) stripped.
Docs sharing a core get merged: shortest name becomes canonical, the rest fold
into its `aliases` array and their docs are deleted. Existing news article
`threat_actors` arrays are rewritten so historical stats/trends stay correct.

Usage:
  python scripts/merge_ta_group_aliases.py --dry-run
  python scripts/merge_ta_group_aliases.py
"""

import argparse
import os
import re
from collections import defaultdict
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

TA_URI = (
    f"mongodb://{os.getenv('TA_MONGO_USER')}:{os.getenv('TA_MONGO_PASS')}"
    f"@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/"
    f"?authSource={os.getenv('TA_DB_NAME')}&authMechanism=SCRAM-SHA-256"
)
NEWS_URI = (
    f"mongodb://{os.getenv('MONGO_USER')}:{os.getenv('MONGO_PASS')}"
    f"@{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/"
    f"?authSource={os.getenv('DB_NAME')}"
)
TA_DB_NAME             = os.getenv("TA_DB_NAME", "threatintel")
TA_GROUPS_COLLECTION   = os.getenv("TA_GROUPS_COLLECTION", "groups")
DB_NAME                = os.getenv("DB_NAME", "")
NEWS_COLLECTION_NAME   = os.getenv("COLLECTION_NAME", "")

_GENERIC_NAME_TOKENS = {
    "ransomware", "group", "gang", "team", "the", "cybercrime", "criminal",
    "collective", "organization", "org", "actor", "apt",
}


def normalize_actor_core(name: str) -> str:
    tokens = re.findall(r"[a-z0-9]+", str(name).lower())
    core = [t for t in tokens if t not in _GENERIC_NAME_TOKENS]
    return " ".join(core) if core else " ".join(tokens)


def main():
    parser = argparse.ArgumentParser(description="Merge near-duplicate TA group entries into aliases")
    parser.add_argument("--dry-run", action="store_true", help="Print planned merges without writing")
    args = parser.parse_args()

    ta_client = MongoClient(TA_URI)
    groups_col = ta_client[TA_DB_NAME][TA_GROUPS_COLLECTION]

    news_client = MongoClient(NEWS_URI)
    news_col = news_client[DB_NAME][NEWS_COLLECTION_NAME] if DB_NAME and NEWS_COLLECTION_NAME else None

    docs = list(groups_col.find({}))
    clusters: dict[str, list[dict]] = defaultdict(list)
    for doc in docs:
        name = doc.get("name", "")
        if not name or str(name).startswith("["):
            continue
        clusters[normalize_actor_core(name)].append(doc)

    dupe_clusters = {k: v for k, v in clusters.items() if len(v) > 1}

    if not dupe_clusters:
        print("No near-duplicate groups found. Nothing to do.")
        return

    print(f"Found {len(dupe_clusters)} cluster(s) with near-duplicate names:")

    total_merged_docs = 0
    total_articles_updated = 0

    for core, members in dupe_clusters.items():
        members_sorted = sorted(members, key=lambda d: (len(d["name"]), d["name"]))
        canonical = members_sorted[0]
        duplicates = members_sorted[1:]

        folded_names = []
        for dup in duplicates:
            folded_names.append(dup["name"])
            folded_names.extend(dup.get("aliases", []))

        existing_aliases = canonical.get("aliases", [])
        new_aliases = list(dict.fromkeys(existing_aliases + folded_names))
        new_aliases = [a for a in new_aliases if a.lower() != canonical["name"].lower()]

        print(f"\n  cluster '{core}':")
        print(f"    canonical -> \"{canonical['name']}\" (_id={canonical['_id']})")
        for dup in duplicates:
            print(f"    fold      <- \"{dup['name']}\" (_id={dup['_id']})")

        if args.dry_run:
            continue

        groups_col.update_one({"_id": canonical["_id"]}, {"$set": {"aliases": new_aliases}})
        groups_col.delete_many({"_id": {"$in": [d["_id"] for d in duplicates]}})
        total_merged_docs += len(duplicates)

        if news_col is not None:
            for old_name in folded_names:
                if old_name.lower() == canonical["name"].lower():
                    continue
                result = news_col.update_many(
                    {"threat_actors": {"$regex": f"^{re.escape(old_name)}$", "$options": "i"}},
                    {"$addToSet": {"threat_actors": canonical["name"]}},
                )
                total_articles_updated += result.modified_count
                news_col.update_many(
                    {},
                    {"$pull": {"threat_actors": {"$regex": f"^{re.escape(old_name)}$", "$options": "i"}}},
                )

    if args.dry_run:
        print("\nDry run — no changes written.")
    else:
        print(f"\nMerged {total_merged_docs} duplicate doc(s); updated threat_actors on {total_articles_updated} article(s).")

    ta_client.close()
    news_client.close()


if __name__ == "__main__":
    main()
