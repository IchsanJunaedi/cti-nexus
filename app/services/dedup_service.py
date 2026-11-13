from datetime import datetime, timedelta

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.database import get_database
from app.config import COLLECTION_NAME


# ── Union-Find ────────────────────────────────────────────────────────────────

def _make_uf(n: int):
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    return find, union


# ── Public service functions ──────────────────────────────────────────────────

async def find_dedup_groups(
    articles: list[dict],
    threshold: float = 0.75,
) -> list[dict]:
    """
    Groups articles with cosine similarity > threshold on title TF-IDF.
    Returns list of canonical articles (one per group), each annotated with:
      _dup_count: int (total in group)
      _dup_sources: list[str] (sources of duplicates, excluding canonical)
      _dup_urls: list[str]
    Articles with no near-duplicates are returned unchanged with _dup_count=1.
    Canonical = first article in group (articles assumed sorted by posted_on desc).
    """
    if len(articles) < 2:
        for a in articles:
            a.setdefault("_dup_count", 1)
            a.setdefault("_dup_sources", [])
            a.setdefault("_dup_urls", [])
        return articles

    # Separate articles with non-empty titles from those without
    valid_indices = [i for i, a in enumerate(articles) if a.get("title", "").strip()]
    invalid_indices = [i for i, a in enumerate(articles) if not a.get("title", "").strip()]

    if len(valid_indices) < 2:
        # Not enough titled articles to compare — return all as singletons
        for a in articles:
            a.setdefault("_dup_count", 1)
            a.setdefault("_dup_sources", [])
            a.setdefault("_dup_urls", [])
        return articles

    titles = [articles[i]["title"].strip() for i in valid_indices]

    try:
        vectorizer = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            min_df=1,
        )
        tfidf_matrix = vectorizer.fit_transform(titles)
    except ValueError:
        # Vectorization failed (e.g., all empty after preprocessing)
        for a in articles:
            a.setdefault("_dup_count", 1)
            a.setdefault("_dup_sources", [])
            a.setdefault("_dup_urls", [])
        return articles

    sim_matrix = cosine_similarity(tfidf_matrix)
    n = len(valid_indices)

    find, union = _make_uf(n)

    # Only scan upper triangle
    for i in range(n):
        for j in range(i + 1, n):
            if sim_matrix[i, j] > threshold:
                union(i, j)

    # Build groups: root -> list of positions in valid_indices
    groups: dict[int, list[int]] = {}
    for pos in range(n):
        root = find(pos)
        groups.setdefault(root, []).append(pos)

    # Build result: one canonical per group + untitled articles as singletons
    result: list[dict] = []

    # Track which original indices have been placed
    placed: set[int] = set()

    for root, positions in groups.items():
        orig_indices = [valid_indices[p] for p in positions]
        # Canonical = first in the positions list (articles already sorted desc by posted_on)
        canonical_orig_idx = orig_indices[0]
        canonical = articles[canonical_orig_idx]
        dup_orig_indices = orig_indices[1:]

        canonical["_dup_count"] = len(orig_indices)
        canonical["_dup_sources"] = [
            articles[i].get("source", "") for i in dup_orig_indices if articles[i].get("source")
        ]
        canonical["_dup_urls"] = [
            articles[i].get("url", "") for i in dup_orig_indices if articles[i].get("url")
        ]

        result.append(canonical)
        for i in orig_indices:
            placed.add(i)

    # Add back any untitled articles as singletons
    for i in invalid_indices:
        a = articles[i]
        a.setdefault("_dup_count", 1)
        a.setdefault("_dup_sources", [])
        a.setdefault("_dup_urls", [])
        result.append(a)

    return result


async def get_dedup_groups(
    days: int = 7,
    threshold: float = 0.75,
    limit: int = 500,
) -> dict:
    """
    Fetches recent articles, runs dedup, returns only groups with >1 article.
    Returns: {"groups": [...], "total_articles": int, "total_groups": int, "duplicates_suppressed": int}
    """
    col = get_database()[COLLECTION_NAME]
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

    cursor = col.find(
        {"posted_on": {"$gte": cutoff}},
        {"_id": 1, "title": 1, "url": 1, "source": 1, "posted_on": 1,
         "impacted_industries": 1, "threat_actors": 1, "news_type": 1},
    ).sort("posted_on", -1).limit(limit)
    articles = await cursor.to_list(length=limit)

    # Convert ObjectId to str for JSON serialisation
    for a in articles:
        a["_id"] = str(a["_id"])

    total_articles = len(articles)

    if total_articles == 0:
        return {
            "groups": [],
            "total_articles": 0,
            "total_groups": 0,
            "duplicates_suppressed": 0,
        }

    deduped = await find_dedup_groups(articles, threshold)

    # Only return actual duplicate groups (dup_count > 1)
    dup_groups = [a for a in deduped if a.get("_dup_count", 1) > 1]
    duplicates_suppressed = sum(
        a.get("_dup_count", 1) - 1 for a in deduped if a.get("_dup_count", 1) > 1
    )

    return {
        "groups": dup_groups,
        "total_articles": total_articles,
        "total_groups": len(dup_groups),
        "duplicates_suppressed": duplicates_suppressed,
    }
