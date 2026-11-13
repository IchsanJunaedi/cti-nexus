"""
Single source of truth for country name normalization.
Used by article_service.py (Python) and exposed via /api/country-groups (JS frontend).
"""

COUNTRY_GROUPS: list[dict] = [
    {"canonical": "North Korea",    "variants": ["North Korea", "North korea", "North Korean", "North korean", "DPRK"]},
    {"canonical": "South Korea",    "variants": ["South Korea", "South korea", "South Korean", "South korean", "Korea", "Korean"]},
    {"canonical": "China",          "variants": ["China", "Chinese", "PRC"]},
    {"canonical": "Philippines",    "variants": ["Philippines", "Philippine", "Filipino"]},
    {"canonical": "United States",  "variants": ["United States", "United states", "US", "USA", "American"]},
    {"canonical": "United Kingdom", "variants": ["United Kingdom", "United kingdom", "UK", "Britain", "British"]},
    {"canonical": "New Zealand",    "variants": ["New Zealand", "New zealand"]},
    {"canonical": "Indonesia",      "variants": ["Indonesia", "Indonesian"]},
    {"canonical": "Vietnam",        "variants": ["Vietnam", "Vietnamese", "Viet Nam"]},
    {"canonical": "Myanmar",        "variants": ["Myanmar", "Burma", "Burmese"]},
    {"canonical": "Taiwan",         "variants": ["Taiwan", "Taiwanese"]},
    {"canonical": "Russia",         "variants": ["Russia", "Russian"]},
    {"canonical": "India",          "variants": ["India", "Indian"]},
    {"canonical": "Japan",          "variants": ["Japan", "Japanese"]},
    {"canonical": "Australia",      "variants": ["Australia", "Australian"]},
    {"canonical": "Malaysia",       "variants": ["Malaysia", "Malaysian"]},
    {"canonical": "Singapore",      "variants": ["Singapore", "Singaporean"]},
    {"canonical": "Thailand",       "variants": ["Thailand", "Thai"]},
    {"canonical": "Pakistan",       "variants": ["Pakistan", "Pakistani"]},
]

# Fast lookup: lowercase variant → canonical name
_variant_to_canonical: dict[str, str] = {}
for _g in COUNTRY_GROUPS:
    for _v in _g["variants"]:
        _variant_to_canonical[_v.lower()] = _g["canonical"]


def normalize_country(c: str) -> str:
    """Return canonical country name for any known variant, or the original string."""
    return _variant_to_canonical.get(c.strip().lower(), c.strip())
