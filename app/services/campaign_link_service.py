from __future__ import annotations


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _link_type(ta_j: float, ioc_j: float, ttp_j: float) -> str:
    if ta_j > 0.5:
        return "same_actor"
    if ioc_j > 0.3:
        return "shared_infra"
    if ttp_j > 0.4:
        return "similar_ttp"
    return "related"


def compute_campaign_links(campaigns: list[dict]) -> list[dict]:
    prepped = []
    for c in campaigns:
        prepped.append({
            "cluster_id":   c["cluster_id"],
            "cluster_name": c.get("cluster_name", c.get("summary_title", c["cluster_id"])),
            "tas":  set(c.get("dominant_tas", []) or []),
            "ttps": set(c.get("attack_techniques", []) or []),
            "iocs": {f"{i['type']}:{i['value']}" for i in (c.get("iocs") or [])},
            "cves": set(c.get("cve_ids", []) or []),
        })

    links: list[dict] = []
    n = len(prepped)
    for i in range(n):
        a = prepped[i]
        for j in range(i + 1, n):
            b = prepped[j]
            ta_j   = _jaccard(a["tas"],  b["tas"])
            ttp_j  = _jaccard(a["ttps"], b["ttps"])
            ioc_j  = _jaccard(a["iocs"], b["iocs"])
            cve_j  = _jaccard(a["cves"], b["cves"])

            score = round(
                40 * ta_j +
                25 * ttp_j +
                25 * ioc_j +
                10 * cve_j,
                2,
            )
            if score <= 20:
                continue

            ltype = _link_type(ta_j, ioc_j, ttp_j)
            links.append({
                "source_id":   a["cluster_id"],
                "source_name": a["cluster_name"],
                "target_id":   b["cluster_id"],
                "target_name": b["cluster_name"],
                "score":       score,
                "shared_tas":  sorted(a["tas"] & b["tas"]),
                "shared_ttps": sorted(a["ttps"] & b["ttps"]),
                "shared_iocs": sorted(a["iocs"] & b["iocs"]),
                "link_type":   ltype,
            })

    return links
