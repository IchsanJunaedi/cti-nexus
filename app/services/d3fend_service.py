import asyncio
import json
import urllib.request

_cache: dict[str, list[dict]] = {}


async def get_d3fend_countermeasures(technique_id: str) -> list[dict]:
    tid = technique_id.upper()
    if tid in _cache:
        return _cache[tid]

    # Sub-techniques: T1059.001 → T1059/001 in URL path
    url_id = tid.replace(".", "/")
    url = f"https://d3fend.mitre.org/api/offensive-technique/attack/{url_id}.json"

    def _fetch():
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    try:
        data = await asyncio.to_thread(_fetch)
        bindings = data.get("off_to_def", {}).get("results", {}).get("bindings", [])
        seen: set[str] = set()
        techniques: list[dict] = []
        for b in bindings:
            name = b.get("def_tech_label", {}).get("value", "")
            # def_tech is an owl URI: .../d3fend.owl#FileAnalysis → "FileAnalysis"
            owl_uri = b.get("def_tech", {}).get("value", "")
            d3f_class = owl_uri.split("#")[-1] if "#" in owl_uri else ""
            d3f_id = b.get("def_tech_id", {}).get("value", d3f_class)
            artifact = b.get("def_artifact_label", {}).get("value", "")
            tactic = b.get("def_tactic_label", {}).get("value", "")
            if name and name not in seen:
                seen.add(name)
                techniques.append({
                    "id": d3f_id,
                    "name": name,
                    "tactic": tactic,
                    "artifact": artifact,
                    "url": f"https://d3fend.mitre.org/technique/d3f:{d3f_class}" if d3f_class else "https://d3fend.mitre.org",
                })
        _cache[tid] = techniques
        return techniques
    except Exception as e:
        print(f"[D3FEND] Lookup failed for {tid}: {e}")
        return []
