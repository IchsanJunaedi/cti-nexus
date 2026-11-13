#!/usr/bin/env python3
"""
wisemap_cti.py — CTI Mind Map Generator for WiseMapping
========================================================
Parses a threat intel report (text, URL, or structured dict),
generates WiseMapping XML, and pushes it to a self-hosted
WiseMapping instance via REST API.

Usage:
  python wisemap_cti.py --text "report.txt" --title "APT29 Campaign"
  python wisemap_cti.py --url https://example.com/threat-report
  python wisemap_cti.py --json cti_data.json
  python wisemap_cti.py --text "report.txt" --dry-run   # only generates XML, no upload

Config (env vars or .env file):
  WISEMAP_BASE_URL  — e.g. http://localhost:8080
  WISEMAP_EMAIL     — your WiseMapping account email
  WISEMAP_PASSWORD  — your WiseMapping account password
"""

import os
import re
import sys
import json
import argparse
import xml.etree.ElementTree as ET
from xml.dom import minidom
from dataclasses import dataclass, field
from typing import Optional
import urllib.request
import urllib.parse
import urllib.error

# ─── Optional dotenv support ─────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ─── Config ──────────────────────────────────────────────────────────────────
BASE_URL      = os.getenv("WISEMAP_BASE_URL", "http://localhost:8080")
EMAIL         = os.getenv("WISEMAP_EMAIL", "test@wisemapping.org")
PASSWORD      = os.getenv("WISEMAP_PASSWORD", "test")

# ─── Colors (WiseMapping hex palette) ────────────────────────────────────────
COLORS = {
    "root":         "#1a1a2e",   # dark navy
    "actor":        "#e94560",   # red
    "ttp":          "#0f3460",   # dark blue
    "ioc":          "#533483",   # purple
    "malware":      "#e94560",   # red
    "network":      "#2e86ab",   # teal
    "host":         "#a23b72",   # magenta
    "vulnerability":"#f18f01",   # orange
    "mitre":        "#0f3460",   # dark blue
    "default":      "#3a3a5c",   # neutral
}

TEXT_COLOR = "#ffffff"

# Valid WiseMapping shape types (from TopicShapeType in source)
SHAPE_ROUNDED = "rounded rectangle"
SHAPE_RECT    = "rectangle"
SHAPE_ELIPSE  = "elipse"
SHAPE_LINE    = "line"

# ─── Layout constants ─────────────────────────────────────────────────────────
# Pixel spacing between branch nodes on each side
BRANCH_Y_STEP   = 120   # vertical gap between top-level branches
CHILD_Y_STEP    = 60    # vertical gap between children
BRANCH_X_OFFSET = 300   # horizontal distance from center to branch root
CHILD_X_OFFSET  = 220   # horizontal distance from branch root to children
GRANDCHILD_X_OFFSET = 200  # further nesting


# ─── Data model ──────────────────────────────────────────────────────────────
@dataclass
class MapNode:
    text: str
    children: list = field(default_factory=list)
    color: str = COLORS["default"]
    note: str = ""
    link: str = ""
    shape: str = SHAPE_ROUNDED   # valid: "rounded rectangle", "rectangle", "elipse", "line"
    font_color: str = TEXT_COLOR  # stored in fontStyle attribute


@dataclass
class CTIReport:
    title: str
    threat_actor: str = ""
    summary: str = ""
    ttps: list = field(default_factory=list)           # [{"id": "T1059", "name": "...", "tactic": "..."}]
    iocs: dict = field(default_factory=dict)           # {"IPs": [], "Domains": [], "Hashes": [], ...}
    malware: list = field(default_factory=list)        # [{"name": "...", "type": "...", "note": "..."}]
    vulnerabilities: list = field(default_factory=list) # [{"cve": "CVE-...", "description": "..."}]
    targets: list = field(default_factory=list)        # ["Finance", "Government", ...]
    references: list = field(default_factory=list)     # ["https://..."]


# ─── IOC Extractor (regex-based, no external deps) ───────────────────────────
class IOCExtractor:
    _VERSION_PREFIX_RE = re.compile(
        r'(?:version|ver|firmware|software|release|patch|build|update|v)\s*[:\s]*'
        r'(\d{1,3}(?:\.\d{1,3}){3})',
        re.IGNORECASE
    )
    PATTERNS = {
        "IPs":      re.compile(
            r'\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b'
        ),
        "Domains":  re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.'
            r'(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*)'
            r'(?:com|net|org|io|gov|edu|mil|int|info|biz|xyz|ru|cn|de|uk|'
            r'co|top|site|online|tech|app|dev|cloud|red|pw|cc|tv|me|mobi))\b',
            re.IGNORECASE
        ),
        "URLs":     re.compile(
            r'(?:https?|hxxps?|fxp|ftp)://[^\s<>"\')\]]+',
            re.IGNORECASE
        ),
        "SHA256":   re.compile(r'\b[0-9a-fA-F]{64}\b'),
        "SHA1":     re.compile(r'\b[0-9a-fA-F]{40}\b'),
        "MD5":      re.compile(r'\b[0-9a-fA-F]{32}\b'),
        "CVEs":     re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
        "Emails":   re.compile(
            r'\b[a-zA-Z0-9_.+-]+(?:\[@\]|@)[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b'
        ),
    }

    # Common legitimate domains to skip
    WHITELIST = {
        "microsoft.com", "google.com", "github.com", "virustotal.com",
        "mitre.org", "cve.org", "nvd.nist.gov", "attack.mitre.org",
        "twitter.com", "linkedin.com", "youtube.com", "wikipedia.org",
    }

    @staticmethod
    def refang(text: str) -> str:
        text = re.sub(r'\[\.\]', '.', text)
        text = re.sub(r'\[dot\]', '.', text, flags=re.IGNORECASE)
        text = re.sub(r'\(dot\)', '.', text, flags=re.IGNORECASE)
        text = re.sub(r'\[@\]|\(at\)|\[at\]', '@', text, flags=re.IGNORECASE)
        text = re.sub(r'hxxps?://', 'https://', text, flags=re.IGNORECASE)
        text = re.sub(r'fxp://', 'ftp://', text, flags=re.IGNORECASE)
        return text

    @classmethod
    def extract(cls, text: str) -> dict:
        text = cls.refang(text)
        version_numbers = {m.group(1) for m in cls._VERSION_PREFIX_RE.finditer(text)}
        results = {}

        for ioc_type, pattern in cls.PATTERNS.items():
            matches = set(pattern.findall(text))
            if ioc_type == "IPs":
                matches = {m for m in matches if m not in version_numbers}
            if ioc_type == "Domains":
                matches = {
                    m for m in matches
                    if not any(m.endswith(w) or m == w for w in cls.WHITELIST)
                }
            if matches:
                results[ioc_type] = sorted(matches)

        # Remove hashes that are subsets of longer hashes
        sha256 = results.get("SHA256", set())
        sha1   = {h for h in results.get("SHA1", set()) if h not in sha256}
        md5    = {h for h in results.get("MD5", set()) if h not in sha256 and h not in sha1}
        if sha1:  results["SHA1"] = sorted(sha1)
        if md5:   results["MD5"]  = sorted(md5)

        return results


# ─── MITRE ATT&CK parser (extract T-codes from text) ─────────────────────────
TECHNIQUE_RE = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')

def extract_techniques(text: str) -> list:
    return sorted(set(TECHNIQUE_RE.findall(text)))


# ─── XML Builder ─────────────────────────────────────────────────────────────
class WiseMappingXMLBuilder:
    """
    Generates valid WiseMapping XML (Tango format) based on the actual
    XMLSerializerTango.ts source from @wisemapping/mindplot npm package.

    Key format rules:
    - Central topic: <topic central="true" ...> — NO position attribute
    - Other topics:  position="x,y"  (comma-separated integers)
    - Font color goes in fontStyle="family;size;color;weight;style" NOT fontColor attr
    - Notes: child element <note><![CDATA[text]]></note>
    - Links: child element <link url="..." urlType="url"/>
    - Valid shapes: "rounded rectangle", "rectangle", "elipse", "line"
    """

    def __init__(self):
        self._id_counter = 1

    def _next_id(self) -> int:
        val = self._id_counter
        self._id_counter += 1
        return val

    def _font_style(self, color: str = TEXT_COLOR, size: int = 0,
                    family: str = "", bold: bool = False) -> str:
        """Encode fontStyle attribute: 'family;size;color;weight;style'"""
        weight = "bold" if bold else ""
        return f"{family};{size or ''};{color};;;"

    def _make_topic(self, parent: ET.Element, node: MapNode,
                    x: int = 0, y: int = 0,
                    is_central: bool = False,
                    order: int = 0,
                    depth: int = 1) -> ET.Element:
        topic = ET.SubElement(parent, "topic")
        topic.set("id", str(self._next_id()))

        # text: use attribute for single-line, child <text> CDATA for multiline
        clean_text = node.text[:120].replace('\n', ' ')
        topic.set("text", clean_text)

        topic.set("bgColor", node.color)
        topic.set("fontStyle", self._font_style(color=node.font_color))
        topic.set("shape", node.shape)

        if is_central:
            topic.set("central", "true")
        else:
            # position must be "x,y" — never NaN, never "left"/"right"
            topic.set("position", f"{x},{y}")
            topic.set("order", str(order))

        # Notes become child <note> elements with CDATA
        if node.note:
            note_el = ET.SubElement(topic, "note")
            note_el.text = f"<![CDATA[{node.note[:1000]}]]>"

        # Links become child <link> elements
        if node.link:
            link_el = ET.SubElement(topic, "link")
            link_el.set("url", node.link)
            link_el.set("urlType", "url")

        # Recurse children — position them relative to this node
        child_x_step = CHILD_X_OFFSET if depth == 1 else GRANDCHILD_X_OFFSET
        total_h = len(node.children) * CHILD_Y_STEP
        start_y = y - total_h // 2

        for i, child in enumerate(node.children):
            child_x = x + child_x_step if x >= 0 else x - child_x_step
            child_y = start_y + i * CHILD_Y_STEP
            self._make_topic(topic, child,
                             x=child_x, y=child_y,
                             order=i, depth=depth + 1)

        return topic

    def _build_branches(self, report: CTIReport) -> list:
        """Build branch MapNode list from CTIReport."""
        branches = []

        # ── Threat Actor ──────────────────────────────────────────────────────
        if report.threat_actor:
            actor_node = MapNode(
                text=f"Threat Actor: {report.threat_actor}",
                color=COLORS["actor"],
                note=report.summary or "",
                children=[]
            )
            if report.targets:
                for t in report.targets:
                    actor_node.children.append(
                        MapNode(text=t, color=COLORS["actor"])
                    )
            branches.append(actor_node)

        # ── TTPs / MITRE ATT&CK ───────────────────────────────────────────────
        if report.ttps:
            tactic_map: dict = {}
            for ttp in report.ttps:
                tactic = ttp.get("tactic", "Unknown")
                if tactic not in tactic_map:
                    tactic_map[tactic] = []
                tactic_map[tactic].append(ttp)

            ttp_node = MapNode(text="TTPs / ATT&CK", color=COLORS["ttp"], children=[])
            for tactic, techs in tactic_map.items():
                tactic_node = MapNode(text=tactic, color=COLORS["ttp"], children=[])
                for t in techs:
                    tid   = t.get("id", "")
                    tname = t.get("name", tid)
                    label = f"{tid} - {tname}" if tid and tname != tid else (tid or tname)
                    link  = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/" if tid else ""
                    tactic_node.children.append(
                        MapNode(text=label, color=COLORS["mitre"],
                                link=link, note=t.get("note", ""))
                    )
                ttp_node.children.append(tactic_node)
            branches.append(ttp_node)

        # ── Malware ───────────────────────────────────────────────────────────
        if report.malware:
            mal_node = MapNode(text="Malware", color=COLORS["malware"], children=[])
            for m in report.malware:
                name  = m.get("name", "Unknown")
                mtype = m.get("type", "")
                label = f"{name} ({mtype})" if mtype else name
                mal_node.children.append(
                    MapNode(text=label, color=COLORS["malware"],
                            note=m.get("note", ""))
                )
            branches.append(mal_node)

        # ── Vulnerabilities ───────────────────────────────────────────────────
        if report.vulnerabilities:
            vuln_node = MapNode(text="Vulnerabilities", color=COLORS["vulnerability"], children=[])
            for v in report.vulnerabilities:
                cve   = v.get("cve", "")
                desc  = v.get("description", "")
                label = cve if cve else desc[:60]
                link  = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else ""
                vuln_node.children.append(
                    MapNode(text=label, color=COLORS["vulnerability"],
                            link=link, note=desc)
                )
            branches.append(vuln_node)

        # ── IOCs ──────────────────────────────────────────────────────────────
        if report.iocs:
            ioc_labels = {
                "IPs":      ("IPs",        COLORS["network"]),
                "Domains":  ("Domains",    COLORS["network"]),
                "URLs":     ("URLs",       COLORS["network"]),
                "SHA256":   ("SHA-256",    COLORS["host"]),
                "SHA1":     ("SHA-1",      COLORS["host"]),
                "MD5":      ("MD5",        COLORS["host"]),
                "CVEs":     ("CVEs",       COLORS["vulnerability"]),
                "Emails":   ("Emails",     COLORS["default"]),
                "Hashes":   ("Hashes",     COLORS["host"]),
            }

            ioc_root = MapNode(text="IOCs", color=COLORS["ioc"], children=[])
            for ioc_type, values in report.iocs.items():
                if not values:
                    continue
                label, color = ioc_labels.get(ioc_type, (ioc_type, COLORS["ioc"]))
                display  = values[:20]
                overflow = len(values) - 20 if len(values) > 20 else 0

                type_node = MapNode(text=f"{label} ({len(values)})",
                                    color=color, children=[])
                for v in display:
                    type_node.children.append(MapNode(text=str(v), color=color))
                if overflow:
                    type_node.children.append(
                        MapNode(text=f"+{overflow} more",
                                color=color,
                                note="\n".join(str(x) for x in values[20:]))
                    )
                ioc_root.children.append(type_node)
            branches.append(ioc_root)

        # ── References ────────────────────────────────────────────────────────
        if report.references:
            ref_node = MapNode(text="References", color=COLORS["default"], children=[])
            for ref in report.references:
                ref_node.children.append(
                    MapNode(text=ref[:80], color=COLORS["default"], link=ref)
                )
            branches.append(ref_node)

        return branches

    def _serialize(self, title: str, branches: list) -> str:
        map_el = ET.Element("map")
        map_el.set("version", "tango")

        root = ET.SubElement(map_el, "topic")
        root.set("central", "true")
        root.set("id", str(self._next_id()))
        root.set("text", title[:120])
        root.set("bgColor", COLORS["root"])
        root.set("fontStyle", self._font_style(color=TEXT_COLOR, bold=True))
        root.set("shape", SHAPE_ROUNDED)

        n = len(branches)
        total_height = (n // 2 + n % 2) * BRANCH_Y_STEP
        right_idx = left_idx = 0

        for i, node in enumerate(branches):
            if i % 2 == 0:
                bx = BRANCH_X_OFFSET
                by = -total_height // 2 + right_idx * BRANCH_Y_STEP
                right_idx += 1
            else:
                bx = -BRANCH_X_OFFSET
                by = -total_height // 2 + left_idx * BRANCH_Y_STEP
                left_idx += 1
            self._make_topic(root, node, x=bx, y=by, order=i, depth=1)

        raw = ET.tostring(map_el, encoding="unicode")
        raw = raw.replace("&lt;![CDATA[", "<![CDATA[")
        raw = raw.replace("]]&gt;", "]]>")
        reparsed = minidom.parseString(raw.encode("utf-8"))
        pretty = reparsed.toprettyxml(indent="  ", encoding=None)
        lines = pretty.split("\n")
        if lines[0].startswith("<?xml"):
            pretty = "\n".join(lines[1:])
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + pretty

    def build(self, report: CTIReport) -> str:
        return self._serialize(report.title, self._build_branches(report))

    def build_from_nodes(self, title: str, branches: list) -> str:
        return self._serialize(title, branches)


# ─── WiseMapping API Client ───────────────────────────────────────────────────
class WiseMappingClient:
    def __init__(self, base_url: str, email: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.email    = email
        self.password = password
        self.token    = None

    def _request(self, method: str, path: str, data=None,
                 content_type: str = "application/json",
                 extra_headers: dict = None) -> tuple:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": content_type}

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if extra_headers:
            headers.update(extra_headers)

        body = None
        if data is not None:
            if isinstance(data, str):
                body = data.encode("utf-8")
            elif isinstance(data, dict):
                body = json.dumps(data).encode("utf-8")
            else:
                body = data

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read()
                status = resp.status
                try:
                    return status, json.loads(raw)
                except Exception:
                    return status, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, body

    def login(self) -> bool:
        """Authenticate via JWT. Tries both known endpoint variants."""
        # Modern versions use /api/restful/authenticate
        # Older self-hosted instances may use /api/login
        for endpoint in ["/api/restful/authenticate", "/api/login"]:
            status, resp = self._request("POST", endpoint, {
                "email": self.email,
                "password": self.password
            })
            if status in (200, 201):
                if isinstance(resp, dict):
                    self.token = (resp.get("jwtToken") or resp.get("token")
                                  or resp.get("access_token"))
                print(f"[✓] Logged in as {self.email} (via {endpoint})")
                return True
        print(f"[✗] Login failed — check credentials and BASE_URL")
        return False

    def _find_map_id_by_title(self, title: str) -> Optional[int]:
        """List all maps and find the most recent one matching the title."""
        status, resp = self._request("GET", "/api/restful/maps/",
                                     content_type="application/json")
        if status == 200 and isinstance(resp, dict):
            maps = resp.get("mindmapsInfo", [])
            matches = [m for m in maps if m.get("title") == title]
            if matches:
                return max(m["id"] for m in matches)
        return None

    def create_map(self, title: str, description: str = "") -> Optional[int]:
        """Create a new empty map and return its ID.

        Modern API: POST /api/restful/maps?title=...&description=...
        The map ID is returned in the 'resourceid' response header.
        Since urllib doesn't expose headers easily, we resolve it by listing maps.
        Falls back to legacy /api/maps endpoint.
        """
        encoded_title = urllib.parse.quote(title)
        encoded_desc  = urllib.parse.quote(description)
        path = f"/api/restful/maps?title={encoded_title}&description={encoded_desc}"
        status, _ = self._request("POST", path, content_type="application/json")
        if status in (200, 201):
            map_id = self._find_map_id_by_title(title)
            if map_id:
                print(f"[✓] Created map: '{title}' (id={map_id})")
                return map_id
        # Fallback: older API
        status2, resp2 = self._request("POST", "/api/maps",
                                        {"title": title, "description": description})
        if status2 in (200, 201):
            map_id = resp2.get("id") if isinstance(resp2, dict) else None
            if map_id:
                print(f"[✓] Created map (legacy): '{title}' (id={map_id})")
                return map_id
        print(f"[✗] Failed to create map ({status}/{status2})")
        return None

    def upload_xml(self, map_id: int, xml_content: str) -> bool:
        """Upload WiseMapping XML content to an existing map.

        Modern API: PUT /api/restful/maps/{id}/document/xml
        Legacy API: PUT /api/maps/{id}/document
        """
        for path in [f"/api/restful/maps/{map_id}/document/xml",
                     f"/api/maps/{map_id}/document"]:
            status, resp = self._request("PUT", path, data=xml_content,
                                         content_type="application/xml")
            if status in (200, 204):
                print(f"[✓] Uploaded XML to map {map_id} (via {path})")
                return True
        print(f"[✗] Failed to upload XML to map {map_id} ({status}): {resp}")
        return False

    def download_xml(self, map_id: int) -> Optional[str]:
        """Download the raw WXML content of a map.

        GET /api/restful/maps/{id}/document/xml  → returns application/xml
        """
        for path in [f"/api/restful/maps/{map_id}/document/xml",
                     f"/api/maps/{map_id}/document"]:
            status, resp = self._request("GET", path, content_type="application/xml")
            if status == 200 and isinstance(resp, str):
                print(f"[✓] Downloaded WXML for map {map_id} ({len(resp)} bytes)")
                return resp
        print(f"[✗] Failed to download map {map_id}")
        return None

    def list_maps(self) -> list:
        """Return list of all maps for the authenticated user.

        GET /api/restful/maps/
        Returns list of dicts: {id, title, created, modified, public}
        """
        status, resp = self._request("GET", "/api/restful/maps/",
                                     content_type="application/json")
        if status == 200 and isinstance(resp, dict):
            maps = resp.get("mindmapsInfo", [])
            return [{"id": m["id"],
                     "title": m.get("title", ""),
                     "created": m.get("creationTime", ""),
                     "modified": m.get("lastModificationTime", ""),
                     "public": m.get("public", False)} for m in maps]
        return []

    def get_map_url(self, map_id: int) -> str:
        return f"{self.base_url}/c/maps/{map_id}/edit"

    def push(self, report: CTIReport, xml_content: str) -> Optional[str]:
        """Full flow: login → create → upload → return editor URL."""
        if not self.login():
            return None
        map_id = self.create_map(report.title, report.summary[:200] if report.summary else "")
        if map_id is None:
            return None
        if self.upload_xml(map_id, xml_content):
            url = self.get_map_url(map_id)
            print(f"[✓] Mind map ready: {url}")
            return url
        return None

    def pull(self, map_id: int, output_path: str) -> bool:
        """Full flow: login → download XML → save to file."""
        if not self.login():
            return False
        xml = self.download_xml(map_id)
        if xml:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(xml)
            print(f"[✓] Saved WXML to: {output_path}")
            return True
        return False




# ─── Text / URL / JSON parsers ────────────────────────────────────────────────
def parse_text_file(filepath: str, title: str = "") -> CTIReport:
    """Auto-extract IOCs and MITRE techniques from a plain text file."""
    with open(filepath, encoding="utf-8", errors="replace") as f:
        text = f.read()

    report_title = title or os.path.splitext(os.path.basename(filepath))[0]
    iocs = IOCExtractor.extract(text)
    techniques = extract_techniques(text)

    # Build basic TTP list from T-codes found
    ttps = [{"id": t, "name": t, "tactic": "Unknown"} for t in techniques]

    # Extract CVEs and move to vulnerabilities
    cves = iocs.pop("CVEs", [])
    vulns = [{"cve": c, "description": ""} for c in cves]

    return CTIReport(
        title=report_title,
        summary=text[:300].replace("\n", " "),
        ttps=ttps,
        iocs=iocs,
        vulnerabilities=vulns,
    )


def parse_url(url: str, title: str = "") -> CTIReport:
    """Fetch a URL and extract IOCs from the HTML/text."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] Failed to fetch URL: {e}")
        raw = ""

    # Strip HTML tags roughly
    text = re.sub(r'<[^>]+>', ' ', raw)
    text = re.sub(r'\s+', ' ', text).strip()

    report_title = title or url.split("/")[-1] or "Threat Report"
    iocs = IOCExtractor.extract(text)
    techniques = extract_techniques(text)
    ttps = [{"id": t, "name": t, "tactic": "Unknown"} for t in techniques]
    cves = iocs.pop("CVEs", [])
    vulns = [{"cve": c, "description": ""} for c in cves]

    return CTIReport(
        title=report_title,
        summary=text[:300],
        ttps=ttps,
        iocs=iocs,
        vulnerabilities=vulns,
        references=[url],
    )


def parse_json_file(filepath: str) -> CTIReport:
    """
    Load a structured CTI JSON file. Expected schema:
    {
      "title": "APT29 Operation SolarWinds",
      "threat_actor": "APT29 / Cozy Bear",
      "summary": "...",
      "targets": ["Government", "Energy"],
      "malware": [{"name": "SUNBURST", "type": "Backdoor", "note": "..."}],
      "ttps": [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
      "iocs": {"IPs": ["1.2.3.4"], "Domains": ["evil.com"]},
      "vulnerabilities": [{"cve": "CVE-2020-10148", "description": "..."}],
      "references": ["https://..."]
    }
    """
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)

    return CTIReport(
        title=data.get("title", "Unknown Campaign"),
        threat_actor=data.get("threat_actor", ""),
        summary=data.get("summary", ""),
        ttps=data.get("ttps", []),
        iocs=data.get("iocs", {}),
        malware=data.get("malware", []),
        vulnerabilities=data.get("vulnerabilities", []),
        targets=data.get("targets", []),
        references=data.get("references", []),
    )


# ─── CLI ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="WiseMapping CTI Tool — push, pull, and list mind maps via REST API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
PUSH (generate + upload):
  python wisemap_cti.py --json report.json
  python wisemap_cti.py --text report.txt --title "Lazarus Group"
  python wisemap_cti.py --url https://example.com/apt-report
  python wisemap_cti.py --json report.json --dry-run  # generate XML only

PULL (download from server):
  python wisemap_cti.py --download 42
  python wisemap_cti.py --download 42 --output my_map.wxml

LIST (show all maps):
  python wisemap_cti.py --list

ENV VARS: WISEMAP_BASE_URL, WISEMAP_EMAIL, WISEMAP_PASSWORD
        """
    )
    # ── Source (mutually exclusive: push OR pull OR list) ─────────────────────
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--text",     metavar="FILE", help="Push: plain text threat report")
    mode.add_argument("--url",      metavar="URL",  help="Push: URL of online threat report")
    mode.add_argument("--json",     metavar="FILE", help="Push: structured CTI JSON file")
    mode.add_argument("--download", metavar="ID",   type=int,
                      help="Pull: download WXML for map ID from server")
    mode.add_argument("--list",     action="store_true",
                      help="List all maps on the server")

    parser.add_argument("--title",    default="",     help="Override mind map title (push only)")
    parser.add_argument("--output",   default="",     help="Output file path")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Generate XML only, skip upload (push only)")
    parser.add_argument("--base-url", default=BASE_URL, help="WiseMapping server URL")
    parser.add_argument("--email",    default=EMAIL)
    parser.add_argument("--password", default=PASSWORD)

    args = parser.parse_args()
    client = WiseMappingClient(args.base_url, args.email, args.password)

    # ── LIST mode ─────────────────────────────────────────────────────────────
    if args.list:
        print(f"[*] Connecting to {args.base_url}...")
        if not client.login():
            sys.exit(1)
        maps = client.list_maps()
        if not maps:
            print("No maps found.")
        else:
            print(f"\n{'ID':<8} {'Title':<50} {'Modified':<22} {'Public'}")
            print("-" * 90)
            for m in sorted(maps, key=lambda x: x["id"]):
                pub = "yes" if m["public"] else "no"
                print(f"{m['id']:<8} {m['title'][:49]:<50} {str(m['modified'])[:21]:<22} {pub}")
        return

    # ── DOWNLOAD (pull) mode ──────────────────────────────────────────────────
    if args.download:
        map_id = args.download
        out_path = args.output or f"wisemap_{map_id}.wxml"
        print(f"[*] Downloading map {map_id} from {args.base_url}...")
        if client.pull(map_id, out_path):
            print(f"\n✅ Saved to: {out_path}\n")
        else:
            sys.exit(1)
        return

    # ── PUSH (generate + upload) mode ─────────────────────────────────────────
    print("[*] Parsing input...")
    if args.text:
        report = parse_text_file(args.text, title=args.title)
    elif args.url:
        report = parse_url(args.url, title=args.title)
    else:
        report = parse_json_file(args.json)
        if args.title:
            report.title = args.title

    print(f"    Title:  {report.title}")
    print(f"    Actor:  {report.threat_actor or '(none)'}")
    print(f"    TTPs:   {len(report.ttps)}")
    print(f"    IOCs:   {sum(len(v) for v in report.iocs.values())}")
    print(f"    Vulns:  {len(report.vulnerabilities)}")

    print("[*] Generating WiseMapping XML...")
    builder = WiseMappingXMLBuilder()
    xml_content = builder.build(report)

    out_path = args.output or f"{report.title.replace(' ', '_')[:50]}.wxml"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(xml_content)
    print(f"[✓] XML saved to: {out_path}")

    if not args.dry_run:
        print(f"[*] Uploading to {args.base_url}...")
        url = client.push(report, xml_content)
        if url:
            print(f"\n🗺️  Mind map URL: {url}\n")
    else:
        print("[*] Dry-run mode — skipping upload.")
        print(f"\n✅ Done. Import {out_path} into WiseMapping manually.\n")


if __name__ == "__main__":
    main()
