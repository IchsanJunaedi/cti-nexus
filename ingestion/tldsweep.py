#!/usr/bin/env python3
"""
TLDSweep - TLD Recon & Domain Intelligence Tool
by Dark Web Informer  ·  https://darkwebinformer.com

Sweeps a domain name across every known TLD to find
what's registered, who owns it, and what's running on it.

    python tldsweep.py example
    python tldsweep.py example --threads 50 --output results.json
    python tldsweep.py example --tld-file custom_tlds.txt --timeout 5
    python tldsweep.py example --newly-registered 30
    python tldsweep.py example --new-only
    python tldsweep.py example --config scan_profile.json
    python tldsweep.py example --html-report report.html
"""

import socket
import ssl
import json
import csv
import sys
import argparse
import os
import time
import datetime
import re
import struct
import hashlib
import html as html_mod
import ipaddress
import signal
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

__version__ = "1.0.0"

_shutdown = threading.Event()
def _signal_handler(signum, frame):
    if _shutdown.is_set():
        sys.exit(1)
    print(f"\n  {C.YEL}[!] Ctrl+C received - finishing in-flight requests...{C.R}")
    _shutdown.set()
signal.signal(signal.SIGINT, _signal_handler)

@dataclass
class DnsResult:
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    cname: List[str] = field(default_factory=list)
    ns: List[str] = field(default_factory=list)
    mx: List[str] = field(default_factory=list)
    txt: List[str] = field(default_factory=list)
    soa: Optional[str] = None
    spf: Optional[str] = None
    dmarc: Optional[str] = None
    resolved: bool = False
    def to_dict(self):
        d = {k: getattr(self, k) for k in ("a","aaaa","cname","ns","mx","txt") if getattr(self, k)}
        if self.soa: d["soa"] = self.soa
        if self.spf: d["spf"] = self.spf
        if self.dmarc: d["dmarc"] = self.dmarc
        d["resolved"] = self.resolved
        return d

@dataclass
class WhoisResult:
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    registrant: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    dnssec: Optional[str] = None
    age_days: Optional[int] = None
    newly_registered: bool = False
    error: Optional[str] = None
    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()
                if v is not None and v != [] and v != "" and k != "error"}

@dataclass
class TlsResult:
    has_tls: bool = False
    subject: Optional[Dict] = None
    issuer: Optional[Dict] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    serial: Optional[str] = None
    san: List[str] = field(default_factory=list)
    note: Optional[str] = None
    def to_dict(self):
        d = {"has_tls": self.has_tls}
        if self.has_tls:
            for k in ("subject","issuer","not_before","not_after","serial","san","note"):
                v = getattr(self, k)
                if v is not None and v != []: d[k] = v
        return d

@dataclass
class HttpResult:
    http_alive: bool = False
    https_alive: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    http_server: Optional[str] = None
    https_server: Optional[str] = None
    http_title: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    redirect_url: Optional[str] = None
    body_hash: Optional[str] = None
    tech_fingerprints: List[str] = field(default_factory=list)
    content_length: Optional[int] = None
    favicon_hash: Optional[str] = None
    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()
                if v is not None and v != [] and v != False}

@dataclass
class ScanResult:
    domain: str
    tld: str
    timestamp: str = ""
    dns: DnsResult = field(default_factory=DnsResult)
    whois: WhoisResult = field(default_factory=WhoisResult)
    tls: TlsResult = field(default_factory=TlsResult)
    http: HttpResult = field(default_factory=HttpResult)
    registered: bool = False
    alive: bool = False
    newly_registered: bool = False
    risk_indicators: List[str] = field(default_factory=list)
    url: str = ""
    ip_info: Dict[str, Any] = field(default_factory=dict)
    asn_info: Dict[str, Any] = field(default_factory=dict)
    def to_dict(self):
        d = {
            "domain": self.domain, "tld": self.tld, "timestamp": self.timestamp,
            "dns": self.dns.to_dict(), "whois": self.whois.to_dict(),
            "tls": self.tls.to_dict(), "http": self.http.to_dict(),
            "registered": self.registered, "alive": self.alive,
            "newly_registered": self.newly_registered,
            "risk_indicators": self.risk_indicators, "url": self.url,
            "ip_info": self.ip_info if self.ip_info else {},
        }
        if self.asn_info: d["asn_info"] = self.asn_info
        return d

from tldsweep_data import COMMON_TLDS, WHOIS_SERVERS

_RE_CREATION = re.compile(
    r"(?:Creation Date|created|Registration Date|Registered on|"
    r"Domain Registration Date|created-date):\s*(.+)", re.I)
_RE_REGISTRAR = re.compile(r"(?:Registrar|Sponsoring Registrar):\s*(.+)", re.I)
_RE_EXPIRY = re.compile(
    r"(?:Expir.*Date|Expiry Date|Expiration Date|paid-till|"
    r"Registry Expiry Date|Expires on):\s*(.+)", re.I)
_RE_UPDATED = re.compile(
    r"(?:Updated Date|modified|Changed|Last Modified|Last Updated):\s*(.+)", re.I)
_RE_REGISTRANT = re.compile(
    r"(?:Registrant Name|Registrant|owner):\s*(.+)", re.I)
_RE_ORG = re.compile(r"(?:Registrant Org.*|Organisation):\s*(.+)", re.I)
_RE_COUNTRY = re.compile(r"(?:Registrant Country|country):\s*(.+)", re.I)
_RE_DNSSEC = re.compile(r"DNSSEC:\s*(.+)", re.I)
_RE_NS = re.compile(r"(?:Name Server|nserver):\s*(.+)", re.I)
_RE_STATUS = re.compile(r"(?:Domain )?Status:\s*(.+)", re.I)
_RE_REFERRAL = re.compile(r"Registrar WHOIS Server:\s*(.+)", re.I)
_RE_DATE_YMD = re.compile(r"(\d{4})[/-](\d{1,2})[/-](\d{1,2})")
_RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.DOTALL)
_RE_LOCATION = re.compile(r"[Ll]ocation:\s*(.+?)[\r\n]")
_RE_SERVER = re.compile(r"[Ss]erver:\s*(.+?)[\r\n]")
_RE_HTTP_STATUS = re.compile(r"HTTP/\d\.\d\s+(\d{3})")

_TECH_FINGERPRINTS = {
    "x-powered-by": {
        "php":"PHP","asp.net":"ASP.NET","express":"Express.js",
        "next.js":"Next.js","nuxt":"Nuxt.js","flask":"Flask",
        "django":"Django","rails":"Ruby on Rails",
    },
    "server": {
        "nginx":"Nginx","apache":"Apache","cloudflare":"Cloudflare",
        "litespeed":"LiteSpeed","iis":"IIS","caddy":"Caddy",
        "envoy":"Envoy","openresty":"OpenResty","vercel":"Vercel",
    },
}

_BOGON_NETWORKS = [ipaddress.ip_network(n) for n in [
    "0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
    "169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.0.2.0/24",
    "192.168.0.0/16","198.18.0.0/15","198.51.100.0/24",
    "203.0.113.0/24","224.0.0.0/4","240.0.0.0/4",
]]

DNS_RESOLVERS = ["1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"]
DNS_RESOLVER_LABELS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
}

_whois_rate_lock = threading.Lock()
_whois_last_query: Dict[str, float] = {}
WHOIS_MIN_INTERVAL = 0.5

SUSPICIOUS_TLDS = {"tk","ml","ga","cf","gq","pw","su","cx","ws","vu","tl","ms"}

class C:
    R="\033[0m"; RED="\033[91m"; GRN="\033[92m"; YEL="\033[93m"
    BLU="\033[94m"; MAG="\033[95m"; CYN="\033[96m"; WHT="\033[97m"
    DIM="\033[2m"; BOLD="\033[1m"; UNDERLINE="\033[4m"
    _links_enabled = True
    @staticmethod
    def disable():
        C._links_enabled = False
        for a in ["R","RED","GRN","YEL","BLU","MAG","CYN","WHT","DIM","BOLD","UNDERLINE"]:
            setattr(C, a, "")
    @staticmethod
    def link(url, label=""):
        d = label or url
        return f"\033]8;;{url}\033\\{d}\033]8;;\033\\" if C._links_enabled else d

def _sanitize_terminal(s):
    s = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?', '', s)
    s = re.sub(r'\x1b[\[\(][^a-zA-Z]*[a-zA-Z]', '', s)
    s = re.sub(r'\x1b[^[\]()\x1b]', '', s)
    return ''.join(c for c in s if c == '\n' or c == '\t' or (ord(c) >= 32))

def is_bogon(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _BOGON_NETWORKS)
    except ValueError:
        return False

def get_ip_info(ips):
    info = {}
    bogons = [ip for ip in ips if is_bogon(ip)]
    if bogons: info["bogon_ips"] = bogons
    if len(ips) > 4: info["multi_ip"] = True; info["ip_count"] = len(ips)
    return info

def resolve_dns(domain, timeout=3.0, retries=2):
    result = DnsResult()
    for attempt in range(retries + 1):
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM, 0, socket.AI_CANONNAME)
            for family, _, _, _, sockaddr in infos:
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in result.a:
                    result.a.append(ip)
                elif family == socket.AF_INET6 and ip not in result.aaaa:
                    result.aaaa.append(ip)
            result.resolved = bool(result.a or result.aaaa)
            break
        except (socket.gaierror, socket.herror, OSError):
            if attempt < retries: time.sleep(0.2 * (attempt + 1))
    return result

def resolve_dns_raw(domain, timeout=1.5, retries=1):
    result = DnsResult()
    for attempt in range(retries + 1):
        try:
            records = _dns_query(domain, 1, timeout)
            for r in records:
                if r not in result.a:
                    result.a.append(r)
            if result.a:
                break
        except Exception:
            if attempt < retries:
                time.sleep(0.1 * (attempt + 1))
    result.resolved = bool(result.a)
    return result

def _dns_query(domain, qtype=1, timeout=3.0, resolver=None):
    resolvers = [resolver] if resolver else DNS_RESOLVERS
    for res in resolvers:
        try:
            txn_id = struct.pack("!H", random.randint(0, 65535))
            qname = b""
            for part in domain.rstrip(".").split("."):
                encoded = part.encode()
                if len(encoded) > 63: return []
                qname += bytes([len(encoded)]) + encoded
            qname += b'\x00'
            packet = txn_id + b'\x01\x00' + struct.pack("!HHHH",1,0,0,0) + qname + struct.pack("!HH",qtype,1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(packet, (res, 53))
                data, addr = sock.recvfrom(4096)
            finally:
                sock.close()
            if addr[0] != res: continue
            if len(data) < 12 or data[:2] != txn_id: continue
            return _parse_dns_response(data)
        except Exception:
            continue
    return []

def _parse_dns_response(data):
    results = []
    if len(data) < 12: return results
    ancount = struct.unpack("!H", data[6:8])[0]
    offset = 12
    while offset < len(data) and data[offset] != 0:
        if data[offset] >= 192: offset += 2; break
        offset += 1 + data[offset]
    else:
        offset += 1
    offset += 4
    for _ in range(ancount):
        if offset >= len(data): break
        if data[offset] >= 192: offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                if data[offset] >= 192: offset += 2; break
                offset += 1 + data[offset]
            else:
                offset += 1
        if offset + 10 > len(data): break
        rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        if rtype == 1 and rdlength == 4:
            results.append(socket.inet_ntoa(rdata))
        elif rtype in (2, 5):
            results.append(_decode_dns_name(data, offset - rdlength))
        elif rtype == 6:
            results.append(_decode_dns_name(data, offset - rdlength))
        elif rtype == 15 and rdlength > 2:
            pref = struct.unpack("!H", rdata[:2])[0]
            results.append(f"{pref} {_decode_dns_name(data, offset - rdlength + 2)}")
        elif rtype == 16:
            txt, i = "", 0
            while i < rdlength:
                tlen = rdata[i]; txt += rdata[i+1:i+1+tlen].decode(errors="replace"); i += 1 + tlen
            results.append(txt)
        elif rtype == 28 and rdlength == 16:
            results.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return results

def _decode_dns_name(data, offset):
    parts, seen = [], set()
    while offset < len(data):
        if offset in seen: break
        seen.add(offset)
        length = data[offset]
        if length == 0: break
        if length >= 192:
            ptr = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            return ".".join(parts) + ("." if parts else "") + _decode_dns_name(data, ptr)
        parts.append(data[offset+1:offset+1+length].decode(errors="replace"))
        offset += 1 + length
    return ".".join(parts)

def get_mx_records(d, t=3.0):
    try: return _dns_query(d, 15, t)
    except Exception: return []
def get_ns_records(d, t=3.0):
    try: return _dns_query(d, 2, t)
    except Exception: return []
def get_txt_records(d, t=3.0):
    try: return _dns_query(d, 16, t)
    except Exception: return []
def get_cname_records(d, t=3.0):
    try: return _dns_query(d, 5, t)
    except Exception: return []
def get_soa_record(d, t=3.0):
    try:
        r = _dns_query(d, 6, t)
        return r[0] if r else None
    except Exception: return None

def check_spf_dmarc(domain, timeout=3.0):
    spf, dmarc = None, None
    try:
        txts = get_txt_records(domain, timeout)
        for t in txts:
            if t.lower().startswith("v=spf1"):
                spf = t; break
    except Exception: pass
    try:
        dmarc_txts = get_txt_records(f"_dmarc.{domain}", timeout)
        for t in dmarc_txts:
            if t.lower().startswith("v=dmarc1"):
                dmarc = t; break
    except Exception: pass
    return spf, dmarc

def _favicon_http_get(url, timeout=3.0, max_bytes=262144):
    """Raw-socket GET of an absolute http(s) URL. Returns (status, headers_str,
    body) or None on any failure. Does not follow redirects itself."""
    from urllib.parse import urlsplit
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query: path += f"?{u.query}"
    sock = None
    try:
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(
                socket.create_connection((host, port), timeout=timeout),
                server_hostname=host)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: {_random_ua()}\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
        sock.sendall(req)
        resp = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk: break
                resp += chunk
                if len(resp) > max_bytes: break
            except socket.timeout: break
        if b"\r\n\r\n" not in resp: return None
        hdr, body = resp.split(b"\r\n\r\n", 1)
        hdr_str = hdr.decode(errors="replace")
        return hdr_str, body
    except Exception:
        return None
    finally:
        if sock:
            try: sock.close()
            except Exception: pass


def _favicon_fetch_follow(url, timeout=3.0, max_redirects=3):
    """GET url, following Location redirects (relative or cross-host). Returns
    (final_url, status_code, headers_str, body) or None."""
    from urllib.parse import urljoin
    for _ in range(max_redirects + 1):
        got = _favicon_http_get(url, timeout)
        if not got: return None
        hdr_str, body = got
        sm = re.search(r"^HTTP/\d\.\d\s+(\d+)", hdr_str)
        status = int(sm.group(1)) if sm else 0
        if status in (301, 302, 303, 307, 308):
            lm = re.search(r"(?im)^Location:\s*(\S+)", hdr_str)
            if not lm: return url, status, hdr_str, body
            url = urljoin(url, lm.group(1).strip())
            continue
        return url, status, hdr_str, body
    return None


def _favicon_hash_body(body):
    if len(body) < 16: return None
    import base64
    b64 = base64.encodebytes(body)
    try:
        import mmh3
        return str(mmh3.hash(b64))
    except ImportError:
        return "md5:" + hashlib.md5(body).hexdigest()


def grab_favicon_hash(domain, timeout=3.0):
    """Fetch a domain's favicon and return its Shodan-compatible (MMH3) hash,
    or an "md5:"-prefixed fallback if mmh3 isn't installed, or None.

    Prefers the homepage's declared <link rel="icon"> tag — that's what browsers
    and Shodan's own crawler actually resolve as "the" favicon, and it can live
    at any path or host. A bare /favicon.ico can exist as an unrelated stale file
    even when the page points elsewhere, so it's only used as a last-resort
    fallback when no <link> tag is found or it fails to fetch."""
    for scheme in ("https", "http"):
        got = _favicon_fetch_follow(f"{scheme}://{domain}/", timeout)
        if not got: continue
        final_url, status, hdr_str, body = got
        if status != 200: continue
        try:
            html_text = body.decode(errors="replace")
        except Exception:
            continue
        lm = re.search(
            r'<link[^>]+rel=["\'](?:shortcut icon|icon|apple-touch-icon)["\'][^>]*>',
            html_text, re.I)
        if not lm: continue
        hm = re.search(r'href=["\']([^"\']+)["\']', lm.group(0), re.I)
        if not hm: continue
        from urllib.parse import urljoin
        icon_url = urljoin(final_url, hm.group(1).strip())
        got2 = _favicon_fetch_follow(icon_url, timeout)
        if not got2: continue
        _, status2, hdr_str2, body2 = got2
        if status2 != 200: continue
        if re.search(r"(?im)^Content-Type:\s*text/html", hdr_str2): continue
        h = _favicon_hash_body(body2)
        if h: return h

    for scheme in ("https", "http"):
        got = _favicon_fetch_follow(f"{scheme}://{domain}/favicon.ico", timeout)
        if not got: continue
        _, status, hdr_str, body = got
        if status != 200: continue
        if re.search(r"(?im)^Content-Type:\s*text/html", hdr_str): continue
        h = _favicon_hash_body(body)
        if h: return h
    return None

def lookup_asn(ip, timeout=2.0):
    if not ip or ":" in ip: return {}
    try:
        parts = ip.split(".")
        query = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.origin.asn.cymru.com"
        results = _dns_query(query, 16, timeout)
        if results:
            fields = results[0].split("|")
            if len(fields) >= 3:
                return {
                    "asn": fields[0].strip(),
                    "prefix": fields[1].strip(),
                    "country": fields[2].strip(),
                }
    except Exception: pass
    return {}

def _format_age(days):
    if days is None: return None
    if days == 0: return "today"
    if days < 7: return f"{days}d"
    if days < 30: return f"{days // 7}w {days % 7}d"
    if days < 365: return f"{days // 30}mo"
    y, rem = divmod(days, 365)
    m = rem // 30
    return f"{y}y {m}mo" if m else f"{y}y"

def _format_eta(done, total, elapsed):
    if done == 0 or elapsed < 0.5: return ""
    rate = done / elapsed
    remaining = (total - done) / rate
    if remaining < 60: return f"~{remaining:.0f}s left"
    if remaining < 3600: return f"~{remaining/60:.0f}m left"
    return f"~{remaining/3600:.1f}h left"


def _load_env_file():
    for base in [os.path.dirname(os.path.abspath(__file__)), os.getcwd()]:
        env_path = os.path.join(base, ".env")
        if os.path.isfile(env_path):
            try:
                with open(env_path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"): continue
                        if "=" not in line: continue
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip()
                        if k and v and k not in os.environ:
                            os.environ[k] = v
            except Exception: pass
            return

_load_env_file()

def _get_notify_config():
    return {
        "discord": os.environ.get("TLDSWEEP_DISCORD_WEBHOOK", ""),
        "telegram_token": os.environ.get("TLDSWEEP_TELEGRAM_TOKEN", ""),
        "telegram_chat": os.environ.get("TLDSWEEP_TELEGRAM_CHAT_ID", ""),
    }

def _notify_discord(webhook_url, payload):
    if not webhook_url: return False
    try:
        from urllib.parse import urlparse
        parsed = urlparse(webhook_url)
        body = json.dumps(payload).encode()
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(
            socket.create_connection((parsed.hostname, 443), timeout=10),
            server_hostname=parsed.hostname)
        try:
            req = (f"POST {parsed.path} HTTP/1.1\r\n"
                   f"Host: {parsed.hostname}\r\n"
                   f"Content-Type: application/json\r\n"
                   f"Content-Length: {len(body)}\r\n"
                   f"Connection: close\r\n\r\n").encode() + body
            sock.sendall(req)
            resp = sock.recv(1024).decode(errors="replace")
        finally:
            sock.close()
        if " 204 " in resp or " 200 " in resp:
            print(f"  {C.GRN}[+] Discord alert sent successfully{C.R}")
            return True
        else:
            sys.stderr.write(f"  {C.YEL}[!] Discord notify returned unexpected status{C.R}\n")
            return False
    except Exception as e:
        sys.stderr.write(f"  {C.YEL}[!] Discord notify failed: {e}{C.R}\n")
        return False

def _notify_telegram(token, chat_id, message):
    if not token or not chat_id: return False
    try:
        body = json.dumps({
            "chat_id": chat_id,
            "text": message[:4096],
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }).encode()
        host = "api.telegram.org"
        path = f"/bot{token}/sendMessage"
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=10),
            server_hostname=host)
        try:
            req = (f"POST {path} HTTP/1.1\r\n"
                   f"Host: {host}\r\n"
                   f"Content-Type: application/json\r\n"
                   f"Content-Length: {len(body)}\r\n"
                   f"Connection: close\r\n\r\n").encode() + body
            sock.sendall(req)
            resp = sock.recv(1024).decode(errors="replace")
        finally:
            sock.close()
        if " 200 " in resp:
            print(f"  {C.GRN}[+] Telegram alert sent successfully{C.R}")
            return True
        else:
            sys.stderr.write(f"  {C.YEL}[!] Telegram notify returned unexpected status{C.R}\n")
            return False
    except Exception as e:
        sys.stderr.write(f"  {C.YEL}[!] Telegram notify failed: {e}{C.R}\n")
        return False

def _send_scan_alert(notify_cfg, base_name, results, new_domains=None, gone_domains=None, elapsed_str=None):
    rc = sum(1 for r in results if r.registered)
    ac = sum(1 for r in results if r.alive)
    nc = sum(1 for r in results if r.newly_registered)
    rf = sum(1 for r in results if r.risk_indicators)
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    newly_lines = []
    for r in sorted(results, key=lambda x: (x.whois.age_days if x.whois.age_days is not None else 9999)):
        if r.newly_registered:
            age = _format_age(r.whois.age_days) or "?"
            newly_lines.append((r.domain, age))
            if len(newly_lines) >= 20: break

    if notify_cfg.get("discord"):
        if nc > 0: color = 0xFF4444
        elif new_domains: color = 0xFFAA00
        else: color = 0x00CC88

        embed = {
            "title": f"{base_name}.*",
            "color": color,
            "timestamp": now_iso,
            "footer": {"text": f"\U0001f977 DarkWebInformer.com - Cyber Threat Intelligence | TLDSweep v{__version__}"},
            "fields": [
                {"name": "Registered", "value": str(rc), "inline": True},
                {"name": "Live", "value": str(ac), "inline": True},
                {"name": "Newly Registered", "value": str(nc), "inline": True},
                {"name": "Risk Flagged", "value": str(rf), "inline": True},
            ],
        }

        if elapsed_str:
            embed["fields"].append({"name": "Scan Time", "value": elapsed_str, "inline": True})

        if newly_lines:
            nl = "\n".join(f"`{d}` - {age}" for d, age in newly_lines)
            embed["fields"].append({"name": "Newly Registered Domains", "value": nl[:1024]})

        if new_domains:
            nd_list = "\n".join(f"`{d}`" for d in sorted(new_domains)[:15])
            if len(new_domains) > 15:
                nd_list += f"\n*... +{len(new_domains)-15} more*"
            embed["fields"].append({"name": f"New Since Last Scan ({len(new_domains)})", "value": nd_list[:1024]})

        if gone_domains:
            gd_list = "\n".join(f"`{d}`" for d in sorted(gone_domains)[:10])
            if len(gone_domains) > 10:
                gd_list += f"\n*... +{len(gone_domains)-10} more*"
            embed["fields"].append({"name": f"Gone Since Last Scan ({len(gone_domains)})", "value": gd_list[:1024]})

        if not nc and not new_domains and not gone_domains:
            embed["description"] = "No changes detected."

        _notify_discord(notify_cfg["discord"], {
            "username": "TLDSweep",
            "avatar_url": "https://darkwebinformer.com/favicon.ico",
            "embeds": [embed],
        })

    if notify_cfg.get("telegram_token") and notify_cfg.get("telegram_chat"):
        tg = [f"<b>TLDSweep</b> | <code>{base_name}.*</code>",
              f"{now_str}",
              "",
              f"Registered: <b>{rc}</b>",
              f"Live: <b>{ac}</b>",
              f"Newly registered: <b>{nc}</b>",
              f"Flagged: <b>{rf}</b>"]

        if elapsed_str:
            tg.append(f"Scan time: <b>{elapsed_str}</b>")

        if newly_lines:
            tg.append("")
            tg.append("<b>Newly registered:</b>")
            for d, age in newly_lines:
                tg.append(f"  <code>{d}</code>  ({age})")

        if new_domains:
            tg.append("")
            tg.append(f"<b>New since last scan ({len(new_domains)}):</b>")
            for d in sorted(new_domains)[:15]:
                tg.append(f"  <code>{d}</code>")
            if len(new_domains) > 15:
                tg.append(f"  ... +{len(new_domains)-15} more")

        if gone_domains:
            tg.append("")
            tg.append(f"<b>Gone since last scan ({len(gone_domains)}):</b>")
            for d in sorted(gone_domains)[:10]:
                tg.append(f"  <code>{d}</code>")

        if not nc and not new_domains and not gone_domains:
            tg.append("")
            tg.append("No changes detected.")

        tg.append("")
        tg.append('\U0001f977 <a href="https://darkwebinformer.com">DarkWebInformer.com</a> - Cyber Threat Intelligence')

        _notify_telegram(notify_cfg["telegram_token"], notify_cfg["telegram_chat"], "\n".join(tg))

def _whois_rate_wait(server):
    with _whois_rate_lock:
        now = time.monotonic()
        last = _whois_last_query.get(server, 0)
        wait = WHOIS_MIN_INTERVAL - (now - last)
        _whois_last_query[server] = max(now, last + WHOIS_MIN_INTERVAL)
    if wait > 0:
        time.sleep(wait)

def _whois_query_str(domain, server):
    if server == "whois.denic.de": return f"-T dn,ace {domain}\r\n"
    if server == "whois.jprs.jp": return f"{domain}/e\r\n"
    if server == "whois.verisign-grs.com": return f"={domain}\r\n"
    return f"{domain}\r\n"

def _whois_raw(domain, server, timeout, connect_timeout):
    _whois_rate_wait(server)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(connect_timeout)
    try:
        sock.connect((server, 43))
        sock.settimeout(timeout)
        sock.sendall(_whois_query_str(domain, server).encode())
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            raw += chunk
            if len(raw) > 65536: break
        return raw.decode(errors="replace")
    finally:
        sock.close()

def whois_fast_creation(domain, tld, connect_timeout=2.0, read_timeout=4.0):
    result = WhoisResult()
    base_tld = tld.split(".")[-1] if "." in tld else tld
    server = WHOIS_SERVERS.get(tld) or WHOIS_SERVERS.get(base_tld) or f"whois.nic.{base_tld}"
    sock = None
    try:
        _whois_rate_wait(server)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(connect_timeout)
        sock.connect((server, 43))
        sock.settimeout(read_timeout)
        sock.sendall(_whois_query_str(domain, server).encode())
        buf, fc, fr = "", False, False
        while True:
            try: chunk = sock.recv(2048)
            except socket.timeout: break
            if not chunk: break
            buf += chunk.decode(errors="replace")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                if not fc:
                    m = _RE_CREATION.search(line)
                    if m and m.group(1).strip():
                        result.creation_date = m.group(1).strip()
                        result.age_days = _calc_age_days(result.creation_date)
                        fc = True
                if not fr:
                    m = _RE_REGISTRAR.search(line)
                    if m and m.group(1).strip():
                        result.registrar = m.group(1).strip()
                        fr = True
                if fc and fr: return result
            if len(buf) > 32768: break
    except Exception as e:
        result.error = str(e)
    finally:
        if sock:
            try: sock.close()
            except Exception: pass
    return result

def whois_lookup(domain, tld, timeout=5.0, connect_timeout=2.0, retries=1):
    result = WhoisResult()
    base_tld = tld.split(".")[-1] if "." in tld else tld
    server = WHOIS_SERVERS.get(tld) or WHOIS_SERVERS.get(base_tld) or f"whois.nic.{base_tld}"
    for attempt in range(retries + 1):
        try:
            raw = _whois_raw(domain, server, timeout, connect_timeout)
            ref = _RE_REFERRAL.search(raw)
            if ref:
                rs = ref.group(1).strip()
                if rs and rs != server:
                    try: raw = _whois_raw(domain, rs, timeout, connect_timeout) + "\n" + raw
                    except Exception: pass
            def _f(p):
                m = p.search(raw)
                return m.group(1).strip() if m and m.group(1).strip() else None
            result.registrar = _f(_RE_REGISTRAR)
            result.creation_date = _f(_RE_CREATION)
            result.expiration_date = _f(_RE_EXPIRY)
            result.updated_date = _f(_RE_UPDATED)
            result.registrant = _f(_RE_REGISTRANT)
            result.registrant_org = _f(_RE_ORG)
            result.registrant_country = _f(_RE_COUNTRY)
            result.dnssec = _f(_RE_DNSSEC)
            result.name_servers = [ns.strip().lower() for ns in _RE_NS.findall(raw) if ns.strip()]
            result.status = [s.strip() for s in _RE_STATUS.findall(raw) if s.strip() and "http" not in s.lower()]
            if result.creation_date:
                result.age_days = _calc_age_days(result.creation_date)
            break
        except Exception as e:
            if attempt < retries: time.sleep(1.0*(attempt+1)); continue
            result.error = str(e)
    return result

def _calc_age_days(date_str):
    date_str = date_str.strip().rstrip(".")
    fmts = [
        "%Y-%m-%dT%H:%M:%SZ","%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S","%Y-%m-%d",
        "%d-%b-%Y","%d %b %Y","%d/%m/%Y",
        "%Y/%m/%d","%Y.%m.%d","%d.%m.%Y",
        "%b %d %Y","%Y-%m-%dT%H:%M:%S.%fZ",
        "%a %b %d %H:%M:%S %Z %Y",
    ]
    now = datetime.datetime.now()
    for fmt in fmts:
        try:
            dt = datetime.datetime.strptime(date_str[:len(now.strftime(fmt))+5], fmt)
            days = (now - dt.replace(tzinfo=None)).days
            if days >= 0: return days
        except (ValueError, OverflowError):
            continue
    m = _RE_DATE_YMD.search(date_str)
    if m:
        try:
            days = (now - datetime.datetime(int(m.group(1)),int(m.group(2)),int(m.group(3)))).days
            if days >= 0: return days
        except ValueError: pass
    return None

def grab_tls_cert(domain, timeout=3.0):
    r = TlsResult()
    for verify in (True, False):
        try:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain,443), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=domain) as ss:
                    cert = ss.getpeercert(binary_form=False)
                    if cert:
                        r.has_tls = True
                        r.subject = dict(x[0] for x in cert.get("subject",[]))
                        r.issuer = dict(x[0] for x in cert.get("issuer",[]))
                        r.not_before = cert.get("notBefore")
                        r.not_after = cert.get("notAfter")
                        r.serial = cert.get("serialNumber")
                        r.san = [v for _,v in cert.get("subjectAltName",[])]
                        return r
                    else:
                        r.has_tls = True
                        r.note = "Certificate present but unparseable"
                        return r
        except ssl.SSLCertVerificationError:
            if verify:
                continue
        except Exception:
            break
    return r

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
]
def _random_ua():
    return random.choice(_USER_AGENTS)

def http_probe(domain, timeout=5.0):
    result = HttpResult()
    for scheme,port,ka,ks,kserv in [
        ("https",443,"https_alive","https_status","https_server"),
        ("http",80,"http_alive","http_status","http_server"),
    ]:
        sock = None
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(
                    socket.create_connection((domain,port), timeout=timeout),
                    server_hostname=domain)
            else:
                sock = socket.create_connection((domain,port), timeout=timeout)
            ua = _random_ua()
            req = (f"GET / HTTP/1.1\r\nHost: {domain}\r\n"
                   f"User-Agent: {ua}\r\n"
                   f"Accept: text/html\r\nAccept-Encoding: identity\r\n"
                   f"Connection: close\r\n\r\n").encode()
            sock.sendall(req)
            resp = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    resp += chunk
                    if len(resp) > 32768: break
                except socket.timeout: break
            rt = resp.decode(errors="replace")
            sm = _RE_HTTP_STATUS.search(rt)
            if sm: setattr(result, ka, True); setattr(result, ks, int(sm.group(1)))
            sv = _RE_SERVER.search(rt)
            if sv: setattr(result, kserv, sv.group(1).strip())
            tm = _RE_TITLE.search(rt)
            if tm and not result.http_title: result.http_title = tm.group(1).strip()[:200]
            lm = _RE_LOCATION.search(rt)
            if lm:
                loc = lm.group(1).strip()
                result.redirect_url = loc
                if loc not in result.redirect_chain: result.redirect_chain.append(loc)
            if b"\r\n\r\n" in resp:
                body = resp.split(b"\r\n\r\n",1)[1]
                if body and not result.body_hash:
                    result.body_hash = hashlib.sha256(body).hexdigest()[:16]
                    result.content_length = len(body)
            hdr = rt.split("\r\n\r\n",1)[0].lower()
            for hn, pats in _TECH_FINGERPRINTS.items():
                hm = re.search(rf"{hn}:\s*(.+?)[\r\n]", hdr)
                if hm:
                    hv = hm.group(1).lower()
                    for kw,tech in pats.items():
                        if kw in hv and tech not in result.tech_fingerprints:
                            result.tech_fingerprints.append(tech)
        except Exception: pass
        finally:
            if sock:
                try: sock.close()
                except Exception: pass
    return result

def dns_batch_scan(base_name, tlds, timeout, dns_threads):
    dns_results = {}
    def _resolve(tld):
        if _shutdown.is_set(): return tld, DnsResult()
        return tld, resolve_dns_raw(f"{base_name}.{tld}", timeout=min(timeout, 1.5))
    with ThreadPoolExecutor(max_workers=dns_threads) as ex:
        futs = {ex.submit(_resolve, t): t for t in tlds}
        total, done = len(futs), 0
        _p0 = time.monotonic()
        for f in as_completed(futs):
            done += 1; tld, dr = f.result(); dns_results[tld] = dr
            eta = _format_eta(done, total, time.monotonic() - _p0)
            sys.stderr.write(f"\r  {C.DIM}[DNS {done}/{total}] {eta}{C.R}    "); sys.stderr.flush()
            if _shutdown.is_set(): break
    sys.stderr.write("\r" + " "*60 + "\r")
    return dns_results

def whois_new_reg_scan(base_name, resolved_tlds, timeout, whois_threads,
                       newly_reg_days, connect_timeout=2.0):
    fast_results = {}
    def _fw(tld):
        if _shutdown.is_set(): return tld, WhoisResult()
        r = whois_fast_creation(f"{base_name}.{tld}", tld,
                                connect_timeout=connect_timeout, read_timeout=timeout)
        if r.age_days is not None: r.newly_registered = r.age_days <= newly_reg_days
        return tld, r
    with ThreadPoolExecutor(max_workers=whois_threads) as ex:
        futs = {ex.submit(_fw, t): t for t in resolved_tlds}
        total, done = len(futs), 0
        _p0 = time.monotonic()
        for f in as_completed(futs):
            done += 1; tld, r = f.result(); fast_results[tld] = r
            eta = _format_eta(done, total, time.monotonic() - _p0)
            sys.stderr.write(f"\r  {C.DIM}[WHOIS {done}/{total}] {eta}{C.R}    "); sys.stderr.flush()
            if _shutdown.is_set(): break
    sys.stderr.write("\r" + " "*60 + "\r")
    return fast_results

def scan_domain(base_name, tld, timeout=5.0, whois_enabled=True,
                http_enabled=True, tls_enabled=True, dns_extra=True,
                dns_prefetch=None, whois_prefetch=None, connect_timeout=2.0,
                newly_reg_days=90):
    domain = f"{base_name}.{tld}"
    r = ScanResult(domain=domain, tld=tld,
                   timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()+"Z")
    if _shutdown.is_set(): return r

    dns = dns_prefetch if dns_prefetch is not None else resolve_dns(domain, timeout=timeout)
    r.dns = dns

    def _check_newly_reg(w):
        if w.age_days is not None and w.age_days <= newly_reg_days:
            w.newly_registered = True
            r.newly_registered = True
            r.risk_indicators.append("NEWLY_REGISTERED")

    if not dns.resolved:
        if whois_enabled:
            fw = whois_prefetch
            if fw and (fw.creation_date or fw.registrar):
                r.registered = True; r.whois = fw
                _check_newly_reg(fw)
            elif not fw:
                w = whois_lookup(domain, tld, timeout=timeout, connect_timeout=connect_timeout)
                if w.creation_date or w.registrar:
                    r.registered = True; r.whois = w
                    _check_newly_reg(w)
        return r

    r.registered = True
    r.ip_info = get_ip_info(dns.a)

    if dns.a and not _shutdown.is_set():
        r.asn_info = lookup_asn(dns.a[0], timeout=timeout)

    if dns_extra and not _shutdown.is_set():
        mx = get_mx_records(domain, timeout); ns = get_ns_records(domain, timeout)
        txt = get_txt_records(domain, timeout); cname = get_cname_records(domain, timeout)
        soa = get_soa_record(domain, timeout)
        if mx: r.dns.mx = mx
        if ns: r.dns.ns = ns
        if txt: r.dns.txt = txt
        if cname: r.dns.cname = cname
        if soa: r.dns.soa = soa
        spf, dmarc = check_spf_dmarc(domain, timeout)
        if spf: r.dns.spf = spf
        if dmarc: r.dns.dmarc = dmarc

    if whois_enabled and not _shutdown.is_set():
        w = whois_lookup(domain, tld, timeout=timeout, connect_timeout=connect_timeout)
        r.whois = w
        _check_newly_reg(w)

    if tls_enabled and not _shutdown.is_set():
        tls = grab_tls_cert(domain, timeout=timeout)
        if tls.has_tls: r.tls = tls

    if http_enabled and not _shutdown.is_set():
        http = http_probe(domain, timeout=timeout)
        r.http = http
        if http.http_alive or http.https_alive: r.alive = True
        if r.alive and not _shutdown.is_set():
            fav = grab_favicon_hash(domain, timeout=timeout)
            if fav: r.http.favicon_hash = fav

    _assess_risk(r, tld)

    if r.http.https_alive: r.url = f"https://{domain}"
    elif r.http.http_alive: r.url = f"http://{domain}"
    else: r.url = f"https://{domain}"
    return r

def _assess_risk(r, tld):
    if tld in SUSPICIOUS_TLDS: r.risk_indicators.append("SUSPICIOUS_TLD")
    age = r.whois.age_days
    if age is not None:
        if age <= 7: r.risk_indicators.append("REGISTERED_WITHIN_7_DAYS")
        elif age <= 30: r.risk_indicators.append("REGISTERED_WITHIN_30_DAYS")
    if r.whois.registrant:
        rl = r.whois.registrant.lower()
        if "privacy" in rl: r.risk_indicators.append("PRIVACY_PROTECTED")
        if "redacted" in rl: r.risk_indicators.append("WHOIS_REDACTED")
    if r.http.http_title:
        pk = ["parked","for sale","coming soon","under construction",
              "buy this domain","domain parking","this domain is for sale"]
        if any(k in r.http.http_title.lower() for k in pk):
            r.risk_indicators.append("PARKED_DOMAIN")
    if r.tls.san and len(r.tls.san) > 50: r.risk_indicators.append("SHARED_TLS_CERT")
    for ip in r.dns.a:
        if is_bogon(ip): r.risk_indicators.append("BOGON_IP"); break
    ns_list = r.dns.ns or r.whois.name_servers
    if ns_list:
        free_prov = ["freedns","afraid.org","he.net","hostinger"]
        for ns in ns_list:
            nl = ns.lower()
            for fp in free_prov:
                if fp in nl and "FREE_DNS_PROVIDER" not in r.risk_indicators:
                    r.risk_indicators.append("FREE_DNS_PROVIDER"); break
    if len(r.http.redirect_chain) > 3: r.risk_indicators.append("DEEP_REDIRECT_CHAIN")
    if r.dns.mx and not r.dns.spf: r.risk_indicators.append("MX_NO_SPF")
    if r.dns.spf and "+all" in r.dns.spf.lower(): r.risk_indicators.append("SPF_PLUS_ALL")

def print_result(r, verbose=False, newly_reg_days=90):
    if not r.registered and not r.alive:
        if verbose: print(f"  {C.DIM}  ·  {r.domain}{C.R}")
        return

    if r.newly_registered or any("REGISTERED_WITHIN" in ri for ri in r.risk_indicators):
        tag = f"{C.RED}{C.BOLD}!!NEW{C.R}"
    elif r.alive: tag = f"{C.GRN}LIVE{C.R} "
    elif r.registered: tag = f"{C.YEL} REG{C.R} "
    else: tag = f"{C.DIM} --- {C.R}"

    risk_parts = []
    for ri in r.risk_indicators:
        risk_parts.append(f"{C.RED}{C.BOLD}{ri}{C.R}")
    risk = f"  {' '.join(risk_parts)}" if risk_parts else ""

    url = r.url or f"https://{r.domain}"
    dd = C.link(url, f"{C.BOLD}{C.UNDERLINE}{r.domain}{C.R}")
    P = "       "
    L = 14

    print(f"\n  {C.DIM}{'─' * 58}{C.R}")
    print(f"  [{tag}]  {dd}{risk}")

    has_dns = r.dns.a or r.dns.aaaa or r.dns.cname or r.dns.ns or r.dns.mx or r.dns.soa
    if has_dns:
        if r.dns.a:     print(f"{P}{C.CYN}{'A':<{L}}{C.R}{', '.join(r.dns.a)}")
        if r.dns.aaaa:  print(f"{P}{C.CYN}{'AAAA':<{L}}{C.R}{', '.join(r.dns.aaaa[:3])}")
        if r.dns.cname: print(f"{P}{C.CYN}{'CNAME':<{L}}{C.R}{_sanitize_terminal(', '.join(r.dns.cname[:3]))}")
        if r.dns.ns:    print(f"{P}{C.CYN}{'NS':<{L}}{C.R}{_sanitize_terminal(', '.join(r.dns.ns[:4]))}")
        if r.dns.mx:    print(f"{P}{C.CYN}{'MX':<{L}}{C.R}{_sanitize_terminal(', '.join(r.dns.mx[:3]))}")
        if r.dns.soa:   print(f"{P}{C.CYN}{'SOA':<{L}}{C.R}{_sanitize_terminal(r.dns.soa)}")
        if r.dns.spf:   print(f"{P}{C.CYN}{'SPF':<{L}}{C.R}{_sanitize_terminal(r.dns.spf[:120])}")
        if r.dns.dmarc: print(f"{P}{C.CYN}{'DMARC':<{L}}{C.R}{_sanitize_terminal(r.dns.dmarc[:120])}")

    if r.asn_info:
        asn_str = f"AS{r.asn_info.get('asn','')} ({r.asn_info.get('country','')}) {r.asn_info.get('prefix','')}"
        print(f"{P}{C.CYN}{'ASN':<{L}}{C.R}{_sanitize_terminal(asn_str)}")

    w = r.whois
    has_whois = w.registrar or w.creation_date or w.expiration_date or w.registrant_org or w.registrant_country or w.name_servers
    if has_whois:
        if has_dns or r.asn_info: print(f"{P}{C.DIM}·{C.R}")
        if w.registrar:
            print(f"{P}{C.MAG}{'Registrar':<{L}}{C.R}{_sanitize_terminal(w.registrar)}")
        if w.creation_date:
            age_h = _format_age(w.age_days)
            age = f"  ({age_h})" if age_h else ""
            print(f"{P}{C.MAG}{'Created':<{L}}{C.R}{_sanitize_terminal(w.creation_date)}{age}")
        if w.expiration_date:
            print(f"{P}{C.MAG}{'Expires':<{L}}{C.R}{_sanitize_terminal(w.expiration_date)}")
        if w.registrant_org:
            print(f"{P}{C.MAG}{'Org':<{L}}{C.R}{_sanitize_terminal(w.registrant_org)}")
        if w.registrant_country:
            print(f"{P}{C.MAG}{'Country':<{L}}{C.R}{_sanitize_terminal(w.registrant_country)}")
        if w.name_servers:
            print(f"{P}{C.MAG}{'NS (WHOIS)':<{L}}{C.R}{_sanitize_terminal(', '.join(w.name_servers[:4]))}")

    if r.tls.has_tls:
        if has_dns or has_whois or r.asn_info: print(f"{P}{C.DIM}·{C.R}")
        issuer = (r.tls.issuer or {}).get("organizationName",
                  (r.tls.issuer or {}).get("commonName", "Unknown"))
        print(f"{P}{C.BLU}{'TLS Issuer':<{L}}{C.R}{_sanitize_terminal(issuer)}")
        if r.tls.san:
            print(f"{P}{C.BLU}{'TLS SANs':<{L}}{C.R}{_sanitize_terminal(', '.join(r.tls.san[:5]))}")

    h = r.http
    has_http = h.https_alive or h.http_alive
    if has_http:
        if has_dns or has_whois or r.tls.has_tls or r.asn_info: print(f"{P}{C.DIM}·{C.R}")
        if h.https_alive:
            print(f"{P}{C.GRN}{'HTTPS':<{L}}{C.R}{h.https_status}  Server: {_sanitize_terminal(h.https_server or '-')}")
        if h.http_alive:
            print(f"{P}{C.GRN}{'HTTP':<{L}}{C.R}{h.http_status}  Server: {_sanitize_terminal(h.http_server or '-')}")
        if h.http_title:
            print(f"{P}{C.GRN}{'Title':<{L}}{C.R}{_sanitize_terminal(h.http_title[:120])}")
        if h.redirect_url:
            _clean_rurl = _sanitize_terminal(h.redirect_url[:200])
            print(f"{P}{C.YEL}{'Redirect':<{L}}{C.R}{C.link(_clean_rurl, _sanitize_terminal(h.redirect_url[:120]))}")
        if h.tech_fingerprints:
            print(f"{P}{C.CYN}{'Tech':<{L}}{C.R}{', '.join(h.tech_fingerprints)}")
        if h.body_hash:
            print(f"{P}{C.DIM}{'Body hash':<{L}}{C.R}{h.body_hash}  ({h.content_length or '?'} bytes)")
        if h.favicon_hash:
            print(f"{P}{C.DIM}{'Favicon':<{L}}{C.R}{h.favicon_hash}")

    print(f"{P}{C.DIM}{'URL':<{L}}{C.R}{C.link(url)}")

def auto_export_json(results, base_name, output_dir="."):
    os.makedirs(output_dir, exist_ok=True)
    fp = os.path.join(output_dir, f"{base_name}_scans.json")
    now = datetime.datetime.now(datetime.timezone.utc)
    active = [r.to_dict() for r in results if r.registered or r.alive]
    entry = {
        "scan_id": now.strftime("%Y%m%d_%H%M%S"),
        "timestamp": now.isoformat()+"Z", "scanner_version": __version__,
        "summary": {
            "tlds_scanned": len(results),
            "registered": sum(1 for r in results if r.registered),
            "alive": sum(1 for r in results if r.alive),
            "newly_registered": sum(1 for r in results if r.newly_registered),
            "risk_flagged": sum(1 for r in results if r.risk_indicators),
        },
        "results": active,
    }
    data = {"domain_base": base_name, "total_scans": 0, "scans": []}
    if os.path.exists(fp):
        try:
            with open(fp, encoding="utf-8") as f: data = json.load(f)
        except Exception: pass
    data["scans"].append(entry); data["total_scans"] = len(data["scans"])
    with open(fp, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, default=str)
    return fp

def export_json(results, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in results], f, indent=2, default=str)
    print(f"\n{C.GRN}[+] JSON exported to {filepath}{C.R}")

def _csv_safe(val):
    s = str(val) if val is not None else ""
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r', '\n'):
        return "'" + s
    return s

def export_csv(results, filepath):
    if not results: return
    fields = [
        "domain","tld","registered","alive","newly_registered",
        "dns_a","dns_aaaa","dns_cname","dns_ns","dns_mx","dns_soa",
        "dns_spf","dns_dmarc",
        "whois_registrar","whois_creation_date","whois_expiration_date",
        "whois_age_days","whois_age_human","whois_registrant_org","whois_registrant_country",
        "tls_issuer","tls_san",
        "http_status","https_status","http_server","http_title",
        "redirect_url","redirect_chain","body_hash","favicon_hash","tech_fingerprints",
        "asn","asn_country","asn_prefix",
        "risk_indicators","timestamp"
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in results:
            w.writerow({
                "domain":r.domain,"tld":r.tld,
                "registered":r.registered,"alive":r.alive,
                "newly_registered":r.newly_registered,
                "dns_a":"|".join(r.dns.a),"dns_aaaa":"|".join(r.dns.aaaa),
                "dns_cname":_csv_safe("|".join(r.dns.cname)),
                "dns_ns":_csv_safe("|".join(r.dns.ns)),
                "dns_mx":_csv_safe("|".join(r.dns.mx)),
                "dns_soa":_csv_safe(r.dns.soa or ""),
                "dns_spf":_csv_safe(r.dns.spf or ""),
                "dns_dmarc":_csv_safe(r.dns.dmarc or ""),
                "whois_registrar":_csv_safe(r.whois.registrar),
                "whois_creation_date":_csv_safe(r.whois.creation_date or ""),
                "whois_expiration_date":_csv_safe(r.whois.expiration_date or ""),
                "whois_age_days":r.whois.age_days if r.whois.age_days is not None else "",
                "whois_age_human":_format_age(r.whois.age_days) or "",
                "whois_registrant_org":_csv_safe(r.whois.registrant_org),
                "whois_registrant_country":_csv_safe(r.whois.registrant_country),
                "tls_issuer":_csv_safe((r.tls.issuer or {}).get("organizationName","")),
                "tls_san":_csv_safe("|".join(r.tls.san)),
                "http_status":r.http.http_status or "",
                "https_status":r.http.https_status or "",
                "http_server":_csv_safe(r.http.https_server or r.http.http_server or ""),
                "http_title":_csv_safe(r.http.http_title),
                "redirect_url":_csv_safe(r.http.redirect_url),
                "redirect_chain":_csv_safe(" → ".join(r.http.redirect_chain)),
                "body_hash":r.http.body_hash or "",
                "favicon_hash":r.http.favicon_hash or "",
                "tech_fingerprints":"|".join(r.http.tech_fingerprints),
                "asn":_csv_safe(r.asn_info.get("asn","")),
                "asn_country":_csv_safe(r.asn_info.get("country","")),
                "asn_prefix":_csv_safe(r.asn_info.get("prefix","")),
                "risk_indicators":"|".join(r.risk_indicators),
                "timestamp":r.timestamp,
            })
    print(f"{C.GRN}[+] CSV exported to {filepath}{C.R}")

def export_html(results, filepath, base_name, elapsed_str=""):
    active = sorted([r for r in results if r.registered or r.alive],
                    key=lambda x: (-int(x.newly_registered), -int(x.alive), -int(x.registered)))
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    e = html_mod.escape
    rc = sum(1 for r in results if r.registered)
    ac = sum(1 for r in results if r.alive)
    nc = sum(1 for r in results if r.newly_registered)
    risk_count = sum(1 for r in active if r.risk_indicators)

    domain_cards = []
    for r in active:
        cls = "new" if r.newly_registered else ("live" if r.alive else "reg")
        tag = "!! NEW" if r.newly_registered else ("LIVE" if r.alive else "REG")

        badges = ""
        for ri in r.risk_indicators:
            badges += f'<span class="badge risk">{e(ri)}</span>'
        for t in r.http.tech_fingerprints:
            badges += f'<span class="badge tech">{e(t)}</span>'

        dns_rows = ""
        if r.dns.a: dns_rows += f'<tr><td class="lbl">A</td><td>{e(", ".join(r.dns.a))}</td></tr>'
        if r.dns.aaaa: dns_rows += f'<tr><td class="lbl">AAAA</td><td>{e(", ".join(r.dns.aaaa[:4]))}</td></tr>'
        if r.dns.cname: dns_rows += f'<tr><td class="lbl">CNAME</td><td>{e(", ".join(r.dns.cname[:3]))}</td></tr>'
        if r.dns.ns: dns_rows += f'<tr><td class="lbl">NS</td><td>{e(", ".join(r.dns.ns[:4]))}</td></tr>'
        if r.dns.mx: dns_rows += f'<tr><td class="lbl">MX</td><td>{e(", ".join(r.dns.mx[:3]))}</td></tr>'
        if r.dns.soa: dns_rows += f'<tr><td class="lbl">SOA</td><td>{e(r.dns.soa)}</td></tr>'
        if r.dns.spf: dns_rows += f'<tr><td class="lbl">SPF</td><td>{e(r.dns.spf[:200])}</td></tr>'
        if r.dns.dmarc: dns_rows += f'<tr><td class="lbl">DMARC</td><td>{e(r.dns.dmarc[:200])}</td></tr>'
        if r.asn_info:
            _asn = f"AS{r.asn_info.get('asn','')} ({r.asn_info.get('country','')}) {r.asn_info.get('prefix','')}"
            dns_rows += f'<tr><td class="lbl">ASN</td><td>{e(_asn)}</td></tr>'

        whois_rows = ""
        w = r.whois
        if w.registrar: whois_rows += f'<tr><td class="lbl">Registrar</td><td>{e(w.registrar)}</td></tr>'
        if w.creation_date:
            age_h = _format_age(w.age_days)
            age = f' <span class="dim">({e(age_h)})</span>' if age_h else ""
            whois_rows += f'<tr><td class="lbl">Created</td><td>{e(w.creation_date)}{age}</td></tr>'
        if w.expiration_date: whois_rows += f'<tr><td class="lbl">Expires</td><td>{e(w.expiration_date)}</td></tr>'
        if w.registrant_org: whois_rows += f'<tr><td class="lbl">Org</td><td>{e(w.registrant_org)}</td></tr>'
        if w.registrant_country: whois_rows += f'<tr><td class="lbl">Country</td><td>{e(w.registrant_country)}</td></tr>'
        if w.name_servers: whois_rows += f'<tr><td class="lbl">NS</td><td>{e(", ".join(w.name_servers[:4]))}</td></tr>'

        tls_rows = ""
        if r.tls.has_tls:
            _ti = r.tls.issuer or {}
            issuer = _ti.get("organizationName", _ti.get("commonName", "Unknown"))
            tls_rows += f'<tr><td class="lbl">Issuer</td><td>{e(issuer)}</td></tr>'
            if r.tls.san:
                tls_rows += f'<tr><td class="lbl">SANs</td><td>{e(", ".join(r.tls.san[:6]))}</td></tr>'

        http_rows = ""
        h = r.http
        if h.https_alive: http_rows += f'<tr><td class="lbl">HTTPS</td><td>{h.https_status} &middot; {e(h.https_server or "-")}</td></tr>'
        if h.http_alive: http_rows += f'<tr><td class="lbl">HTTP</td><td>{h.http_status} &middot; {e(h.http_server or "-")}</td></tr>'
        if h.http_title: http_rows += f'<tr><td class="lbl">Title</td><td>{e(h.http_title[:120])}</td></tr>'
        if h.redirect_url:
            _rurl = h.redirect_url
            if _rurl.lower().startswith(("http://","https://")):
                http_rows += f'<tr><td class="lbl">Redirect</td><td><a href="{e(_rurl)}" target="_blank">{e(_rurl[:100])}</a></td></tr>'
            else:
                http_rows += f'<tr><td class="lbl">Redirect</td><td>{e(_rurl[:100])}</td></tr>'
        if h.body_hash: http_rows += f'<tr><td class="lbl">Body hash</td><td><code>{e(h.body_hash)}</code> ({h.content_length or "?"} bytes)</td></tr>'
        if h.favicon_hash: http_rows += f'<tr><td class="lbl">Favicon</td><td><code>{e(h.favicon_hash)}</code></td></tr>'

        sections = ""
        if dns_rows: sections += f'<div class="sect"><div class="sect-title">DNS</div><table>{dns_rows}</table></div>'
        if whois_rows: sections += f'<div class="sect"><div class="sect-title">WHOIS</div><table>{whois_rows}</table></div>'
        if tls_rows: sections += f'<div class="sect"><div class="sect-title">TLS</div><table>{tls_rows}</table></div>'
        if http_rows: sections += f'<div class="sect"><div class="sect-title">HTTP</div><table>{http_rows}</table></div>'

        domain_cards.append(f"""<div class="card {cls}" onclick="this.classList.toggle('open')">
<div class="card-head">
<span class="tag {cls}">{tag}</span>
<a href="{e(r.url)}" target="_blank" class="domain" onclick="event.stopPropagation()">{e(r.domain)}</a>
<span class="ip">{e(", ".join(r.dns.a[:2]))}</span>
<span class="badges">{badges}</span>
<span class="chevron">&#9662;</span>
</div>
<div class="card-body">{sections}</div>
</div>""")

    cards_html = "\n".join(domain_cards)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TLDSweep - {e(base_name)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Space+Grotesk:wght@400;600;700&display=swap');
:root{{
--bg:#0a0e14;--bg2:#111820;--bg3:#1a2230;--border:#1e2a3a;
--text:#b4c0d0;--text2:#6b7d93;--accent:#00d4ff;--accent2:#0090b0;
--red:#ff6b7a;--red-bg:rgba(255,107,122,.1);--red-border:rgba(255,107,122,.3);
--green:#26de81;--green-bg:rgba(38,222,129,.06);--green-border:rgba(38,222,129,.2);
--yellow:#fed330;--yellow-bg:rgba(254,211,48,.06);
}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'JetBrains Mono',monospace;background:var(--bg);color:var(--text);padding:0;min-height:100vh;font-size:15px}}
.top-bar{{background:var(--bg2);border-bottom:1px solid var(--border);padding:20px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}}
.brand{{display:flex;align-items:baseline;gap:12px}}
.brand h1{{font-family:'Space Grotesk',sans-serif;font-size:1.6em;font-weight:700;color:var(--accent);letter-spacing:-.5px}}
.brand .ver{{color:var(--text2);font-size:.8em}}
.brand-link{{color:var(--text2);font-size:.8em;text-decoration:none;border-bottom:1px solid transparent}}
.brand-link:hover{{color:var(--accent);border-bottom-color:var(--accent)}}
.target{{font-family:'Space Grotesk',sans-serif;font-size:1.15em;color:var(--text);opacity:.7}}
.meta-row{{background:var(--bg2);border-bottom:1px solid var(--border);padding:10px 32px;font-size:.82em;color:var(--text2);display:flex;gap:24px;flex-wrap:wrap}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;padding:24px 32px}}
.stat{{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:18px 20px;position:relative;overflow:hidden}}
.stat::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px}}
.stat.s-info::before{{background:var(--accent)}}.stat.s-ok::before{{background:var(--green)}}
.stat.s-warn::before{{background:var(--red)}}.stat.s-risk::before{{background:var(--yellow)}}
.stat .num{{font-family:'Space Grotesk',sans-serif;font-size:2.2em;font-weight:700;line-height:1}}
.stat.s-info .num{{color:var(--accent)}}.stat.s-ok .num{{color:var(--green)}}
.stat.s-warn .num{{color:var(--red)}}.stat.s-risk .num{{color:var(--yellow)}}
.stat .label{{color:var(--text2);font-size:.78em;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
.toolbar{{padding:16px 32px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}}
.search{{background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:9px 14px;border-radius:4px;font-family:inherit;font-size:.88em;width:300px;outline:none;transition:border .2s}}
.search:focus{{border-color:var(--accent)}}
.filter-btn{{background:var(--bg2);border:1px solid var(--border);color:var(--text2);padding:7px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:.8em;transition:all .15s}}
.filter-btn:hover,.filter-btn.active{{border-color:var(--accent);color:var(--accent)}}
.count{{color:var(--text2);font-size:.8em;margin-left:auto}}
.cards{{padding:0 32px 40px;display:flex;flex-direction:column;gap:6px}}
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:6px;cursor:pointer;transition:border .15s;overflow:hidden}}
.card:hover{{border-color:var(--accent2)}}
.card.new{{border-left:3px solid var(--red);background:var(--red-bg)}}
.card.live{{border-left:3px solid var(--green);background:var(--green-bg)}}
.card.reg{{border-left:3px solid var(--text2)}}
.card-head{{display:flex;align-items:center;gap:12px;padding:11px 16px;font-size:.92em;flex-wrap:wrap}}
.tag{{font-size:.72em;font-weight:700;padding:3px 9px;border-radius:3px;text-transform:uppercase;letter-spacing:.5px;flex-shrink:0}}
.tag.new{{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}}
.tag.live{{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}}
.tag.reg{{background:var(--bg3);color:var(--text2);border:1px solid var(--border)}}
.domain{{color:var(--accent);text-decoration:none;font-weight:600}}.domain:hover{{text-decoration:underline}}
.ip{{color:var(--text2);font-size:.88em}}
.badges{{display:flex;gap:4px;flex-wrap:wrap}}
.badge{{font-size:.68em;padding:3px 7px;border-radius:3px;font-weight:600;letter-spacing:.3px}}
.badge.risk{{background:rgba(255,107,122,.15);color:var(--red);border:1px solid rgba(255,107,122,.25)}}
.badge.tech{{background:rgba(0,212,255,.08);color:var(--accent);border:1px solid rgba(0,212,255,.15)}}
.chevron{{margin-left:auto;color:var(--text2);transition:transform .2s;font-size:.75em;flex-shrink:0}}
.card.open .chevron{{transform:rotate(180deg)}}
.card-body{{max-height:0;overflow:hidden;transition:max-height .25s ease}}
.card.open .card-body{{max-height:800px}}
.card-body>.sect{{padding:0 16px 12px 40px}}
.sect-title{{font-size:.72em;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text2);margin-bottom:4px;padding-top:8px;border-top:1px solid var(--border)}}
.sect:first-child .sect-title{{border-top:none}}
.card-body table{{width:100%;font-size:.88em;border-collapse:collapse}}
.card-body td{{padding:4px 0;vertical-align:top}}
.card-body .lbl{{width:90px;color:var(--text2);font-weight:600}}
.card-body a{{color:var(--accent);text-decoration:none}}.card-body a:hover{{text-decoration:underline}}
.card-body code{{background:var(--bg3);padding:1px 5px;border-radius:3px;font-size:.9em}}
.dim{{color:var(--text2)}}
@media(max-width:700px){{
.top-bar,.meta-row,.stats,.toolbar,.cards{{padding-left:16px;padding-right:16px}}
.search{{width:100%}}.card-head{{font-size:.82em}}.card-body>.sect{{padding-left:20px}}
}}
</style></head><body>

<div class="top-bar">
<div class="brand">
<h1>TLDSweep</h1>
<span class="ver">v{__version__}</span>
<a href="https://darkwebinformer.com" target="_blank" class="brand-link">by Dark Web Informer</a>
</div>
<div class="target">{e(base_name)}.*</div>
</div>

<div class="meta-row">
<span>{now}</span>
<span>{len(results)} TLDs scanned</span>
<span>{elapsed_str or "-"} elapsed</span>
</div>

<div class="stats">
<div class="stat s-info"><div class="num">{len(results)}</div><div class="label">Scanned</div></div>
<div class="stat s-ok"><div class="num">{rc}</div><div class="label">Registered</div></div>
<div class="stat s-ok"><div class="num">{ac}</div><div class="label">Live</div></div>
<div class="stat s-warn"><div class="num">{nc}</div><div class="label">Newly Reg</div></div>
<div class="stat s-risk"><div class="num">{risk_count}</div><div class="label">Flagged</div></div>
</div>

<div class="toolbar">
<input type="text" class="search" id="search" placeholder="Filter domains..." oninput="applyFilters()">
<button class="filter-btn" onclick="toggleFilter(this,'all')" data-f="all">All</button>
<button class="filter-btn" onclick="toggleFilter(this,'new')" data-f="new">New</button>
<button class="filter-btn" onclick="toggleFilter(this,'live')" data-f="live">Live</button>
<button class="filter-btn" onclick="toggleFilter(this,'risk')" data-f="risk">Flagged</button>
<span class="count" id="count">{len(active)} results</span>
</div>

<div class="cards" id="cards">
{cards_html}
</div>

<script>
let activeFilter='all';
function toggleFilter(btn,f){{
document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
btn.classList.add('active');activeFilter=f;applyFilters();
}}
function applyFilters(){{
const q=document.getElementById('search').value.toLowerCase();
let shown=0;
document.querySelectorAll('.card').forEach(c=>{{
const text=c.textContent.toLowerCase();
const matchQ=!q||text.includes(q);
let matchF=true;
if(activeFilter==='new')matchF=c.classList.contains('new');
else if(activeFilter==='live')matchF=c.classList.contains('live');
else if(activeFilter==='risk')matchF=c.querySelector('.badge.risk')!==null;
const vis=matchQ&&matchF;
c.style.display=vis?'':'none';
if(vis)shown++;
}});
document.getElementById('count').textContent=shown+' results';
}}
document.querySelector('[data-f="all"]').classList.add('active');
</script>
</body></html>""")
    print(f"{C.GRN}[+] HTML report exported to {filepath}{C.R}")

def load_config(path):
    if not os.path.exists(path):
        print(f"{C.RED}[!] Config not found: {path}{C.R}"); sys.exit(1)
    with open(path, encoding="utf-8") as f: text = f.read()
    try: return json.loads(text)
    except json.JSONDecodeError: pass
    cfg = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if ":" in line:
            k, v = line.split(":",1); k = k.strip().replace("-","_"); v = v.strip()
            if v.lower() in ("true","yes"): cfg[k] = True
            elif v.lower() in ("false","no"): cfg[k] = False
            elif v.isdigit(): cfg[k] = int(v)
            else:
                try: cfg[k] = float(v)
                except Exception: cfg[k] = v
    return cfg

def load_tld_list(tld_file=None):
    if tld_file and os.path.exists(tld_file):
        with open(tld_file, encoding="utf-8") as f:
            tlds = [l.strip().lower().lstrip(".") for l in f if l.strip() and not l.startswith("#")]
        seen, deduped = set(), []
        for t in tlds:
            if t not in seen: seen.add(t); deduped.append(t)
        print(f"{C.CYN}[*] Loaded {len(deduped)} TLDs from {tld_file}{C.R}")
        return deduped
    return COMMON_TLDS

def _print_banner():
    _dwi_link = C.link("https://darkwebinformer.com", "Dark Web Informer")
    print(f"""
{C.CYN}{C.BOLD}  ╺┳╸╻  ╺┳┓┏━┓╻ ╻┏━╸┏━╸┏━┓
   ┃ ┃   ┃┃┗━┓┃╻┃┣╸ ┣╸ ┣━┛
   ╹ ┗━╸╺┻┛┗━┛┗┻┛┗━╸┗━╸╹  {C.R}{C.DIM}v{__version__}{C.R}
{C.DIM}  by {_dwi_link}{C.R}""")

def _menu_input(prompt, default=""):
    suffix = f" [{default}]" if default else ""
    val = input(f"  {C.CYN}{prompt}{C.R}{suffix}: ").strip()
    return val if val else default

def _menu_choice(prompt, options, default=1):
    print(f"\n  {C.CYN}{prompt}{C.R}")
    for i, (key, label) in enumerate(options, 1):
        marker = f"{C.BOLD}>" if i == default else " "
        print(f"  {marker} {i}) {label}{C.R}")
    val = input(f"  {C.DIM}Choice [{default}]:{C.R} ").strip()
    try:
        idx = int(val) if val else default
        if 1 <= idx <= len(options): return options[idx - 1][0]
    except ValueError: pass
    return options[default - 1][0]

def _menu_toggle(prompt, default=True):
    yn = "Y/n" if default else "y/N"
    val = input(f"  {C.CYN}{prompt}{C.R} [{yn}]: ").strip().lower()
    if not val: return default
    return val in ("y", "yes")

def interactive_menu():
    W = 62
    _print_banner()
    print(f"{C.DIM}  {'─' * W}{C.R}")
    print(f"\n  {C.BOLD}SCAN CONFIGURATION{C.R}\n")

    base_name = ""
    while not base_name:
        base_name = input(f"  {C.CYN}Target domain{C.R} (e.g. example): ").strip().lower().replace(" ", "")
        if not base_name:
            print(f"  {C.RED}Domain required.{C.R}")

    mode = _menu_choice("Scan mode", [
        ("full", "Full    - DNS + WHOIS + TLS + HTTP"),
        ("new",  "New-Only - DNS + WHOIS creation-date check"),
        ("quick","Quick   - DNS only"),
    ], default=1)

    no_whois = False; no_http = False; no_tls = False
    if mode == "full":
        print(f"\n  {C.BOLD}MODULES{C.R}")
        whois_on = _menu_toggle("WHOIS lookup", True)
        http_on  = _menu_toggle("HTTP probe",   True)
        tls_on   = _menu_toggle("TLS grab",     True)
        no_whois = not whois_on; no_http = not http_on; no_tls = not tls_on

    print(f"\n  {C.BOLD}PERFORMANCE{C.R}")
    dns_threads = int(_menu_input("DNS threads", "100"))
    threads     = int(_menu_input("Recon threads", "30"))
    timeout     = float(_menu_input("Timeout (sec)", "5.0"))
    con_timeout = float(_menu_input("Connect timeout (sec)", "2.0"))
    newly_days  = int(_menu_input("New-reg threshold (days)", "90"))

    print(f"\n{C.DIM}  {'─' * W}{C.R}\n")

    ns = argparse.Namespace(
        domain=base_name,
        threads=threads, dns_threads=dns_threads, whois_threads=20,
        timeout=timeout, connect_timeout=con_timeout,
        output=None, csv=None, html_report=None,
        output_dir=".", no_auto_json=False,
        tld_file=None, newly_registered=newly_days,
        config=None,
        new_only=(mode == "new"), quick=(mode == "quick"),
        no_whois=no_whois, no_http=no_http, no_tls=no_tls,
        no_color=False, verbose=False, registered_only=False,
        resolvers=None, watch=0,
        discord_webhook=None, telegram=None,
    )
    return ns

def main():
    if len(sys.argv) > 1 and sys.argv[1] not in ("-V", "--version", "-h", "--help"):
        cli_mode = True
    elif len(sys.argv) == 1:
        cli_mode = False
    else:
        cli_mode = True

    parser = argparse.ArgumentParser(
        description=f"TLDSweep v{__version__} - TLD recon & domain intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example
  %(prog)s example --threads 50 --output results.json
  %(prog)s example --newly-registered 30 --csv results.csv
  %(prog)s example --new-only
  %(prog)s example --quick
  %(prog)s example --html-report report.html
  %(prog)s example --config profile.json

Run with no arguments for interactive mode.
        """)
    parser.add_argument("domain", nargs="?", default=None, help="Base domain name to scan")
    parser.add_argument("-t","--threads", type=int, default=30)
    parser.add_argument("--dns-threads", type=int, default=100)
    parser.add_argument("--whois-threads", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--connect-timeout", type=float, default=2.0)
    parser.add_argument("-o","--output", help="Standalone JSON export")
    parser.add_argument("--csv", help="CSV export")
    parser.add_argument("--html-report", help="Interactive HTML report")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--no-auto-json", action="store_true")
    parser.add_argument("--tld-file")
    parser.add_argument("--newly-registered", type=int, default=90)
    parser.add_argument("--config", help="JSON or key:value config file")
    mg = parser.add_mutually_exclusive_group()
    mg.add_argument("--new-only", action="store_true", help="DNS + WHOIS creation-date only")
    mg.add_argument("--quick", action="store_true", help="DNS only")
    parser.add_argument("--no-whois", action="store_true")
    parser.add_argument("--no-http", action="store_true")
    parser.add_argument("--no-tls", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("-v","--verbose", action="store_true")
    parser.add_argument("--registered-only", action="store_true")
    parser.add_argument("--resolvers", help="Comma-separated DNS resolvers (e.g. 1.1.1.1,9.9.9.9)")
    parser.add_argument("--watch", type=int, default=0, metavar="MIN",
                        help="Re-scan every N minutes (0=disabled)")
    parser.add_argument("--discord-webhook", help="Discord webhook URL for alerts (or set TLDSWEEP_DISCORD_WEBHOOK)")
    parser.add_argument("--telegram", metavar="TOKEN:CHAT_ID",
                        help="Telegram bot token:chat_id for alerts (or set TLDSWEEP_TELEGRAM_TOKEN + TLDSWEEP_TELEGRAM_CHAT_ID)")
    parser.add_argument("-V","--version", action="version", version=f"%(prog)s {__version__}")

    if cli_mode:
        args = parser.parse_args()
        if not args.domain:
            parser.error("domain is required in CLI mode")
        if args.config:
            cfg = load_config(args.config)
            for k, v in cfg.items():
                if hasattr(args, k) and getattr(args, k) == parser.get_default(k):
                    setattr(args, k, v)
        if args.no_color: C.disable()
    else:
        args = interactive_menu()

    base_name = args.domain.lower().strip().replace(" ","")
    base_name = re.sub(r'[/\\<>:"|?*\x00-\x1f]', '', base_name).lstrip('.')
    if not base_name:
        print(f"  {C.RED}[!] Invalid domain name.{C.R}")
        sys.exit(1)

    global DNS_RESOLVERS, DNS_RESOLVER_LABELS
    if args.resolvers:
        DNS_RESOLVERS = [r.strip() for r in args.resolvers.split(",") if r.strip()]
        DNS_RESOLVER_LABELS = {r: "custom" for r in DNS_RESOLVERS}

    notify_cfg = _get_notify_config()
    if args.discord_webhook:
        notify_cfg["discord"] = args.discord_webhook
    if args.telegram and ":" in args.telegram:
        parts = args.telegram.rsplit(":", 1)
        if len(parts) == 2:
            notify_cfg["telegram_token"] = parts[0]
            notify_cfg["telegram_chat"] = parts[1]
    _has_notify = bool(notify_cfg.get("discord") or
                       (notify_cfg.get("telegram_token") and notify_cfg.get("telegram_chat")))

    tlds = load_tld_list(args.tld_file)

    if args.new_only:
        ml = "New-Only (DNS + fast WHOIS)"; we,he,te,de = True,False,False,False
    elif args.quick:
        ml = "Quick (DNS only)"; we,he,te,de = False,False,False,False
    else:
        ml = "Full (DNS+WHOIS+HTTP+TLS)"
        we,he,te,de = not args.no_whois, not args.no_http, not args.no_tls, True

    W = 62
    _print_banner()
    print(f"""{C.DIM}  {'─' * W}{C.R}

  {C.CYN}Target      {C.R}│  {C.BOLD}{base_name}.*{C.R}
  {C.CYN}TLDs        {C.R}│  {len(tlds)}
  {C.CYN}Threads     {C.R}│  {args.dns_threads} dns  /  {args.threads} recon
  {C.CYN}Timeout     {C.R}│  {args.timeout}s  (connect {args.connect_timeout}s)
  {C.CYN}Mode        {C.R}│  {ml}
  {C.CYN}New Reg     {C.R}│  Flag if ≤ {args.newly_registered} days
  {C.CYN}Resolvers   {C.R}│  {', '.join(f'{r} ({DNS_RESOLVER_LABELS.get(r, "")})' for r in DNS_RESOLVERS)}
  {C.CYN}Alerts      {C.R}│  {'Discord ✓' if notify_cfg.get('discord') else '-'}  {'Telegram ✓' if (notify_cfg.get('telegram_token') and notify_cfg.get('telegram_chat')) else '-'}
  {C.CYN}Watch       {C.R}│  {'Every ' + str(args.watch) + ' min' if args.watch else 'Off'}
  {C.CYN}Started     {C.R}│  {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

{C.DIM}  {'─' * W}{C.R}
""")

    results: List[ScanResult] = []
    _t0 = time.monotonic()

    if not args.quick:
        print(f"  {C.CYN}[1/3] DNS sweep across {len(tlds)} TLDs...{C.R}")
        dns_cache = dns_batch_scan(base_name, tlds, args.timeout, args.dns_threads)
        if _shutdown.is_set(): print(f"\n  {C.YEL}[!] Interrupted{C.R}"); return
        resolved = [t for t,d in dns_cache.items() if d.resolved]
        print(f"  {C.GRN}      → {len(resolved)} resolved{C.R}\n")

        whois_cache = {}
        if we and resolved:
            print(f"  {C.CYN}[2/3] Fast WHOIS on {len(resolved)} domains...{C.R}")
            whois_cache = whois_new_reg_scan(base_name, resolved, args.timeout,
                                             args.whois_threads, args.newly_registered,
                                             args.connect_timeout)
            if _shutdown.is_set(): print(f"\n  {C.YEL}[!] Interrupted{C.R}"); return
            nf = sum(1 for w in whois_cache.values() if w.newly_registered)
            print(f"  {C.RED if nf else C.GRN}      → {nf} newly registered{C.R}\n")

        if args.new_only:
            print(f"  {C.CYN}[3/3] Building results (new-only)...{C.R}\n")
            for tld in tlds:
                domain = f"{base_name}.{tld}"
                dr = dns_cache.get(tld, DnsResult())
                fw = whois_cache.get(tld, WhoisResult())
                r = ScanResult(domain=domain, tld=tld,
                               timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()+"Z",
                               dns=dr, whois=fw,
                               registered=dr.resolved or bool(fw.creation_date),
                               newly_registered=fw.newly_registered,
                               url=f"https://{domain}")
                if fw.newly_registered:
                    r.risk_indicators.append("NEWLY_REGISTERED")
                    if fw.age_days is not None:
                        if fw.age_days <= 7: r.risk_indicators.append("REGISTERED_WITHIN_7_DAYS")
                        elif fw.age_days <= 30: r.risk_indicators.append("REGISTERED_WITHIN_30_DAYS")
                if tld in SUSPICIOUS_TLDS and r.registered: r.risk_indicators.append("SUSPICIOUS_TLD")
                results.append(r)
        else:
            print(f"  {C.CYN}[3/3] Full recon on {len(resolved)} domains...{C.R}")
            with ThreadPoolExecutor(max_workers=args.threads) as ex:
                futs = {}
                for tld in tlds:
                    if _shutdown.is_set(): break
                    futs[ex.submit(scan_domain, base_name, tld, args.timeout,
                                   we, he, te, de,
                                   dns_cache.get(tld), whois_cache.get(tld),
                                   args.connect_timeout,
                                   args.newly_registered)] = tld
                total, done = len(futs), 0
                _p0 = time.monotonic()
                for f in as_completed(futs):
                    done += 1; tld = futs[f]
                    try:
                        r = f.result(); results.append(r)
                        if not args.registered_only or r.registered or r.alive:
                            print_result(r, args.verbose, args.newly_registered)
                        eta = _format_eta(done, total, time.monotonic() - _p0)
                        sys.stderr.write(f"\r  {C.DIM}[{done}/{total}] Full recon... {eta}{C.R}    ")
                        sys.stderr.flush()
                    except Exception as e:
                        sys.stderr.write(f"\r  {C.RED}[!] Error {base_name}.{tld}: {e}{C.R}\n")
                    if _shutdown.is_set(): break
            sys.stderr.write("\r" + " "*60 + "\r")
    else:
        with ThreadPoolExecutor(max_workers=args.dns_threads) as ex:
            futs = {}
            for tld in tlds:
                if _shutdown.is_set(): break
                futs[ex.submit(scan_domain, base_name, tld, args.timeout,
                               False,False,False,False)] = tld
            total, done = len(futs), 0
            _p0 = time.monotonic()
            for f in as_completed(futs):
                done += 1; tld = futs[f]
                try:
                    r = f.result(); results.append(r)
                    if not args.registered_only or r.registered:
                        print_result(r, args.verbose)
                    eta = _format_eta(done, total, time.monotonic() - _p0)
                    sys.stderr.write(f"\r  {C.DIM}[{done}/{total}] DNS scan... {eta}{C.R}    ")
                    sys.stderr.flush()
                except Exception as e:
                    sys.stderr.write(f"\r  {C.RED}[!] Error {base_name}.{tld}: {e}{C.R}\n")
                if _shutdown.is_set(): break
        sys.stderr.write("\r" + " "*60 + "\r")

    if args.new_only:
        for r in sorted(results, key=lambda x: (-int(x.newly_registered), -int(x.registered))):
            if r.registered or r.alive:
                print_result(r, args.verbose, args.newly_registered)

    rc = sum(1 for r in results if r.registered)
    ac = sum(1 for r in results if r.alive)
    nc = sum(1 for r in results if r.newly_registered)
    intr = " (interrupted)" if _shutdown.is_set() else ""
    elapsed = time.monotonic() - _t0
    if elapsed >= 3600:
        elapsed_str = f"{int(elapsed // 3600)}h {int((elapsed % 3600) // 60)}m {elapsed % 60:.1f}s"
    elif elapsed >= 60:
        elapsed_str = f"{int(elapsed // 60)}m {elapsed % 60:.1f}s"
    else:
        elapsed_str = f"{elapsed:.1f}s"

    print(f"""
{C.DIM}  {'─' * 62}{C.R}
{C.BOLD}  SCAN COMPLETE{C.R}{C.DIM}{intr}{C.R}
{C.DIM}  {'─' * 62}{C.R}
  {C.CYN}TLDs scanned       {C.R}│  {len(tlds)}
  {C.GRN}Registered         {C.R}│  {rc}
  {C.GRN}Live (HTTP/S)      {C.R}│  {ac}
  {C.RED}Newly registered   {C.R}│  {nc}
  {C.CYN}Elapsed            {C.R}│  {elapsed_str}
{C.DIM}  {'─' * 62}{C.R}
""")

    results.sort(key=lambda r: (-int(r.newly_registered), -int(r.alive), -int(r.registered)))

    if not args.no_auto_json:
        sf = os.path.join(args.output_dir, f"{base_name}_scans.json")
        prev = set()
        if os.path.exists(sf):
            try:
                with open(sf, encoding="utf-8") as f: pd = json.load(f)
                if pd.get("scans"):
                    prev = {r["domain"] for r in pd["scans"][-1].get("results",[])}
            except Exception: pass
        fp = auto_export_json(results, base_name, args.output_dir)
        ts = 0
        try:
            with open(fp, encoding="utf-8") as f: ts = json.load(f).get("total_scans",0)
        except Exception: pass
        _ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        hp = os.path.join(args.output_dir, f"{base_name}_report_{_ts}.html")
        export_html(results, hp, base_name, elapsed_str)
        print(f"  {C.GRN}[+] Auto-saved to {C.BOLD}{fp}{C.R}")
        print(f"  {C.GRN}[+] HTML report  → {C.BOLD}{hp}{C.R}")
        print(f"  {C.DIM}    Scan #{ts} logged{C.R}")
        curr = {r.domain for r in results if r.registered or r.alive}
        nd, gd = curr - prev, prev - curr
        if prev:
            if nd:
                print(f"\n  {C.RED}{C.BOLD}NEW since last scan ({len(nd)}):{C.R}")
                for d in sorted(nd): print(f"    {C.RED}+ {C.link(f'https://{d}', d)}{C.R}")
            if gd:
                print(f"\n  {C.YEL}GONE since last scan ({len(gd)}):{C.R}")
                for d in sorted(gd): print(f"    {C.DIM}- {d}{C.R}")
            if not nd and not gd: print(f"\n  {C.DIM}  No changes since last scan.{C.R}")
        print()

        if _has_notify:
            _send_scan_alert(notify_cfg, base_name, results,
                             nd if prev else None, gd if prev else None,
                             elapsed_str=elapsed_str)

    if args.output: export_json([r for r in results if r.registered or r.alive], args.output)
    if args.csv: export_csv([r for r in results if r.registered or r.alive], args.csv)
    if args.html_report: export_html(results, args.html_report, base_name, elapsed_str)

    if args.watch > 0 and not _shutdown.is_set():
        print(f"\n  {C.CYN}[*] Watch mode: re-scanning every {args.watch} minutes. Ctrl+C to stop.{C.R}\n")
        while not _shutdown.is_set():
            for _ in range(args.watch * 60):
                if _shutdown.is_set(): break
                time.sleep(1)
            if _shutdown.is_set(): break
            print(f"\n  {C.CYN}{'═' * 62}{C.R}")
            print(f"  {C.CYN}{C.BOLD}  WATCH: Starting re-scan at {datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S UTC')}{C.R}")
            print(f"  {C.CYN}{'═' * 62}{C.R}\n")
            _shutdown.clear()
            results = []
            _t0 = time.monotonic()
            if not args.quick:
                dns_cache = dns_batch_scan(base_name, tlds, args.timeout, args.dns_threads)
                if _shutdown.is_set(): break
                resolved = [t for t,d in dns_cache.items() if d.resolved]
                whois_cache = {}
                if we and resolved:
                    whois_cache = whois_new_reg_scan(base_name, resolved, args.timeout,
                                                     args.whois_threads, args.newly_registered,
                                                     args.connect_timeout)
                if _shutdown.is_set(): break
                if args.new_only:
                    for tld in tlds:
                        domain = f"{base_name}.{tld}"
                        dr = dns_cache.get(tld, DnsResult())
                        fw = whois_cache.get(tld, WhoisResult())
                        r = ScanResult(domain=domain, tld=tld,
                                       timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()+"Z",
                                       dns=dr, whois=fw,
                                       registered=dr.resolved or bool(fw.creation_date),
                                       newly_registered=fw.newly_registered,
                                       url=f"https://{domain}")
                        if fw.newly_registered:
                            r.risk_indicators.append("NEWLY_REGISTERED")
                        if tld in SUSPICIOUS_TLDS and r.registered:
                            r.risk_indicators.append("SUSPICIOUS_TLD")
                        results.append(r)
                else:
                    with ThreadPoolExecutor(max_workers=args.threads) as ex:
                        futs = {ex.submit(scan_domain, base_name, t, args.timeout,
                                          we, he, te, de, dns_cache.get(t), whois_cache.get(t),
                                          args.connect_timeout, args.newly_registered): t for t in tlds}
                        for f in as_completed(futs):
                            try: results.append(f.result())
                            except Exception: pass
                            if _shutdown.is_set(): break
            else:
                with ThreadPoolExecutor(max_workers=args.dns_threads) as ex:
                    futs = {ex.submit(scan_domain, base_name, t, args.timeout,
                                      False,False,False,False): t for t in tlds}
                    for f in as_completed(futs):
                        try: results.append(f.result())
                        except Exception: pass
                        if _shutdown.is_set(): break
            if _shutdown.is_set(): break
            elapsed = time.monotonic() - _t0
            elapsed_str = f"{elapsed:.1f}s" if elapsed < 60 else f"{int(elapsed//60)}m {elapsed%60:.1f}s"
            rc = sum(1 for r in results if r.registered)
            nc = sum(1 for r in results if r.newly_registered)
            print(f"\n  {C.BOLD}WATCH SCAN COMPLETE{C.R} - {rc} registered, {nc} newly registered, {elapsed_str}")
            results.sort(key=lambda r: (-int(r.newly_registered), -int(r.alive), -int(r.registered)))
            if not args.no_auto_json:
                auto_export_json(results, base_name, args.output_dir)
                _ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
                hp = os.path.join(args.output_dir, f"{base_name}_report_{_ts}.html")
                export_html(results, hp, base_name, elapsed_str)
            for r in results:
                if r.newly_registered:
                    print_result(r, args.verbose, args.newly_registered)
            if _has_notify:
                _send_scan_alert(notify_cfg, base_name, results, elapsed_str=elapsed_str)

if __name__ == "__main__":
    main()
