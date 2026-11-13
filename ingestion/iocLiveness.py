"""IOC liveness checker.

Reads news_db.iocs, probes domain/ip/url/url_with_path IOCs to determine
whether the underlying infrastructure is still live, and detects sinkholed
infrastructure. Feeds ScraperNewsWeb's confidence_service.compute_ioc_actionability
so dead/sinkholed infra isn't recommended for "block_now".

Probing per type:
  domain          -> DNS resolve, then optional HTTP HEAD to http://<domain>
  url             -> resolve hostname from URL, then HTTP HEAD on the URL itself
  url_with_path   -> resolve hostname (no scheme in value), HEAD http://<value>
  ip              -> TCP connect probe to common ports (443, 80)

Sinkhole detection (small, documented set — extend via config.yml `liveness.sinkhole_networks`):
  - Resolved/probed IP is 0.0.0.0, ::, or in 127.0.0.0/8 (RFC 5735 loopback /
    "blackhole" — DNS firewalls and RPZ feeds commonly rewrite sinkholed
    domains to these. 127.0.53.53 specifically is ICANN's documented
    name-collision wildcard response).
  - Resolved/probed IP falls in a CIDR listed under config.yml `liveness.sinkhole_networks`
    (populate from feeds such as Shadowserver's sinkhole report or Spamhaus DROP).
  - Reverse DNS (PTR) of the resolved IP contains a hint string from
    _SINKHOLE_NS_HINTS (e.g. "sinkhole").

Writes per IOC:
  liveness            : "live" | "dead" | "sinkholed" | "unknown"
  liveness_checked_at : datetime (UTC)
  liveness_http_status: int      # optional, only set when an HTTP HEAD succeeded

Re-check cadence: only IOCs whose liveness_checked_at is missing or older than
RECHECK_HOURS.

Add crontab (every 12h):
  0 */12 * * * cd /path/to/ScraperNewsRevamp && python3 iocLiveness.py
Requires config.yml news_db section (see otxEnrichment.py). Optional:
  liveness:
    sinkhole_networks: ["203.0.113.0/24"]   # extra CIDRs, see comment above
"""

import socket
import time
import ipaddress
import yaml
import requests
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from pymongo import MongoClient

BATCH_SIZE     = 30
RECHECK_HOURS  = 24
DNS_TIMEOUT    = 5
TCP_TIMEOUT    = 3
HTTP_TIMEOUT   = 8
SLEEP_BETWEEN  = 1.0  # seconds between probes — network politeness

_PROBE_TYPES = ["domain", "ip", "url", "url_with_path"]
_PROBE_PORTS = (443, 80)

# Hostname substrings seen in sinkhole PTR records (e.g. "sinkhole.shadowserver.org").
_SINKHOLE_NS_HINTS = {"sinkhole", "sink-hole", "blackhole"}

with open("config/config.yml", "r") as f:
    cfg = yaml.safe_load(f)

NEWS_DB_URI = (
    f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
    f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
)

_SINKHOLE_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in cfg.get("liveness", {}).get("sinkhole_networks", [])
]


def _is_blackhole_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_unspecified or addr.is_loopback


def _reverse_dns(ip: str) -> str:
    with ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(socket.gethostbyaddr, ip)
        try:
            hostname, _, _ = future.result(timeout=DNS_TIMEOUT)
            return hostname.lower()
        except Exception:
            return ""


def _is_sinkhole_ip(ip: str) -> bool:
    if _is_blackhole_ip(ip):
        return True
    try:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in _SINKHOLE_NETWORKS):
            return True
    except ValueError:
        pass
    ptr = _reverse_dns(ip)
    return any(hint in ptr for hint in _SINKHOLE_NS_HINTS)


def _resolve(host: str) -> tuple[list[str], str]:
    """DNS resolve host. Returns (ips, status) with status in ok|nxdomain|timeout|error."""
    with ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(socket.getaddrinfo, host, None)
        try:
            results = future.result(timeout=DNS_TIMEOUT)
            ips = list(dict.fromkeys(r[4][0] for r in results))
            return ips, "ok"
        except FutureTimeoutError:
            return [], "timeout"
        except socket.gaierror:
            return [], "nxdomain"
        except Exception:
            return [], "error"


def _tcp_probe(ip: str) -> str:
    for port in _PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
                return "live"
        except OSError:
            continue
    return "dead"


def _http_head(url: str) -> int | None:
    try:
        resp = requests.head(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
        return resp.status_code
    except Exception:
        return None


def _extract_host(ioc_type: str, value: str) -> tuple[str, str]:
    """Returns (hostname_to_resolve, url_to_probe_with_head)."""
    if ioc_type == "domain":
        return value, f"http://{value}"
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or "", value
    # url_with_path without scheme, e.g. "evil.com/bad/path"
    host = value.split("/", 1)[0].split(":")[0]
    return host, f"http://{value}"


def _check_liveness(ioc_type: str, value: str) -> tuple[str, int | None]:
    if ioc_type == "ip":
        if _is_sinkhole_ip(value):
            return "sinkholed", None
        return _tcp_probe(value), None

    host, probe_url = _extract_host(ioc_type, value)
    if not host:
        return "unknown", None

    ips, status = _resolve(host)
    if status in ("timeout", "error"):
        return "unknown", None
    if status == "nxdomain" or not ips:
        return "dead", None

    for ip in ips:
        if _is_sinkhole_ip(ip):
            return "sinkholed", None

    http_status = _http_head(probe_url)
    return "live", http_status


def main() -> None:
    client = MongoClient(NEWS_DB_URI)
    try:
        col = client[cfg["news_db"]["db"]]["iocs"]
        cutoff = datetime.now(timezone.utc) - timedelta(hours=RECHECK_HOURS)

        docs = list(col.find(
            {
                "type": {"$in": _PROBE_TYPES},
                "$or": [
                    {"liveness_checked_at": {"$exists": False}},
                    {"liveness_checked_at": {"$lt": cutoff}},
                ],
            },
            {"_id": 1, "type": 1, "value": 1},
            limit=BATCH_SIZE,
        ))

        if not docs:
            print("[Liveness] No IOCs due for a liveness check")
            return

        print(f"[Liveness] Checking {len(docs)} IOCs")
        counts = {"live": 0, "dead": 0, "sinkholed": 0, "unknown": 0, "failed": 0}

        for i, doc in enumerate(docs):
            try:
                liveness, http_status = _check_liveness(doc["type"], doc["value"])
                update = {
                    "liveness": liveness,
                    "liveness_checked_at": datetime.now(timezone.utc),
                }
                if http_status is not None:
                    update["liveness_http_status"] = http_status
                col.update_one({"_id": doc["_id"]}, {"$set": update})
                counts[liveness] += 1
            except Exception as e:
                print(f"[Liveness] Error {doc['type']}/{doc['value']}: {e}")
                counts["failed"] += 1

            if i < len(docs) - 1:
                time.sleep(SLEEP_BETWEEN)

        print(f"[Liveness] Done — {counts}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
