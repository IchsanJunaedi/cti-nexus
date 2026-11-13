# SOURCE-OF-TRUTH for IOC regex patterns.
# ScraperNewsWeb/app/services/newsletter_service.py mirrors this implementation.
# When updating extraction logic, change here first, then sync to newsletter_service.py.
import re
import ipaddress as _ipaddress

_SEP = r'(?:\.|\.|\[\.\]|\[\.|\.  \]|\(\.\)|\{\.\}|\[dot\]|\(dot\))'
_DEFANG_SEP = r'(?:\[\.\]|\[\.|\.  \]|\(\.\)|\{\.\}|\[dot\]|\(dot\))'
_LABEL = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?'
_ALPHA_LABEL = r'(?:[a-zA-Z0-9]*[a-zA-Z][a-zA-Z0-9]*)'

_TLD = (
    r'(?:com|net|org|io|gov|edu|mil|int|info|biz|xyz|ru|cn|de|uk|co|top|site|'
    r'online|tech|app|dev|cloud|red|pw|cc|tv|me|mobi|ly|to|sh|gg|is|am|fm|ac|'
    r'in|jp|fr|eu|au|nz|ca|br|pl|nl|se|no|fi|dk|ch|at|be|il|sg|hk|tw|kr|th|'
    r'id|my|ph|vn|ua|tr|sa|ae|za|ng|ke|gh)'
)

_RE_IP = re.compile(r'\b(?:\d{1,3})(?:\s*' + _SEP + r'\s*(?:\d{1,3})){3}\b')
_RE_VERSION_PREFIX = re.compile(
    r'(?:version|ver|firmware|software|release|patch|build|update|v)\s*[:\s]*'
    r'(\d{1,3}(?:\.\d{1,3}){3})',
    re.IGNORECASE
)
_RE_URL_PROTO = re.compile(
    r'(?:hxxps?|https?|fxp|ftp)://(?:' + _LABEL + r'(?:\s*' + _SEP + r'\s*))+[a-zA-Z]{2,}(?:/[^\s]*)?'
)
_RE_URL_PATH = re.compile(
    r'(?:' + _ALPHA_LABEL + r'(?:' + _SEP + r'))'
    + r'(?:' + _LABEL + r'(?:' + _SEP + r'))*'
    + _TLD + r'/[^\s]+'
)
_RE_EMAIL = re.compile(
    r'[a-zA-Z0-9._%+-]+(?:\s*(?:\[@\]|\[at\]|@|\(@\))\s*)' + _LABEL
    + r'(?:\s*' + _SEP + r'\s*)+[a-zA-Z]{2,}'
)
_RE_DOMAIN_DEFANGED = re.compile(
    _LABEL
    + r'(?:\s*' + _SEP + r'\s*' + _LABEL + r')*'
    + r'\s*' + _DEFANG_SEP + r'\s*'
    + r'[a-zA-Z]{2,}'
)
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_CVE    = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

_PRIVATE_NETWORKS = [
    _ipaddress.ip_network("0.0.0.0/8"),
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("100.64.0.0/10"),
    _ipaddress.ip_network("127.0.0.0/8"),
    _ipaddress.ip_network("169.254.0.0/16"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.0.0.0/24"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("198.18.0.0/15"),
    _ipaddress.ip_network("255.255.255.255/32"),
]

_RE_DEFANG_DOT = re.compile(r'\s*(?:\[\.\]|\[\.|\.  \]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\\.)\s*')
_RE_DEFANG_PROTO = re.compile(r'^hxx(ps?)://', re.IGNORECASE)
_RE_DEFANG_FXP = re.compile(r'^fxp://', re.IGNORECASE)


def _refang(value: str) -> str:
    v = _RE_DEFANG_DOT.sub('.', value)
    v = _RE_DEFANG_PROTO.sub(r'htt\1://', v)
    v = _RE_DEFANG_FXP.sub('ftp://', v)
    return v.strip()


def _is_private_ip(raw: str) -> bool:
    clean = _RE_DEFANG_DOT.sub('.', raw)
    try:
        return any(_ipaddress.ip_address(clean) in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


_RE_EXTRACT_DOMAIN = re.compile(r'^(?:https?://)?([^/:?\s]+)')


def _url_domain(url: str) -> str:
    m = _RE_EXTRACT_DOMAIN.match(url.lower())
    return m.group(1) if m else ""


def _email_domain(email: str) -> str:
    parts = re.split(r'[@\[\(]at[\)\]]', email.lower())
    if len(parts) == 2:
        return parts[1].strip().lstrip('[').rstrip(']').strip()
    if '@' in email:
        return email.split('@', 1)[1].lower()
    return ""


def _filter_iocs(ioc_dict: dict, source_url: str = "", allowlist: dict | None = None) -> dict:
    url_domains: set = (allowlist or {}).get("url_domains", set())
    email_domains: set = (allowlist or {}).get("email_domains", set())
    allowlisted_ips: set = (allowlist or {}).get("ips", set())
    source_domain = _url_domain(source_url) if source_url else ""

    def _ok_ip(v: str) -> bool:
        if _is_private_ip(v):
            return False
        clean = _RE_DEFANG_DOT.sub('.', v)
        return clean not in allowlisted_ips

    def _ok_url(v: str) -> bool:
        d = _url_domain(v)
        if source_domain and (d == source_domain or d.endswith("." + source_domain)):
            return False
        return d not in url_domains

    def _ok_email(v: str) -> bool:
        return _email_domain(v) not in email_domains

    filters = {"ips": _ok_ip, "urls": _ok_url, "urls_with_path": _ok_url, "emails": _ok_email}
    result = {}
    for key, values in ioc_dict.items():
        fn = filters.get(key)
        result[key] = [v for v in values if fn is None or fn(v)]
    return {k: v for k, v in result.items() if v}


def extract_iocs(text: str, source_url: str = "", allowlist: dict | None = None) -> dict:
    if not text:
        return {}
    version_numbers = {m.group(1) for m in _RE_VERSION_PREFIX.finditer(text)}
    urls = list(dict.fromkeys(_refang(u) for u in _RE_URL_PROTO.findall(text)))
    text_no_urls = _RE_URL_PROTO.sub(" ", text)
    urls_with_path = list(dict.fromkeys(_refang(u) for u in _RE_URL_PATH.findall(text_no_urls)))
    text_no_urls_or_paths = _RE_URL_PATH.sub(" ", text_no_urls)
    raw = {
        "ips":            [ip for ip in dict.fromkeys(_RE_IP.findall(text)) if ip not in version_numbers],
        "urls":           urls,
        "urls_with_path": urls_with_path,
        "domains":        list(dict.fromkeys(_RE_DOMAIN_DEFANGED.findall(text_no_urls_or_paths))),
        "emails":         list(dict.fromkeys(_RE_EMAIL.findall(text))),
        "sha256":         list(dict.fromkeys(_RE_SHA256.findall(text))),
        "sha1":           list(dict.fromkeys(_RE_SHA1.findall(text))),
        "md5":            list(dict.fromkeys(_RE_MD5.findall(text))),
        "cves":           list(dict.fromkeys(m.upper() for m in _RE_CVE.findall(text))),
    }
    return _filter_iocs({k: v for k, v in raw.items() if v}, source_url=source_url, allowlist=allowlist)
