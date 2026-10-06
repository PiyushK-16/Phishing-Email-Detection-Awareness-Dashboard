"""Static URL analysis. URLs are NEVER fetched or opened - string inspection only.
Note: HTTPS only means the connection is encrypted; phishing sites use HTTPS too."""
import re
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "tiny.example", "short.example"}
KEYWORDS = ["verify", "login", "signin", "secure", "account", "update", "password", "confirm",
            "suspend", "billing", "wallet", "invoice", "unlock"]
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def defang(url):
    """Safe representation so nobody clicks it by accident."""
    return re.sub(r"^http", "hxxp", url, flags=re.I).replace(".", "[.]")[:300]


def analyze_url(url):
    url = (url or "").strip()
    findings, score = [], 0

    def add(msg, pts):
        nonlocal score
        findings.append(msg)
        score += pts

    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return {"url": defang(url), "score": 30, "findings": ["URL could not be parsed (malformed)"],
                "details": {}}
    is_ip = bool(IP_RE.match(host))
    labels = host.split(".") if host and not is_ip else []
    subdomains = max(len(labels) - 2, 0)
    full = (host + p.path + (p.query or "")).lower()
    hits = [k for k in KEYWORDS if k in full]

    if not host:
        add("No hostname found", 30)
    if is_ip:
        add("Raw IP address used instead of a domain name", 40)
    if p.scheme != "https":
        add("Non-HTTPS URL (note: HTTPS alone never proves safety)", 15)
    if hits:
        add("Suspicious keyword(s) in URL: " + ", ".join(hits[:4]), min(10 * len(hits), 30))
    if host in SHORTENERS:
        add("URL-shortener pattern hides the real destination", 20)
    if subdomains >= 3:
        add(f"Excessive subdomains ({subdomains})", 20)
    if "@" in p.netloc:
        add("'@' in URL authority can disguise the real host", 25)
    if "xn--" in host:
        add("Punycode hostname (possible look-alike characters)", 15)
    if host.count("-") >= 3:
        add("Many hyphens in hostname", 10)
    if len(url) > 75:
        add("Very long URL", 10)
    if port not in (None, 80, 443):
        add(f"Unusual port {port}", 10)
    return {"url": defang(url), "score": min(score, 100), "findings": findings,
            "details": {"scheme": p.scheme, "hostname": host, "path": p.path, "query": p.query,
                        "url_length": len(url), "hostname_length": len(host), "subdomains": subdomains,
                        "is_ip": is_ip, "https": p.scheme == "https", "keywords": hits}}
