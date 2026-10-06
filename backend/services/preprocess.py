"""Preprocessing helpers.
We DO NOT lowercase/strip punctuation from the stored text: capitals ("URGENT"),
exclamation marks and URL characters are evidence. We only remove control characters
and normalise whitespace."""
import re
from email.utils import parseaddr

URL_RE = re.compile(r"(?:https?|hxxps?)://[^\s<>\"')\]]+", re.I)
EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)$")


def sanitize(text, max_len=50000):
    text = "" if text is None else str(text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)  # control chars
    return text[:max_len]


def clean_text(text):
    return re.sub(r"[ \t]+", " ", sanitize(text)).strip()


def extract_urls(text):
    """Find URLs (static string matching only - never visited)."""
    urls = [u.rstrip(".,;:!?") for u in URL_RE.findall(sanitize(text))]
    return [re.sub(r"^hxxp", "http", u, flags=re.I) for u in urls]


def parse_sender(raw):
    """Return (display_name, address, domain). domain is '' if the address is invalid."""
    display, addr = parseaddr(sanitize(raw, 400))
    addr = addr.strip().lower()
    m = EMAIL_RE.match(addr)
    return display.strip(), addr, (m.group(1) if m else "")


def extract_extension(filename):
    name = re.split(r"[\\/]", sanitize(filename, 255))[-1].lower()
    return ("." + name.rsplit(".", 1)[1]) if "." in name else ""


def load_dataset(path):
    """Load CSV, fill missing values, drop duplicates."""
    import pandas as pd
    df = pd.read_csv(path).fillna("")
    for col in ("sender", "subject", "body", "urls", "attachment_name"):
        df[col] = df[col].astype(str).map(clean_text)
    return df.drop_duplicates(subset=["sender", "subject", "body"]).reset_index(drop=True)
