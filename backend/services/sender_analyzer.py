"""Sender analysis. Unfamiliar != malicious: signals are weak and only add to a score."""
import re
from .preprocess import parse_sender

LOOKALIKE_WORDS = ["secure", "verify", "alert", "account", "login", "signin", "update", "billing", "helpdesk"]
LOCAL_WORDS = ["security", "alert", "verify", "admin", "support", "billing"]
SUSPICIOUS_TLDS = {"xyz", "top", "click", "zip", "work", "rest", "country"}
GENERIC = {"team", "support", "service", "services", "notifications", "notification", "alerts", "admin",
           "department", "desk", "helpdesk", "noreply", "security", "office", "update", "customer", "care"}


def analyze_sender(raw_sender, display_name=None):
    display, addr, domain = parse_sender(raw_sender)
    display = display_name or display
    findings, score = [], 0

    def add(msg, pts):
        nonlocal score
        findings.append(msg)
        score += pts

    if not domain:
        return {"score": 40, "findings": ["Sender address is missing or not a valid email format"],
                "domain": "", "subdomain_count": 0, "domain_length": 0}
    labels = domain.split(".")
    sub = max(len(labels) - 2, 0)
    registered = labels[-2]
    local = addr.split("@")[0]
    if sub >= 3:
        add(f"Excessive subdomains in sender domain ({sub})", 15)
    if len(domain) > 30:
        add("Unusually long sender domain", 10)
    if domain.count("-") >= 2:
        add("Multiple hyphens in sender domain", 10)
    if sum(c.isdigit() for c in domain) >= 3:
        add("Several digits in sender domain", 10)
    if re.search(r"(?<=[a-z])[01](?=[a-z])", registered):
        add("Possible character substitution (e.g. 0 for o, 1 for l)", 10)
    if "xn--" in domain:
        add("Punycode domain (possible look-alike characters)", 15)
    if any(w in domain for w in LOOKALIKE_WORDS):
        add("Sender domain contains an account/security-style word (common in look-alike domains)", 15)
    if labels[-1] in SUSPICIOUS_TLDS:
        add("Sender uses a TLD often abused in bulk campaigns", 10)
    if any(w in local for w in LOCAL_WORDS):
        add("Sender name uses authority words (security/admin/support)", 5)
    if display:
        if "@" in display and display.lower().strip() != addr:
            add("Display name contains a different email address", 25)
        else:
            toks = [t for t in re.findall(r"[a-z]{4,}", display.lower()) if t not in GENERIC]
            if toks and not any(t in domain.replace("-", "") for t in toks):
                add("Display name does not match the sender domain", 15)
    return {"score": min(score, 100), "findings": findings, "domain": domain,
            "subdomain_count": sub, "domain_length": len(domain)}
