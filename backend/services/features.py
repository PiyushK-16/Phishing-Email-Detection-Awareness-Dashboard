"""Feature engineering: turns analyzer output into a flat numeric dictionary."""
import re
from .preprocess import extract_urls, sanitize
from .sender_analyzer import analyze_sender
from .content_analyzer import analyze_content
from .url_analyzer import analyze_url, SHORTENERS
from .attachment_analyzer import analyze_attachment

FEATURE_NAMES = ["urgent_keyword_count", "credential_keyword_count", "financial_keyword_count",
                 "threat_keyword_count", "url_count", "suspicious_url_count", "has_ip_url",
                 "has_shortened_url_pattern", "sender_domain_length", "subdomain_count",
                 "suspicious_attachment", "generic_greeting", "contains_password_request",
                 "contains_personal_info_request", "exclamation_count", "uppercase_ratio",
                 "body_length", "subject_length"]


def compute_parts(sender, subject, body, attachment_name=""):
    urls = extract_urls(body)
    return {"sender": analyze_sender(sender), "content": analyze_content(subject, body),
            "urls": [analyze_url(u) for u in urls], "attachment": analyze_attachment(attachment_name),
            "subject": sanitize(subject, 300), "body": sanitize(body)}


def features_from_parts(p):
    c, s, urls = p["content"], p["sender"], p["urls"]
    return {
        "urgent_keyword_count": c["counts"]["urgency"],
        "credential_keyword_count": c["counts"]["credential"],
        "financial_keyword_count": c["counts"]["financial"],
        "threat_keyword_count": c["counts"]["fear"],
        "url_count": len(urls),
        "suspicious_url_count": sum(u["score"] >= 30 for u in urls),
        "has_ip_url": int(any(u["details"].get("is_ip") for u in urls)),
        "has_shortened_url_pattern": int(any(u["details"].get("hostname") in SHORTENERS for u in urls)),
        "sender_domain_length": s["domain_length"],
        "subdomain_count": s["subdomain_count"],
        "suspicious_attachment": int(p["attachment"]["score"] >= 35),
        "generic_greeting": int(c["generic_greeting"]),
        "contains_password_request": int(bool(re.search(r"password", p["subject"] + p["body"], re.I))
                                         and c["counts"]["credential"] > 0),
        "contains_personal_info_request": int(c["counts"]["personal_info"] > 0),
        "exclamation_count": c["exclamation_count"],
        "uppercase_ratio": c["uppercase_ratio"],
        "body_length": len(p["body"]),
        "subject_length": len(p["subject"]),
    }


def extract_email_features(sender, subject, body, attachment_name=""):
    return features_from_parts(compute_parts(sender, subject, body, attachment_name))
