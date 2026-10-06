"""Rule-based scoring + optional ML = hybrid, explainable risk assessment.
Weights and thresholds are PROJECT ASSUMPTIONS - calibrate with validation data."""
from .features import compute_parts
from .preprocess import parse_sender

WEIGHTS = {"sender": 15, "urgency": 10, "fear": 10, "credential": 20, "financial": 10, "reward": 10,
           "personal_info": 10, "call_to_action": 5, "generic_greeting": 5, "formatting": 5,
           "url": 20, "ip_url_bonus": 10, "attachment": 25}
# Note: there is deliberately no "SAFE" label - static analysis can never prove an email is safe.
BANDS = [(20, "LOW RISK"), (40, "MODERATE RISK"), (70, "SUSPICIOUS"), (100, "HIGH RISK / LIKELY PHISHING")]
RULE_WEIGHT, ML_WEIGHT = 0.6, 0.4

ACTIONS = {
    "LOW RISK": ["No strong phishing indicators, but stay alert to context.",
                 "If anything feels unexpected, verify through a trusted channel."],
    "MODERATE RISK": ["Treat links and attachments with caution.",
                      "Verify the sender through a trusted channel before acting."],
    "SUSPICIOUS": ["Do not click links or open attachments.", "Verify the sender via a trusted channel.",
                   "Report the email to your security team."],
    "HIGH RISK / LIKELY PHISHING": ["Do not click links.", "Do not open unexpected attachments.",
                                    "Verify the sender through a trusted channel.",
                                    "Report the suspicious email to the security team.",
                                    "Use the organization's official website/app directly."],
}


def classify(score):
    for limit, label in BANDS:
        if score <= limit:
            return label
    return BANDS[-1][1]


def calculate_phishing_score(parts):
    """Return (score 0-100, list of indicator dicts with the points each added)."""
    ind = []

    def add(kind, desc, sev, pts):
        ind.append({"type": kind, "description": desc, "severity": sev, "points": pts})

    if parts["sender"]["score"] >= 15:
        add("sender", "Suspicious sender pattern: " + "; ".join(parts["sender"]["findings"][:2]), "medium", WEIGHTS["sender"])
    for f in parts["content"]["findings"]:
        if f["type"] in WEIGHTS:
            add(f["type"], f["description"], f["severity"], WEIGHTS[f["type"]])
    urls = parts["urls"]
    if any(u["score"] >= 30 for u in urls):
        worst = max(urls, key=lambda u: u["score"])
        add("url", "Suspicious URL structure: " + "; ".join(worst["findings"][:2]), "high", WEIGHTS["url"])
        if any(u["details"].get("is_ip") for u in urls):
            add("url", "URL points to a raw IP address", "high", WEIGHTS["ip_url_bonus"])
    if parts["attachment"]["score"] >= 35:
        add("attachment", "Attachment requires caution: " + parts["attachment"]["findings"][0], "high", WEIGHTS["attachment"])
    return min(sum(i["points"] for i in ind), 100), ind


def get_ml_probability(sender, subject, body, attachment_name=""):
    try:
        from ml.predict import predict_phishing_probability
        return predict_phishing_probability(sender, subject, body, attachment_name)
    except Exception:
        return None


def analyze_email(sender, subject, body, attachment_name="", use_ml=True):
    parts = compute_parts(sender, subject, body, attachment_name)
    rule_score, indicators = calculate_phishing_score(parts)
    prob = get_ml_probability(sender, subject, body, attachment_name) if use_ml else None
    final = round(RULE_WEIGHT * rule_score + ML_WEIGHT * prob * 100) if prob is not None else rule_score
    cls = classify(final)
    return {"risk_score": final, "rule_score": rule_score, "ml_probability": prob, "classification": cls,
            "indicators": indicators, "sender": parts["sender"], "url_analyses": parts["urls"],
            "attachment": parts["attachment"], "keywords": parts["content"]["keywords"],
            "recommendations": ACTIONS[cls],
            "note": "Automated score supports, not replaces, analyst judgment. Thresholds are assumptions."}
