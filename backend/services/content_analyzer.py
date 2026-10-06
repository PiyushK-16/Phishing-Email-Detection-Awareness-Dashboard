"""Social-engineering language detection (regex based, explainable)."""
import re
from .preprocess import sanitize

PATTERNS = {
    "urgency": (r"\b(urgent|immediately|act now|right away|asap|within 24 hours|expires? (?:today|soon)|final notice|last warning|today only)\b",
                "Urgent or time-pressure language", "medium"),
    "fear": (r"\b(suspend(?:ed|sion)?|terminated?|locked|closed permanently|legal action|unauthori[sz]ed|compromised|will be (?:deleted|disabled|blocked|closed))\b",
             "Fear/threat language (account loss, penalties)", "medium"),
    "financial": (r"\b(invoice|outstanding payment|payment (?:due|failed|overdue)|wire transfer|gift cards?|overdue|refund)\b",
                  "Financial pressure language", "medium"),
    "credential": (r"\b(?:verify|confirm|enter|provide|send|update|re-?enter) your (?:password|login|credentials|account|identity)|password (?:will )?expires?|(?:one-time|verification) (?:code|passcode)\b",
                   "Credential/verification request", "high"),
    "reward": (r"\b(you have won|you've won|winner|prize|claim your|lottery|free gift)\b",
               "Prize/reward claim", "medium"),
    "personal_info": (r"\b(personal (?:details|information)|date of birth|social security|card number|bank details)\b",
                      "Request for personal information", "high"),
    "call_to_action": (r"\b(click (?:here|the link|below)|log ?in (?:now|here)|open the attachment|download now|follow the link)\b",
                       "Suspicious call to action", "low"),
}
GREETING_RE = re.compile(r"\b(dear (?:customer|user|member|client|account holder|sir/madam)|valued customer)\b", re.I)


def analyze_content(subject, body):
    subject, body = sanitize(subject, 300), sanitize(body)
    text = f"{subject}\n{body}"
    counts, findings, keywords = {}, [], []
    for cat, (rx, desc, sev) in PATTERNS.items():
        m = [x if isinstance(x, str) else x[0] for x in re.findall(rx, text, re.I)]
        m = [x.lower() for x in m if x]
        n = len(list(re.finditer(rx, text, re.I)))
        counts[cat] = n
        if n:
            keywords += [t.group(0).lower() for t in re.finditer(rx, text, re.I)]
            findings.append({"type": cat, "description": desc, "severity": sev})
    generic = bool(GREETING_RE.search(text))
    if generic:
        findings.append({"type": "generic_greeting", "description": "Generic greeting (not addressed by name)", "severity": "low"})
    letters = [c for c in text if c.isalpha()]
    upper = (sum(c.isupper() for c in letters) / len(letters)) if letters else 0.0
    excl = text.count("!")
    formatting = (excl >= 3 or (len(letters) > 20 and upper > 0.4))
    if formatting:
        findings.append({"type": "formatting", "description": "Unusual formatting (many '!' or excessive capitals)", "severity": "low"})
    return {"counts": counts, "findings": findings, "keywords": sorted(set(keywords)),
            "generic_greeting": generic, "exclamation_count": excl, "uppercase_ratio": round(upper, 3),
            "formatting": formatting}
