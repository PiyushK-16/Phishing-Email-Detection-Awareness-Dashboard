"""Shared helpers: build the model input row (TF-IDF text + structured indicators)."""
from backend.services.features import extract_email_features, FEATURE_NAMES
from backend.services.preprocess import parse_sender


def row_from_email(sender, subject, body, attachment_name=""):
    feats = extract_email_features(sender, subject, body, attachment_name)
    domain = parse_sender(sender)[2]
    return {"text": f"{subject} {body} {domain} {attachment_name}", **{k: feats[k] for k in FEATURE_NAMES}}
