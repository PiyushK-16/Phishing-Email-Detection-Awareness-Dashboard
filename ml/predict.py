"""Load the trained pipeline and return P(phishing). Returns None if no model is trained."""
import os
import joblib, pandas as pd
from ml.common import row_from_email

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "phishing_model.joblib")
_model = None


def load_model():
    global _model
    if _model is None and os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
    return _model


def predict_phishing_probability(sender, subject, body, attachment_name=""):
    model = load_model()
    if model is None:
        return None
    row = pd.DataFrame([row_from_email(sender, subject, body, attachment_name)])
    return float(model.predict_proba(row)[0][1])
