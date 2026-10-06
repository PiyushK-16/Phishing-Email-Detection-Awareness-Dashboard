"""Run from project root: pytest -v"""
import os
import pytest
from backend.services.risk_engine import analyze_email, classify
from backend.services.url_analyzer import analyze_url
from backend.services.sender_analyzer import analyze_sender
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.content_analyzer import analyze_content
from backend.services.features import extract_email_features
from backend.services import preprocess

PH = ("Security Alert <security-alert@account-check.invalid.test>", "URGENT: Verify Your Account Immediately",
      "Dear customer, your account will be suspended within 24 hours. Verify your password now: http://198.51.100.10/verify-account")
OK = ("Example Training Team <training@example.org>", "Cybersecurity Workshop Reminder",
      "Hi team, the cybersecurity workshop is on Friday at 14:00 in room 12.")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    from backend.app import create_app
    return create_app().test_client()

def test01_legitimate_email_low():
    r = analyze_email(*OK, use_ml=False); assert r["classification"] == "LOW RISK" and r["risk_score"] == 0
def test02_phishing_demo_high():
    assert analyze_email(*PH, use_ml=False)["classification"].startswith("HIGH")
def test03_credential_request():
    assert analyze_content("", "Please verify your password")["counts"]["credential"] == 1
def test04_financial():
    assert analyze_content("Invoice overdue", "")["counts"]["financial"] >= 1
def test05_generic_greeting():
    assert analyze_content("", "Dear customer, hello")["generic_greeting"]
def test06_safe_url():
    assert analyze_url("https://portal.example.org/exams")["score"] == 0
def test07_raw_ip_url():
    assert analyze_url("http://198.51.100.10/x")["details"]["is_ip"]
def test08_non_https():
    assert any("Non-HTTPS" in f for f in analyze_url("http://example.org")["findings"])
def test09_excessive_subdomains():
    assert any("subdomains" in f for f in analyze_url("https://a.b.c.d.example.net/")["findings"])
def test10_url_keyword():
    assert any("keyword" in f for f in analyze_url("https://example.org/verify-login")["findings"])
def test11_no_url():
    assert analyze_email(*OK, use_ml=False)["url_analyses"] == []
def test12_multiple_urls():
    assert len(analyze_email("a@example.org", "s", "http://198.51.100.1/a and https://example.org/b", use_ml=False)["url_analyses"]) == 2
def test13_normal_attachment():
    assert analyze_attachment("report.pdf")["score"] == 0
def test14_executable_attachment():
    assert analyze_attachment("setup.exe")["risk"] == "HIGH"
def test15_double_extension():
    assert analyze_attachment("invoice.pdf.exe")["score"] == 90
def test16_empty_subject():
    assert analyze_content("", "hello")["counts"]["urgency"] == 0
def test17_empty_body():
    assert analyze_email("a@example.org", "Hello", "", use_ml=False)["risk_score"] == 0
def test18_invalid_sender():
    assert analyze_sender("not-an-email")["score"] >= 40
def test19_uppercase_ratio():
    assert analyze_content("", "URGENT ACT NOW OR LOSE ACCESS")["uppercase_ratio"] > 0.9
def test20_exclamations():
    assert analyze_content("", "Hi!!! Wow!!!")["formatting"]
def test21_score_boundaries():
    assert [classify(s) for s in (0, 20, 21, 40, 41, 70, 71, 100)] == [
        "LOW RISK", "LOW RISK", "MODERATE RISK", "MODERATE RISK", "SUSPICIOUS", "SUSPICIOUS",
        "HIGH RISK / LIKELY PHISHING", "HIGH RISK / LIKELY PHISHING"]
def test22_database_save(client):
    r = client.post("/api/analyze", json=dict(sender=PH[0], subject=PH[1], body=PH[2])); assert r.status_code == 201
    assert r.get_json()["analysis_id"] == 1
def test23_api_validation(client):
    assert client.post("/api/analyze", json={"sender": 5}).status_code == 400
    assert client.post("/api/analyze", json={"sender": "a@example.org"}).status_code == 400
    assert client.post("/api/analyze/url", json={}).status_code == 400
@pytest.mark.skipif(not os.path.exists("models/phishing_model.joblib"), reason="model not trained")
def test24_ml_prediction():
    from ml.predict import predict_phishing_probability as p
    assert p(*PH) > p(*OK)
def test25_history_retrieval_and_delete(client):
    client.post("/api/analyze", json=dict(sender=PH[0], subject=PH[1], body=PH[2]))
    assert len(client.get("/api/analyses?classification=HIGH RISK / LIKELY PHISHING").get_json()) == 1
    assert client.get("/api/analyses/1").get_json()["indicators"]
    assert client.get("/api/dashboard/stats").get_json()["total"] == 1
    assert client.delete("/api/analyses/1").status_code == 204 and client.get("/api/analyses/1").status_code == 404
def test26_features_keys():
    f = extract_email_features(*PH); assert f["has_ip_url"] == 1 and f["urgent_keyword_count"] >= 1
def test27_url_defanged_and_extraction():
    assert "hxxp" in analyze_url("http://example.org")["url"] and preprocess.extract_urls("see hxxp://198.51.100.1/a.")[0] == "http://198.51.100.1/a"
def test28_https_not_trusted():
    assert analyze_url("https://198.51.100.10/verify")["score"] >= 30
def test29_xss_text_stored_as_data(client):
    r = client.post("/api/analyze", json=dict(sender="a@example.org", subject="<script>alert(1)</script>", body="hi")); assert r.status_code == 201
