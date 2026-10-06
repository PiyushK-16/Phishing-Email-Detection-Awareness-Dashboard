# Project Guide (concepts, workflow, GitHub, resume, interview)

## 1. Concepts
**Phishing**: messages that impersonate trusted parties to trick people into revealing credentials, paying money or running malware. **Why dangerous**: it targets people, bypasses technical controls, and is a common first step of breaches. **Manipulation**: urgency, fear, authority, reward, curiosity. **Indicators** are clues (raw-IP link, mismatched sender, credential request); *no single indicator proves phishing*, so we add weighted signals. **Explainability** lets analysts verify and tune decisions and lets users learn, instead of trusting a black box.
**Technical flow**: input -> sanitize -> sender/subject/body/URL/attachment analysis -> feature extraction -> rules (+ML) -> score -> class -> explanation -> recommendation -> dashboard.
Aggressive text cleaning (lowercasing everything, stripping punctuation/digits) would erase evidence such as CAPS, "!!!", IP octets and URL characters.

## 2. Industry relevance
SOC teams, secure email gateways, anti-spam and awareness platforms all combine sender, URL, attachment and language signals plus analyst triage. Skills shown: SOC Analyst (triage, scoring), Email Security Analyst (sender/URL/attachment inspection), Threat Intel (indicators), Incident Response (recommended actions), Security Awareness (education module).

## 3. SOC workflow
Reported -> triage -> sender -> URL -> attachment metadata -> content -> score -> analyst review -> classify -> respond. The score supports analyst judgment; it never replaces it.

## 4. MITRE ATT&CK (high level)
Phishing is Initial Access technique T1566 with sub-techniques Spearphishing Attachment (T1566.001), Spearphishing Link (T1566.002) and Spearphishing via Service (T1566.003). Please confirm current IDs/names on attack.mitre.org. Mapping findings to a framework gives shared vocabulary and traceable documentation: attachment indicators -> .001, URL indicators -> .002.

## 5. Confusion matrix
TP phishing caught · TN legit passed · FP legit flagged (alert fatigue) · FN phishing missed (most dangerous). Accuracy misleads on imbalanced data; precision limits false alarms, recall limits misses, F1 balances them.

## 6. Git commands
```bash
git init && git add . && git commit -m "Initialize phishing detection project"
git branch -M main
git remote add origin https://github.com/<you>/Phishing-Email-Detection-Awareness-Dashboard.git
git push -u origin main
```
Better: make one commit per module using the messages in your brief (dataset generator, preprocessing, sender, content, URL, attachment, risk engine, ML, evaluation, dashboard, awareness, history, tests, docs). Topics: cybersecurity, phishing-detection, email-security, soc, python, machine-learning, nlp, threat-detection, security-awareness, url-analysis, defensive-security.

## 7. 13-day plan
D1 repo+architecture · D2 `data/generate_dataset.py` · D3 `preprocess.py` · D4 `sender_analyzer.py`, `content_analyzer.py` · D5 `url_analyzer.py` · D6 `attachment_analyzer.py` · D7 `risk_engine.py`, `features.py` · D8 `ml/*` · D9 `frontend/`, `app.py` · D10 awareness tab · D11 `db.py`, history · D12 `tests/` · D13 README/report. Each day: commit + one screenshot proving it (folder tree, dataset head, sender findings, URL findings, attachment finding, score breakdown, metrics/confusion matrix, dashboard, awareness, history, pytest output, repo page).
Screenshot names: `01_folder_structure.png`, `02_dataset_head.png`, `05_analyzer_phishing_high.png`, `06_analyzer_legit_low.png`, `10_dashboard_charts.png`, `12_confusion_matrix.png`, `14_history.png`, `16_pytest_pass.png`, `20_github_readme.png`.

## 8. Report outline
Abstract; Introduction; Problem; Objectives; Phishing & social engineering background; Existing approaches; Proposed system; Architecture; Dataset; Preprocessing; Features; Sender/URL/Attachment analysis; Rule engine; ML; Hybrid; Scoring; Explainability; Dashboard; Awareness; Testing; Security & privacy; Results (use YOUR real numbers); FP/FN; Limitations; Future scope; Conclusion.

## 9. Resume
- Built a defensive phishing-analysis dashboard (Python, Flask, SQLite, scikit-learn) scoring emails 0-100 with explainable sender, URL, attachment and social-engineering indicators.
- Engineered 18 email features and a hybrid rule + TF-IDF ML detector; evaluated with precision/recall/F1 and confusion matrices.
- Implemented secure coding controls (XSS-safe rendering, CSP, input validation, rate limiting, metadata-only storage) with 29 automated tests.

LinkedIn blurb: "Phishing Email Detection & Awareness Dashboard: a defensive tool that triages synthetic emails with explainable risk scoring, static URL/sender/attachment analysis, optional ML, SOC-style analytics and a user awareness module."

## 10. Interview Q&A
1. **Explain your project.** A Flask + Python dashboard that analyzes an email's sender, content, URLs and attachment name, produces a 0-100 explainable risk score, stores metadata history and shows analytics. Everything is static and uses synthetic data.
2. **What is phishing / why does it work?** Impersonation plus psychological pressure (urgency, fear, reward) to get credentials, money or malware execution.
3. **How do you analyze URLs safely?** String parsing only: raw IP, scheme, keywords, subdomains, shorteners, '@', punycode. Never visiting; output is defanged.
4. **Does HTTPS mean safe?** No, it only encrypts the connection; attackers use HTTPS too. I add points for non-HTTPS but a risky HTTPS URL still scores.
5. **How does scoring work?** Weighted indicators capped at 100, mapped to bands. Weights are assumptions I'd calibrate on validation data.
6. **Why explainability?** Analysts need to verify and tune decisions; users learn from the reasons.
7. **Which features and models did you use?** 18 structured features plus TF-IDF; Logistic Regression, Naive Bayes, Random Forest. They all scored perfectly on my synthetic set, which tells me the data is too easy, not that the model is perfect.
8. **Precision vs recall?** Precision limits false alarms; recall limits missed phishing. Missed phishing is costlier, so I'd favour recall while watching alert fatigue.
9. **False positives/negatives in your system?** Legit HR "urgent" email gets urgency points; a polite HTTPS phish scored 0 on rules but the ML flagged it, which motivated the hybrid score.
10. **How is it secure and how would a SOC use it?** Escaped output, CSP, validation, rate limiting, no body storage, never executing anything; analysts use it for first triage, then confirm manually.
