"""Filename-only attachment analysis. Attachments are never opened or executed."""
import re

DANGEROUS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".msi", ".jar", ".com", ".lnk"}
ARCHIVES = {".zip", ".rar", ".7z", ".iso", ".img"}
MACRO = {".docm", ".xlsm", ".pptm"}
DOCS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".ppt", ".pptx"}


def analyze_attachment(filename):
    name = re.split(r"[\\/]", (filename or "").strip())[-1].lower()[:255]
    if not name:
        return {"score": 0, "risk": "NONE", "findings": [], "extension": ""}
    parts = name.split(".")
    ext = "." + parts[-1] if len(parts) > 1 else ""
    findings, score = [], 0
    if len(parts) >= 3 and "." + parts[-2] in DOCS and (ext in DANGEROUS or ext in ARCHIVES):
        findings.append(f"Double extension '.{parts[-2]}{ext}' disguises a risky file type")
        score = 90
    elif ext in DANGEROUS:
        findings.append(f"Executable/script extension {ext}")
        score = 70
    elif ext in MACRO:
        findings.append(f"Macro-enabled Office file {ext}")
        score = 45
    elif ext in ARCHIVES:
        findings.append(f"Archive type {ext} can hide other files")
        score = 35
    risk = "HIGH" if score >= 70 else "MEDIUM" if score >= 35 else "LOW"
    return {"score": score, "risk": risk, "findings": findings, "extension": ext}
