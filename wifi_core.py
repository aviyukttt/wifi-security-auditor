"""Dependency-free defensive checks used by the Wi-Fi auditor."""
from __future__ import annotations

import re


def password_findings(password: str) -> tuple[str, list[str]]:
    findings: list[str] = []
    score = 0
    length = len(password)
    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        findings.append("Use at least 12 characters; 16+ is preferable.")
    if re.search(r"[a-z]", password): score += 1
    else: findings.append("Add lowercase letters.")
    if re.search(r"[A-Z]", password): score += 1
    else: findings.append("Add uppercase letters.")
    if re.search(r"\d", password): score += 1
    else: findings.append("Add numbers.")
    if re.search(r"[^A-Za-z0-9]", password): score += 1
    else: findings.append("Add symbols or spaces.")
    lowered = password.casefold()
    common = ("password", "qwerty", "letmein", "admin", "welcome", "iloveyou", "changeme", "wifi")
    if any(word in lowered for word in common):
        score = max(0, score - 3)
        findings.append("Avoid common words and router/default-password patterns.")
    if re.search(r"(.)\1\1", password):
        score = max(0, score - 1)
        findings.append("Avoid repeated characters.")
    if password and (password.isdigit() or password.isalpha()):
        findings.append("Use a mix of character types or a long random passphrase.")
    if score >= 7 and not findings:
        label = "Strong"
    elif score >= 5:
        label = "Moderate"
    else:
        label = "Weak"
    if not findings:
        findings.append("No obvious weakness signals detected locally.")
    return label, findings
