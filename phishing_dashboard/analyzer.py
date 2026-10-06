"""Explainable, local-only heuristic analysis. No network requests are made."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>()\[\]{}\"']+")
URGENCY = ("urgent", "immediately", "action required", "suspend", "expired", "final notice", "within 24 hours")
CREDENTIALS = ("password", "passcode", "login", "verify your account", "confirm your account", "credentials")
FINANCIAL = ("wire transfer", "payment", "invoice", "gift card", "bank account", "refund")
THREATS = ("account will be closed", "legal action", "terminated", "locked", "penalty")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
SUSPICIOUS_EXT = {"exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "msi", "hta"}


def _finding(title: str, points: int, detail: str) -> dict:
    return {"title": title, "points": points, "detail": detail}


def inspect_url(raw: str) -> dict:
    value = raw.rstrip(".,;:!?")
    candidate = value if "://" in value else "http://" + value
    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    flags = []
    try:
        ipaddress.ip_address(host.strip("[]"))
        flags.append("IP address used as hostname")
    except ValueError:
        pass
    if parsed.scheme != "https":
        flags.append("not using HTTPS")
    if host in SHORTENERS:
        flags.append("URL shortening service")
    if len(host.split(".")) >= 5:
        flags.append("many hostname labels")
    if any(word in (host + parsed.path).lower() for word in ("login", "verify", "secure", "account", "password")):
        flags.append("sensitive-action wording in URL")
    if "@" in parsed.netloc:
        flags.append("userinfo marker in URL authority")
    return {"url": value, "host": host or "unparsed", "flags": flags}


def analyze_email(sender: str, subject: str, body: str, attachment: str = "") -> dict:
    sender, subject, body = sender or "", subject or "", body or ""
    text = f"{subject}\n{body}".lower()
    findings = []
    points = 0
    def add(title: str, weight: int, detail: str) -> None:
        nonlocal points
        points += weight
        findings.append(_finding(title, weight, detail))

    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", sender.strip()):
        add("Sender format is unusual", 8, "The supplied sender does not match a basic email-address shape.")
    domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
    if domain and (len(domain) > 45 or domain.count("-") >= 3 or len(domain.split(".")) >= 5):
        add("Unusual sender domain shape", 12, f"Domain pattern: {domain}")
    for words, title, weight in ((URGENCY, "Urgency or account pressure", 12), (CREDENTIALS, "Credential-related wording", 18), (FINANCIAL, "Financial request wording", 16), (THREATS, "Threat or consequence wording", 12)):
        matched = [w for w in words if w in text]
        if matched:
            add(title, weight, "Matched wording: " + ", ".join(matched))
    if re.search(r"\b(dear customer|dear user|hello user|valued customer)\b", text):
        add("Generic greeting", 6, "The greeting does not identify the recipient.")
    if "!" * 2 in subject + body:
        add("Repeated exclamation marks", 4, "Repeated punctuation can add pressure; it is not proof of phishing.")
    urls = [inspect_url(u) for u in URL_RE.findall(body)]
    for item in urls:
        if item["flags"]:
            add("URL has review indicators", min(20, 6 + 3 * len(item["flags"])), f"{item['host']}: {', '.join(item['flags'])}")
    if attachment:
        name = attachment.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        suffixes = re.findall(r"\.([a-z0-9]+)", name)
        if any(s in SUSPICIOUS_EXT for s in suffixes):
            add("Potentially executable attachment name", 25, "Filename extension suggests executable or script content; file was not opened.")
        if len(suffixes) >= 2 and suffixes[-1] in {"pdf", "doc", "docx", "jpg", "png"}:
            add("Multiple attachment extensions", 12, "Multiple suffixes can disguise a file type; filename inspection alone is limited.")
    score = min(100, points)
    classification = "SAFE" if score < 15 else "LOW RISK" if score < 35 else "SUSPICIOUS" if score < 60 else "HIGH RISK / LIKELY PHISHING"
    recommendations = ["Verify unexpected requests through a known, independent contact method.", "Do not enter credentials after following an unexpected email link.", "Report suspicious messages through your organization's process."]
    if any(x["flags"] for x in urls):
        recommendations.insert(0, "Do not open flagged links; have them reviewed with approved security tooling.")
    if attachment:
        recommendations.append("Do not open an unexpected attachment; filename analysis does not establish file safety.")
    return {"risk_score": score, "classification": classification, "findings": findings, "urls": urls, "recommendations": recommendations}
