"""Generate deterministic labeled examples using reserved fictional domains."""
from __future__ import annotations
import csv
import random
from pathlib import Path

DOMAINS = ["example.com", "example.org", "example.net", "invalid.test"]
LEGIT = [
    ("University notice", "Campus library hours update", "The library will follow the posted schedule this week."),
    ("HR update", "Benefits enrollment reminder", "Please review the benefits summary on the internal portal."),
    ("Project update", "Weekly project notes", "The team notes from today's meeting are ready for review."),
    ("Meeting reminder", "Planning meeting tomorrow", "Our planning meeting is scheduled for 10 AM tomorrow."),
    ("Shopping confirmation", "Order confirmation", "Your sample order has been recorded. This is a fictional confirmation."),
    ("Newsletter", "Monthly research newsletter", "Here are this month's research and community updates."),
    ("Password confirmation", "Password changed", "This confirms your password was changed. Contact support if you did not make this change."),
    ("Fictional bank notice", "Monthly statement available", "Your fictional Example Bank statement is available in the sample portal."),
]
PHISH = [
    ("Fake account verification", "Urgent: verify your account", "Dear customer, verify your account immediately or access will be suspended. Login at http://verify.invalid.test/account."),
    ("Fake invoice", "Payment overdue", "Please pay this invoice immediately to avoid a penalty. Reply with payment details."),
    ("Fake prize", "You won a reward", "Claim your prize now by confirming your password and personal information."),
    ("Fake password expiry", "Password expires today", "Your password expired. Login immediately at http://192.0.2.10/login to restore access."),
    ("Fake delivery", "Delivery problem", "Your package is delayed. Verify your account at http://bit.ly/sample-delivery."),
    ("Fake HR request", "Urgent HR payroll check", "Dear user, send your bank account details immediately for payroll verification."),
    ("Fake executive request", "Confidential gift card request", "Purchase gift cards urgently and send the codes to me. Do not discuss this request."),
]

def generate_dataset(path: str | Path, rows: int = 500, seed: int = 42) -> Path:
    rng = random.Random(seed)
    out = Path(path); out.parent.mkdir(parents=True, exist_ok=True)
    records = []
    for i in range(rows):
        label = "LEGITIMATE" if i % 2 == 0 else "PHISHING"
        category, subject, body = rng.choice(LEGIT if label == "LEGITIMATE" else PHISH)
        domain = rng.choice(DOMAINS)
        sender = f"{category.lower().replace(' ', '.')}{i}@{domain}"
        urls = ";".join(__import__("re").findall(r"https?://\S+", body))
        records.append({"email_id": f"SYN-{i+1:04}", "sender": sender, "sender_domain": domain, "subject": subject, "body": body, "urls": urls, "attachment_name": "", "label": label})
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0])); writer.writeheader(); writer.writerows(records)
    return out

if __name__ == "__main__":
    print(generate_dataset(Path(__file__).resolve().parents[1] / "data" / "phishing_email_dataset.csv"))
