# Phishing Email Detection & Awareness Dashboard

A local, defensive learning project for analyzing synthetic or authorized email samples. It combines transparent heuristic indicators, static URL and attachment-name inspection, an explainable risk score, local analysis history, and a short awareness guide.

## Features

- Analyze sender, subject, message body, URLs, and an optional attachment filename.
- Show indicator-by-indicator reasons, a 0–100 heuristic score, and practical next steps.
- Inspect URLs as text only; the app never visits a URL or opens an attachment.
- Keep analysis history in a local SQLite database.
- Generate a deterministic 500-row synthetic dataset with fictional/reserved domains.
- Optional machine-learning direction is documented; the shipped detector does not claim to use a trained model.

## Architecture

```text
Streamlit UI → analyzer.py (local heuristics) → explainable findings
            ↘ database.py → local SQLite history
            ↘ dataset.py → synthetic CSV generator
```

## Run locally

Requires Python 3.10 or newer.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python -m phishing_dashboard.dataset
streamlit run app.py
```

Open the local address printed by Streamlit. The generated dataset is saved to `data/phishing_email_dataset.csv`; history is stored locally in `data/history.sqlite3`.

## Detection and limitations

The baseline uses multiple simple indicators for urgency, credential and financial wording, sender-domain shape, URL structure, and attachment filename suffixes. One indicator never proves phishing. A “SAFE” result means only that configured rules found few signals; it is not a safety guarantee. The project does not perform reputation lookups, follow links, inspect actual attachment bytes, or validate SPF/DKIM/DMARC. Rule thresholds can create false positives and false negatives.

## Safety and privacy

Use synthetic, fictional, or explicitly authorized samples. Uploaded `.txt` and `.eml` files are treated as text; no active content is executed. The sample app stores sender, subject, score, and findings in a local SQLite database. Avoid entering confidential messages and remove `data/history.sqlite3` when you no longer need the local history.

## Disclaimer

This project is designed for cybersecurity education and defensive analysis using synthetic or authorized data.
