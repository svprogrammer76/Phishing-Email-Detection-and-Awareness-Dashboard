# Project Documentation: Phishing Email Detection & Awareness Dashboard

This companion document keeps career, Git, report, proof-building, and interview material outside the README.

## Simple and technical explanation

Phishing is social engineering delivered through messages that try to persuade a recipient to disclose information, transfer value, or take an unsafe action. A detector can surface clues such as pressure language, unusual sender patterns, suspicious URL structure, or risky attachment names. No clue alone proves malicious intent; legitimate notices can be urgent and attackers can write polished messages. Explanations help a reviewer challenge a score, understand what evidence contributed, and decide what to do next.

The application accepts an email sample, inspects sender/subject/body/URLs/filename locally, extracts indicators, sums capped heuristic weights, maps the score to a label, explains findings, and gives safe response suggestions. Human review remains necessary.

## Industry and SOC relevance

SOC analysts triage reports, preserve evidence, correlate signals, and route incidents. Email-security analysts tune controls and review delivery/authentication evidence. Threat-intelligence analysts add context from trusted sources. Incident responders scope impact and coordinate containment. This project demonstrates defensive triage concepts, explainability, safe input handling, data visualization, and awareness messaging. It is a teaching prototype, not an enterprise gateway.

## Architecture and implemented scope

Streamlit provides the local UI. `phishing_dashboard/analyzer.py` runs deterministic rules and static URL/filename checks. `database.py` stores minimal history in SQLite. `dataset.py` creates labeled fictional examples. There is no authentication, API service, live reputation integration, attachment execution, or active URL fetching. Those require threat modeling and additional engineering before production use.

Risk bands: 0–14 SAFE, 15–34 LOW RISK, 35–59 SUSPICIOUS, 60–100 HIGH RISK / LIKELY PHISHING. These are heuristic thresholds, not calibrated probabilities.

## Synthetic dataset and preprocessing

Generate 500 records with `python -m phishing_dashboard.dataset`. Fields are `email_id`, `sender`, `sender_domain`, `subject`, `body`, `urls`, `attachment_name`, and `label`. Examples use reserved domains (`example.com`, `.org`, `.net`) and `.test`; the IP example uses documentation-only `192.0.2.10`. Categories cover university, HR, projects, meetings, shopping, newsletters, password confirmations, fictional bank notices, and fake account/invoice/prize/password/delivery/HR/executive requests. The generator is deterministic with seed 42 and balanced labels.

The app preserves original text for keyword/URL review rather than aggressively removing punctuation or URLs. It bounds uploaded sample text to 100,000 characters. A future training pipeline should validate required columns, handle missing values, deduplicate rows, normalize labels, and split data before fitting transforms to avoid leakage.

## Detection logic and interpretation

Indicators include urgency, credentials, finance, threats, generic greetings, repeated exclamation marks, unusual sender domain shape, URL scheme/hostname/shortener/sensitive wording, and executable-like or multiple filename suffixes. Weights are transparent heuristics and can overlap. A URL is parsed but never requested over the network. The filename is never opened. Display-name mismatch, real domain age/reputation, email headers, and visible-link/destination mismatch are not available in this simple input UI.

False positives can arise from legitimate password resets, finance notices, shorteners, or urgent messages. False negatives can arise from novel wording, compromised legitimate accounts, hidden links, clean-looking domains, or missing headers. Review context and approved mail-security tooling.

## Optional machine learning and evaluation plan

ML is intentionally optional and not represented as implemented. A next step could train a scikit-learn `TfidfVectorizer` plus Logistic Regression on the synthetic CSV, using a stratified held-out split and a saved pipeline. Synthetic examples are simplistic and do not establish real-world performance. Report precision, recall, F1, support, confusion matrix, split seed, class balance, and limitations; prioritize recall for triage only after an explicit operational decision about review load. Compare ML and rules separately before any hybrid score.

## Database and privacy

SQLite stores timestamp, sender, subject, score, classification, and serialized findings. It does not store the full body or uploaded file. The database is local and ignored by Git. Do not analyze confidential production mail without authorization and a suitable privacy review. No external requests are made.

## Security awareness tips

Check the full sender address, treat urgency as a cue, avoid entering credentials from unexpected links, verify requests using independently known contact details, do not open unexpected executable files, and report messages through the organization's process. Preserve the original message for responders.

## MITRE ATT&CK context

Phishing and spearphishing are represented in MITRE ATT&CK's social-engineering and initial-access knowledge base. Technique names and mappings evolve; consult the current ATT&CK Enterprise matrix before assigning technique IDs. This prototype maps no individual finding to a technique because its indicators are too general to justify that attribution.

## Testing plan

Manually verify legitimate and synthetic urgent samples; credential and financial wording; generic greetings; absent, multiple, HTTP, shortener, and documentation-IP URLs; common and executable-like attachment names; invalid sender; empty body/subject; repeated punctuation; score boundaries; SQLite persistence; uploaded text limits; and UI navigation. For future automated coverage, test URL parsing, weight capping, classification boundaries, database round trips, dataset row count/domain allowlist, and safe handling of malformed input. Do not treat a successful demo as evidence of detection efficacy.

## Local GitHub workflow

Repository name: `Phishing-Email-Detection-Awareness-Dashboard`.

Description: “Defensive cybersecurity dashboard for analyzing synthetic email content, sender patterns, URLs, attachments, and social-engineering indicators to generate explainable phishing risk assessments.”

Suggested topics: `cybersecurity`, `phishing-detection`, `email-security`, `soc`, `python`, `nlp`, `threat-detection`, `security-awareness`, `url-analysis`, `defensive-security`.

```bash
git init
git add .
git commit -m "Initialize phishing detection project"
git branch -M main
git remote add origin https://github.com/USERNAME/Phishing-Email-Detection-Awareness-Dashboard.git
git push -u origin main
```

Use small, truthful commits as work is completed: “Add synthetic email dataset generator”, “Implement explainable rule-based analysis”, “Add static URL and attachment-name checks”, “Add local analysis history”, “Build dashboard and awareness page”, “Document limitations and safe usage”. Do not manufacture a development history or claim ML/tests/features that are not present.

## Proof-building schedule and screenshot checklist

Suggested sequence: repository/architecture; generator and dataset statistics; analyzer and example cases; dashboard/history; awareness guidance; documentation and limitations. Capture real evidence after running the app. Suggested filenames: `01-project-structure.png`, `02-architecture.png`, `03-synthetic-dataset.png`, `04-dataset-stats.png`, `05-analyzer-form.png`, `06-legitimate-analysis.png`, `07-synthetic-phishing-analysis.png`, `08-url-findings.png`, `09-risk-score-and-reasons.png`, `10-dashboard.png`, `11-history.png`, `12-awareness.png`, `13-readme-preview.png`, `14-git-history.png`. Do not present planned screenshots as captured results.

## Project report outline

Abstract; introduction and problem statement; objectives; phishing and social engineering background; existing approaches; proposed architecture; synthetic dataset; preprocessing and features; sender/content/URL/filename analysis; rule scoring and explainability; dashboard and local persistence; privacy and safe-use design; manual evaluation plan; false positives and false negatives; limitations; future improvements; conclusion.

Future defensive work: header parsing for SPF/DKIM/DMARC results, robust file metadata inspection in an isolated environment, approved reputation integrations, user feedback, carefully evaluated NLP, calibration, audit controls, and SOC ticket/SIEM integration. Each adds privacy, reliability, and operational requirements.

## Resume and LinkedIn proof

**Resume bullets (adapt to work actually completed):**

- Built a local Python dashboard that analyzes synthetic email samples with transparent sender, social-engineering, URL, and attachment-filename indicators.
- Implemented capped heuristic risk scoring with per-indicator explanations and response recommendations to support defensive triage.
- Added fictional 500-record dataset generation, SQLite analysis history, and awareness guidance while avoiding URL fetches and attachment execution.

**Two-line description:** A defensive email-triage learning tool that surfaces explainable phishing indicators in synthetic or authorized samples. Includes static URL review, local analysis history, and security-awareness guidance.

**LinkedIn project description:** Developed a beginner-friendly cybersecurity project for defensive phishing analysis. The local dashboard combines transparent rule-based indicators across sender patterns, message language, URLs, and attachment filenames, then presents an explainable score and safe next steps. Synthetic data uses fictional domains. The app stores minimal history locally and never visits links or opens attachments. Results are educational triage aids, not proof that an email is safe or malicious.

**Skills demonstrated:** Python, Streamlit, SQLite, pandas, email security, phishing triage, feature design, explainable rules, URL parsing, secure-by-default decisions, data visualization, privacy-aware documentation, Git.

## Interview preparation: 10 questions and answers

1. **Explain your project.** I built a local dashboard that accepts synthetic or authorized email details, checks several explainable indicators, assigns a heuristic score, and shows why the score was produced along with safe next steps. It also keeps minimal local history and includes awareness guidance. It supports analyst review; it does not replace a mail gateway.
2. **What is phishing?** Phishing is social engineering that uses a message to persuade someone to disclose information or take an unsafe action. I look for multiple contextual clues instead of treating a single word as proof.
3. **How does your scoring work?** Each configured indicator contributes a documented weight, the total is capped at 100, and fixed bands map it to a label. It is not a probability and the weights need validation before operational use.
4. **How do you analyze URLs safely?** I parse the text for features such as scheme, hostname shape, shortener use, and sensitive-action wording. The app never makes a network request or opens the destination.
5. **What features did you use?** Keyword groups for urgency, credentials, finance, and threats; basic sender-domain shape; generic greeting and punctuation; URL structure; and attachment filename suffixes. These are interpretable but incomplete.
6. **Why can false positives and false negatives happen?** Legitimate notices may be urgent or discuss passwords, while attackers can use benign language, compromised accounts, or clean-looking links. Missing headers and context also limit the result, so I show findings and recommend human verification.
7. **Why is explainability useful?** A reviewer can see which evidence raised the score, challenge a weak signal, and choose a proportionate action. That matters because automated scores can be wrong.
8. **How would you evaluate an ML model?** I would use a stratified held-out split, report precision, recall, F1 and a confusion matrix, compare against the rule baseline, and check for leakage. Synthetic-only results would not prove generalization to real mail.
9. **How could a SOC analyst use this?** As an educational first-pass triage aid after a user report: inspect signals, preserve the original email, verify through approved tools, and escalate according to policy. It does not perform containment or replace analyst judgment.
10. **What are the main security and privacy choices?** The project uses fictional examples, runs locally, makes no URL requests, never executes attachments, bounds uploaded text, and stores only sender, subject, score, and findings rather than the body. Production use would require stronger access, retention, and privacy controls.
