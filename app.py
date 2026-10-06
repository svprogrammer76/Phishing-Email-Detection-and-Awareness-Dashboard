"""Local Streamlit interface for the defensive phishing email analyzer."""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from phishing_dashboard.analyzer import analyze_email  # noqa: E402
from phishing_dashboard.database import init_db, list_analyses, save_analysis  # noqa: E402
from phishing_dashboard.dataset import generate_dataset  # noqa: E402

st.set_page_config(page_title="Phishing Email Detection & Awareness", page_icon="🛡️", layout="wide")
init_db()
st.title("🛡️ Phishing Email Detection & Awareness Dashboard")
st.caption("Defensive analysis of synthetic or authorized email samples. Results support human review.")

page = st.sidebar.radio("Workspace", ["Analyze email", "Dashboard", "Awareness"])
if page == "Analyze email":
    st.subheader("Analyze a message")
    uploaded = st.file_uploader("Optional safe sample (.txt or .eml)", type=["txt", "eml"])
    preset = ""
    if uploaded:
        try:
            preset = uploaded.getvalue().decode("utf-8", errors="replace")[:100_000]
        except Exception:
            preset = ""
    with st.form("analyze"):
        sender = st.text_input("Sender address", placeholder="security@example.org")
        subject = st.text_input("Subject")
        body = st.text_area("Email body", value=preset, height=220)
        attachment = st.text_input("Attachment filename (optional)")
        submitted = st.form_submit_button("Analyze email", type="primary")
    if submitted:
        result = analyze_email(sender, subject, body, attachment)
        save_analysis(sender, subject, result)
        c1, c2, c3 = st.columns(3)
        c1.metric("Risk score", f"{result['risk_score']}/100")
        c2.metric("Classification", result["classification"])
        c3.metric("URLs", len(result["urls"]))
        st.progress(result["risk_score"] / 100)
        st.markdown("### Why this result")
        if result["findings"]:
            for item in result["findings"]:
                st.write(f"- **{item['title']}** (+{item['points']}): {item['detail']}")
        else:
            st.info("No configured indicators were found. This does not prove the message is safe.")
        st.markdown("### URL review")
        if result["urls"]:
            st.dataframe(pd.DataFrame(result["urls"]), use_container_width=True, hide_index=True)
        else:
            st.write("No URLs detected.")
        st.markdown("### Recommended actions")
        for action in result["recommendations"]:
            st.write(f"- {action}")
        st.caption("URLs are inspected as text only; the application never visits links or opens attachments.")
elif page == "Dashboard":
    st.subheader("Analysis history and aggregate view")
    rows = list_analyses()
    if not rows:
        st.info("No analyses saved yet. Analyze an email to start building local history.")
    else:
        df = pd.DataFrame(rows)
        a, b = st.columns(2)
        a.metric("Saved analyses", len(df))
        b.metric("High risk", int((df.risk_score >= 60).sum()))
        st.bar_chart(df.classification.value_counts())
        st.area_chart(df.set_index("created_at")["risk_score"])
        st.dataframe(df, use_container_width=True, hide_index=True)
    if st.button("Generate 500-row synthetic dataset"):
        path = generate_dataset(ROOT / "data" / "phishing_email_dataset.csv", rows=500)
        st.success(f"Generated {path.relative_to(ROOT)} using fictional domains.")
elif page == "Awareness":
    st.subheader("Pause, inspect, verify")
    for title, detail in [
        ("Check the sender", "Read the full address and domain. Display names can be copied."),
        ("Treat urgency as a cue", "Pressure to act quickly is worth checking, but urgency alone does not prove fraud."),
        ("Inspect links safely", "Hover in a suitable environment or use approved tools. Do not enter credentials from an unexpected message."),
        ("Verify through another channel", "Contact the organization using a known, independently obtained number or website."),
        ("Handle attachments carefully", "Unexpected executable or script files should be reported, not opened."),
        ("Report and preserve context", "Use your organization's reporting process and preserve the original message for responders."),
    ]:
        with st.expander(title):
            st.write(detail)
    st.info("An automated score is a triage aid. Context and analyst review matter; false positives and missed threats are possible.")
