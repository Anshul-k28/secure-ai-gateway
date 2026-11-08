"""Streamlit security dashboard. Reads the JSONL logging spine and renders
the Task 6 views: traffic, blocked vs allowed, violation mix, latency, top users.

Run:  streamlit run dashboard/app.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import streamlit as st

import config

st.set_page_config(page_title="Secure AI Gateway — Security Dashboard", layout="wide")
st.title("🛡️ Secure AI Gateway — Security Dashboard")


@st.cache_data(ttl=5)
def load_logs(path):
    if not os.path.exists(path):
        return pd.DataFrame()
    rows = [json.loads(l) for l in open(path) if l.strip()]
    df = pd.DataFrame(rows)
    if not df.empty:
        df["ts"] = pd.to_datetime(df["ts"], unit="s")
    return df


df = load_logs(config.LOG_PATH)
if df.empty:
    st.warning("No logs yet. Send traffic through the gateway first.")
    st.stop()

# Keep terminal decisions for traffic counts
total = len(df)
blocked = (df["decision"] == "blocked").sum()
allowed = (df["decision"] == "allowed").sum()
redacted = (df["decision"] == "redacted").sum()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total events", total)
c2.metric("Blocked", int(blocked))
c3.metric("Allowed", int(allowed))
c4.metric("Redacted", int(redacted))

st.subheader("Blocked vs Allowed")
st.bar_chart(df["decision"].value_counts())

st.subheader("Violation type breakdown")
v = df[df["violation_type"].notna()]["violation_type"].value_counts()
if not v.empty:
    st.bar_chart(v)
else:
    st.info("No violations logged.")

col_a, col_b = st.columns(2)
with col_a:
    st.subheader("Latency (ms) distribution")
    lat = df["latency_ms"].dropna()
    if not lat.empty:
        st.write(lat.describe()[["mean", "50%", "max"]] if "50%" in lat.describe()
                 else lat.describe())
        st.line_chart(lat.reset_index(drop=True))
with col_b:
    st.subheader("Top-risk users (by blocks)")
    risk = (df[df["decision"] == "blocked"]
            .groupby("user_id").size().sort_values(ascending=False).head(10))
    if not risk.empty:
        st.bar_chart(risk)

st.subheader("Recent events")
st.dataframe(df.sort_values("ts", ascending=False)
             [["ts", "user_id", "stage", "decision", "violation_type", "latency_ms"]]
             .head(50), use_container_width=True)
