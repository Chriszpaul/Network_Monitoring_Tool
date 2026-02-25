import streamlit as st
import sqlite3
import pandas as pd
import time

DB_NAME = "alerts.db"

st.set_page_config(page_title="Network Security Dashboard", layout="wide")

st.title("🛡️ Network Monitoring Dashboard")
st.caption("Live alerts (auto refresh every 2 sec)")

# ------------------------------
# LOAD DATA
# ------------------------------
def load_alerts():
    conn = sqlite3.connect(DB_NAME)

    query = """
        SELECT timestamp, severity, score, message
        FROM alerts
        ORDER BY id DESC
        LIMIT 50
    """

    df = pd.read_sql_query(query, conn)
    conn.close()
    return df


# ------------------------------
# DISPLAY DATA
# ------------------------------
df = load_alerts()

if df.empty:
    st.warning("No alerts yet...")
else:
    st.dataframe(df, use_container_width=True)

    st.subheader("Alert Statistics")

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Alerts", len(df))
    col2.metric("Warnings", len(df[df["severity"] == "WARNING"]))
    col3.metric("Info Alerts", len(df[df["severity"] == "INFO"]))


# ------------------------------
# SIMPLE AUTO REFRESH (WORKS EVERYWHERE)
# ------------------------------
time.sleep(2)
st.rerun()