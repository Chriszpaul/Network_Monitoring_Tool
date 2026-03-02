import streamlit as st
import sqlite3
import pandas as pd
import time
from core.config import CONFIG

DB_NAME = "alerts.db"

st.set_page_config(
    page_title="Network Security Dashboard",
    layout="wide"
)

# ==============================
# LIGHT PROFESSIONAL THEME
# ==============================
st.markdown("""
<style>
.main {
    background-color: #f8fafc;
}
h1, h2, h3 {
    color: #0f172a;
}
.block-container {
    padding-top: 1.5rem;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Network Monitoring & Threat Intelligence")
st.caption("Real-time Monitoring • Packet Analysis • Threat Detection")

# ==============================
# DATABASE LOADERS
# ==============================
@st.cache_data(ttl=2)
def load_alerts():
    try:
        conn = sqlite3.connect(DB_NAME)
        df = pd.read_sql_query("""
            SELECT *
            FROM alerts
            ORDER BY id DESC
            LIMIT 200
        """, conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()


@st.cache_data(ttl=2)
def load_packets():
    try:
        conn = sqlite3.connect(DB_NAME)
        df = pd.read_sql_query("""
            SELECT *
            FROM packets
            ORDER BY id DESC
            LIMIT 500
        """, conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()


alerts_df = load_alerts()
packets_df = load_packets()

# ==============================
# EMPTY STATE
# ==============================
if alerts_df.empty and packets_df.empty:
    st.warning("No traffic captured yet...")
    time.sleep(2)
    st.rerun()

# ==============================
# LIVE METRICS
# ==============================
st.subheader("📊 Live Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", len(alerts_df))
col2.metric("Warnings", len(alerts_df[alerts_df["severity"]=="WARNING"]))
col3.metric("Critical", len(alerts_df[alerts_df["severity"]=="CRITICAL"]))
col4.metric("Packets Captured", len(packets_df))

st.divider()

# ==============================
# FILTERS
# ==============================
st.subheader("🔍 Filters")

f1, f2 = st.columns(2)

with f1:
    protocol_filter = st.selectbox(
        "Protocol",
        ["All"] + sorted(
            packets_df["protocol"].dropna().unique().tolist()
        ) if not packets_df.empty else ["All"]
    )

with f2:
    severity_filter = st.selectbox(
        "Severity",
        ["All"] + sorted(
            alerts_df["severity"].dropna().unique().tolist()
        ) if not alerts_df.empty else ["All"]
    )

# Apply filters
if protocol_filter != "All" and not packets_df.empty:
    packets_df = packets_df[packets_df["protocol"] == protocol_filter]

if severity_filter != "All" and not alerts_df.empty:
    alerts_df = alerts_df[alerts_df["severity"] == severity_filter]

st.divider()

# ==============================
# ANALYTICS
# ==============================
left, right = st.columns(2)

with left:
    if not packets_df.empty:
        st.subheader("🌐 Top Source IPs")
        st.bar_chart(packets_df["src_ip"].value_counts().head(10))

with right:
    if not packets_df.empty:
        st.subheader("📡 Protocol Distribution")
        st.bar_chart(packets_df["protocol"].value_counts())

st.divider()

# ==============================
# LIVE PACKET STREAM
# ==============================
st.subheader("🧪 Live Packet Stream (Wireshark Style)")

if not packets_df.empty:
    st.dataframe(
        packets_df[
            ["timestamp","src_ip","dst_ip","protocol","port","packet_size"]
        ],
        use_container_width=True,
        height=380
    )

st.divider()

# ==============================
# ALERT STREAM
# ==============================
st.subheader("🚨 Alert Log")

if not alerts_df.empty:
    st.dataframe(
        alerts_df[
            ["timestamp","severity","score","src_ip","message"]
        ],
        use_container_width=True,
        height=300
    )

# ==============================
# AUTO REFRESH (SMOOTH)
# ==============================
time.sleep(CONFIG["AUTO_REFRESH_SEC"])
st.rerun()