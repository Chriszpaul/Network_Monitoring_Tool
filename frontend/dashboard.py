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
# SIDEBAR CONFIG
# ==============================
st.sidebar.title("Configuration")

CONFIG["WINDOW_SIZE"] = st.sidebar.slider(
    "Packet Window Size", 10, 200, CONFIG["WINDOW_SIZE"]
)

CONFIG["PORT_SCAN_THRESHOLD"] = st.sidebar.slider(
    "Port Scan Threshold", 3, 50, CONFIG["PORT_SCAN_THRESHOLD"]
)

CONFIG["TRAFFIC_SPIKE_THRESHOLD"] = st.sidebar.slider(
    "Traffic Spike Threshold", 50, 1000, CONFIG["TRAFFIC_SPIKE_THRESHOLD"]
)

CONFIG["AUTO_REFRESH_SEC"] = st.sidebar.slider(
    "Dashboard Refresh (sec)", 1, 10, CONFIG["AUTO_REFRESH_SEC"]
)

CONFIG["SAVE_RAW_PACKETS"] = st.sidebar.checkbox(
    "Save Raw Packets", CONFIG["SAVE_RAW_PACKETS"]
)

# ==============================
# THEME
# ==============================
st.markdown("""
<style>
.main { background-color: #f8fafc; }
h1, h2, h3 { color: #0f172a; }
</style>
""", unsafe_allow_html=True)

st.title("Network Monitoring and Threat Intelligence")
st.caption("Real-time Monitoring and Analysis")

# ==============================
# LOAD DATA
# ==============================
@st.cache_data(ttl=2)
def load_alerts():
    try:
        conn = sqlite3.connect(DB_NAME)
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 200", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()


@st.cache_data(ttl=2)
def load_packets():
    try:
        conn = sqlite3.connect(DB_NAME)
        df = pd.read_sql_query("SELECT * FROM packets ORDER BY id DESC LIMIT 500", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()


alerts_df = load_alerts()
packets_df = load_packets()

# ==============================
# ALERT POPUP
# ==============================
if not alerts_df.empty:
    latest = alerts_df.iloc[0]

    if latest["severity"] == "CRITICAL":
        st.error(f"Critical Alert: {latest['message']}")
    elif latest["severity"] == "WARNING":
        st.warning(f"Warning: {latest['message']}")

# ==============================
# EMPTY STATE
# ==============================
if alerts_df.empty and packets_df.empty:
    st.warning("No traffic captured yet")
    time.sleep(2)
    st.rerun()

# ==============================
# METRICS
# ==============================
st.subheader("Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", len(alerts_df))
col2.metric("Warnings", len(alerts_df[alerts_df["severity"] == "WARNING"]))
col3.metric("Critical", len(alerts_df[alerts_df["severity"] == "CRITICAL"]))
col4.metric("Packets", len(packets_df))

st.divider()

# ==============================
# FILTERS
# ==============================
st.subheader("Filters")

filtered_packets = packets_df.copy()
filtered_alerts = alerts_df.copy()

c1, c2 = st.columns(2)

with c1:
    protocol_filter = st.selectbox(
        "Protocol",
        ["All"] + sorted(filtered_packets["protocol"].dropna().unique().tolist())
        if not filtered_packets.empty else ["All"]
    )

with c2:
    severity_filter = st.selectbox(
        "Severity",
        ["All"] + sorted(filtered_alerts["severity"].dropna().unique().tolist())
        if not filtered_alerts.empty else ["All"]
    )

if protocol_filter != "All":
    filtered_packets = filtered_packets[
        filtered_packets["protocol"] == protocol_filter
    ]

if severity_filter != "All":
    filtered_alerts = filtered_alerts[
        filtered_alerts["severity"] == severity_filter
    ]

st.divider()

# ==============================
# SUSPICIOUS IP RANKING
# ==============================
st.subheader("Suspicious IP Ranking")

if not alerts_df.empty:
    ip_risk = (
        alerts_df.groupby("src_ip")["score"]
        .sum()
        .sort_values(ascending=False)
        .head(10)
    )
    st.bar_chart(ip_risk)
else:
    st.info("No data")

# ==============================
# GRAPHS
# ==============================
left, right = st.columns(2)

with left:
    st.subheader("Top Source IPs")
    if not filtered_packets.empty:
        st.bar_chart(filtered_packets["src_ip"].value_counts().head(10))
    else:
        st.info("No data")

with right:
    st.subheader("Protocol Distribution")
    if not filtered_packets.empty:
        st.bar_chart(filtered_packets["protocol"].value_counts())
    else:
        st.info("No data")

st.divider()

# ==============================
# TRAFFIC SPEED
# ==============================
st.subheader("Traffic Speed")

if not filtered_packets.empty:
    df = filtered_packets.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    speed = df.groupby(df["timestamp"].dt.floor("S")).size()
    st.line_chart(speed)
else:
    st.info("No data")

st.divider()

# ==============================
# PACKET STREAM
# ==============================
st.subheader("Packet Stream")

if not filtered_packets.empty:
    st.dataframe(
        filtered_packets[
            ["timestamp", "src_ip", "dst_ip", "protocol", "port", "packet_size"]
        ],
        use_container_width=True,
        height=350
    )
else:
    st.info("No data")

st.divider()

# ==============================
# ALERT STYLING
# ==============================
def style_alerts(row):
    if row["severity"] == "CRITICAL":
        return ["background-color: #ffcccc"] * len(row)
    elif row["severity"] == "WARNING":
        return ["background-color: #fff3cd"] * len(row)
    else:
        return [""] * len(row)

# ==============================
# ALERT LOG
# ==============================
st.subheader("Alert Log")

if not filtered_alerts.empty:
    st.dataframe(
        filtered_alerts[
            ["timestamp", "severity", "score", "src_ip", "protocol", "message"]
        ].style.apply(style_alerts, axis=1),
        use_container_width=True,
        height=300
    )
else:
    st.info("No alerts")

# ==============================
# AUTO REFRESH
# ==============================
time.sleep(CONFIG["AUTO_REFRESH_SEC"])
st.rerun()