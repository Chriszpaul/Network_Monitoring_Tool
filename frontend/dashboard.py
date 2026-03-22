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
# LIVE CONFIG PANEL
# ==============================
<<<<<<< HEAD
st.sidebar.title(" Live Configuration")
=======
st.sidebar.title("Live Configuration")
>>>>>>> bdbfba2f558eeb46d0e93ae07dd8ba41432e768c

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
    "Save Raw Packets (Expert Mode)", CONFIG["SAVE_RAW_PACKETS"]
)

# ==============================
# UI THEME
# ==============================
st.markdown("""
<style>
.main { background-color: #f8fafc; }
h1, h2, h3 { color: #0f172a; }
.block-container { padding-top: 1.5rem; }
</style>
""", unsafe_allow_html=True)

<<<<<<< HEAD
st.title(" Network Monitoring & Threat Intelligence")
=======
st.title("Network Monitoring & Threat Intelligence")
>>>>>>> bdbfba2f558eeb46d0e93ae07dd8ba41432e768c
st.caption("Real-time Monitoring • Packet Analysis • Threat Detection")

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
#  ALERT POPUP (FIXED POSITION)
# ==============================
if not alerts_df.empty:
    latest = alerts_df.iloc[0]

    if latest["severity"] == "CRITICAL":
        st.error(f" CRITICAL: {latest['message']}")
        st.toast(" Critical Threat Detected!", icon="")

    elif latest["severity"] == "WARNING":
        st.warning(f"⚠ WARNING: {latest['message']}")

# ==============================
# EMPTY STATE
# ==============================
if alerts_df.empty and packets_df.empty:
    st.warning("No traffic captured yet...")
    time.sleep(2)
    st.rerun()

# ==============================
# METRICS
# ==============================
<<<<<<< HEAD
st.subheader(" Live Overview")
=======
st.subheader("Live Overview")
>>>>>>> bdbfba2f558eeb46d0e93ae07dd8ba41432e768c

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", len(alerts_df))
col2.metric("Warnings", len(alerts_df[alerts_df["severity"] == "WARNING"]))
col3.metric("Critical", len(alerts_df[alerts_df["severity"] == "CRITICAL"]))
col4.metric("Packets", len(packets_df))

st.divider()

# ==============================
# FILTERS (FIXED PROPERLY)
# ==============================
<<<<<<< HEAD
st.subheader(" Filters")
=======
st.subheader("Filters")
>>>>>>> bdbfba2f558eeb46d0e93ae07dd8ba41432e768c

filtered_packets = packets_df.copy()
filtered_alerts = alerts_df.copy()

col1, col2 = st.columns(2)

with col1:
    protocol_filter = st.selectbox(
        "Protocol",
        ["All"] + sorted(filtered_packets["protocol"].dropna().unique().tolist())
        if not filtered_packets.empty else ["All"]
    )

with col2:
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
# GRAPHS (FIXED)
# ==============================
left, right = st.columns(2)

with left:
<<<<<<< HEAD
    st.subheader(" Top Source IPs")
    if not filtered_packets.empty:
        st.bar_chart(filtered_packets["src_ip"].value_counts().head(10))
    else:
        st.info("No data")

with right:
    st.subheader(" Protocol Distribution")
    if not filtered_packets.empty:
        st.bar_chart(filtered_packets["protocol"].value_counts())
    else:
        st.info("No data")
=======
    if not packets_df.empty:
        st.subheader("Top Source IPs")
        st.bar_chart(packets_df["src_ip"].value_counts().head(10))

with right:
    if not packets_df.empty:
        st.subheader("Protocol Distribution")
        st.bar_chart(packets_df["protocol"].value_counts())
>>>>>>> bdbfba2f558eeb46d0e93ae07dd8ba41432e768c

st.divider()

# ==============================
# PACKET STREAM
# ==============================
<<<<<<< HEAD
st.subheader(" Live Packet Stream")
=======
st.subheader("Live Packet Stream (Wireshark Style)")
>>>>>>> bdbfba2f558eeb46d0e93ae07dd8ba41432e768c

if not filtered_packets.empty:
    st.dataframe(
        filtered_packets[
            ["timestamp", "src_ip", "dst_ip", "protocol", "port", "packet_size"]
        ],
        use_container_width=True,
        height=350
    )
else:
    st.info("No packet data")

st.divider()

# ==============================
# 🎨 ALERT STYLING
# ==============================
<<<<<<< HEAD
def style_alerts(row):
    if row["severity"] == "CRITICAL":
        return ["background-color: #ffcccc"] * len(row)
    elif row["severity"] == "WARNING":
        return ["background-color: #fff3cd"] * len(row)
    else:
        return [""] * len(row)
=======
st.subheader("Alert Log")
>>>>>>> bdbfba2f558eeb46d0e93ae07dd8ba41432e768c

# ==============================
# ALERT LOG (FIXED + STYLED)
# ==============================
st.subheader(" Alert Log")

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