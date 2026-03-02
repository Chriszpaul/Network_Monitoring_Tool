# ===============================
# GLOBAL CONFIGURATION
# ===============================

CONFIG = {

    # ===============================
    # CAPTURE SETTINGS
    # ===============================
    "WINDOW_SIZE": 50,
    "SAVE_RAW_PACKETS": True,

    # ===============================
    # DETECTION THRESHOLDS
    # ===============================
    "PORT_SCAN_THRESHOLD": 5,
    "TRAFFIC_SPIKE_THRESHOLD": 200,
    "ACTIVE_IP_THRESHOLD": 3,
    "LIVE_ACTIVITY_THRESHOLD": 5,

    # ===============================
    # THREAT SCORING
    # ===============================
    "PORT_SCAN_SCORE": 80,
    "TRAFFIC_SPIKE_SCORE": 60,
    "ACTIVE_IP_SCORE": 10,

    # ===============================
    # DASHBOARD
    # ===============================
    "AUTO_REFRESH_SEC": 2,
    "LIGHT_MODE": True,

    # ===============================
    # ALERT CONTROL
    # ===============================
    "ALERT_COOLDOWN_SEC": 20
}