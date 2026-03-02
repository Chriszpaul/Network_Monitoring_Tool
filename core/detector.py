# =====================================
# CONFIG (USER ADJUSTABLE PARAMETERS)
# =====================================

PORT_SCAN_THRESHOLD = 10        # unique ports
TRAFFIC_SPIKE_THRESHOLD = 300   # packets per window
ACTIVE_IP_THRESHOLD = 3         # info alert
LIVE_ACTIVITY_THRESHOLD = 5     # lightweight alert


from core.config import CONFIG


# ===============================
# PORT SCAN DETECTION
# ===============================
def detect_port_scan(traffic):

    alerts = []

    for ip, ports in traffic.items():

        unique_ports = {p for p in ports if p is not None}

        if len(unique_ports) >= CONFIG["PORT_SCAN_THRESHOLD"]:

            alerts.append({
                "message": f"Possible Port Scan from {ip}",
                "score": CONFIG["PORT_SCAN_SCORE"],
                "type": "PORT_SCAN"
            })

    return alerts


# ===============================
# TRAFFIC SPIKE
# ===============================
def detect_traffic_spike(packet_count):

    alerts = []

    for ip, count in packet_count.items():

        if count >= CONFIG["TRAFFIC_SPIKE_THRESHOLD"]:

            alerts.append({
                "message": f"Traffic spike from {ip} (packets: {count})",
                "score": CONFIG["TRAFFIC_SPIKE_SCORE"],
                "type": "TRAFFIC_SPIKE"
            })

    return alerts


# ===============================
# ACTIVE CONNECTION
# ===============================
def detect_active_ip(packet_count):

    alerts = []

    for ip, count in packet_count.items():

        if count >= CONFIG["ACTIVE_IP_THRESHOLD"]:

            alerts.append({
                "message": f"Active connection from {ip}",
                "score": CONFIG["ACTIVE_IP_SCORE"],
                "type": "ACTIVE_IP"
            })

    return alerts

# =====================================
# LIVE ACTIVITY (LIGHTWEIGHT ALERT)
# =====================================
def detect_live_activity(packet_count):

    alerts = []

    for ip, count in packet_count.items():

        # only show meaningful live traffic
        if count >= LIVE_ACTIVITY_THRESHOLD:
            alerts.append(
                f"ℹ Live traffic observed from {ip}"
            )

    return alerts