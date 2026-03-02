# =====================================
# CONFIG (USER ADJUSTABLE PARAMETERS)
# =====================================

PORT_SCAN_THRESHOLD = 10        # unique ports
TRAFFIC_SPIKE_THRESHOLD = 300   # packets per window
ACTIVE_IP_THRESHOLD = 3         # info alert
LIVE_ACTIVITY_THRESHOLD = 5     # lightweight alert


# =====================================
# PORT SCAN DETECTION
# =====================================
def detect_port_scan(traffic):

    alerts = []

    for ip, ports in traffic.items():

        # remove invalid ports safely
        unique_ports = {p for p in ports if p is not None}

        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            alerts.append(
                f"⚠ Possible Port Scan detected from {ip} "
                f"(unique ports: {len(unique_ports)})"
            )

    return alerts


# =====================================
# TRAFFIC SPIKE DETECTION
# =====================================
def detect_traffic_spike(packet_count):

    alerts = []

    for ip, count in packet_count.items():

        if count >= TRAFFIC_SPIKE_THRESHOLD:
            alerts.append(
                f"⚠ High traffic spike detected from {ip} "
                f"(packets: {count})"
            )

    return alerts


# =====================================
# ACTIVE CONNECTION (INFO LEVEL)
# =====================================
def detect_active_ip(packet_count):

    alerts = []

    for ip, count in packet_count.items():

        # avoids spam
        if count >= ACTIVE_IP_THRESHOLD:
            alerts.append(
                f"ℹ Active connection from {ip} "
                f"(packets: {count})"
            )

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