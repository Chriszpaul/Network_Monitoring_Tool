def detect_port_scan(traffic):

    alerts = []

    for ip in traffic:
        unique_ports = set(traffic[ip])

        if len(unique_ports) > 3:
            alerts.append(
                f"Possible Port Scan detected from {ip}"
            )

    return alerts

def detect_traffic_spike(packet_count):

    alerts = []

    for ip in packet_count:
        if packet_count[ip] > 200:
            alerts.append(
                f"High traffic detected from {ip}"
            )

    return alerts

def detect_active_ip(packet_count):

    alerts = []

    for ip, count in packet_count.items():

        # show only meaningful activity
        if count >= 1:
            alerts.append(
                f"ℹ Active connection from {ip} (packets: {count})"
            )

    return alerts

def detect_live_activity(packet_count):

    alerts = []

    for ip, count in packet_count.items():
        # LOWERED threshold for live demo
        if count >= 1:
            alerts.append(f"ℹ Active connection observed from {ip}")

    return alerts