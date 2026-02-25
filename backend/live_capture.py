from scapy.all import sniff
from core.analyzer import analyze_packets
from core.detector import (
    detect_active_ip,
    detect_port_scan,
    detect_traffic_spike,
    detect_live_activity
)
from core.report import generate_report
from core.database import init_db, save_alert, save_packet


# ===============================
# CONFIG
# ===============================
WINDOW_SIZE = 50   # analyze every 50 packets


# ===============================
# STARTUP
# ===============================
print("LIVE CAPTURE STARTED (Ctrl+C to stop)")
init_db()
print("Database initialized")


# ===============================
# GLOBAL STORAGE
# ===============================
captured_packets = []
last_alerts = set()


# ===============================
# PACKET PROCESSING
# ===============================
def process_packet(packet):

    global last_alerts

    captured_packets.append(packet)

    # analyze in WINDOWS (not every packet)
    if len(captured_packets) >= WINDOW_SIZE:

        traffic, packet_count = analyze_packets(captured_packets)

        alerts = []
        alerts += detect_port_scan(traffic)
        alerts += detect_traffic_spike(packet_count)
        alerts += detect_active_ip(packet_count)
        alerts += detect_live_activity(packet_count)

        new_alerts = set(alerts) - last_alerts

        for alert in new_alerts:

            if "⚠" in alert:
                severity = "WARNING"
            elif "ℹ" in alert:
                severity = "INFO"
            else:
                severity = "UNKNOWN"

            save_alert(alert, severity)

        if new_alerts:
            generate_report(list(new_alerts))

        last_alerts = set(alerts)

        # clear buffer (window finished)
        captured_packets.clear()


# ===============================
# START SNIFFING
# ===============================
sniff(prn=process_packet, store=False)