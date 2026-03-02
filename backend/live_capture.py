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
from core.config import CONFIG


# ===============================
# CONFIG (USER ADJUSTABLE LATER)
# ===============================
WINDOW_SIZE = 50        # packets per analysis cycle
SAVE_RAW_PACKETS = True # expert mode switch

print("LIVE CAPTURE STARTED (Ctrl+C to stop)")
init_db()
print("Database initialized")

captured_packets = []
last_alerts = set()


# ===============================
# PACKET PROCESSING
# ===============================
def process_packet(packet):

    global last_alerts

    captured_packets.append(packet)

    # analyze only when window is full
    if len(captured_packets) >= WINDOW_SIZE:

        try:
            traffic, packet_count, packet_details, protocol_stats = analyze_packets(captured_packets)

        except Exception as e:
            print("Analyzer error:", e)
            captured_packets.clear()
            return

        # ==================================
        # SAVE RAW PACKETS (EXPERT VIEW)
        # ==================================
        if SAVE_RAW_PACKETS:
            for p in packet_details:
                try:
                    save_packet(
                        src_ip=p.get("src_ip"),
                        dst_ip=p.get("dst_ip"),
                        protocol=p.get("protocol"),
                        port=p.get("port"),
                        packet_size=p.get("packet_size")
                    )
                except Exception as e:
                    print("Packet save error:", e)

        # ==================================
        # DETECTION
        # ==================================
        alerts = []
        alerts += detect_port_scan(traffic)
        alerts += detect_traffic_spike(packet_count)
        alerts += detect_active_ip(packet_count)
        alerts += detect_live_activity(packet_count)

        new_alerts = set(alerts) - last_alerts

        # ==================================
        # SAVE ALERTS
        # ==================================
        for alert in new_alerts:

            if "⚠" in alert:
                severity = "WARNING"
            elif "ℹ" in alert:
                severity = "INFO"
            else:
                severity = "UNKNOWN"

            details = packet_details[-1] if packet_details else {}

            try:
                save_alert(
                    message=alert,
                    severity=severity,
                    src_ip=details.get("src_ip"),
                    dst_ip=details.get("dst_ip"),
                    protocol=details.get("protocol"),
                    port=details.get("port"),
                    packet_count=details.get("packet_count")
                )
            except Exception as e:
                print("Alert save error:", e)

        # ==================================
        # TERMINAL REPORT
        # ==================================
        if new_alerts:
            generate_report(list(new_alerts))

        # remember last alerts
        last_alerts = set(alerts)

        # clear window
        captured_packets.clear()


# ===============================
# START SNIFFING
# ===============================
sniff(prn=process_packet, store=False)