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
# CONFIG
# ===============================
WINDOW_SIZE = CONFIG["WINDOW_SIZE"]
SAVE_RAW_PACKETS = CONFIG["SAVE_RAW_PACKETS"]

print("LIVE CAPTURE STARTED (Ctrl+C to stop)")
init_db()
print("Database initialized")

captured_packets = []
last_alert_messages = set()


# ===============================
# PACKET PROCESSING
# ===============================
def process_packet(packet):

    global last_alert_messages

    captured_packets.append(packet)

    # analyze only when window full
    if len(captured_packets) < WINDOW_SIZE:
        return

    try:
        traffic, packet_count, packet_details, protocol_stats = analyze_packets(
            captured_packets
        )

    except Exception as e:
        print("Analyzer error:", e)
        captured_packets.clear()
        return

    # ==================================
    # SAVE RAW PACKETS (EXPERT MODE)
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

    # normalize alerts (dict + string safe)
    normalized_alerts = []

    for a in alerts:
        if isinstance(a, dict):
            normalized_alerts.append(a)
        else:
            # fallback for old string alerts
            normalized_alerts.append({
                "message": str(a),
                "score": 10,
                "type": "INFO"
            })

    # deduplicate by message
    current_messages = {a["message"] for a in normalized_alerts}
    new_messages = current_messages - last_alert_messages

    # ==================================
    # SAVE ALERTS
    # ==================================
    for alert in normalized_alerts:

        message = alert["message"]

        if message not in new_messages:
            continue

        score = alert.get("score", 10)

        # score → severity
        if score >= 80:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "WARNING"
        else:
            severity = "INFO"

        details = packet_details[-1] if packet_details else {}

        try:
            save_alert(
                message=message,
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
    if new_messages:
        generate_report(list(new_messages))

    # update memory
    last_alert_messages = current_messages

    # clear window
    captured_packets.clear()


# ===============================
# START SNIFFING
# ===============================
sniff(prn=process_packet, store=False)