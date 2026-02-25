from scapy.all import rdpcap

from core.analyzer import analyze_packets
from core.detector import detect_port_scan, detect_traffic_spike
from core.report import generate_report

print("Network Monitoring Tool Started...")

# Load PCAP file
packets = rdpcap("sample.pcap")

# Analyze traffic
traffic, packet_count = analyze_packets(packets)

# Detection
alerts = []
alerts += detect_port_scan(traffic)
alerts += detect_traffic_spike(packet_count)

# Generate report
generate_report(alerts)