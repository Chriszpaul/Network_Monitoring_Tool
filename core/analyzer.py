from scapy.layers.inet import IP, TCP, UDP

def analyze_packets(packets):

    traffic = {}
    packet_count = {}
    packet_details = []
    protocol_stats = {"TCP": 0, "UDP": 0, "OTHER": 0}

    for pkt in packets:

        if IP in pkt:

            src = pkt[IP].src
            dst = pkt[IP].dst

            proto = "OTHER"
            port = None

            if TCP in pkt:
                proto = "TCP"
                port = pkt[TCP].dport

            elif UDP in pkt:
                proto = "UDP"
                port = pkt[UDP].dport

            protocol_stats[proto] += 1

            traffic.setdefault(src, []).append(port)
            packet_count[src] = packet_count.get(src, 0) + 1

            packet_details.append({
                "src_ip": src,
                "dst_ip": dst,
                "protocol": proto,
                "port": port,
                "packet_size": len(pkt),
                "packet_count": packet_count[src]
            })

    return traffic, packet_count, packet_details, protocol_stats