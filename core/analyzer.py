from scapy.layers.inet import IP, TCP, UDP, ICMP

def analyze_packets(packets):

    traffic = {}
    packet_count = {}
    packet_details = []
    protocol_stats = {}

    for pkt in packets:

        if IP in pkt:

            src = pkt[IP].src
            dst = pkt[IP].dst

            proto = "OTHER"
            port = None

            # ============================
            # PROTOCOL DETECTION (UPGRADED)
            # ============================
            if TCP in pkt:
                port = pkt[TCP].dport

                if port == 80:
                    proto = "HTTP"
                elif port == 443:
                    proto = "HTTPS"
                elif port == 22:
                    proto = "SSH"
                elif port == 21:
                    proto = "FTP"
                elif port == 25:
                    proto = "SMTP"
                else:
                    proto = "TCP"

            elif UDP in pkt:
                port = pkt[UDP].dport

                if port == 53:
                    proto = "DNS"
                else:
                    proto = "UDP"

            elif ICMP in pkt:
                proto = "ICMP"
                port = None

            # ============================
            # STATS
            # ============================
            protocol_stats[proto] = protocol_stats.get(proto, 0) + 1

            # ============================
            # TRAFFIC MAP
            # ============================
            traffic.setdefault(src, []).append(port)
            packet_count[src] = packet_count.get(src, 0) + 1

            # ============================
            # PACKET DETAILS
            # ============================
            packet_details.append({
                "src_ip": src,
                "dst_ip": dst,
                "protocol": proto,
                "port": port,
                "packet_size": len(pkt),
                "packet_count": packet_count[src]
            })

    return traffic, packet_count, packet_details, protocol_stats