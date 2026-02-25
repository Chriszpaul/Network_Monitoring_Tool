from scapy.layers.inet import IP, TCP, UDP

def analyze_packets(packets):

    traffic = {}
    packet_count = {}

    for pkt in packets:

        if pkt.haslayer(IP):

            src_ip = pkt[IP].src

            if src_ip not in traffic:
                traffic[src_ip] = []

            packet_count[src_ip] = packet_count.get(src_ip, 0) + 1

            if pkt.haslayer(TCP):
                traffic[src_ip].append(pkt[TCP].dport)

            elif pkt.haslayer(UDP):
                traffic[src_ip].append(pkt[UDP].dport)

    return traffic, packet_count