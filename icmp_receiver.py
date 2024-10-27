from scapy.all import sniff, ICMP,IP

def handle_packet(packet):
    if ICMP in packet:
        print(f"Received ICMP packet from {packet[IP].src}")

# Sniff for ICMP packets
sniff(filter="icmp", prn=handle_packet)