from scapy.all import IP, ICMP, send

# Define the target IP address
target_ip = "172.19.0.2"

# Create an ICMP packet
icmp_packet = IP(dst=target_ip)/ICMP()

# Send the packet
send(icmp_packet)