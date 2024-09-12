from scapy.all import sniff, IP, TCP, UDP, ICMP

# Function to map protocol numbers to names
def protocol_name(proto):
    protocols = {6: "TCP", 17: "UDP", 1: "ICMP"}
    return protocols.get(proto, f"Other Protocol ({proto})")

# Function to process the packet
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\nSource IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {protocol_name(ip_layer.proto)}")
        
        # Check if TCP/UDP/ICMP is present
        if packet.haslayer(TCP):
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
            print(f"Payload: {bytes(packet[TCP].payload)}")
        elif packet.haslayer(UDP):
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
            print(f"Payload: {bytes(packet[UDP].payload)}")
        elif packet.haslayer(ICMP):
            print("ICMP Packet")
        else:
            print("Other Protocol")

# Sniffing the packets
print("Starting the Packet Sniffer...")
sniff(filter="ip", prn=process_packet, store=False)

