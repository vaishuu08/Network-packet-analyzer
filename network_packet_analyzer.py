from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] Packet: {ip_layer.src} -> {ip_layer.dst}")
        print(f"    Protocol: {packet.proto}")
        
        if TCP in packet:
            print(f"    TCP Payload: {bytes(packet[TCP].payload)}")
        elif UDP in packet:
            print(f"    UDP Payload: {bytes(packet[UDP].payload)}")
        else:
            print("    Other Protocol Detected")

# Sniff packets (use 'iface' to specify a network interface if needed)
print("[*] Starting network packet capture...")
sniff(prn=packet_callback, count=10)  # Captures 10 packets; remove 'count' for continuous capture
