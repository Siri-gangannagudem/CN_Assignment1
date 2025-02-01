from scapy.all import sniff, wrpcap

# Output pcap file name
pcap_file = "captured_traffic.pcap"

captured_packets = []

# Packet handling function
def packet_handler(packet):
    print(packet.summary())  
    captured_packets.append(packet)  # Store packets

sniff(prn=packet_handler, store=True, count=100)

# Save packets to a pcap file
wrpcap(pcap_file, captured_packets)

print(f"Packets saved to {pcap_file}")
