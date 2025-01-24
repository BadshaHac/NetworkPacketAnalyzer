from scapy.utils import wrpcap

def save_packets_to_file(packets, filename="captured_packets.pcap"):
    wrpcap(filename, packets)
    print(f"Packets saved to {filename}")