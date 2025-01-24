from scapy.utils import wrpcap

class PacketSaver:
    def __init__(self):
        self.packets = []

    def add_packet(self, packet):
        self.packets.append(packet)

    def save_to_file(self, filename="captured_packets.pcap"):
        wrpcap(filename, self.packets)
        print(f"Packets saved to {filename}")