from scapy.all import sniff

class PacketSniffer:
    def __init__(self, callback):
        self.callback = callback
        self.sniffing = False

    def process_packet(self, packet):
        if packet.haslayer("IP"):
            ip_layer = packet["IP"]
            source_ip = ip_layer.src
            destination_ip = ip_layer.dst
            protocol = ip_layer.proto
            self.callback(source_ip, destination_ip, protocol)

    def start_sniffing(self):
        self.sniffing = True
        sniff(prn=self.process_packet, store=False, stop_filter=lambda x: not self.sniffing)

    def stop_sniffing(self):
        self.sniffing = False