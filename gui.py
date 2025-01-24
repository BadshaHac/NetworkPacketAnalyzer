import tkinter as tk
from tkinter import ttk
from packet_sniffer import PacketSniffer

class PacketAnalyzerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Packet Analyzer")
        self.sniffer = PacketSniffer(self.add_packet_to_table)

        # Create a table to display packets
        self.columns = ("Source IP", "Destination IP", "Protocol")
        self.packet_table = ttk.Treeview(self.root, columns=self.columns, show="headings")
        for col in self.columns:
            self.packet_table.heading(col, text=col)
        self.packet_table.pack(fill="both", expand=True)

        # Create Start and Stop buttons
        self.start_button = tk.Button(self.root, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side="left", padx=10, pady=10)

        self.stop_button = tk.Button(self.root, text="Stop Capture", command=self.stop_capture, state="disabled")
        self.stop_button.pack(side="left", padx=10, pady=10)

    def add_packet_to_table(self, source_ip, destination_ip, protocol):
        self.packet_table.insert("", "end", values=(source_ip, destination_ip, protocol))

    def start_capture(self):
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.sniffer.start_sniffing()

    def stop_capture(self):
        self.sniffer.stop_sniffing()
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def run(self):
        self.root.mainloop()