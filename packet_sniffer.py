import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import threading

class PacketSniffer:
    def __init__(self, interface=None):
        self.interface = interface
        self.root = tk.Tk()
        self.root.title("Advanced Packet Sniffer")
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=100, height=30)
        self.text_area.pack(pady=10)
        self.start_sniffer()

    def packet_callback(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            protocol = packet.getlayer(1).name

            log = f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}, Protocol: {protocol}\n"
            
            if packet.haslayer(TCP):
                log += f"TCP: Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}\n"
            elif packet.haslayer(UDP):
                log += f"UDP: Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}\n"
            elif packet.haslayer(ICMP):
                log += "ICMP Packet\n"

            payload = bytes(packet[IP].payload)
            if payload:
                log += f"Payload: {payload[:50]}...\n"
            log += "-" * 60 + "\n"
            self.display_packet(log)

    def display_packet(self, log):
        self.text_area.insert(tk.END, log)
        self.text_area.yview(tk.END)

    def start_sniffer(self):
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def sniff_packets(self):
        try:
            sniff(iface=self.interface, prn=self.packet_callback, store=0)  # Removed the socket argument
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run(self):
        self.root.mainloop()

def get_wifi_interface():
    interfaces = get_if_list()
    for iface in interfaces:
        if "wlan" in iface.lower() or "wifi" in iface.lower():
            return iface
    return None

if __name__ == "__main__":
    wifi_interface = get_wifi_interface()
    if wifi_interface:
        print(f"Using Wi-Fi interface: {wifi_interface}")
    else:
        print("No Wi-Fi interface found! Using default interface.")
        wifi_interface = None
    
    sniffer = PacketSniffer(wifi_interface)
    sniffer.run()
