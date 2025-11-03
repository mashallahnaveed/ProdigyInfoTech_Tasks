import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from scapy.all import sniff, wrpcap, get_if_list
from datetime import datetime
import threading

class PacketAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 Network Packet Analyzer")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        # --- UI Elements ---
        ttk.Label(root, text="Interface:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.interface = ttk.Combobox(root, values=get_if_list(), width=50)
        self.interface.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(root, text="Packet Limit:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.packet_limit = ttk.Entry(root, width=10)
        self.packet_limit.insert(0, "50")
        self.packet_limit.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        self.start_btn = ttk.Button(root, text="Start Capture", command=self.start_capture)
        self.start_btn.grid(row=2, column=0, padx=10, pady=10)

        self.stop_btn = ttk.Button(root, text="Stop", command=self.stop_capture, state="disabled")
        self.stop_btn.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        self.output = scrolledtext.ScrolledText(root, width=80, height=20, wrap=tk.WORD)
        self.output.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        self.capturing = False
        self.captured_packets = []

    def start_capture(self):
        iface = self.interface.get()
        if not iface:
            messagebox.showerror("Error", "Please select a network interface!")
            return

        try:
            count = int(self.packet_limit.get())
        except ValueError:
            messagebox.showerror("Error", "Packet limit must be a number.")
            return

        self.captured_packets.clear()
        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, f"🌐 Starting capture on {iface} — {count} packets max\n\n")

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.capturing = True

        thread = threading.Thread(target=self.capture_packets, args=(iface, count))
        thread.start()

    def stop_capture(self):
        self.capturing = False
        self.output.insert(tk.END, "\n🛑 Capture stopped by user.\n")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def analyze_packet(self, packet):
        if not self.capturing:
            return False

        info = []
        info.append("=" * 50)
        info.append(f"📡 Packet #{len(self.captured_packets) + 1}")
        info.append(f"🔸 Time: {datetime.now().strftime('%H:%M:%S')}")

        if packet.haslayer("IP"):
            ip = packet["IP"]
            info.append(f"🌍 Source: {ip.src}  ➤  Dest: {ip.dst}")
            info.append(f"📨 Protocol: {ip.proto}")

        if packet.haslayer("TCP"):
            tcp = packet["TCP"]
            info.append(f"🔹 TCP — Src Port: {tcp.sport}, Dst Port: {tcp.dport}")
        elif packet.haslayer("UDP"):
            udp = packet["UDP"]
            info.append(f"🔹 UDP — Src Port: {udp.sport}, Dst Port: {udp.dport}")

        self.captured_packets.append(packet)
        self.output.insert(tk.END, "\n".join(info) + "\n\n")
        self.output.see(tk.END)

    def capture_packets(self, iface, count):
        try:
            sniff(iface=iface, prn=self.analyze_packet, count=count, stop_filter=lambda x: not self.capturing)
        finally:
            if self.captured_packets:
                wrpcap("captured_packets.pcap", self.captured_packets)
                self.output.insert(tk.END, f"\n✅ Saved {len(self.captured_packets)} packets to captured_packets.pcap\n")
            self.stop_capture()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerGUI(root)
    root.mainloop()
