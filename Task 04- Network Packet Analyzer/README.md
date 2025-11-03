🌐 Task 04 — Network Packet Analyzer (GUI)

Description:
A Python-based Network Packet Analyzer with a graphical interface that captures, analyzes, and saves real-time network traffic using Scapy.
This tool demonstrates how cybersecurity professionals can monitor packets, identify communication protocols, and understand traffic flow in a controlled environment.

Key Features:

🧭 Interface Selection: Dynamically lists available network interfaces using scapy.get_if_list().

📦 Live Packet Capture: Captures and displays real-time network packets with IP and port details.

⚙️ Protocol Detection: Detects and displays IP, TCP, and UDP layers from captured traffic.

🧵 Threaded Sniffing: Uses multithreading to keep the GUI responsive during live capture.

💾 PCAP Export: Automatically saves captured packets to captured_packets.pcap for later analysis in Wireshark or similar tools.

🛑 Start/Stop Control: Begin or halt capture anytime through simple buttons.

🧹 Scrollable Output Panel: Displays analyzed packet details in an interactive log viewer.

How It Works:

Select a network interface from the dropdown.

Set the number of packets to capture.

Click “Start Capture” — the tool begins analyzing packets in real time.

View detailed metadata: source IP, destination IP, protocol, and port information.

Stop capture manually or wait for it to reach the limit — results are automatically saved as captured_packets.pcap.

Skills Demonstrated:

Network Traffic Analysis

Scapy Packet Manipulation

Tkinter GUI Programming

Multithreading in Python

Practical Cybersecurity Tool Development

Usage:

Install dependencies:

pip install scapy tk


Run the analyzer:

python packet_analyzer_gui.py


Select an interface, set a packet limit, and start capturing.

⚠️ Note: Run the script with administrative/root privileges to allow packet capture on most systems.

Output Example:

🌐 Starting capture on Wi-Fi — 50 packets max

==================================================
📡 Packet #1

🔸 Time: 14:32:11

🌍 Source: 192.168.0.10  ➤  Dest: 142.250.190.14

📨 Protocol: 6

🔹 TCP — Src Port: 52345, Dst Port: 443


Developer:
🧠 Mashallah Naveed

✨ Developed as part of the Prodigy InfoTech Cybersecurity Internship
