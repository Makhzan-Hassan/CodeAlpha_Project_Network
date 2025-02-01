from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


def analyze_packet(packet):
    """
    Analyze captured packets and print relevant information.
    """
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"\n[IP Packet] {ip_layer.src} -> {ip_layer.dst}")

        # Analyze TCP packets
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"  [TCP] Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}, Flags: {tcp_layer.flags}")

        # Analyze UDP packets
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"  [UDP] Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")
        else:
            print("  Protocol: Other (Non-TCP/UDP)")


def start_sniffer(interface=None):
    """
    Start the network sniffer.
    :param interface: Network interface to sniff on (e.g., 'eth0', 'wlan0').
    """
    print(f"Starting sniffer on interface: {interface or 'default'}...\nPress Ctrl+C to stop.")
    sniff(iface=interface, filter="ip", prn=analyze_packet, store=False)


if __name__ == "__main__":
    interface = input("Enter the network interface to sniff on (leave blank for default): ").strip()
    start_sniffer(interface if interface else None)
