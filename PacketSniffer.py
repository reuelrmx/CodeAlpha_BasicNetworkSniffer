import scapy.all as scapy
import netifaces
import socket

#color codes
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_RESET = "\033[0m"

def print_color(text, color):
    print(f"{color}{text}{COLOR_RESET}")
    
def get_available_interfaces():
    interfaces = netifaces.interfaces()
    return interfaces

def display_interfaces(interfaces):
    print("Available network interfaces:")
    for i, interface in enumerate(interfaces, start=1):
        print(f"{i}. {interface}")

def select_interface(interfaces):
    while True:
        try:
            choice = int(input("Enter the number corresponding to the interface you want to sniff: "))
            if choice < 1 or choice > len(interfaces):
                print("Invalid choice. Please enter a valid number.")
                continue
            return interfaces[choice - 1]
        except ValueError:
            print("Invalid input. Please enter a number.")

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def resolve_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return "Unknown"


def process_packet(packet):
    print("=" * 50)
    
    # Ethernet Frame
    if packet.haslayer(scapy.Ether):
        source_mac = packet[scapy.Ether].src
        destination_mac = packet[scapy.Ether].dst
        print_color(f"Ethernet Frame: Source MAC: {source_mac}, Destination MAC: {destination_mac}", COLOR_YELLOW)

    # IP Packet
    if packet.haslayer(scapy.IP):
        if packet.haslayer(scapy.IPv6):
            source_ip = packet[scapy.IPv6].src
            destination_ip = packet[scapy.IPv6].dst
            print_color(f"IPv6 Packet: Source IP: {source_ip}, Destination IP: {destination_ip}", COLOR_CYAN)
        else:
            source_ip = packet[scapy.IP].src
            destination_ip = packet[scapy.IP].dst
            print_color(f"IPv4 Packet: Source IP: {source_ip}, Destination IP: {destination_ip}", COLOR_CYAN)

        # Transport Layer (TCP/UDP)
        if packet.haslayer(scapy.TCP):
            source_port = packet[scapy.TCP].sport
            destination_port = packet[scapy.TCP].dport
            print_color(f"TCP Packet: Source Port: {source_port}, Destination Port: {destination_port}", COLOR_GREEN)
            # Extracting HTTP host from HTTP packets
            if packet.haslayer(scapy.Raw) and b"HTTP" in packet[scapy.Raw].load:
                http_data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                host_index = http_data.find("Host: ")
                if host_index != -1:
                    host_end_index = http_data.find("\r\n", host_index)
                    host = http_data[host_index + len("Host: "):host_end_index]
                    print_color(f"HTTP Host: {host}", COLOR_GREEN)

        elif packet.haslayer(scapy.UDP):
            source_port = packet[scapy.UDP].sport
            destination_port = packet[scapy.UDP].dport
            print_color(f"UDP Packet: Source Port: {source_port}, Destination Port: {destination_port}", COLOR_GREEN)
    
    print("=" * 50)



# Get available network interfaces
interfaces = get_available_interfaces()

# Display available network interfaces
display_interfaces(interfaces)

# Select interface
selected_interface = select_interface(interfaces)
print(f"Selected interface: {selected_interface}")

# Start sniffing packets on the selected interface
sniff_packets(selected_interface)
