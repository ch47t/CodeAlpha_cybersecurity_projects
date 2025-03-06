import argparse
from scapy.all import sniff, IP, TCP, UDP

###################################################### Args ##############################################
parser = argparse.ArgumentParser(description='Basic Network Sniffer')
parser.add_argument('-n', '--count', type=int, default=10, help='Specify the number of packets to capture (default: 10)')
parser.add_argument('-i', '--interface', type=str, default=None, help='Specify the network interface (e.g., "eth0", "wlan0") or leave as None for default')
parser.add_argument('-f', '--filter', type=str, default='', 
                    help='''Specify a BPF filter. Examples:
                    - "tcp": Capture only TCP traffic.
                    - "udp": Capture only UDP traffic.
                    - "icmp": Capture only ICMP traffic.
                    - "host 192.168.1.1": Capture traffic to or from the IP 192.168.1.1.
                    - "src 192.168.1.100": Capture traffic from the source IP 192.168.1.100.
                    - "dst 192.168.1.1": Capture traffic to the destination IP 192.168.1.1.
                    ''')
args = parser.parse_args()

################################################  COLORS  #############################################################
# Text colors
def print_red(string):
    print("\033[91m" + string + "\033[0m")
def print_green(string):
    print("\033[92m" + string + "\033[0m")
def print_yellow(string):
    print("\033[93m" + string + "\033[0m")
def print_blue(string):
    print("\033[94m" + string + "\033[0m")

################################################  PACKET CALLBACK  ####################################################
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print_blue(f"Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")

        # Check for TCP
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print_green(f"TCP: {src_port} -> {dst_port}")

            # Identify common TCP protocols
            if dst_port == 80:
                print_yellow("Protocol: HTTP")
            elif dst_port == 443:
                print_yellow("Protocol: HTTPS")
            elif dst_port == 22:
                print_yellow("Protocol: SSH")
            elif dst_port == 21:
                print_yellow("Protocol: FTP")
            elif dst_port == 25:
                print_yellow("Protocol: SMTP")

        # Check for UDP
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print_yellow(f"UDP: {src_port} -> {dst_port}")

            # Identify common UDP protocols
            if dst_port == 53:
                print_yellow("Protocol: DNS")

        # Check for ICMP
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print_red(f"ICMP: Type={icmp_type}, Code={icmp_code}")

        print_red("-" * 50)

################################################  START SNIFFER  #####################################################
def start_sniffer(interface=None, count=10, filter=""):
    print_green(f"Starting network sniffer on interface: {interface or 'default'}")
    print_green(f"Filter: {filter or 'None'}")
    sniff(iface=interface, prn=packet_callback, count=count, filter=filter)

################################################  MAIN  ##############################################################
if __name__ == "__main__":
    start_sniffer(interface=args.interface, count=args.count, filter=args.filter)