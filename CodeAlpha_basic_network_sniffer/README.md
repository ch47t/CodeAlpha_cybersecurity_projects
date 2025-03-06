# Basic Network Sniffer

A simple Python-based network sniffer that captures and analyzes network traffic. This tool helps you understand how data flows on a network and how network packets are structured.

## Features
- Capture and analyze network packets.
- Filter packets by protocol (e.g., TCP, UDP, ICMP).
- Filter packets by IP address (source or destination).
- Identify common protocols like HTTP, HTTPS, SSH, DNS, etc.

## Requirements
- Python 3.x
- Scapy library

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-sniffer.git
   cd network-sniffer
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
## Usage
Run the network sniffer with the following command:
   ```bash
   python network_sniffer.py [-h] [-n COUNT] [-i INTERFACE] [-f FILTER]
   Arguments
   -n, --count: Number of packets to capture (default: 10).

   -i, --interface: Network interface to sniff on (e.g., eth0, wlan0). If not specified, the default interface is used.

   -f, --filter: BPF filter to apply. Examples:

      tcp: Capture only TCP traffic.
      udp: Capture only UDP traffic.
      icmp: Capture only ICMP traffic.
      host 192.168.1.1: Capture traffic to or from the IP 192.168.1.1.
      src 192.168.1.100: Capture traffic from the source IP 192.168.1.100.
      dst 192.168.1.1: Capture traffic to the destination IP 192.168.1.1.

   Examples:
      python network_sniffer.py -i wlan0 -n 20
      python network_sniffer.py -f "tcp"
      python network_sniffer.py -f "host 192.168.1.1"
      python network_sniffer.py -f "udp port 53"
   ```
---

### How to Use
1. Save the `requirements.txt` and `README.md` files in your project directory.
2. Run `pip install -r requirements.txt` to install the dependencies.
3. Use the `README.md` as a guide for running and understanding the project.

---

