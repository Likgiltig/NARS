"""
Threaded Port Scan
    
Required library:
    pip install scapy

Examples:
    # Scan a specific target
        python pscan.py -t 192.168.1.100

    # Scan specific ports
        python pscan.py -p 22,80,443

    # Scan a range of ports
        python pscan.py -p 20-100
"""
import threading, argparse
from scapy.all import *

def scan_port(host, port):
    resp = sr1(IP(dst=host)/TCP(sport=RandShort(), dport=port, flags="S"), timeout=1, verbose=0)
    if resp:
        if resp.haslayer(TCP):
            if resp[TCP].flags == "SA":
                print(f"Port {port} on {host} is open")
                open_ports.append(port)

def main_scan(target, specific_ports=None):
    print("Portscan started.")
    
    # Common ports list
    common_ports = [21, 22, 23, 25, 53, 80, 443, 110, 143, 139, 445, 3389, 135, 137, 138, 
                    144, 444, 546, 547, 587, 631, 993, 995, 1025, 1080, 1723, 3306, 
                    3389, 5900, 8080, 8443]
    
    global open_ports
    open_ports = []
    threads = []

    # Determine which ports to scan
    ports_to_scan = specific_ports or common_ports

    for port in ports_to_scan:
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    # Print results
    if len(open_ports) > 0:
        print(f"Open ports on {target} are {sorted(open_ports)}")
    else:
        print(f"No open ports found on {target}")
    
    print("Portscan completed.")

def parse_port_list(port_string):
    """
    Parse a comma-separated list of ports or port ranges.
    Supports individual ports and ranges like 20-25.
    """
    ports = []
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Simple Port Scanner')
    parser.add_argument('-t', '--target', 
                        default='192.168.1.1', 
                        help='Target host IP address (default: 192.168.1.1)')
    parser.add_argument('-p', '--ports', 
                        help='Specific ports to scan. Can be single ports or ranges. '
                             'Example: 22,80,443 or 20-100')
    args = parser.parse_args()

    main_scan(
        target=args.target, 
        specific_ports=parse_port_list(args.ports) if args.ports else None
    )

if __name__ == "__main__":
    main()
