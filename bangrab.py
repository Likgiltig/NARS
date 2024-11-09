import argparse
import socket
import concurrent.futures
import sys

def parse_ports(port_input):
    """
    Parse port input into a list of integers
    
    :param port_input: String of ports (e.g. '22,80' or '20-100')
    :return: List of unique ports
    """
    ports = []
    try:
        for part in port_input.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))
    except ValueError:
        print(f"Error: Invalid port specification '{port_input}'")
        sys.exit(1)

def grab_banner(target, port, timeout=2):
    """
    Attempt to grab a banner from a specific port
    
    :param target: Target IP or hostname
    :param port: Port number to scan
    :param timeout: Connection timeout
    :return: Dictionary with port information
    """
    result = {
        'port': port,
        'status': 'Closed',
        'banner': None,
        'error': None
    }
    
    try:
        # Create socket with timeout
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            
            # Attempt to connect
            connection_result = sock.connect_ex((target, port))
            
            # Check if port is open
            if connection_result == 0:
                result['status'] = 'Open'
                
                try:
                    # Try to receive banner
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # For some protocols, send a newline to trigger response
                    if not banner and port in [21, 25, 110, 143]:
                        sock.send(b'\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    result['banner'] = banner
                
                except (socket.timeout, socket.error) as e:
                    result['error'] = str(e)
    
    except Exception as e:
        result['error'] = str(e)
    
    return result

def scan_target(target, ports=None, timeout=2, max_workers=20):
    """
    Scan target for open ports and grab banners
    
    :param target: Target IP or hostname
    :param ports: List of ports to scan
    :param timeout: Connection timeout
    :param max_workers: Maximum concurrent threads
    :return: List of port scan results
    """
    # Default common ports if none provided
    default_ports = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        80,    # HTTP
        443,   # HTTPS
        3389,  # RDP
        8080   # Alternative HTTP
    ]
    
    # Use provided ports or default
    scan_ports = ports or default_ports
    
    # Scan ports concurrently
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create futures for each port
        futures = {
            executor.submit(grab_banner, target, port, timeout): port 
            for port in scan_ports
        }
        
        # Collect results
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result['status'] == 'Open':
                results.append(result)
    
    return results

def print_report(target, results):
    """
    Print a formatted report of scan results
    
    :param target: Target IP or hostname
    :param results: List of port scan results
    """
    print(f"\n--- Banner Grab Report for {target} ---")
    
    if not results:
        print("No open ports found.")
        return
    
    for port_info in results:
        print(f"\nPort {port_info['port']}:")
        print(f"  Status: {port_info['status']}")
        
        if port_info['banner']:
            print(f"  Banner: {port_info['banner']}")
        
        if port_info['error']:
            print(f"  Error: {port_info['error']}")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Banner Grabbing Tool')
    parser.add_argument('-t', '--target', 
                        required=True, 
                        help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', 
                        help='Specific ports to scan. '
                             'Example: 22,80,443 or 20-100')
    parser.add_argument('--timeout', 
                        type=float, 
                        default=2, 
                        help='Connection timeout in seconds (default: 2)')
    parser.add_argument('--max-workers', 
                        type=int, 
                        default=20, 
                        help='Maximum concurrent workers (default: 20)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Parse ports if specified
    ports = parse_ports(args.ports) if args.ports else None
    
    # Scan target and get results
    results = scan_target(
        target=args.target, 
        ports=ports, 
        timeout=args.timeout,
        max_workers=args.max_workers
    )
    
    # Print report
    print_report(args.target, results)

if __name__ == "__main__":
    main()
