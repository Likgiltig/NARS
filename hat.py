import sys, argparse
import whois, socket, json
import subprocess, platform
from urllib.request import urlopen
from urllib.parse import urlparse

def resolve_host(host):
    """Resolve hostname/URL to IP address"""
    try:
        # Remove any protocol and path from URL
        parsed = urlparse(host)
        if parsed.netloc:
            host = parsed.netloc
        elif parsed.path:
            host = parsed.path
            
        # Remove port if present
        if ':' in host:
            host = host.split(':')[0]
            
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None
    except Exception as e:
        print(f"Error resolving host: {str(e)}")
        return None

def get_dns_info(ip):
    try:
        return socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror):
        return None, None, None
    except Exception as e:
        print(f"DNS lookup error: {str(e)}")
        return None, None, None

def get_whois_info(ip):
    try:
        return whois.whois(ip)
    except Exception:
        return None

def get_geolocation(ip):
    try:
        response = urlopen(f"http://ip-api.com/json/{ip}")
        data = json.loads(response.read().decode())
        return data
    except Exception as e:
        print(f"Error fetching geolocation data: {str(e)}")
        return None

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def perform_traceroute(target):
    print("\n[+] Performing Traceroute:")
    try:
        # Determine the operating system and set appropriate command
        if platform.system().lower() == "windows":
            cmd = ["tracert", target]  # -d prevents DNS resolution, making it faster
        else:
            cmd = ["traceroute", target]  # -n prevents DNS resolution
        
        # Run the traceroute command
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Process and print output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                # Clean up the output
                line = output.strip()
                if line and not line.startswith('Tracing') and not line.startswith('Trace') and not line.startswith('over'):
                    print(line)

        # Get any errors
        errors = process.stderr.read()
        if errors:
            print(f"Errors during traceroute: {errors}")
    except Exception as e:
        print(f"Error performing traceroute: {str(e)}")
        return None

def analyze_target(target):
    print(f"\nResolving target: {target}")
    
    # If input is not an IP, try to resolve it
    if not is_valid_ip(target):
        ip = resolve_host(target)
        if not ip:
            print(f"Error: Could not resolve '{target}' to an IP address")
            sys.exit(1)
        print(f"Resolved to IP: {ip}")
    else:
        ip = target
    
    # Print Report
    print("\n=== IP Analysis Report ===")
    print(f"\nTarget: {target}")
    print(f"IP Address: {ip}")
    
    # DNS Section
    print("\n[+] DNS Information:")
    hostname, aliases, addresses = get_dns_info(ip)
    if hostname:
        print(f"Hostname: {hostname}")
        if aliases:
            print("Aliases:", ", ".join(aliases))
    else:
        print("No DNS records found")
    
    # WHOIS Section
    print("\n[+] WHOIS Information:")
    whois_data = get_whois_info(ip)
    if whois_data:
        if hasattr(whois_data, 'org'):
            print(f"Organization: {whois_data.org}")
        if hasattr(whois_data, 'country'):
            print(f"Country: {whois_data.country}")
        if hasattr(whois_data, 'emails'):
            print(f"Contact: {whois_data.emails[0] if isinstance(whois_data.emails, list) else whois_data.emails}")
    else:
        print("No WHOIS data found")
    
    # Geolocation Section
    print("\n[+] Geolocation Information:")
    geo_data = get_geolocation(ip)
    if geo_data and geo_data.get('status') != 'fail':
        cords = [geo_data.get('lat', 'N/A'), geo_data.get('lon', 'N/A')]
        url = f"https://www.google.com/maps/place/{cords[0]},{cords[1]}"
        print(f"Country: {geo_data.get('country', 'N/A')}")
        print(f"City: {geo_data.get('city', 'N/A')}")
        print(f"Region: {geo_data.get('regionName', 'N/A')}")
        print(f"ISP: {geo_data.get('isp', 'N/A')}")
        print(f"Coordinates: {cords[0]}, {cords[1]}")
        print("Link:", url)
    else:
        print("No geolocation data found")

    # Perform Traceroute
    perform_traceroute(target)

def main():
    parser = argparse.ArgumentParser(
        description='Host Analysis Tool - Performs DNS, WHOIS, Geolocation and Trace Route on IP/URL',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='IP address or URL to analyze'
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 1.2'
    )

    args = parser.parse_args()
    
    # Show help if no target provided
    if not args.target:
        parser.print_help()
        sys.exit(1)
        
    analyze_target(args.target)

if __name__ == "__main__":
    main()
