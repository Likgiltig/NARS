

### **Network Analysis and Reconnaissance Suite (NARS)**

**This is a small suite of network analysis tools designed for security assessment and network reconnaissance. The suite combines passive and active scanning techniques with detailed host analysis capabilities.**

 - **pscan.py - Portscanner:** This is a multi-threaded port scanner using Scapy. It uses TCP SYN scanning (half-open scanning). It comes with a default list of common ports.
  	 - `python pscan.py -t 192.168.1.1 -p 80,443,8080`
  	 - `python pscan.py -t 192.168.1.1 -p 20-100`
 - **hat.py - Host Analysis Tool:** This is a host analysis tool that collects various types of network and location information about a target IP address or domain. It perform DNS, WHOIS, Geolocation and Trace Route.
 	 - `python hat.py google.com`
 - **hostscan.py - Passive Host Scanner:** This is a simple passive network scanner that monitors network traffic to detect hosts on a specific subnet, it captures 1000 packets and prints out the findings.
	 - `python hostscan.py`
  - **bangrab.py - Banner Grabbing Tool:** This is a banner grabbing tool - a network security tool that scans ports on a target system and attempts to retrieve service banners.
	  - `python bangrab.py -t 192.168.1.1 -p 80,443,8080 --timeout 1`

 
**Works on both Windows and Linux.**



**Installation:**

 - **Windows:** 
 Npcap (https://npcap.com/) needs to be installed for Scapy to work

   ```bash
   pip install scapy python-whois
   ```

 - **Debian:**

   ```bash
    sudo apt install python3-scapy libpcap-dev whois tcpdump
    pip install scapy python-whois
   ```


 **Additional requirements:**
   - Root/Administrator privileges may be required for Host Analysis Tool (hat.py)

