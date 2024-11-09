from scapy.all import *

# Passive host scanner
def packet_handler(pkt):
    if pkt.haslayer(IP):
        if target in str({pkt[IP].src}):
            if str({pkt[IP].src}) not in local_addresses:   
                local_addresses.append(str({pkt[IP].src}))
                print(f"Source IP: {pkt[IP].src}")
                print(f"Destination IP: {pkt[IP].dst}")
                print(f"Protocol: {pkt[IP].proto}")

local_addresses = []
target = '192.168.1.'

sniff(prn=packet_handler, count=1000)
print('\nFound',str(len(local_addresses)),'in search:')
for n in local_addresses:
    print('\t',n)
