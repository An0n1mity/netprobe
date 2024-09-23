#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR

# Configure interface to send packets, update to your own interface
iface = "eth0"  # Replace with your actual network interface

# Define constant addresses for client and server
client_mac = "00:11:22:33:44:55"  # Fixed MAC for client
server_mac = "aa:bb:cc:dd:ee:ff"  # Fixed MAC for the DHCP/DNS server
dns_server_ip = "192.168.1.1"     # DNS server IP
client_ip = "192.168.1.100"       # Client IP

def generate_mac():
    """Generate a random MAC address."""
    return RandMAC()._fix()

### DHCP Functions

def send_dhcp_discover():
    """Simulate sending a DHCP Discover packet from the client."""
    mac_address = generate_mac()  # Random MAC for client

    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_address, type=0x0800) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=[mac_address], xid=RandInt(), flags=0x8000) /
        DHCP(options=[("message-type", "discover"), ("end")])
    )

    print(f"Sending DHCP Discover from MAC: {mac_address}")
    sendp(dhcp_discover, iface=iface, verbose=1)
    return mac_address

def send_dhcp_offer(client_mac, client_ip="192.168.1.100"):
    """Simulate the DHCP server sending an Offer to the client."""
    dhcp_offer = (
        Ether(dst=client_mac, src=server_mac, type=0x0800) /  # Server MAC remains constant
        IP(src="192.168.1.1", dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(chaddr=[client_mac], yiaddr=client_ip, siaddr="192.168.1.1", xid=RandInt()) /
        DHCP(options=[("message-type", "offer"), ("server_id", "192.168.1.1"), ("end")])
    )

    print(f"Sending DHCP Offer to MAC: {client_mac}, offering IP: {client_ip}")
    sendp(dhcp_offer, iface=iface, verbose=1)

def send_dhcp_request(client_mac, requested_ip="192.168.1.100"):
    """Simulate sending a DHCP Request from the client."""
    dhcp_request = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=client_mac, type=0x0800) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=[client_mac], xid=RandInt(), flags=0x8000) /
        DHCP(options=[("message-type", "request"), ("requested_addr", requested_ip), 
                      ("server_id", "192.168.1.1"), ("end")])
    )

    print(f"Sending DHCP Request from MAC: {client_mac}, requesting IP: {requested_ip}")
    sendp(dhcp_request, iface=iface, verbose=1)

def send_dhcp_ack(client_mac, client_ip="192.168.1.100"):
    """Simulate the DHCP server sending an Acknowledgment to the client."""
    dhcp_ack = (
        Ether(dst=client_mac, src=server_mac, type=0x0800) /
        IP(src="192.168.1.1", dst=client_ip) /
        UDP(sport=67, dport=68) /
        BOOTP(chaddr=[client_mac], yiaddr=client_ip, siaddr="192.168.1.1", xid=RandInt()) /
        DHCP(options=[("message-type", "ack"), ("server_id", "192.168.1.1"), ("end")])
    )

    print(f"Sending DHCP Acknowledgment to MAC: {client_mac}, confirming IP: {client_ip}")
    sendp(dhcp_ack, iface=iface, verbose=1)

### mDNS (Multicast DNS) Functions

def send_mdns_query(domain_to_query="example.com"):
    """Simulate sending an mDNS query from the client."""
    eth = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast Ethernet frame
    ip = IP(dst="224.0.0.251")            # Multicast IP for mDNS
    udp = UDP(sport=5353, dport=5353)     # mDNS uses UDP port 5353
    dns_query = DNS(rd=1, qd=DNSQR(qname=domain_to_query, qtype="A"))  # DNS query for domain

    packet = eth / ip / udp / dns_query  # Full mDNS query packet
    print(f"Sending mDNS Query for {domain_to_query}")
    sendp(packet, iface=iface, verbose=1)

def send_mdns_response(domain_to_query="example.com", response_ip="192.168.1.1"):
    """Simulate the DNS server responding to the mDNS query."""
    eth = Ether(dst=client_mac, src=server_mac)  # Unicast back to client MAC
    ip = IP(dst=client_ip, src=dns_server_ip)    # Response IPs
    udp = UDP(sport=5353, dport=5353)            # mDNS uses UDP port 5353
    dns_response = DNS(id=1, qr=1, aa=1, qd=DNSQR(qname=domain_to_query, qtype="A"),
                       an=DNSRR(rrname=domain_to_query, rdata=response_ip))  # DNS answer

    packet = eth / ip / udp / dns_response  # Full DNS response packet
    print(f"Sending mDNS Response: {domain_to_query} is at {response_ip}")
    sendp(packet, iface=iface, verbose=1)

def send_arp_request(target_ip="192.168.1.1"):
    """Simulate sending an ARP Request from the client."""
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=target_ip)
    print(f"Sending ARP Request: Who has {target_ip}?")
    sendp(arp_request, iface=iface, verbose=1)

def send_arp_reply(client_mac, target_ip="192.168.1.1"):
    """Simulate the server responding to the ARP Request."""
    arp_reply = Ether(dst=client_mac, src=server_mac) / ARP(op="is-at", psrc=target_ip, hwdst=client_mac)
    print(f"Sending ARP Reply: {target_ip} is at {server_mac}")
    sendp(arp_reply, iface=iface, verbose=1)


def send_pcap_file(pcap_file):
    """Send a PCAP file using Scapy."""
    packets = rdpcap(pcap_file)  # Read packets from PCAP file
    sendp(packets, iface=iface, verbose=1)  # Send packets

### Main Sequence

if __name__ == "__main__":
    # Simulate DHCP transaction
    #client_mac = send_dhcp_discover()  # Client sends DHCP Discover
    #send_dhcp_request(client_mac)      # Client sends DHCP Request

    send_pcap_file("pcaps/DHCP/DHCP.pcap")  # Send a PCAP file with DHCP transaction
    send_pcap_file("pcaps/ARP/arp.pcap")  # Send a PCAP file with DHCP transaction


