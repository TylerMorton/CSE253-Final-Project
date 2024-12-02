#!/bin/python3

from scapy.all import ARP, Ether, sendp
import sys

print(sys.argv)

if len(sys.argv) != 3:
    print("Incorrect, include dst ip and iface")
    exit()

broadcast = "ff:ff:ff:ff:ff:ff"

arp = ARP(pdst=f"{sys.argv[1]}", hwdst=broadcast)
arp.htype = 1
ether = Ether(dst=broadcast)
pkt = ether / arp

result = sendp(pkt, iface=f"{sys.argv[2]}")
