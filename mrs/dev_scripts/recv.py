from scapy.all import sniff

packet = sniff(iface="lo", filter="arp", count = 1)[0]
packet.show()
