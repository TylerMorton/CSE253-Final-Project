from scapy.all import *

# creating a random optional flag
# Create an IPv4 packet with a custom header and send it over the loopback interface
ip_packet = IP(dst="127.0.0.1", options=[IPOption(b'\x83\x03\x10'), IPOption(b'\x83\x03\x10')])

# Display the packet structure
#ip_packet.show2()

# Send the packet via loopback
send(ip_packet)

