#!/bin/python3

from scapy.all import *


ip_option = IPOption(b'\x03\x00\x01')

ip_packet = IP(dst="127.0.0.1", options=[ip_option])

send(ip_packet)
