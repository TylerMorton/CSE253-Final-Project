#!/bin/bash

ip link set eth0 name gateway
ip link set gateway up

ip link set eth1 name plc
ip link set plc up

ip link set eth2 name wifi
ip link set plc up