#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys


def spoof():
    packet = scapy.ARP(op=2, pdst='172.17.0.3', hwdst='02:42:ac:11:00:03', psrc='172.17.0.1')
    print(packet.show())
    print(packet.summary())

spoof()