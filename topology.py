"""
# pkt = sniff(filter= "tcp" and " host 192.168.2.12") 先不解決libpcap的問題
print(pkt)   # output: <test.pcap: TCP:2 UDP:0 ICMP:0 Other:0>
print(pkt.show())  # 概述 0000 Ether / IP / TCP 192.168.2.202:50091 > 192.168.2.12:iso_tsap PA / Raw0001 Ether / IP / TCP 192.168.2.202:50091 > 192.168.2.12:iso_tsap PA / Raw
print("\npkt[1].show()")  # 詳細內容且已經分類好
print(len(pkt[0]))  # output:175

"""

import binascii

#! /usr/bin/env python
from scapy.all import *


def find_mms(pkt):
    a = 0
    b = 0
    record_mms = []
    for n in range(0, len(pkt)):
        content = binascii.hexlify(bytes(pkt[n])).decode()
        if content.find('0300') != -1 and content.find('02f080') != -1:
            record_mms.append(a)
            set
            a = a+1
            b = b+1
        else:
            a = a+1
    print(b)
    return record_mms, b


def find_mms_ip_num(pkt):
    print(len(find_mms_dst_ip(pkt)))


def find_mms_dst_ip(pkt):
    IP.payload_guess = []

    ips = set(p[IP].dst for p in pkt if IP in p)
    print("find_mms_dst_ip")
    ip_set = set(ip for ip in ips if ip.find('192.168.2') != -1)

    return ip_set


def find_mms_src_ip(pkt):
    IP.payload_guess = []

    ips = set(p[IP].src for p in pkt if IP in p)
    print("find_mms_src_ip")
    for ip in ips:
        if (ip.find('192.168.2') != -1):
            print(ip)


def find_protocol(pkt):  # 查看有哪些protocol
    pkt = sniff(offline=pkt)
    # pkt.nsummary()
    # print(pkt)


def topology(filename):

    pkt = rdpcap(filename)

    find_mms_ip_num(pkt)
    find_mms_src_ip(pkt)
    find_mms_dst_ip(pkt)
    find_protocol(pkt)


# topology("real1.pcap")
topology("digital-twins-afternoon.pcap")
# topology("real-afternoon.pcap")

'''
    pkt = rdpcap("test.pcapng")  
    pkt1 = rdpcap("test1.pcapng")  
'''
