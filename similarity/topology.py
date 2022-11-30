#! /usr/bin/env python

from scapy.all import *

# from time_lu import find_accuray_mms


def find_mms_src_ip(pkt):
    path = 'topology_output.txt'
    with open(path, 'w') as f:
        print("find_mms_src", find_mms_src(pkt), file=f)

    return find_mms_src(pkt)


def find_mms_dst_ip(pkt):
    path = 'topology_output.txt'
    with open(path, 'a') as f:
        print("find_mms_dst", find_mms_dst(pkt), file=f)

    return find_mms_dst(pkt)


def find_mms_src_ip_num(pkt):
    path = 'topology_output.txt'
    with open(path, 'a') as f:
        print("find_mms_src_num", find_mms_src(pkt), file=f)

    return len(find_mms_src(pkt))


def find_mms_dst_ip_num(pkt):
    path = 'topology_output.txt'
    with open(path, 'a') as f:
        print("find_mms_dst_num", find_mms_dst(pkt), file=f)

    return len(find_mms_dst(pkt))


def find_mms_src(pkt):
    IP.payload_guess = []

    ips = set(p[IP].src for p in pkt if IP in p)
    ip_set = set(ip for ip in ips if ip.find('192.168.2') != -1)

    return ip_set


def find_mms_dst(pkt):
    IP.payload_guess = []

    ips = set(p[IP].dst for p in pkt if IP in p)
    ip_set = set(ip for ip in ips if ip.find('192.168.2') != -1)

    return ip_set


def find_topology(pkt):

    src_ip = find_mms_src_ip(pkt)
    dst_ip = find_mms_dst_ip(pkt)
    src_ip_num = find_mms_src_ip_num(pkt)
    dst_ip_num = find_mms_dst_ip_num(pkt)
    return src_ip, dst_ip, src_ip_num, dst_ip_num


def compare_topology_similarity(pkt1, pkt2):
    pkt1_src_ip, pkt1_dst_ip, pkt1_src_ip_num, pkt1_dst_ip_num = find_topology(pkt1)
    pkt2_src_ip, pkt2_dst_ip, pkt2_src_ip_num, pkt2_dst_ip_num = find_topology(pkt2)

    if pkt1_src_ip == pkt2_src_ip:
        print("mms_src_ip similarity:100%")
    if pkt1_dst_ip == pkt2_dst_ip:
        print("mms_dst_ip similarity:100%")
    if pkt1_src_ip_num == pkt2_src_ip_num:
        print("mms_src_ip_num similarity:100%")
    if pkt1_dst_ip_num == pkt2_dst_ip_num:
        print("mms_dst_ip_num similarity:100%")
