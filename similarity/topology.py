#! /usr/bin/env python

from scapy.all import *


def find_mms_src_ip(pkt):   # find_mms_src_ip：回傳pkt中mms src ip
    return find_mms_src(pkt)


def find_mms_dst_ip(pkt):   # find_mms_dst_ip：回傳pkt中mms dst ip
    return find_mms_dst(pkt)


def find_mms_src_ip_num(pkt):   # find_mms_src_ip_num：回傳pkt中mms src ip數量
    return len(find_mms_src(pkt))


def find_mms_dst_ip_num(pkt):   # find_mms_dst_ip_num：回傳pkt中dst ip數量
    return len(find_mms_dst(pkt))


def find_mms_src(pkt):  # find_mms_src：擷取傳入pkt中mms的src
    IP.payload_guess = []

    ips = set(p[IP].src for p in pkt if IP in p)
    ip_set = set(ip for ip in ips if ip.find('192.168.2') != -1)

    return ip_set


def find_mms_dst(pkt):  # find_mms_dst：擷取傳入pkt中mms的dst
    IP.payload_guess = []

    ips = set(p[IP].dst for p in pkt if IP in p)
    ip_set = set(ip for ip in ips if ip.find('192.168.2') != -1)

    return ip_set


def find_topology(pkt):  # find_topology:傳入封包進行以上mms ip擷取並回傳

    src_ip = find_mms_src_ip(pkt)
    dst_ip = find_mms_dst_ip(pkt)
    src_ip_num = find_mms_src_ip_num(pkt)
    dst_ip_num = find_mms_dst_ip_num(pkt)
    return src_ip, dst_ip, src_ip_num, dst_ip_num


def compare_topology_similarity(pkt1, pkt2):    # compare_topology_similarity：比較兩個封包，讓主程式（similarity.py)呼叫並回傳兩個封包之相似度
    pkt1_src_ip, pkt1_dst_ip, pkt1_src_ip_num, pkt1_dst_ip_num = find_topology(pkt1)
    pkt2_src_ip, pkt2_dst_ip, pkt2_src_ip_num, pkt2_dst_ip_num = find_topology(pkt2)

    if pkt1_src_ip == pkt2_src_ip:
        src_ip = 100
    if pkt1_dst_ip == pkt2_dst_ip:
        dst_ip = 100
    if pkt1_src_ip_num == pkt2_src_ip_num:
        src_ip_num = 100
    if pkt1_dst_ip_num == pkt2_dst_ip_num:
        dst_ip_num = 100

    return src_ip, dst_ip, src_ip_num, dst_ip_num, pkt1_src_ip,  pkt1_dst_ip, pkt1_src_ip_num, pkt1_dst_ip_num, pkt2_src_ip, pkt2_dst_ip, pkt2_src_ip_num, pkt2_dst_ip_num
