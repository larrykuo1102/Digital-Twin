import binascii
import re

from scapy.all import *

# from myParser import Parser as myParser

pkt = rdpcap('mms_cap1.pcapng')
print("1.", pkt[0])
content = binascii.hexlify(bytes(pkt[0])).decode()
print("2.", content)


def Read_and_Parse_Encapsulation(pkt):
    print("1.", pkt[0])
    content = binascii.hexlify(bytes(pkt[0])).decode()
    print("2.", content)

    cotp_index = re.search('0300....02f080', content).span()  # search COTP
    content = content[cotp_index[0]:]

    start_index = 0
    tkpt_length = int(content[start_index+4:start_index+8], 16)*2
    tpkt_payload = content[start_index:start_index+tkpt_length]

    TPKT = [tpkt_payload[:2], tpkt_payload[2:4], tpkt_payload[4:8]]
    print("TKPT", TPKT)
    COTP = [tpkt_payload[8:10], tpkt_payload[10:12], tpkt_payload[12:14]]
    print("COTP", COTP)
    ISO8327A = [tpkt_payload[14:16], tpkt_payload[16:18]]
    print("ISO8327A", ISO8327A)
    ISO8327B = [tpkt_payload[18:20], tpkt_payload[20:22]]
    print("ISO8327B", ISO8327B)

    print("ISO8823 begin with 61", tpkt_payload[22:24])

    print("ISO8823 payload", tpkt_payload[24:])

    # ISO8823, rest = Parser( tpkt_payload[22:], "ISO8823" )
    # MMS, rest = Parser( rest, "MMS" )


Read_and_Parse_Encapsulation(pkt)

# all_packets = sniff(offline = 'abb es_open ds_open cb_open2close_pcap.pcap', filter='dst host 192.168.2.13', prn=lambda x: x.summary() ) # 效率好
# print(all_packets)
# for per_packet in all_packets :
