import binascii
import json
import re

from scapy.all import *

from myParser import Parser as myParser


def Read_and_Parse_Encapsulation(pkt):
    all_packet_data = []
    content = binascii.hexlify(bytes(pkt)).decode()
    # print(content)
    find_cotp = re.search('0300....02f080', content)  # search COTP
    if (find_cotp == None):
        return all_packet_data
    cotp_index = find_cotp.span()
    content = content[cotp_index[0]:]

    start_index = 0
    tkpt_length = int(content[start_index+4:start_index+8], 16)*2
    tpkt_payload = content[start_index:start_index+tkpt_length]

    TPKT = [tpkt_payload[:2], tpkt_payload[2:4], tpkt_payload[4:8]]
    all_packet_data.append({'TPKT': TPKT})
    # print("TKPT", TPKT)
    COTP = [tpkt_payload[8:10], tpkt_payload[10:12], tpkt_payload[12:14]]
    all_packet_data.append({'COTP': COTP})
    # print("COTP", COTP)
    ISO8327A = [tpkt_payload[14:16], tpkt_payload[16:18]]
    all_packet_data.append({'ISO8327A': ISO8327A})
    # print("ISO8327A", ISO8327A)
    ISO8327B = [tpkt_payload[18:20], tpkt_payload[20:22]]
    all_packet_data.append({'ISO8327B': ISO8327B})
    # print("ISO8327B", ISO8327B)

    # print("ISO8823 begin with 61", tpkt_payload[22:24])

    # print("ISO8823 payload", tpkt_payload[24:])

    rest, ISO8823 = myParser(tpkt_payload[22:], "ISO8823")
    all_packet_data.append(ISO8823[0])

    rest, MMS = myParser(rest, "MMS")
    all_packet_data.append(MMS[0])
    return all_packet_data

    print(json.dumps(all_packet_data, indent=2))

all_packets = sniff(offline='situation1_morning_again.pcap',
                    filter='tcp and dst host not 192.168.2.11 and dst host not 192.168.2.12 and src host not 192.168.2.11 and src host not 192.168.2.12')

pkt = rdpcap('mms_cap1.pcapng')
# print("1.", pkt[0])
content = binascii.hexlify(bytes(pkt[0])).decode()
# print("2.", content)
for index, i in enumerate(all_packets):
    # print("index", index)
    output = Read_and_Parse_Encapsulation(i)
    # print(output)
    if (len(output) != 0):
        with open('output_Data/packet_{0}.json'.format(str(index)), "w") as file:
            print('output_Data/packet_{0}.json'.format(str(index)))
            json.dump(output, file, indent=2)


# a = Ether()/IP(dst='192.168.2.13')/TCP()/"test scapy by python"
# sendp(a)
# a = IP(dst='192.168.2.13')/TCP()/"test scapy by python"
# all_packets[0].show()
# sendp(pkt[0])
# for i in pkt:
#     sendp(i)
# send(pkt[1])
# print(a)
# sniff(iface="en0", filter='tcp and dst host 192.168.2.13 and src host 192.168.2.202', prn=lambda x: x.show())
# all_packets = sniff(offline = 'abb es_open ds_open cb_open2close_pcap.pcap', filter='dst host 192.168.2.13', prn=lambda x: x.summary() ) # 效率好
# print(all_packets)
