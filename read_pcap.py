from binascii import hexlify
from scapy.all import *
import binascii
import re



# print( a )
# print( len(a[0][1]))
pkt = rdpcap('mms_cap1.pcapng')
print( "1.", bytes(pkt[0]))
print("2.", binascii.hexlify(bytes(pkt[0])).decode())



def Read( pkt ) :

    content = binascii.hexlify(bytes(pkt[0])).decode()

    cotp_index = re.search('0300....02f080', content).span() # search COTP

    print(cotp_index)
    print(len(content))
    content = content[108:]
    print( 'test1', content )

    end = False
    list_temp = []
    start_index = 0
    while ( start_index != len(content) ) :
        print(start_index)
        tkpt_length = int(content[start_index+4:start_index+8], 16)*2
        tpkt_payload = content[start_index:start_index+tkpt_length]
        list_temp.append(tpkt_payload)
        start_index += tkpt_length
        
        
def ParseEncapsulate( content ):

    
    TPKT = [content[:2], content[2:4], content[4:8]]
    print("TKPT", TPKT)
    COTP = [content[8:10], content[10:12], content[12:14]]
    print("COTP", COTP)
    ISO8327A = [content[14:16], content[16:18]]
    print("ISO8327A",ISO8327A)
    ISO8327B = [content[18:20], content[20:22]]
    print("ISO8327B",ISO8327B)
    print("is 61", content[22:24])
    ISO8823 = []
        
# Read(pkt)

# print(scapy_cap.summary())
# print(scapy_cap.hexraw())
# a = hexdump(scapy_cap[0])
# , filter='dst host 192.168.2.13'

# all_packets = sniff(offline = 'abb es_open ds_open cb_open2close_pcap.pcap', filter='dst host 192.168.2.13', prn=lambda x: x.summary() ) # 效率好
# print(all_packets)
# for per_packet in all_packets :
    
#     pass


    
    

# import argparse
# import os

# os.argv[0]