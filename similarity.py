import json

from scapy.all import *

from Compare import compare_MMS_Context
from read_pcap import Parse_PCAP

if __name__ == '__main__':

    # read two pcap(must be pcap not pcapng)
    realSystem = sniff(offline='./pcap_file/s1-morning.pcap',
                       filter='tcp')

    DigitalTwins = sniff(offline='./pcap_file/situation1_morning_again.pcap',
                         filter='tcp')
    # make two files parser
    realSystem_list = Parse_PCAP(realSystem)
    DigitalTwins_list = Parse_PCAP(DigitalTwins)
    # similarity
    print('begin similarity')
    compare_MMS_context_result = compare_MMS_Context(realSystem_list, DigitalTwins_list)
    print(json.dumps(compare_MMS_context_result, indent=2))
    # similarity report
    print('similarity report')
