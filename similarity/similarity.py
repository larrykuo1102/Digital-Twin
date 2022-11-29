
from Compare import compare_MMS_Context, compare_confirmed_count, compare_request_count, compare_response_count, compare_unconfirmed_count, get_read_elapsed, get_response_count, get_response_elapsed
from read_pcap import Parse_PCAP
from scapy.all import *


def Output_Compare_MMS_Context(result):
    print("summary :", result['summary'])
    print("itemID_and_domainID_count", result['itemID_and_domainID_count'])


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

    print(compare_response_count(realSystem_list, DigitalTwins_list))
    print(compare_request_count(realSystem_list, DigitalTwins_list))
    print(compare_confirmed_count(realSystem_list, DigitalTwins_list))
    print(compare_unconfirmed_count(realSystem_list, DigitalTwins_list))

    compare_MMS_context_result = compare_MMS_Context(realSystem_list, DigitalTwins_list)

    Output_Compare_MMS_Context(compare_MMS_context_result)
    # similarity report
    print('similarity report')
