
from Compare import (compare_confirmed_count, compare_MMS_Context,
                     compare_request_count, compare_response_count,
                     compare_unconfirmed_count)
from read_pcap import Parse_PCAP
from scapy.all import *


def Output_Compare_MMS_Context(result):
    '''
    result = {
        'itemID': [],
        'domainID': [],
        'module': [],
        'itemID_and_domainID_count': [],
        'summary': [],
        'result': {
            'summary': temp_summary/num,
            'count_digital': temp_count_digital/num,
            'count_real': temp_count_real/num,
            'count_similarity': 1 - (abs(temp_count_digital/num - temp_count_real/num) / (temp_count_real/num))
        }
    }
    '''
    print("MMS_Context_Similarity:", result['result']['summary'])
    print("ItemID_and_DomainID_count_Similarity:", result['result']['count_similarity'])


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
    print('begin similarity\n')

    print("compare_response_count:", compare_response_count(realSystem_list, DigitalTwins_list))
    print("compare_request_count:", compare_request_count(realSystem_list, DigitalTwins_list))
    print("compare_confirmed_count:", compare_confirmed_count(realSystem_list, DigitalTwins_list))
    print("compare_unconfirmed_count:", compare_unconfirmed_count(realSystem_list, DigitalTwins_list))

    compare_MMS_context_result = compare_MMS_Context(realSystem_list, DigitalTwins_list, 3)
    Output_Compare_MMS_Context(compare_MMS_context_result)
    # similarity report
    print('\nsimilarity report')
