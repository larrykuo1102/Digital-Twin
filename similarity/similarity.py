
from Compare import (compare_confirmed_count, compare_MMS_Context,
                     compare_request_count, compare_response_count,
                     compare_unconfirmed_count)
from read_pcap import Parse_PCAP
from scapy.all import *
from time_similarity import find_accuray_mms
from topology import compare_topology_similarity


def Output_frequecy_and_time_gap(result):
    print("total")
    print("real total:", result['total'][0])
    print("digital total:",  result['total'][1])
    print("real_mms total:",  result['total'][2])
    print("digital_mms total:",  result['total'][3])
    print("real_mms_SEL to HMI total:",  result['total'][4])
    print("digital_mms_SEL to HMI total:",  result['total'][5])
    print("real_mms_AQF to HMI total:",  result['total'][6])
    print("digital_mms_AQF to HMI total:",  result['total'][7])
    print("real_mms_REF to HMI total:",  result['total'][8])
    print("digital_mms_REF to HMI total:",  result['total'][9])
    print("real_mms_HMI total:",  result['total'][10])
    print("digital_mms_HMI total:",  result['total'][11])
    print("real_mms_HMI to SEL total:",  result['total'][12])
    print("digital_mms_HMI to ES.E total:", result['total'][13])
    print("real_mms_HMI to AQF total:", result['total'][14])
    print("digital_mms_HMI to AQF total:",  result['total'][15])
    print("real_mms_HMI to REF total:",  result['total'][16])
    print("digital_mms_HMI to REF total:",  result['total'][17])
    print()
    print("mms SEL to HMI total accuracy:", result['total_accuracy'][0], "%")
    print("mms AQF to HMI total accuracy:", result['total_accuracy'][1], "%")
    print("mms REF to HMI total accuracy:", result['total_accuracy'][2], "%")
    print("mms HMI total accuracy:", result['total_accuracy'][3], "%")
    print("mms HMI to SEL total accuracy:", result['total_accuracy'][4], "%")
    print("mms HMI to AQF total accuracy:", result['total_accuracy'][5], "%")
    print("mms HMI to REF total accuracy:", result['total_accuracy'][6], "%")
    print()
    print("time")
    #print("time gap: accuray", result['time'][0], "%")
    print("mms time gap: accuray", result['time'][1], "%")
    print("mms_SEL to HMI time gap: accuracy", result['time'][2], "%")
    print("mms_AQF to HMI time gap: accuracy", result['time'][3], "%")
    print("mms_REF to HMI time gap: accuracy", result['time'][4], "%")
    print("mms_HMI time gap: accuracy", result['time'][5], "%")
    print("mms_HMI to SEL time gap: accuracy", result['time'][6], "%")
    print("mms_HMI to AQF time gap: accuracy", result['time'][7], "%")
    print("mms_HMI to REF time gap: accuracy", result['time'][8], "%")
    print()
    print("frequency")
    print("mms frequency: accuracy", result['frequency'][0], "%")
    print("mms_SEL to HMI frequency: accuracy", result['frequency'][1], "%")
    print("mms_AQF to HMI frequency: accuracy", result['frequency'][2], "%")
    print("mms_REF to HMI frequency: accuracy", result['frequency'][3], "%")
    print("mms_HMI frequency: accuracy", result['frequency'][4], "%")
    print("mms_HMI to SEL frequency: accuracy", result['frequency'][5], "%")
    print("mms_HMI to AQF frequency: accuracy", result['frequency'][6], "%")
    print("mms_HMI to REF frequency: accuracy", result['frequency'][7], "%\n")


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

    compare_topology_similarity(realSystem, DigitalTwins)

    time_accuray_and_relation = find_accuray_mms(realSystem, DigitalTwins)
    Output_frequecy_and_time_gap(time_accuray_and_relation)

    print("compare_response_count:", compare_response_count(realSystem_list, DigitalTwins_list))
    print("compare_request_count:", compare_request_count(realSystem_list, DigitalTwins_list))
    print("compare_confirmed_count:", compare_confirmed_count(realSystem_list, DigitalTwins_list))
    print("compare_unconfirmed_count:", compare_unconfirmed_count(realSystem_list, DigitalTwins_list))

    compare_MMS_context_result = compare_MMS_Context(realSystem_list, DigitalTwins_list, 3)
    Output_Compare_MMS_Context(compare_MMS_context_result)
    # similarity report
    print('\nsimilarity report')
