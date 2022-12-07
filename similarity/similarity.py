
import os

from Compare import (compare_confirmed_count, compare_MMS_Context,
                     compare_request_count, compare_response_count,
                     compare_unconfirmed_count)
from read_pcap import Parse_PCAP
from scapy.all import *
from time_similarity import find_accuray_mms
from topology import compare_topology_similarity


def Output_frequecy_and_time_gap(result):
    # print("Each ip relation packets sum")
    # print("real total:", result['total'][0])
    # print("digital total:",  result['total'][1])
    # print("real_mms total:",  result['total'][2])
    # print("digital_mms total:",  result['total'][3])
    # print("real_mms_SEL to HMI total:",  result['total'][4])
    # print("digital_mms_SEL to HMI total:",  result['total'][5])
    # print("real_mms_AQF to HMI total:",  result['total'][6])
    # print("digital_mms_AQF to HMI total:",  result['total'][7])
    # print("real_mms_REF to HMI total:",  result['total'][8])
    # print("digital_mms_REF to HMI total:",  result['total'][9])
    # print("real_mms_HMI total:",  result['total'][10])
    # print("digital_mms_HMI total:",  result['total'][11])
    # print("real_mms_HMI to SEL total:",  result['total'][12])
    # print("digital_mms_HMI to ES.E total:", result['total'][13])
    # print("real_mms_HMI to AQF total:", result['total'][14])
    # print("digital_mms_HMI to AQF total:",  result['total'][15])
    # print("real_mms_HMI to REF total:",  result['total'][16])
    # print("digital_mms_HMI to REF total:",  result['total'][17])
    # print("Each ip relation packets sum")
    # print("mms SEL to HMI sum accuracy:", result['total_accuracy'][0], "%")
    # print("mms AQF to HMI sum accuracy:", result['total_accuracy'][1], "%")
    # print("mms REF to HMI sum accuracy:", result['total_accuracy'][2], "%")
    # print("mms HMI sum accuracy:", result['total_accuracy'][3], "%")
    # print("mms HMI to SEL sum accuracy:", result['total_accuracy'][4], "%")
    # print("mms HMI to AQF sum accuracy:", result['total_accuracy'][5], "%")
    # print("mms HMI to REF sum accuracy:", result['total_accuracy'][6], "%")
    # print()
    # print("Time Gap Accuracy")
    #print("time gap: accuray", result['time'][0], "%")
    # print("mms time gap: accuray", result['time'][1], "%")
    # print("mms_SEL to HMI time gap: accuracy", result['time'][2], "%")
    # print("mms_AQF to HMI time gap: accuracy", result['time'][3], "%")
    # print("mms_REF to HMI time gap: accuracy", result['time'][4], "%")
    # print("mms_HMI time gap: accuracy", result['time'][5], "%")
    # print("mms_HMI to SEL time gap: accuracy", result['time'][6], "%")
    # print("mms_HMI to AQF time gap: accuracy", result['time'][7], "%")
    # print("mms_HMI to REF time gap: accuracy", result['time'][8], "%")
    # print()
    # print("frequency")
    # print("mms frequency: accuracy", result['frequency'][0], "%")
    # print("mms_SEL to HMI frequency: accuracy", result['frequency'][1], "%")
    # print("mms_AQF to HMI frequency: accuracy", result['frequency'][2], "%")
    # print("mms_REF to HMI frequency: accuracy", result['frequency'][3], "%")
    # print("mms_HMI frequency: accuracy", result['frequency'][4], "%")
    # print("mms_HMI to SEL frequency: accuracy", result['frequency'][5], "%")
    # print("mms_HMI to AQF frequency: accuracy", result['frequency'][6], "%")
    # print("mms_HMI to REF frequency: accuracy", result['frequency'][7], "%\n")
    print("Each ip relation sum similarity: ", result['average'][0])
    print("Time gap similarity", result['average'][1])
    print("Frequency similarity", result['average'][2])
    print()


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
    print("\nMMS_Context_Similarity:", result['result']['summary'])
    print("ItemID_and_DomainID_count_Similarity:", result['result']['count_similarity'])
    print()


if __name__ == '__main__':
    os.makedirs('../Compare_MMS_Context', 777, exist_ok=True)
    os.makedirs('../output_data', 777, exist_ok=True)
    # read two pcap(must be pcap not pcapng)
    realSystem = sniff(offline='../pcap_file/s1-afternoon.pcap',
                       filter='tcp')

    DigitalTwins = sniff(offline='../pcap_file/Digital-Twins-situation1-afternoon.pcap',
                         filter='tcp')
    # make two files parser
    realSystem_list = Parse_PCAP(realSystem)
    DigitalTwins_list = Parse_PCAP(DigitalTwins)

    print('begin similarity\n')

    # IP similarity
    src_ip, dst_ip, src_ip_num, dst_ip_num, pkt1_src_ip, pkt1_dst_ip, pkt1_src_ip_num, pkt1_dst_ip_num, pkt2_src_ip, pkt2_dst_ip, pkt2_src_ip_num, pkt2_dst_ip_num = compare_topology_similarity(
        realSystem, DigitalTwins)

    print("mms_src_ip similarity:", src_ip, "%")
    print("mms_dst_ip similarity:", dst_ip, "%")
    print("mms_src_ip_num similarity:", src_ip_num, "%")
    print("mms_dst_ip_num similarity:", dst_ip_num, "%\n")
    ip_similarity: float = (float(src_ip)+float(dst_ip)+float(src_ip_num)+float(dst_ip_num))/4

    # Time gap similarity, Frequency similarity, Packet Sum similarity
    miss_rate: float = 0.03  # 時間間隔的誤差
    time_accuray_and_relation = find_accuray_mms(realSystem, DigitalTwins, miss_rate)
    Output_frequecy_and_time_gap(time_accuray_and_relation)
    time_accuray_and_relation_result = 0.0
    for i in time_accuray_and_relation['average']:
        time_accuray_and_relation_result += float(i)
    time_accuray_and_relation_result = time_accuray_and_relation_result/len(time_accuray_and_relation['average'])

    # request and response sum similarity
    compare_request_count_result = compare_request_count(realSystem_list, DigitalTwins_list)
    compare_response_count_result = compare_response_count(realSystem_list, DigitalTwins_list)
    print("compare_response_count:", compare_request_count_result)
    print("compare_request_count:", compare_request_count_result)

    # confirmed and unfirmed sum similarity
    compare_confirmed_count_result = compare_confirmed_count(realSystem_list, DigitalTwins_list)
    compare_unconfirmed_count_result = compare_unconfirmed_count(realSystem_list, DigitalTwins_list)
    print("compare_confirmed_count:", compare_confirmed_count_result)
    print("compare_unconfirmed_count:", compare_unconfirmed_count_result)

    compare_request_response_result = (compare_request_count_result + compare_response_count_result) / 2
    compare_confirmed_unconfirmed_result = (compare_confirmed_count_result*0.9 + compare_unconfirmed_count_result*0.1)
    # MMS context similarity
    compare_MMS_context_result = compare_MMS_Context(realSystem_list, DigitalTwins_list, 3)
    Output_Compare_MMS_Context(compare_MMS_context_result)
    compare_MMS = float(compare_MMS_context_result['result']['summary']) * 0.5 + float(compare_MMS_context_result['result']['count_similarity']) * 0.5

    final_result = (compare_request_response_result*0.5+compare_confirmed_unconfirmed_result*0.5) + \
        compare_MMS + ip_similarity/100 + time_accuray_and_relation_result/100
    final_result = final_result/4
    print("final similarity is :", final_result)
    # similarity report
    print('\nsimilarity report')

    path = "topology_output.txt"
    with open(path, 'w') as f:
        print("realSystem_src_ip", pkt1_src_ip, "\nDigitalTwins_src_ip", pkt2_src_ip, "\nrealSystem_dst_ip", pkt1_dst_ip, "\nDigitalTwins_dst_ip", pkt2_dst_ip, "\nrealSystem_src_ip_num", pkt1_src_ip_num,
              "\nDigitalTwins_src_ip_num", pkt2_dst_ip_num, "\nrealSystem_dst_ip_num", pkt1_dst_ip_num, "\nDigitalTwins_dst_ip_num", pkt2_dst_ip_num, file=f)
