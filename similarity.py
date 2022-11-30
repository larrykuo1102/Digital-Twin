from Compare import compare_MMS_Context
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
    print("real_mms_11 to 202 total:",  result['total'][4])
    print("digital_mms_11 to 202 total:",  result['total'][5])
    print("real_mms_12 to 202 total:",  result['total'][6])
    print("digital_mms_12 to 202 total:",  result['total'][7])
    print("real_mms_13 to 202 total:",  result['total'][8])
    print("digital_mms_13 to 202 total:",  result['total'][9])
    print("real_mms_202 total:",  result['total'][10])
    print("digital_mms_202 total:",  result['total'][11])
    print("real_mms_202 to 11 total:",  result['total'][12])
    print("digital_mms_202 to 11 total:", result['total'][13])
    print("real_mms_202 to 12 total:", result['total'][14])
    print("digital_mms_202 to 12 total:",  result['total'][15])
    print("real_mms_202 to 13 total:",  result['total'][16])
    print("digital_mms_202 to 13 total:",  result['total'][17])
    print()
    print("time")
    #print("time gap: accuray", result['time'][0], "%")
    print("mms time gap: accuray", result['time'][1], "%")
    print("mms_11 to 202 time gap: accuray", result['time'][2], "%")
    print("mms_12 to 202 time gap: accuray", result['time'][3], "%")
    print("mms_13 to 202 time gap: accuray", result['time'][4], "%")
    print("mms_202 time gap: accuray", result['time'][5], "%")
    print("mms_202 to 11 time gap: accuray", result['time'][6], "%")
    print("mms_202 to 12 time gap: accuray", result['time'][7], "%")
    print("mms_202 to 13 time gap: accuray", result['time'][8], "%")
    print()
    print("frequency")
    print("mms frequency: accuray", result['frequency'][0], "%")
    print("mms_11 to 202 frequency: accuray", result['frequency'][1], "%")
    print("mms_12 to 202 frequency: accuray", result['frequency'][2], "%")
    print("mms_13 to 202 frequency: accuray", result['frequency'][3], "%")
    print("mms_202 frequency: accuray", result['frequency'][4], "%")
    print("mms_202 to 11 frequency: accuray", result['frequency'][5], "%")
    print("mms_202 to 12 frequency: accuray", result['frequency'][6], "%")
    print("mms_202 to 13 frequency: accuray", result['frequency'][7], "%")


if __name__ == '__main__':

    # read two pcap(must be pcap not pcapng)
    realSystem = sniff(offline='s1-morning.pcap',
                       filter='tcp')

    DigitalTwins = sniff(offline='situation1_morning_again.pcap',
                         filter='tcp')

    # make two files parser
    realSystem_list = Parse_PCAP(realSystem)
    DigitalTwins_list = Parse_PCAP(DigitalTwins)
    # similarity

    compare_topology_similarity(realSystem, DigitalTwins)

    print('begin similarity')

    time_accuray_and_relation = find_accuray_mms(realSystem, DigitalTwins)
    Output_frequecy_and_time_gap(time_accuray_and_relation)

    compare_MMS_Context(realSystem_list, DigitalTwins_list)
    # similarity report
    print('similarity report')
