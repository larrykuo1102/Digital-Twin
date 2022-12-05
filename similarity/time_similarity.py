import binascii

from scapy.all import *


def caculate_time(real, digital):  # 計算所有時間
    real_time = []
    digital_time = []
    real_time_gap = []
    digital_time_gap = []
    gap = []
    total_gap = 0
    real_total_gap = 0
    for pkt in real:
        real_time.append(pkt.time)
    for pkt in digital:
        digital_time.append(pkt.time)
    # print(real_time[0])
    # print(digital_time[0])
    for n in range(0, len(real_time)-1):
        real_total_gap = real_total_gap+(abs(real_time[n+1]-real_time[n]))
        real_time_gap.append(real_time[n+1]-real_time[n])
    real_average_gap = real_total_gap/(len(real_time)-2)
    # print(real_average_gap)
    for n in range(0, len(digital_time)-1):
        digital_time_gap.append(digital_time[n+1]-digital_time[n])
    # print(digital_time_gap[5])
    if (len(real_time) > len(digital_time)):
        for n in range(0, len(digital_time)-1):
            total_gap = total_gap+(abs(digital_time_gap[n]-real_time_gap[n]))
            gap.append(abs(digital_time_gap[n]-real_time_gap[n]))
        #average_gap = total_gap/(len(digital_time)-2)
    else:
        for n in range(0, len(real_time)-1):
            total_gap = total_gap+(abs(digital_time_gap[n]-real_time_gap[n]))
            gap.append(abs(digital_time_gap[n]-real_time_gap[n]))

    #print("accuray_average:", 100-((abs(average_gap-real_average_gap))/real_average_gap)*100, "%")
    a = 0
    b = 0
    for n in range(0, len(gap)):
        b = b+1
        if (gap[n] < float(real_average_gap)+float(real_average_gap)*0.03):
            a = a+1

    time_accuray = (a/b)*100
    #print("time accuray:", (a/b)*100, "%")
    time_gap_real = real_time[len(real_time)-1]-real_time[0]
    #freq_real = (len(real_time)-1)/time_gap_real
    time_gap_digital = digital_time[len(digital_time)-1]-digital_time[0]
    #freq_digital = (len(digital_time)-1)/time_gap_digital
    # print(len(real_time)-1)
    # print(freq_real)
   # print(freq_digital)
    return time_gap_real, time_gap_digital, time_accuray


def caculate_time2(real, digital, number1, number2):  # 計算時間在mms number1是real的mms位置 number2是digital的mms位置
    real_time = []
    digital_time = []
    real_time_gap = []
    digital_time_gap = []
    gap = []
    real_total_gap = 0
    for pkt in real:
        real_time.append(pkt.time)
    for pkt in digital:
        digital_time.append(pkt.time)
    for n in range(0, len(number1)-1):
        real_total_gap = real_total_gap+(abs(real_time[(number1[n+1])]-real_time[(number1[n])]))
        real_time_gap.append(real_time[(number1[n+1])]-real_time[(number1[n])])
    real_average_gap = real_total_gap/(len(number1)-2)
    for n in range(0, len(number2)-1):
        digital_time_gap.append(digital_time[number2[n+1]]-digital_time[number2[n]])
    if (len(number1) > len(number2)):
        for n in range(0, len(number2)-1):
            gap.append(abs(digital_time_gap[n]-real_time_gap[n]))
    else:
        for n in range(0, len(number1)-1):
            gap.append(abs(digital_time_gap[n]-real_time_gap[n]))
    a = 0  # 記錄符合門檻的數量
    b = 0  # 為總數
    for n in range(0, len(gap)):
        b = b+1
        if (gap[n] < float(real_average_gap)*1.03):
            a = a+1
    time_accuray = (a/b)*100
    time_gap_real = real_time[len(real_time)-1]-real_time[0]
    time_gap_digital = digital_time[len(digital_time)-1]-digital_time[0]
    return time_gap_real, time_gap_digital, time_accuray, real_time_gap, len(real_time_gap), digital_time_gap


def caculate_frequency_mms(real, digital, real_mms, digital_mms, real_total, digital_total):
    real_time = []
    digital_time = []
    total = 0
    for pkt in real:
        real_time.append(pkt.time)
    for pkt in digital:
        digital_time.append(pkt.time)
    real_time_total = real_time[len(real_time)-1]-real_time[0]
    digital_time_total = digital_time[len(digital_time)-1]-digital_time[0]
    if (real_time_total > digital_time_total):
        compare_time = digital_time_total
        for i in range(0, len(real_time)):
            if (real_time[real_mms[i]] < real_time[real_mms[0]]+compare_time):
                total = total+1
            else:
                break
        digital_freq = digital_total/compare_time
        real_freq = total/compare_time
    else:
        compare_time = real_time_total
        for i in range(0, len(digital_time)):
            if (digital_time[digital_mms[i]] < digital_time[digital_mms[0]]+digital_time):
                total = total+1
            else:
                break
        real_freq = real_total/compare_time
        digital_freq = total/compare_time
    return real_freq, digital_freq


def caculate_accuray_frequency(real_freq, digital_freq):

    total_percent = 100-(((abs(real_freq-digital_freq))/real_freq)*100)
    return total_percent


def caculate_mms_total_proportion(real_mms_total, digital_mms_total):
    mms_proportion = (abs(real_mms_total-digital_mms_total))/real_mms_total
    return mms_proportion


def caculate_accuray_total(mms_total_proportion, real_mms_total, digital_mms_total):
    other_proportion = (abs(real_mms_total-digital_mms_total))/real_mms_total
    if mms_total_proportion == 0:
        total_percent = 100
    else:
        total_percent = 100-(((abs(mms_total_proportion-other_proportion))/mms_total_proportion)*100)
    return total_percent


def find_mms(pkt):
    a = 0  # a是紀錄位置
    b = 0  # b是紀錄個數
    record_mms = []
    for n in range(0, len(pkt)):
        content = binascii.hexlify(bytes(pkt[n])).decode()
        if content.find('0300') != -1 and content.find('02f080') != -1:
            record_mms.append(a)
            a = a+1
            b = b+1
        else:
            a = a+1
    return record_mms, b


def find_mechine_mms(pkt, string):  # 找一個src到隨機的dest封包
    a = 0  # 紀錄mms位置
    b = 0  # 紀錄個數
    string2 = str()
    record_mechine = []
    #record_mechine_mms_number = []
    if string == 'c0a8020b':
        string2 = 'b'
    elif string == 'c0a8020c':
        string2 = 'c'
    elif string == 'c0a8020d':
        string2 = 'd'
    else:
        string2 = 'a'
    for n in range(0, len(pkt)):
        content = binascii.hexlify(bytes(pkt[n])).decode()
        if content.find(string) != -1 and content.find('0300') != -1 and content.find('02f080') != -1 and content[59] == string2:
            record_mechine .append(a)
            a = a+1
            b = b+1
        else:
            a = a+1
    return record_mechine, b


def find_mechine_mms_fixed_dest(pkt, string, dest):  # 找一個src到固定的dest封包
    a = 0
    b = 0
    Source_1 = str()
    record_mechine = []
    #record_mechine_mms_number = []
    if string == 'c0a8020b':
        Source_1 = 'b'
    elif string == 'c0a8020c':
        Source_1 = 'c'
    elif string == 'c0a8020d':
        Source_1 = 'd'
    else:
        Source_1 = 'a'
    for n in range(0, len(pkt)):
        content = binascii.hexlify(bytes(pkt[n])).decode()
        if content.find(string) != -1 and content.find('0300') != -1 and content.find('02f080') != -1 and content[59] == Source_1 and content[67] == dest:
            record_mechine .append(a)
            a = a+1
            b = b+1
        else:
            a = a+1
    return record_mechine, b


def write_file(mechine, mechine_name):  # 把mms的位置寫進文字檔案 方便檢查
    with open(mechine_name+'.txt', 'w') as fp:
        a = 1
        for item in mechine:
            if (a % 21 == 0):
                fp.write("\n")
            fp.write("%s " % item)
            a = a+1


def find_accuray_mms(real, digital):
    mechine = ['c0a8020b', 'c0a8020c', 'c0a8020d', 'c0a802ca']
    dest = ['a', 'b', 'c', 'd']
    last_time = caculate_time(real, digital)
    mms_dict = {}
    real_mms = find_mms(real)
    digital_mms = find_mms(digital)
    last_time_mms = caculate_time2(real, digital, real_mms[0], digital_mms[0])
    freq_mms = caculate_frequency_mms(real, digital, real_mms[0], digital_mms[0], real_mms[1], digital_mms[1])
    accuray_freq_mms = caculate_accuray_frequency(freq_mms[0], freq_mms[1])  # 0是real 1是digital
    proportion_total_mms = caculate_mms_total_proportion(real_mms[1], digital_mms[1])
    #write_file(real_mms[0], "real_mms")
    #write_file(digital_mms[0], "digital_mms")

    real_mechine_11 = find_mechine_mms(real, mechine[0])
    digital_mechine_11 = find_mechine_mms(digital, mechine[0])
    last_time_mms_11 = caculate_time2(real, digital, real_mechine_11[0], digital_mechine_11[0])
    freq_11 = caculate_frequency_mms(real, digital, real_mechine_11[0], digital_mechine_11[0], real_mechine_11[1], digital_mechine_11[1])
    accuray_freq_11 = caculate_accuray_frequency(freq_11[0], freq_11[1])  # 0是real 1是digital
    accuray_total_11 = caculate_accuray_total(proportion_total_mms, real_mechine_11[1], digital_mechine_11[1])
    #write_file(real_mechine_11[0], "real_mechine_11")
    #write_file(digital_mechine_11[0], "digital_mechine_11")

    real_mechine_12 = find_mechine_mms(real, mechine[1])
    digital_mechine_12 = find_mechine_mms(digital, mechine[1])
    last_time_mms_12 = caculate_time2(real, digital, real_mechine_12[0], digital_mechine_12[0])
    freq_12 = caculate_frequency_mms(real, digital, real_mechine_12[0], digital_mechine_12[0], real_mechine_12[1], digital_mechine_12[1])
    accuray_freq_12 = caculate_accuray_frequency(freq_12[0], freq_12[1])  # 0是real 1是digital
    accuray_total_12 = caculate_accuray_total(proportion_total_mms, real_mechine_12[1], digital_mechine_12[1])
    #write_file(real_mechine_12[0], "real_mechine_12")
    #write_file(digital_mechine_12[0], "digital_mechine_12")

    real_mechine_13 = find_mechine_mms(real, mechine[2])
    digital_mechine_13 = find_mechine_mms(digital, mechine[2])
    last_time_mms_13 = caculate_time2(real, digital, real_mechine_13[0], digital_mechine_13[0])
    freq_13 = caculate_frequency_mms(real, digital, real_mechine_13[0], digital_mechine_13[0], real_mechine_13[1], digital_mechine_13[1])
    accuray_freq_13 = caculate_accuray_frequency(freq_13[0], freq_13[1])  # 0是real 1是digital
    accuray_total_13 = caculate_accuray_total(proportion_total_mms, real_mechine_13[1], digital_mechine_13[1])
    #write_file(real_mechine_13[0], "real_mechine_13")
    #write_file(digital_mechine_13[0], "digital_mechine_13")

    real_mechine_202 = find_mechine_mms(real, mechine[3])
    digital_mechine_202 = find_mechine_mms(digital, mechine[3])
    last_time_mms_202 = caculate_time2(real, digital, real_mechine_202[0], digital_mechine_202[0])
    freq_202 = caculate_frequency_mms(real, digital, real_mechine_202[0], digital_mechine_202[0], real_mechine_202[1], digital_mechine_202[1])
    accuray_freq_202 = caculate_accuray_frequency(freq_202[0], freq_202[1])  # 0是real 1是digital
    accuray_total_202 = caculate_accuray_total(proportion_total_mms, real_mechine_202[1], digital_mechine_202[1])
    #write_file(real_mechine_202[0], "real_mechine_202")
    #write_file(digital_mechine_202[0], "digital_mechine_202")

    real_mechine_202_to_11 = find_mechine_mms_fixed_dest(real, mechine[3], dest[1])
    digital_mechine_202_to_11 = find_mechine_mms_fixed_dest(digital, mechine[3], dest[1])
    last_time_mms_202_to_11 = caculate_time2(real, digital, real_mechine_202_to_11[0], digital_mechine_202_to_11[0])
    freq_202_to_11 = caculate_frequency_mms(
        real, digital, real_mechine_202_to_11[0], digital_mechine_202_to_11[0], real_mechine_202_to_11[1], digital_mechine_202_to_11[1])
    accuray_freq_202_to_11 = caculate_accuray_frequency(freq_202_to_11[0], freq_202_to_11[1])  # 0是real 1是digital
    accuray_total_202_to_11 = caculate_accuray_total(proportion_total_mms, real_mechine_202_to_11[1], digital_mechine_202_to_11[1])
    #write_file(real_mechine_202_to_11[0], "real_mechine_202_to_11")
    #write_file(digital_mechine_202_to_11[0], "digital_mechine_202_to_11")

    real_mechine_202_to_12 = find_mechine_mms_fixed_dest(real, mechine[3], dest[2])
    digital_mechine_202_to_12 = find_mechine_mms_fixed_dest(digital, mechine[3], dest[2])
    last_time_mms_202_to_12 = caculate_time2(real, digital, real_mechine_202_to_12[0], digital_mechine_202_to_12[0])
    freq_202_to_12 = caculate_frequency_mms(
        real, digital, real_mechine_202_to_12[0], digital_mechine_202_to_12[0], real_mechine_202_to_12[1], digital_mechine_202_to_12[1])
    accuray_freq_202_to_12 = caculate_accuray_frequency(freq_202_to_12[0], freq_202_to_12[1])  # 0是real 1是digital
    accuray_total_202_to_12 = caculate_accuray_total(proportion_total_mms, real_mechine_202_to_12[1], digital_mechine_202_to_12[1])
    #write_file(real_mechine_202_to_12[0], "real_mechine_202_to_12")
    #write_file(digital_mechine_202_to_12[0], "digital_mechine_202_to_12")

    real_mechine_202_to_13 = find_mechine_mms_fixed_dest(real, mechine[3], dest[3])
    digital_mechine_202_to_13 = find_mechine_mms_fixed_dest(digital, mechine[3], dest[3])
    last_time_mms_202_to_13 = caculate_time2(real, digital, real_mechine_202_to_13[0], digital_mechine_202_to_13[0])
    accuray_freq_202_to_13 = caculate_frequency_mms(
        real, digital, real_mechine_202_to_13[0], digital_mechine_202_to_13[0], real_mechine_202_to_13[1], digital_mechine_202_to_13[1])
    accuray_freq_202_to_13 = caculate_accuray_frequency(accuray_freq_202_to_13[0], accuray_freq_202_to_13[1])  # 0是real 1是digital
    accuray_total_202_to_13 = caculate_accuray_total(proportion_total_mms, real_mechine_202_to_13[1], digital_mechine_202_to_13[1])
    #write_file(real_mechine_202_to_13[0], "real_mechine_202_to_13")
    #write_file(digital_mechine_202_to_13[0], "digital_mechine_202_to_13")

    total_value = [len(real), len(digital), real_mms[1], digital_mms[1], real_mechine_11[1], digital_mechine_11[1], real_mechine_12[1],
                   digital_mechine_12[1], real_mechine_13[1], digital_mechine_13[1], real_mechine_202[1], digital_mechine_202[1],
                   real_mechine_202_to_11[1], digital_mechine_202_to_11[1], real_mechine_202_to_12[1], digital_mechine_202_to_12[1],
                   real_mechine_202_to_13[1], digital_mechine_202_to_13[1]]
    total_accuracy = [accuray_total_11, accuray_total_12, accuray_total_13, accuray_total_202, accuray_total_202_to_11,
                      accuray_total_202_to_12, accuray_total_202_to_13]
    # print("total")
    # print("real total:", len(real))
    # print("digital total:", len(digital))
    # print("real_mms total:", real_mms[1])
    # print("digital_mms total:", digital_mms[1])

    # print("real_mms_11 to 202 total:", real_mechine_11[1])
    # print("digital_mms_11 to 202 total:", digital_mechine_11[1])
    # print("real_mms_12 to 202 total:", real_mechine_12[1])
    # print("digital_mms_12 to 202 total:", digital_mechine_12[1])
    # print("real_mms_13 to 202 total:", real_mechine_13[1])
    # print("digital_mms_13 to 202 total:", digital_mechine_13[1])
    # print("real_mms_202 total:", real_mechine_202[1])
    # print("digital_mms_202 total:", digital_mechine_202[1])
    # print("real_mms_202 to 11 total:", real_mechine_202_to_11[1])
    # print("digital_mms_202 to 11 total:", digital_mechine_202_to_11[1])
    # print("real_mms_202 to 12 total:", real_mechine_202_to_12[1])
    # print("digital_mms_202 to 12 total:", digital_mechine_202_to_12[1])
    # print("real_mms_202 to 13 total:", real_mechine_202_to_13[1])
    average_accuracy_total = (accuray_total_11+accuray_total_12+accuray_total_13 +
                              accuray_total_202_to_11+accuray_total_202_to_12+accuray_total_202_to_13)/6
    # print()
    average_accuracy_time = (last_time_mms_11[2]+last_time_mms_12[2]+last_time_mms_13[2] +
                             last_time_mms_202_to_11[2]+last_time_mms_202_to_12[2]+last_time_mms_202_to_13[2])/6
    time_value = [last_time[2], last_time_mms[2], last_time_mms_11[2], last_time_mms_12[2], last_time_mms_13[2],
                  last_time_mms_202[2], last_time_mms_202_to_11[2], last_time_mms_202_to_12[2], last_time_mms_202_to_13[2], average_accuracy_time]
    # print("time")
    # print("time gap: accuray", last_time[2], "%")
    # print("mms time gap: accuray", last_time_mms[2], "%")
    # print("mms_11 to 202 time gap: accuray", last_time_mms_11[2], "%")
    # print("mms_12 to 202 time gap: accuray", last_time_mms_12[2], "%")
    # print("mms_13 to 202 time gap: accuray", last_time_mms_13[2], "%")
    # print("mms_202 time gap: accuray", last_time_mms_202[2], "%")
    # print("mms_202 to 11 time gap: accuray", last_time_mms_202_to_11[2], "%")
    # print("mms_202 to 12 time gap: accuray", last_time_mms_202_to_12[2], "%")
    # print("mms_202 to 13 time gap: accuray", last_time_mms_202_to_13[2], "%")
    # print()
    average_accuracy_frequency = (accuray_freq_11+accuray_freq_12+accuray_freq_13 +
                                  accuray_freq_202_to_11+accuray_freq_202_to_12+accuray_freq_202_to_13)/6
    frequency_value = [accuray_freq_11, accuray_freq_12, accuray_freq_13, accuray_freq_202,
                       accuray_freq_202_to_11, accuray_freq_202_to_12, accuray_freq_202_to_13]
    average = [average_accuracy_total, average_accuracy_time, average_accuracy_frequency]
    # print("frequency")
    # print("mms frequency: accuray", accuray_freq_mms, "%")
    # print("mms_11 to 202 frequency: accuray", accuray_freq_11, "%")
    # print("mms_12 to 202 frequency: accuray", accuray_freq_12, "%")
    # print("mms_13 to 202 frequency: accuray", accuray_freq_13, "%")
    # print("mms_202 frequency: accuray", accuray_freq_202, "%")
    # print("mms_202 to 11 frequency: accuray", accuray_freq_202_to_11, "%")
    # print("mms_202 to 12 frequency: accuray", accuray_freq_202_to_12, "%")
    # print("mms_202 to 13 frequency: accuray", accuray_freq_202_to_13, "%")
    mms_dict = {"total": total_value,
                "total_accuracy": total_accuracy,
                "time": time_value,
                "frequency": frequency_value,
                "average": average}
    return mms_dict


real = rdpcap('s1-morning.pcap')
digital = rdpcap('situation1_morning_again.pcap')
time_accuray_and_relation = find_accuray_mms(real, digital)
# print(time_accuray_and_relation['frequency'][7])
