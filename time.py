import binascii

from scapy.all import *


def caculate_time(real, digital):  # 計算所有時間
    real_time = []
    digital_time = []
    real_time_gap = []
    digital_time_gap = []
    gap = []
    for pkt in real:
        real_time.append(pkt.time)
    for pkt in digital:
        digital_time.append(pkt.time)
    # print(real_time[0])
    # print(digital_time[0])
    for n in range(0, len(real_time)-1):
        real_time_gap.append(real_time[n+1]-real_time[n])
    # print(real_time_gap[5])
    for n in range(0, len(digital_time)-1):
        digital_time_gap.append(digital_time[n+1]-digital_time[n])
    # print(digital_time_gap[5])
    if (len(real_time) > len(digital_time)):
        for n in range(0, len(digital_time)-1):
            gap.append(abs(digital_time_gap[n]-real_time_gap[n]))
    else:
        for n in range(0, len(real_time)-1):
            gap.append(abs(digital_time_gap[n]-real_time_gap[n]))
    # print(gap[5])
    a = 0
    b = 0
    for n in range(0, len(gap)):
        b = b+1
        if (gap[n] < 0.9):
            a = a+1
    print("accuray:", (a/b)*100, "%")
    time_gap_real = real_time[len(real_time)-1]-real_time[0]
    freq_real = (len(real_time)-1)/time_gap_real
    time_gap_digital = digital_time[len(digital_time)-1]-digital_time[0]
    freq_digital = (len(digital_time)-1)/time_gap_digital
    # print(len(real_time)-1)
    # print(freq_real)
   # print(freq_digital)
    return time_gap_real, time_gap_digital


def caculate_time2(real, digital, number1, number2):  # 計算時間在mms number1是real的mms位置 number2是digital的mms位置
    real_time = []
    digital_time = []
    real_time_gap = []
    digital_time_gap = []
    gap = []
    for pkt in real:
        real_time.append(pkt.time)
    # print(real_time[len(real_time)-1])
    for pkt in digital:
        digital_time.append(pkt.time)
    for n in range(0, len(number1)-1):
        real_time_gap.append(real_time[(number1[n])+1]-real_time[(number1[n])])
    # print(real_time_gap[5])
    for n in range(0, len(number2)-1):
        digital_time_gap.append(digital_time[number2[n]+1]-digital_time[number2[n]])
    # print(digital_time_gap[5])
    if (len(number1) > len(number2)):
        for n in range(0, len(number2)-1):
            gap.append(abs(digital_time_gap[n]-real_time_gap[n]))
    else:
        for n in range(0, len(number2)-1):
            gap.append(abs(digital_time_gap[n]-real_time_gap[n]))
    # print(gap[5])
    a = 0
    b = 0
    for n in range(0, len(gap)):
        b = b+1
        if (gap[n] < 0.05):
            a = a+1
    print("mms accuray:", (a/b)*100, "%")


def caculate_frequency_mms(total, time):
    freq = total/time
    #print("frequency:", freq)
    return freq


def caculate_accuray_frequency(real_freq, digital_freq):
    print("frequency accuray:", 100-(((abs(real_freq-digital_freq))/real_freq)*100), "%")


def find_mms(pkt):  # b是紀錄mms的個數，a是跑全部的紀錄
    a = 0
    b = 0
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
    a = 0
    b = 0
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


real = rdpcap('real-afternoon.pcap')
digital = rdpcap('digital-twins-afternoon.pcap')
mechine = ['c0a8020b', 'c0a8020c', 'c0a8020d', 'c0a802ca']
dest = ['a', 'b', 'c', 'd']
last_time = caculate_time(real, digital)
real_mms = find_mms(real)
digital_mms = find_mms(digital)
real_freq_mms = caculate_frequency_mms(real_mms[1], last_time[0])
digital_freq_mms = caculate_frequency_mms(digital_mms[1], last_time[1])
accuray_freq = caculate_accuray_frequency(real_freq_mms, digital_freq_mms)
real_mechine_11 = find_mechine_mms(real, mechine[0])
digital_mechine_11 = find_mechine_mms(digital, mechine[0])
real_mechine_12 = find_mechine_mms(real, mechine[1])
digital_mechine_12 = find_mechine_mms(digital, mechine[1])
real_mechine_13 = find_mechine_mms(real, mechine[2])
digital_mechine_13 = find_mechine_mms(digital, mechine[2])
real_mechine_202 = find_mechine_mms(real, mechine[3])
digital_mechine_202 = find_mechine_mms(digital, mechine[3])
real_mechine_202_to_11 = find_mechine_mms_fixed_dest(real, mechine[3], dest[1])
digital_mechine_202_to_11 = find_mechine_mms_fixed_dest(digital, mechine[3], dest[1])
real_mechine_202_to_12 = find_mechine_mms_fixed_dest(real, mechine[3], dest[2])
digital_mechine_202_to_12 = find_mechine_mms_fixed_dest(digital, mechine[3], dest[2])
real_mechine_202_to_13 = find_mechine_mms_fixed_dest(real, mechine[3], dest[3])
digital_mechine_202_to_13 = find_mechine_mms_fixed_dest(digital, mechine[3], dest[3])
# print(real_mms)
# print(digital_mms)
print("real_mms total:", real_mms[1])
print("digital_mms total:", digital_mms[1])
caculate_time2(real, digital, real_mms[0], digital_mms[0])

# print(real_mechine_11)
print("real_mms_11 to 202 total:", real_mechine_11[1])
print("digital_mms_11 to 202 total:", digital_mechine_11[1])
caculate_time2(real, digital, real_mechine_11[0], digital_mechine_11[0])
print("real_mms_12 to 202 total:", real_mechine_12[1])
print("digital_mms_12 to 202 total:", digital_mechine_12[1])
caculate_time2(real, digital, real_mechine_12[0], digital_mechine_12[0])
print("real_mms_13 to 202 total:", real_mechine_13[1])
print("digital_mms_13 to 202 total:", digital_mechine_13[1])
caculate_time2(real, digital, real_mechine_13[0], digital_mechine_13[0])
print("real_mms_202 total:", real_mechine_202[1])
print("digital_mms_202 total:", digital_mechine_202[1])
caculate_time2(real, digital, real_mechine_202[0], digital_mechine_202[0])

print("real_mms_202 to 11 total:", real_mechine_202_to_11[1])
print("digital_mms_202 to 11 total:", digital_mechine_202_to_11[1])
caculate_time2(real, digital, real_mechine_202_to_11[0], digital_mechine_202_to_11[0])

print("real_mms_202 to 12 total:", real_mechine_202_to_12[1])
print("digital_mms_202 to 12 total:", digital_mechine_202_to_12[1])
caculate_time2(real, digital, real_mechine_202_to_12[0], digital_mechine_202_to_12[0])

print("real_mms_202 to 13 total:", real_mechine_202_to_13[1])
print("digital_mms_202 to 13 total:", digital_mechine_202_to_13[1])
caculate_time2(real, digital, real_mechine_202_to_13[0], digital_mechine_202_to_13[0])

# print(real_mechine_202_to_11)
#w = find_mms(pkt)
# print(w)
# time()
