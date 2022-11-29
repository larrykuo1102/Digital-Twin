import json
from re import match


def align(real_sys: list, digital_twins: list):
    # digital_twins_shift: int
    # isAlign: bool = False
    # MMS == true
    # IP == true
    # Request or Response == true
    # read or Write == true
    real_sys_shift = 0
    digital_twins_shift = 0
    isAlign = False

    while isAlign != True:

        if digital_twins_shift == len(digital_twins) or real_sys_shift == len(real_sys):
            break

        real_proto = Is_MMS_or_GOOSE(real_sys[real_sys_shift])

        if real_proto == None:
            print(real_sys[real_sys_shift])
            real_sys_shift += 1
            continue

        digit_proto = Is_MMS_or_GOOSE(digital_twins[digital_twins_shift])

        if real_proto == digit_proto:
            real_IP = getIP(real_sys[real_sys_shift])
            digit_IP = getIP(digital_twins[digital_twins_shift])
            if real_IP == digit_IP:
                if real_proto == "MMS":
                    # confirmed or unconfirmed
                    real_pdu = Is_Confirmed_or_UnConfirmed(
                        real_sys[real_sys_shift])
                    digit_pdu = Is_Confirmed_or_UnConfirmed(
                        digital_twins[digital_twins_shift])
                    if (real_pdu == digit_pdu) and (real_pdu != None):
                        if real_pdu == "unconfirmed":
                            # read or write
                            real_re = Is_Read_or_Write(
                                real_sys[real_sys_shift])
                            digit_re = Is_Read_or_Write(
                                digital_twins[digital_twins_shift])
                            if (real_re == digit_re) and (real_re != None):
                                isAlign = True
                                break
                        elif real_pdu == "confirmed":
                            # response or request
                            real_re = Is_Request_or_Response(
                                real_sys[real_sys_shift])
                            digit_re = Is_Request_or_Response(
                                digital_twins[digital_twins_shift])
                            if (real_re == digit_re) and (real_re != None):
                                # read or write
                                real_re = Is_Read_or_Write(
                                    real_sys[real_sys_shift])
                                digit_re = Is_Read_or_Write(
                                    digital_twins[digital_twins_shift])
                                if (real_re == digit_re) and (real_re != None):
                                    isAlign = True
                                    break
                        else:
                            pass
                elif real_proto == "GOOSE":
                    pass
                else:
                    pass
            pass

        digital_twins_shift += 1
        if digital_twins_shift == len(digital_twins):
            real_sys_shift += 1
            digital_twins_shift = 0

    return real_sys[real_sys_shift:], digital_twins[digital_twins_shift:]


def getIP(pkt: dict) -> dict:
    pktlist = list(pkt.values())
    return pktlist[0]


def Is_MMS_or_GOOSE(pkt: dict):
    pktlist = list(pkt.keys())
    proto = pktlist[len(pktlist)-1]
    if (proto == "MMS") or (proto == "GOOSE"):
        return proto
    else:
        return None


def Is_Request_or_Response(pkt: dict):
    tag = pkt.get("MMS")
    assert tag != None
    tag = list(tag[0].keys())[0]
    if tag.find("Request") != -1:
        return "Request"
    elif tag.find("Response") != -1:
        return "Response"
    else:
        return None


def Is_Confirmed_or_UnConfirmed(pkt: dict):
    tag = pkt.get("MMS")
    assert tag != None
    tag = list(tag[0].keys())[0]
    if tag.find("confirmed") != -1:
        return "confirmed"
    elif tag.find("unconfirmed") != -1:
        return "unconfirmed"
    else:
        return None


def Is_Read_or_Write(pkt: dict):
    tag = pkt.get("MMS")
    assert tag != None
    tag = list(tag[0].values())[0]
    temp = list(tag[0].keys())
    if Is_Confirmed_or_UnConfirmed(pkt) == "unconfirmed":
        tag = temp[0]
    elif Is_Confirmed_or_UnConfirmed(pkt) == "confirmed":
        tag = temp[1]
    if tag.find("Read") != -1:
        return "Read"
    elif tag.find("Write") != -1:
        return "Write"
    else:
        return None


def Longest_Common_Subsequence(text1: str, text2: str) -> str:

    (m, n) = (len(text1), len(text2))

    dp = [["" for x in range(n+1)] for y in range(m+1)]

    for i in range(1, m+1):
        for j in range(1, n+1):
            if text1[i-1] == text2[j-1]:
                dp[i][j] = dp[i-1][j-1] + text1[i-1]
            else:
                if len(dp[i-1][j]) >= len(dp[i][j-1]):
                    dp[i][j] = dp[i-1][j]
                else:
                    dp[i][j] = dp[i][j-1]

    return dp[m][n]


# print(Longest_Common_Subsequence("fafabcdef", "fadabc"))

# dict1 = {"IP_src":"1234", "IP_dst":"5678"}
# dict2 = {"IP_src":"1234", "IP_dst":"5678"}
# assert dict1 == dict2
module_map = {
    'MMS': [['confirmed_RequestPDU', 'confirmed_ResponsePDU', 'unconfirmed_PDU']],
    'confirmed_RequestPDU':  ['invokeID', ['Write_Request', 'Read_Request', 'GetVariableAccessAttributes_Request']],
    'confirmed_ResponsePDU': ['invokeID', ['Read_Response', 'Write_Response', 'GetVariableAccessAttributes_Response']],
    'unconfirmed_PDU': ['informationReport'],
    'Read_Request': ['VariableAccessSpecification'],
    'Read_Response': ['listOfAccessResult'],
    'Write_Request': ['VariableAccessSpecification', 'listofData'],
    'Write_Response': ['Item'],
    'Item': ['Write_success'],
    'GetVariableAccessAttributes_Request': ['ObjectName'],
    'GetVariableAccessAttributes_Response': ['ObjectName'],
    'VariableAccessSpecification': [['listofVariable', 'variableListName', 'listofVariables']],
    'listofVariable': [['VariableSpecification', 'listofVariable']],
    'listofVariables': [['VariableSpecification', 'listofVariable']],
    'VariableSpecification': ['ObjectName'],
    'listOfAccessResult': ['AccessResult'],
    'variableListName': ['ObjectName'],
    'ObjectName': [['domain-specific', 'vmd-specific']],
    'domain-specific': ['domainID', 'itemID'],
    'success': [['structure', 'boolean', 'bit-string', 'integer', 'unsigned', 'visible-string', 'binary-time', 'utc-time']],
    'structure': [['boolean', 'integer']],
    'informationReport': ['VariableAccessSpecification', 'listOfAccessResult'],
}

input_module = []


def compare_MMS_module(twins: dict, module_name: str):  # parsered result
    if (module_name == 'MMS'):
        input_module.clear()
    # 有沒有符合 module
    check_valid: bool = True
    # next_dict: dict = twins.get(module_name)
    next_list: list = twins.get(module_name)
    map_list = module_map.get(module_name)
    input_module.append(module_name)
    # print(module_name)
    if (next_list != None and map_list != None):
        # next_dict = next_list[0]

        # print(map_list)

        for next_dict in next_list:

            for neccessary in map_list:
                check_neccessary: bool = False
                if (isinstance(neccessary, list)):
                    for each in neccessary:
                        # if several module exsits one in twins' data -> keep check next level module
                        if (each in next_dict.keys()):
                            check_neccessary = True
                            if not compare_MMS_module(next_dict, each):
                                check_valid = False
                                assert False, f'module Error {module_name} {each}'
                    if not check_neccessary:
                        check_valid = False
                else:
                    # if this module exsits one in twins' data -> keep check next level module
                    if (neccessary in next_dict.keys()):
                        if not compare_MMS_module(next_dict, neccessary):
                            check_valid = False
                            assert False, f'module Error {module_name} {neccessary}'
                    else:
                        check_valid = False
                        assert False, f'module Error {neccessary} missed'
    elif (map_list == None):
        if (module_name == 'ObjectName'):
            # print('ObjectName similarity')
            pass
        elif (module_name == 'itemID'):
            # print('itemID similarity')
            input_module.append(next_list)
            pass
        elif (module_name == 'domainID'):
            input_module.append(next_list)
            # print('domainID similarity')
            pass
        elif (module_name == 'invokeID'):
            # print('invokeID similarity')
            pass
        elif (module_name == 'Write_success'):
            # print('invokeID similarity')
            pass
        return True
    else:
        check = False

    if (check_valid == False):
        return False

    return input_module


def get_itemID(module_list: list):
    result = []
    for i in range(len(module_list)):
        if (module_list[i] == 'itemID'):
            result.append(module_list[i+1])
            i + 1
    return result


def get_domainID(module_list: list):
    result = []
    for i in range(len(module_list)):
        if (module_list[i] == 'domainID'):
            result.append(module_list[i+1])
            i + 1
    return result


# compare_MMS(twins, "MMS")
def compare_MMS_Context(realSystem_list, DigitalTwins_list):
    chance = 3
    chance_domainID = []
    chance_itemID = []
    chance_module = []
    chance_summary = []
    while (chance > 0):
        try:

            # align
            realSystem_list, DigitalTwins_list = align(
                realSystem_list, DigitalTwins_list)
            # compare
            fail = 0
            fail_list = []
            all_itemID_similarity = 0.0
            all_domainID_similarity = 0.0
            all_module_similarity = 0.0

            packet_length = len(DigitalTwins_list) if len(realSystem_list) > len(
                DigitalTwins_list) else len(realSystem_list)

            for real, digital in zip(realSystem_list, DigitalTwins_list):
                try:
                    digitaltwins_temp = compare_MMS_module(
                        digital, 'MMS').copy()
                    realsystem_temp = compare_MMS_module(real, 'MMS').copy()
                    all_module_similarity += 1
                    # itemID similarity
                    digitaltwins_itemID = get_itemID(digitaltwins_temp)
                    realsystem_itemID = get_itemID(realsystem_temp)
                    itemID_similarity = 0.0
                    if len(realsystem_itemID) == 0 and len(digitaltwins_itemID) != 0:
                        all_itemID_similarity += 0
                    elif len(realsystem_itemID) != 0 and len(digitaltwins_itemID) != 0:
                        for real_itemID, digital_itemID in zip(realsystem_itemID, digitaltwins_itemID):
                            # LCS()
                            itemID_similarity += compare_itemID(
                                real_itemID, digital_itemID)
                            # print(itemID_similarity, real_itemID, digital_itemID)
                        all_itemID_similarity += itemID_similarity / \
                            len(realsystem_itemID)
                    elif len(realsystem_itemID) != 0 and len(digitaltwins_itemID) == 0:
                        all_itemID_similarity += 0
                    else:
                        all_itemID_similarity += 1
                    # domainID similarity
                    digitaltwins_domainID = get_domainID(digitaltwins_temp)
                    realsystem_domainID = get_domainID(realsystem_temp)
                    domain_LCS = 0

                    if len(realsystem_domainID) == 0 and len(digitaltwins_domainID) != 0:
                        domain_LCS += 0
                    elif len(realsystem_domainID) != 0 and len(digitaltwins_domainID) != 0:
                        for real_domainID, digital_domainID in zip(realsystem_domainID, digitaltwins_domainID):
                            domain_LCS += len(Longest_Common_Subsequence(
                                real_domainID, digital_domainID))/len(real_domainID)
                            # print(domain_LCS, real_domainID, digital_domainID)
                        all_domainID_similarity += domain_LCS / \
                            len(realsystem_domainID)
                    elif len(realsystem_domainID) != 0 and len(digitaltwins_domainID) == 0:
                        domain_LCS += 0
                    else:
                        all_domainID_similarity += 1

                    # print('DigitalTwins:', digitaltwins_temp)
                    # print('RealSystem:', realsystem_temp)
                except Exception as e:
                    print(e)
                    fail += 1
                    fail_list.append(digital)
                    # all_itemID_similarity += 1
                    print('fail', fail)

            with open(f'packet_{chance}_result.json', "w") as file:
                json.dump(fail_list, file, indent=2)
            DigitalTwins_list = DigitalTwins_list[1:]
            # print('itemID similarity', all_itemID_similarity / packet_length, '%')
            # print('domainID similarity', all_domainID_similarity / packet_length, '%')
            # print('module similarity', all_module_similarity/packet_length)
            chance_itemID.append(all_itemID_similarity / packet_length)
            chance_domainID.append(all_domainID_similarity / packet_length)
            chance_module.append(all_module_similarity/packet_length)
            summary_similarity = 5/7 * all_module_similarity/packet_length + 1/7 * \
                all_itemID_similarity / packet_length + 1 / \
                7 * all_domainID_similarity / packet_length
            chance_summary.append(summary_similarity)
            all_itemID_similarity = 0.0
            all_domainID_similarity = 0.0
            all_module_similarity = 0.0

        except Exception as e:
            print(e)
        chance -= 1
    print(f'{len(chance_itemID)} chances itemID', chance_itemID)
    print(f'{len(chance_domainID)} chances domainID', chance_domainID)
    print(f'{len(chance_module)} chances module', chance_module)
    print('all similarity =', f'{len(chance_summary)}', chance_summary)


def compare_COTP():
    pass

# print(Longest_Common_Subsequence("abcde", "ace"))
# print(Longest_Common_Subsequence("fafabcdef", "fadabc"))


def compare_itemID(real_sys_ID: str, digit_twins_ID: str):
    real_names = real_sys_ID.split("24")
    twins_names = digit_twins_ID.split("24")
    real_length = len(real_names)
    twins_length = len(twins_names)
    all_subq = 0
    for idx in range(min(real_length, twins_length)):
        subsq = Longest_Common_Subsequence(real_names[idx], twins_names[idx])
        if idx == 0:
            if len(subsq) < len(real_names[idx]):
                all_subq += len(subsq)
                break
            else:
                all_subq += len(subsq)
        else:
            all_subq += len(subsq)
    all_length = 0
    for idx in real_names:
        all_length += len(idx)
    # print(all_subq)
    # print(all_length)
    return all_subq / all_length


def compare_domainID(real_sys_ID: str, digit_twins_ID: str):
    subsq = Longest_Common_Subsequence(real_sys_ID, digit_twins_ID)
    return len(subsq) / len(real_sys_ID)


def get_time(pkt: dict) -> float:
    time = pkt.get('time')
    assert time != None
    return float(time)


def get_response_count(pktlist: list, elapsed=0.0):
    total = 0
    begin = 0.0
    if elapsed == 0.0:
        for value in pktlist:
            if Is_Request_or_Response(value) == "Response":
                total += 1
    else:
        for value in pktlist:
            if Is_Request_or_Response(value) == "Response":
                total += 1
                if total == 1:
                    begin = get_time(value)
                else:
                    if get_time(value) > begin + elapsed:
                        total -= 1
                        break
                    elif get_time(value) == begin + elapsed:
                        break
    return total


def get_request_count(pktlist: list, elapsed=0.0):
    total = 0
    begin = 0.0
    if elapsed == 0.0:
        for value in pktlist:
            if Is_Request_or_Response(value) == "Request":
                total += 1
    else:
        for value in pktlist:
            if Is_Request_or_Response(value) == "Request":
                total += 1
                if total == 1:
                    begin = get_time(value)
                else:
                    if get_time(value) > begin + elapsed:
                        total -= 1
                        break
                    elif get_time(value) == begin + elapsed:
                        break
    return total


def get_confirmed_count(pktlist: list, elapsed=0.0):
    total = 0
    begin = 0.0
    if elapsed == 0.0:
        for value in pktlist:
            if Is_Confirmed_or_UnConfirmed(value) == "confirmed":
                total += 1
    else:
        for value in pktlist:
            if Is_Confirmed_or_UnConfirmed(value) == "confirmed":
                total += 1
                if total == 1:
                    begin = get_time(value)
                else:
                    if get_time(value) > begin + elapsed:
                        total -= 1
                        break
                    elif get_time(value) == begin + elapsed:
                        break
    return total


def get_unconfirmed_count(pktlist: list, elapsed=0.0):
    total = 0
    begin = 0.0
    if elapsed == 0.0:
        for value in pktlist:
            if Is_Confirmed_or_UnConfirmed(value) == "unconfirmed":
                total += 1
    else:
        for value in pktlist:
            if Is_Confirmed_or_UnConfirmed(value) == "unconfirmed":
                total += 1
                if total == 1:
                    begin = get_time(value)
                else:
                    if get_time(value) > begin + elapsed:
                        total -= 1
                        break
                    elif get_time(value) == begin + elapsed:
                        break
    return total


def get_response_elapsed(pktlist: list):
    count = 0
    begin = 0.0
    end = 0.0
    for value in pktlist:
        if Is_Request_or_Response(value) == "Response":
            if count == 0:
                begin = get_time(value)
            else:
                end = get_time(value)
            count += 1
    return end - begin


def get_request_elapsed(pktlist: list):
    count = 0
    begin = 0.0
    end = 0.0
    for value in pktlist:
        if Is_Request_or_Response(value) == "Request":
            if count == 0:
                begin = get_time(value)
            else:
                end = get_time(value)
            count += 1
    return end - begin


def get_confirmed_elapsed(pktlist: list):
    count = 0
    begin = 0.0
    end = 0.0
    for value in pktlist:
        if Is_Confirmed_or_UnConfirmed(value) == "confirmed":
            if count == 0:
                begin = get_time(value)
            else:
                end = get_time(value)
            count += 1
    return end - begin


def get_unconfirmed_elapsed(pktlist: list):
    count = 0
    begin = 0.0
    end = 0.0
    for value in pktlist:
        if Is_Confirmed_or_UnConfirmed(value) == "unconfirmed":
            if count == 0:
                begin = get_time(value)
            else:
                end = get_time(value)
            count += 1
    return end - begin


def compare_confirmed_count(real_sys_list: list, Digit_twins_list: list):
    real_elapsed = get_confirmed_elapsed(real_sys_list)
    twins_elapsed = get_confirmed_elapsed(Digit_twins_list)
    if real_elapsed >= twins_elapsed:
        real_count = get_confirmed_count(real_sys_list, twins_elapsed)
        twins_count = get_confirmed_count(Digit_twins_list, twins_elapsed)
    else:
        real_count = get_confirmed_count(real_sys_list, real_elapsed)
        twins_count = get_confirmed_count(Digit_twins_list, real_elapsed)

    return 1 - abs(real_count-twins_count) / real_count


def compare_unconfirmed_count(real_sys_list: list, Digit_twins_list: list):
    real_elapsed = get_unconfirmed_elapsed(real_sys_list)
    twins_elapsed = get_confirmed_elapsed(Digit_twins_list)
    if real_elapsed >= twins_elapsed:
        real_count = get_confirmed_count(real_sys_list, twins_elapsed)
        twins_count = get_confirmed_count(Digit_twins_list, twins_elapsed)
    else:
        real_count = get_confirmed_count(real_sys_list, real_elapsed)
        twins_count = get_confirmed_count(Digit_twins_list, real_elapsed)

    return 1 - abs(real_count-twins_count) / real_count


def compare_request_count(real_sys_list: list, Digit_twins_list: list):
    real_elapsed = get_request_elapsed(real_sys_list)
    twins_elapsed = get_request_elapsed(Digit_twins_list)
    if real_elapsed >= twins_elapsed:
        real_count = get_request_count(real_sys_list, twins_elapsed)
        twins_count = get_request_count(Digit_twins_list, twins_elapsed)
    else:
        real_count = get_request_count(real_sys_list, real_elapsed)
        twins_count = get_request_count(Digit_twins_list, real_elapsed)

    return 1 - abs(real_count-twins_count) / real_count


def compare_response_count(real_sys_list: list, Digit_twins_list: list):
    real_elapsed = get_response_elapsed(real_sys_list)
    twins_elapsed = get_response_elapsed(Digit_twins_list)
    if real_elapsed >= twins_elapsed:
        real_count = get_response_count(real_sys_list, twins_elapsed)
        twins_count = get_response_count(Digit_twins_list, twins_elapsed)
    else:
        real_count = get_response_count(real_sys_list, real_elapsed)
        twins_count = get_response_count(Digit_twins_list, real_elapsed)

    return 1 - abs(real_count-twins_count) / real_count
