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


print(Longest_Common_Subsequence("abcde", "ace"))
print(Longest_Common_Subsequence("fafabcdef", "fadabc"))

# dict1 = {"IP_src":"1234", "IP_dst":"5678"}
# dict2 = {"IP_src":"1234", "IP_dst":"5678"}
# assert dict1 == dict2


def Is_Read_or_Write():
    pass


module_map = {
    'MMS': [['confirmed_RequestPDU', 'confirmed_ResponsePDU', 'unconfirmed_PDU']],
    'confirmed_RequestPDU':  ['invokeID', ['Write_Request', 'Read_Request', 'GetVariableAccessAttributes_Request']],
    'confirmed_ResponsePDU': ['invokeID', ['Read_Response', 'Write_Response', 'GetVariableAccessAttributes_Response']],
    'unconfirmed_PDU': ['informationReport'],
    'Read_Request': ['VariableAccessSpecification'],
    'Read_Response': ['listOfAccessResult'],
    'Write_Request': ['VariableAccessSpecification', 'listofData'],
    'Write_Response': ['VariableAccessSpecification'],
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
    'success': [['structure', 'boolean', 'bit-string', 'integer', 'unsigned', 'visible-string', 'binary-time', 'utc-time', 'utc-time']],
    'structure': [['boolean', 'integer']],
    'informationReport': ['VariableAccessSpecification', 'listOfAccessResult'],
}

input_module = []


def compare_MMS(twins: dict, module_name: str):  # parsered result
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
                        if (each in next_dict.keys()):  # if several module exsits one in twins' data -> keep check next level module
                            check_neccessary = True
                            if not compare_MMS(next_dict, each):
                                check_valid = False
                                assert False, f'module Error {module_name} {each}'
                    if not check_neccessary:
                        check_valid = False
                else:
                    if (neccessary in next_dict.keys()):  # if this module exsits one in twins' data -> keep check next level module
                        if not compare_MMS(next_dict, neccessary):
                            check_valid = False
                            assert False, f'module Error {module_name} {neccessary}'
                    else:
                        check_valid = False
                        assert False, f'module Error {neccessary} missed'
    elif (map_list == None):
        if (module_name == 'ObjectName'):
            print('ObjectName similarity')
            pass
        elif (module_name == 'itemID'):
            print('itemID similarity')
            input_module.append(next_list)
            pass
        elif (module_name == 'domainID'):
            input_module.append(next_list)
            print('domainID similarity')
            pass
        elif (module_name == 'invokeID'):
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


def compare_COTP():
    pass
