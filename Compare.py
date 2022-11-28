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
    all_length = 0
    for idx in real_names:
        all_length += len(idx)
    print(all_subq)
    print(all_length)
    return all_subq / all_length

def compare_domainID(real_sys_ID: str, digit_twins_ID: str):
    subsq = Longest_Common_Subsequence(real_sys_ID, digit_twins_ID)
    return len(subsq) / len(real_sys_ID)

print(compare_itemID('4c544747494f3524535424496e6430352474','4c544747494f3524535424496e64303524737456616c'))
# print(compare_itemID("4d56474150433124535424496e64312474","4c544747494f3524535424496e64303524737456616c"))
# print(compare_itemID("4d56474150433124535424496e643124737456616c","4c544747494f3524535424496e6430352474"))
# print(compare_itemID("MVGAPC1$ST$Ind1$t", "LTGGIO5$ST$Ind05$q"))
