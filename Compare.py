def align(real_sys: list, digital_twins: list):
    # digital_twins_shift: int
    # isAlign: bool = False
    # MMS == true
    # IP == true
    # Request or Response == true
    # read or Write == true
    digital_twins_shift = 0
    isAlign = False
    while isAlign != True:
        real_proto = Is_MMS_or_GOOSE(real_sys[0])
        digit_proto = Is_MMS_or_GOOSE(digital_twins[digital_twins_shift])

        if digital_twins_shift == len(digital_twins):
            break
        if real_proto == digit_proto:
            real_IP = getIP(real_sys[0])
            digit_IP = getIP(digital_twins[digital_twins_shift])
            if real_IP == digit_IP:
                if real_proto == "MMS":
                    # confirmed or unconfirmed
                    real_pdu = Is_Confirmed_or_UnConfirmed(real_sys[0])
                    digit_pdu = Is_Confirmed_or_UnConfirmed(digital_twins[digital_twins_shift])
                    if (real_pdu == digit_pdu) & (real_pdu != None):
                        if real_pdu == "unconfirmed":
                            # read or write
                            real_re = Is_Read_or_Write(real_sys[0])
                            digit_re = Is_Read_or_Write(digital_twins[digital_twins_shift])
                            if (real_re == digit_re) & (real_re != None):
                                isAlign = True
                        else:
                            # response or request
                            real_re = Is_Request_or_Response(real_sys[0])
                            digit_re = Is_Request_or_Response(digital_twins[digital_twins_shift])
                            if (real_re == digit_re) & (real_re != None):
                                # read or write
                                real_re = Is_Read_or_Write(real_sys[0])
                                digit_re = Is_Read_or_Write(digital_twins[digital_twins_shift])
                                if (real_re == digit_re) & (real_re != None):
                                    isAlign = True
                elif real_proto == "GOOSE":
                    pass
                else:
                    pass
            pass

        digital_twins_shift += 1
        pass

    return digital_twins[digital_twins_shift:]


def getIP(pkt: dict) -> dict:
    pktlist = list(pkt.keys())
    return pktlist[0]


def Is_MMS_or_GOOSE(pkt: dict):
    pktlist = list(pkt.keys())
    proto = pktlist[len(pktlist)-1]
    if (proto == "MMS") | (proto == "GOOSE"):
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
