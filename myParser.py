

# --------------------------ASN1&BER Parser Information--------------------------
# I.    object code 1byte 8 bits
#       01                                                                   2                                   34567
#       00(universal) 01(Application) 10(context-specific) 11(Private)      1(sequence, set, choice) 0(value)    tab number
#       a1(1010 0001)            81(1000 0001)

# II.   length 3 types
#       1. short definite -> 2 bytes length value
#       2. long definite -> start with 81 (1000 0001) *first bit has to be 1
#       3. infinite

# III.  X length content

# --------------------------End--------------------------

import json


class _Parser():
    MMS_data = []
    rest_content = ''

    def Parser(self, content):
        self.rest_content = content
        pass


[{"MMMPDU": [{"name1": "value1", "name2": ["value2"]}

             ]
  }
 ]


def getoneByte(hex_value) -> str:  # return value 1. onebyte value, 2. rest of value
    return str(hex_value[:2]), str(hex_value[2:])


def calculate_hex(hex_value: str):  # get a byte value and translate to binary -> return
    binary_value = bin(0)
    if (hex_value != ''):
        binary_value = bin(int(str(hex_value), 16))[2:].zfill(8)
    return str(binary_value)


def ASN1_check_length_type(value) -> int:  # value is a byte of hex ex: FF
    # return 1 : short definite 2: long definite 3: infinite
    binary_value = calculate_hex(value)
    if (binary_value[0] == '0'):
        return 1
    elif (binary_value[0] == '1' and int(binary_value[1:], 2) != 0):
        return 2
    else:
        return 3


def ASN1_get_length(content):  # return length and rest of content
    first_byte, rest = getoneByte(content)
    length_type = ASN1_check_length_type(first_byte)
    tlv_length: int
    if (length_type == 1):
        tlv_length = int(first_byte, 16)
    elif (length_type == 2):
        byte_length = int(calculate_hex(first_byte)[1:], 2)  # a08'1'83
        # print( byte_length )
        byte_length_content = ''
        for i in range(byte_length):
            second_byte, rest = getoneByte(rest)
            byte_length_content += second_byte
            tlv_length = int(byte_length_content, 16)
    elif (length_type == 3):
        print("ASN1_get_length 3 infinite type !")
    else:
        print("ASN1_get_length failed!")

    return tlv_length, rest


def ASN1_parser(value: str) -> dict:  # make data to be tag+length+value
    '''
    data = {
        tag : int,
        tag_type : str,
        length : int,
        value : str
    }
    '''
    data = {}
    object_byte, rest = getoneByte(value)
    data['tag'] = object_byte

    object_byte_binary = calculate_hex(object_byte)  # get binary of a byte ex: a1 -> 10100001
    # check first two bits

    data['tag_type'] = str(object_byte_binary[:2])  # analyze tag type

    data["length"], rest = ASN1_get_length(rest)  # analyze length

    data['value'] = rest[:data["length"]*2]  # get the data of length

    rest = rest[data["length"]*2:]

    return dict(data), rest


def MMS_Parser(value: str, mms_data: list):
    temp_dict = {}
    temp_list = []
    mms_data.append(temp_dict)

    data, rest = ASN1_parser(value)

    if data['tag'] == 'a0':
        temp_dict['confirmed_RequestPDU'] = temp_list
        rest = confirmed_RequestPDU(data['value'], temp_list)
    elif data['tag'] == 'a1':
        temp_dict['confirmed_ResponsePDU'] = temp_list
        rest = confirmed_ResponsePDU(data['value'], temp_list)
    elif data['tag'] == 'a3':
        temp_dict['unconfirmed_PDU'] = temp_list
        rest = unconfirmed_PDU(data['value'], temp_list)
    return rest


def ISO8823_Parser(value: str):
    data, rest = ASN1_parser(value)
    if data['tag'] == 'a0':
        confirmed_RequestPDU(data['value'])
    elif data['tag'] == 'a1':
        rest = confirmed_ResponsePDU(data['value'])

    data['value']
    return rest


def confirmed_RequestPDU(value: str, mms_data: list):
    temp_dict = {}
    mms_data.append(temp_dict)

    data, rest = ASN1_parser(value)
    if (data['tag'] == '02'):  # invokeID
        temp_dict['invokeID'] = data['value']

    data, rest = ASN1_parser(rest)
    if (data['tag'] == 'a5'):  # write
        temp_list = []
        temp_dict['Write_Request'] = temp_list
        rest = Write_Request(data['value'], temp_list)
    elif (data['tag'] == 'a4'):
        temp_list = []
        temp_dict['Read_Request'] = temp_list
        rest = Read_Request(data['value'], temp_list)
        pass

    return rest


def Write_Request(value: str, mms_data: list):
    temp_dict = {}
    mms_data.append(temp_dict)

    data, rest = ASN1_parser(value)
    if (data['tag'] == 'a0'):
        temp_list = []
        temp_dict['VariableAccessSpecification'] = temp_list
        rest = VariableAccessSpecification(data['value'], temp_list)

    return rest


def Read_Response(value: str, mms_data: list):
    temp_dict = {}
    temp_list = []
    mms_data.append(temp_dict)
    temp_dict['listOfAccessResult'] = temp_list
    rest = listOfAccessResult(value, temp_list)

    return rest


def Read_Request(value: str, mms_data: list):
    temp_dict = {}
    mms_data.append(temp_dict)
    data, rest = ASN1_parser(value)

    if (data['tag'] == 'a1'):
        temp_list = []
        temp_dict['VariableAccessSpecification'] = temp_list
        rest = VariableAccessSpecification(data['value'], temp_list)

    return rest


def VariableAccessSpecification(value: str, mms_data: list):
    temp_dict = {}
    temp_list = []
    mms_data.append(temp_dict)

    data, rest = ASN1_parser(value)
    rest2 = rest
    if (data['tag'] == '30'):
        temp_list = []
        temp_dict['listofVariable'] = temp_list
        listofVariable(data['value'], temp_list)
    elif (data['tag'] == 'a0'):
        temp_list = []
        temp_dict['listofVariable2'] = temp_list
        rest = listofVariable(data['value'], temp_list)
    elif data['tag'] == 'a1':
        temp_list = []
        temp_dict['variableListName'] = temp_list
        variableListName(data['value'], temp_list)
    return rest2


def listOfAccessResult(value: str, mms_data: list):
    temp_dict = {}
    temp_list = []
    mms_data.append(temp_dict)
    data, rest = ASN1_parser(value)
    print(data, "\n", rest)
    temp_dict['AccessResult'] = temp_list
    rest = AccessResult(data['value'], temp_list)
    while rest != "":
        temp_dict = {}
        temp_list = []
        mms_data.append(temp_dict)
        temp_dict['AccessResult'] = temp_list
        rest = AccessResult(rest, temp_list)

    return rest


def listofVariable(value: str, mms_data: list):  # 'list'ofVariable
    temp_dict = {}
    mms_data.append(temp_dict)

    data, rest = ASN1_parser(value)
    # 可能會有很多個 這個地方要再改
    if (data['tag'] == 'a0'):
        temp_list = []
        temp_dict['VariableSpecification'] = temp_list
        rest = VariableSpecification(value, temp_list)

    elif (data['tag'] == '30'):
        temp_list = []
        temp_dict['listofVariable'] = temp_list
        listofVariable(data['value'], temp_list)
        while (rest != ''):
            data, rest = ASN1_parser(rest)
            if (data['tag'] == '30'):
                temp_list = list()
                temp_dict = dict()
                mms_data.append(temp_dict)
                temp_dict['listofVariable'] = temp_list
                listofVariable(data['value'], temp_list)
    return rest


def VariableSpecification(value: str, mms_data: list):
    temp_dict = {}
    mms_data.append(temp_dict)

    data, rest = ASN1_parser(value)
    if (data['tag'] == 'a0'):
        temp_list = []
        temp_dict['ObjectName'] = temp_list
        rest = ObjectName(data['value'], temp_list)
    return rest


def variableListName(value: str, mms_data: list):
    temp_dict = {}
    temp_list = []
    mms_data.append(temp_dict)

    data, rest = ASN1_parser(value)
    temp_dict['ObjectName'] = data['value']
    return rest


def ObjectName(value: str, mms_data: list):
    temp_dict = {}
    mms_data.append(temp_dict)
    data, rest = ASN1_parser(value)
    if (data['tag'] == 'a1'):
        temp_list = []
        temp_dict['domain-specific'] = temp_list
        data, rest = ASN1_parser(data['value'])
        if (data['tag'] == '1a'):
            temp_list.append({"domainID": data['value']})
        data, rest = ASN1_parser(rest)
        if (data['tag'] == '1a'):
            temp_list.append({"itemID": data['value']})
    elif (data['tag'] == 'a0'):
        pass
    return rest


def AccessResult(value: str, mms_data: list):
    temp_dict = {}
    temp_list = []
    mms_data.append(temp_dict)
    temp_dict['success'] = temp_list
    rest = Data(value, temp_list)
    return rest


def Data(value: str, mms_data: list):
    data, rest = ASN1_parser(value)
    if data['tag'] == 'a2':
        temp_dict = {}
        temp_list = []
        temp_iist2 = []
        mms_data.append(temp_dict)
        temp_dict['structure'] = temp_list
        structure(data['value'], temp_list)
    elif data['tag'] == '83':
        mms_data.append({"boolean": data['value']})
    elif data['tag'] == '84':
        mms_data.append({"bit-string": data['value']})
    elif data['tag'] == '85':
        mms_data.append({"integer": data['value']})
    elif data['tag'] == '86':
        mms_data.append({"unsigned": data['value']})
    elif data['tag'] == '8a':
        mms_data.append({"visible-string": data['value']})
    elif data['tag'] == '8c':
        mms_data.append({"binary-time": data['value']})
    elif data['tag'] == '91':
        mms_data.append({"utc-time": data['value']})
    elif data['tag'] == '89':
        mms_data.append({"octet-string": data['value']})
    return rest


def structure(value: str, mms_data: list):
    data, rest = ASN1_parser(value)
    if data['tag'] == '83':
        mms_data.append({"boolean": data['value']})
    elif data['tag'] == '85':
        mms_data.append({"integer": data['value']})
    while rest != "":
        rest = Data(rest, mms_data)
    return rest


def informationReport(value: str, mms_data: list):
    temp_dict = {}
    temp_list = []
    temp_list2 = []
    mms_data.append(temp_dict)

    temp_dict['VariableAccessSpecification'] = temp_list
    rest = VariableAccessSpecification(value, temp_list)
    temp_dict['listOfAccessResult'] = temp_list2
    rest = listOfAccessResult(rest, temp_list2)
    return rest


def confirmed_ResponsePDU(value: str, mms_data: list):
    temp_dict = {}
    mms_data.append(temp_dict)

    data, rest = ASN1_parser(value)
    if (data['tag'] == '02'):  # invokeID
        temp_dict['invokeID'] = data['value']

    data, rest = ASN1_parser(rest)
    if (data['tag'] == 'a4'):  # read
        temp_list = []
        temp_dict['Read_Response'] = temp_list
        rest = Read_Response(data['value'], temp_list)
    elif (data['tag'] == '81'):
        pass

    return rest


def unconfirmed_PDU(value: str, mms_data: list):
    temp_dict = {}
    temp_list = []
    mms_data.append(temp_dict)

    data, rest = ASN1_parser(value)
    if data['tag'] == 'a0':
        temp_dict['informationReport'] = temp_list
        rest = informationReport(data['value'], temp_list)

    return rest


def Parser(content: str, protocol: str) -> list:
    MMS_data: list = []
    rest = ''
    data, content = ASN1_parser(content)

    if (protocol == 'ISO8823' and data["tag"] == '61'):
        rest = ISO8823_Parser(data['value'])
    elif (protocol == 'MMS'):
        temp_dict = {}
        temp_list = []
        temp_dict['MMS'] = temp_list
        MMS_data.append(temp_dict)
        rest = MMS_Parser(data['value'], temp_list)
        return MMS_data
    elif (protocol == 'GOOSE'):
        pass


# test_input = "a962a0600202021ba55aa0273025a023a1211a0a5245463632304354524c1a134342435357493124434f24506f732453424f77a02fa22d830101a214850103890f454c495053452d49454336313835308601009108000000000000000a83010084020600"
#test_input = "a01ca11a020215aba414a11291086322c3739df3b6bf8403030000830100"
test_input = "a081c6a381c3a081c0a1058003525054a081b68a1453454c3735314346472f4c4c4e30245250244d588403067880860200f78c06014540d337398a1753454c3735314346472f4c4c4e302444617461536574318601018403010004a268a212850101840303000091086322a1dd92b020bfa212830100840303000091086322a1dd92b020bfa21684020640840303000091086322be4389fbe7bf830100a212830100840303000091086322a1dd92b020bfa212830100840303000091086322a1dd92b020bf84020240 "
#test_input = "a07fa07d02020226a477a175a0733023a021a11f1a0953454c373531414e4e1a124c544747494f3524535424496e64303524743023a021a11f1a0953454c373531414e4e1a124c544747494f3524535424496e64303524713027a025a1231a0953454c373531414e4e1a164c544747494f3524535424496e64303524737456616c"
#test_input = "a05ea35ca05aa0273025a023a1211a0a5245463632304354524c1a134342435357493124434f24506f73244f706572a02fa22d830101a214850103890f454c495053452d49454336313835308601009108000000000000000a83010084020600"
parsed = json.dumps(Parser(test_input, "MMS"), indent=2)
print(parsed)
# print(Parser(test_input, "MMS"))
