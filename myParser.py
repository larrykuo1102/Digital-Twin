

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

class _Parser() :
    MMS_data = []
    rest_content = ''
    def Parser(self, content ) :
        self.rest_content = content
        
        pass

[ { "MMMPDU": [ { "name1" : "value1", "name2" : ["value2"] }
    
                ] 
   } 
 ]





def getoneByte( hex_value ) -> str : # return value 1. onebyte value, 2. rest of value
    return str(hex_value[:2]), str(hex_value[2:])

def calculate_hex( hex_value : str ) : # get a byte value and translate to binary -> return
    binary_value = bin(0)
    if ( hex_value != '' ) :
        binary_value = bin(int( str(hex_value),16))[2:].zfill(8)
    return str(binary_value)

def ASN1_check_length_type( value ) -> int : # value is a byte of hex ex: FF
    # return 1 : short definite 2: long definite 3: infinite
    binary_value = calculate_hex(value)
    if ( binary_value[0] == '0' ) :
        return 1
    elif ( binary_value[0] == '1' and int( binary_value[1:], 2) != 0 ) :
        return 2
    else : 
        return 3
    

def ASN1_get_length( content ) : # return length and rest of content
    first_byte, rest = getoneByte( content )
    length_type = ASN1_check_length_type( first_byte )
    tlv_length : int
    if ( length_type == 1 ) :
        tlv_length = int( first_byte, 16 )
    elif ( length_type == 2 ) :
        byte_length =  int(calculate_hex( first_byte )[1:], 2) # a08'1'83
        # print( byte_length )
        byte_length_content = ''
        for i in range( byte_length ) :
            second_byte, rest = getoneByte( rest )
            byte_length_content += second_byte
            tlv_length = int(byte_length_content, 16)
    elif ( length_type == 3 ) :
        print( "ASN1_get_length 3 infinite type !")
    else :
        print( "ASN1_get_length failed!")
        
    
    return tlv_length, rest

def ASN1_parser( value : str ) -> dict : # make data to be tag+length+value
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
    
    object_byte_binary = calculate_hex(object_byte) # get binary of a byte ex: a1 -> 10100001
    # check first two bits
    
    data['tag_type'] = str(object_byte_binary[:2]) # analyze tag type
    
    data["length"], rest = ASN1_get_length( rest ) # analyze length  
      
    data['value'] = rest[:data["length"]*2] # get the data of length  
    
    rest = rest[data["length"]*2:]
    
    return dict(data), rest

def MMS_Parser( value : str, mms_data : list ) :
    temp_dict = {}
    mms_data.append( temp_dict )
    
    data, rest = ASN1_parser(value)
    if data['tag'] == 'a0' :
        temp_list = []
        temp_dict['Confirmed_RequestPDU'] = temp_list
        rest = Confirmed_RequestPDU( data['value'], temp_list )
    elif data['tag'] == 'a1' :
        temp_list = []
        temp_dict['Confirmed_ResponsePDU'] = temp_list
        rest = Confirmed_ResponsePDU( data['value'], temp_list ) 
    elif data['tag'] == 'a3' :
        temp_list = []
        temp_dict['Unconfirmed_ResponsePDU'] = temp_list
        rest = Unconfirmed_ResponsePDU( data['value'], temp_list ) 
    return rest
    
def ISO8823_Parser( value : str ) :
    data, rest = ASN1_parser(value)
    if data['tag'] == 'a0' :
        Confirmed_RequestPDU( data['value'] )
    elif data['tag'] == 'a1' :
        rest = confirmed_ResponsePDU( data['value'] ) 
    
    data['value']
    return rest


def Confirmed_RequestPDU( value : str, mms_data : list ) :
    temp_dict = {}
    mms_data.append( temp_dict )
    
    data, rest = ASN1_parser(value)
    if ( data['tag'] == '02') : # invokeID
        temp_dict['invokeID'] = data['value']
        
    data, rest = ASN1_parser(rest)
    if ( data['tag'] == 'a5' ) : # write
        temp_list = []
        temp_dict['Write_Request'] = temp_list
        rest = Write_Request( data['value'], temp_list )
    elif ( data['tag'] == 'a4') : # read
        temp_list = []
        temp_dict['Read_Request'] = temp_list
        rest = Read_Request( data['value'], temp_list )
    elif ( data['tag'] == '81' ) :
        pass
    
    return rest

def Write_Request( value : str, mms_data : list ) :
    temp_dict = {}
    mms_data.append( temp_dict )
    
    data, rest = ASN1_parser(value)
    if ( data['tag'] == 'a0') :
        temp_list = []
        temp_dict['VariableAccessSpecification'] = temp_list
        rest = VariableAccessSpecification( data['value'], temp_list )
    
    return rest

def Read_Request( value : str, mms_data : list) :
    temp_dict = {}
    mms_data.append( temp_dict)

    data, rest = ASN1_parser(value)
    if (data['tag'] == 'a0') :
        temp_list =[]
        temp_dict['VariableAccessSpecification'] =temp_list
        rest = VariableAccessSpecification( data['value'], temp_list)

    return rest

def VariableAccessSpecification( value : str, mms_data : list ) :
    temp_dict = {}
    mms_data.append( temp_dict )
    
    data, rest = ASN1_parser(value)
    if ( data['tag'] == '30') :
        temp_list = []
        temp_dict['listofVariable'] = temp_list
        listofVariable( data['value'], temp_list )
        
    return rest
    

def listofVariable( value : str, mms_data : list ) : # 'list'ofVariable
    temp_dict = {}
    mms_data.append( temp_dict )
    
    data, rest = ASN1_parser(value) 
    # 可能會有很多個 這個地方要再改
    if ( data['tag'] == 'a0') :
        temp_list = []
        temp_dict['ObjectName'] = temp_list
        rest = ObjectName( data['value'], temp_list )
        
    return rest

def ObjectName( value : str, mms_data : list ) :
    temp_dict = {}
    mms_data.append( temp_dict )
    
    data, rest = ASN1_parser(value)
    if ( data['tag'] == 'a1' ) :
        temp_list = []
        temp_dict['domain-specific'] = temp_list
        data,rest = ASN1_parser(data['value'])
        if ( data['tag'] == '1a') :
            temp_list.append({"domainID" : data['value']})
        data,rest = ASN1_parser(rest)
        if ( data['tag'] == '1a') :
            temp_list.append({"itemID" : data['value']})
    elif ( data['tag'] == 'a0') :
        pass
    
    return rest
    

def confirmed_ResponsePDU( value : str, mms_data : list ) :
    temp_dict = {}
    mms_data.append( temp_dict )
    
    data, rest = ASN1_parser(value)
    if ( data['tag'] == '02') : # invokeID
        temp_dict['invokeID'] = data['value']
        
    data, rest = ASN1_parser(rest)
    if ( data['tag'] == 'a5' ) : # write
        temp_list = []
        temp_dict['Write_Response'] = temp_list
        rest = Write_Response( data['value'], temp_list )
    elif ( data['tag'] == 'a4') : # read
        temp_list = []
        temp_dict['Read_Response'] = temp_list
        rest = Read_Response( data['value'], temp_list )
    elif ( data['tag'] == '81' ) :
        pass
    
    return rest


def Parser( content : str, protocol : str ) -> list : 
    MMS_data :list = []
    rest = ''
    data, content = ASN1_parser(content)
    
    if ( protocol == 'ISO8823' and data["tag"] == '61' ) : 
        rest = ISO8823_Parser( data['value'] )
    elif ( protocol == 'MMS') :
        temp_dict = {}
        temp_list = []
        temp_dict['MMS'] = temp_list
        MMS_data.append( temp_dict )
        rest = MMS_Parser(data['value'], temp_list)
        return MMS_data
    elif ( protocol == 'GOOSE') :
        pass
    

test_input =   "a9ffa082012202020d8ea482011aa1820116a08201123029a027a1251a0b41514632353552656c61791a16456e657267794d4d54523124535424546f74576824743029a027a1251a0b41514632353552656c61791a16456e657267794d4d54523124535424546f7457682471302ea02ca12a1a0b41514632353552656c61791a1b456e657267794d4d54523124535424546f7457682461637456616c302ba029a1271a0b41514632353552656c61791a18456e657267794d4d54523124535424546f74564172682474302ba029a1271a0b41514632353552656c61791a18456e657267794d4d54523124535424546f745641726824713030a02ea12c1a0b41514632353552656c61791a1d456e657267794d4d54523124535424546f74564172682461637456616c"
# test_input = "a962a06302020d90a55da02a3028a026a1241a0b41514632353552656c61791a154f424a33435357493324434f24506f732453424f77a02fa22d830100a214850103890f454c495053452d49454336313835308601069108000000000000000a83010084020600"
# test_input = "a962a0600202021ba55aa0273025a023a1211a0a5245463632304354524c1a134342435357493124434f24506f732453424f77a02fa22d830101a214850103890f454c495053452d49454336313835308601009108000000000000000a83010084020600"    
a = Parser(test_input, "MMS")
print(a)

