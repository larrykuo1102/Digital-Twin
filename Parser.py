

# --------------------------Parser Information--------------------------
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

from http.client import RESET_CONTENT
import this


class Paser() :
    MMS_data = []
    rest_content = ''
    def Parser(self, content ) :
        self.rest_content = content
        
        pass

[ { "MMMPDU": [ { "name1" : "value1", "name2" : ["value2"] }
    
                ] 
   } 
 ]


[ ( "MMMPDU", [ ("name1", "value1"), ("name2", []) ] )
    
]

MMS_data :list 


def getoneByte( hex_value ) : # return value 1. onebyte value, 2. rest of value
    return hex_value[:2], hex_value[2:]

def calculate_hex( hex_value ) : # get a byte value and translate to binary -> return 
    binary_value = bin(int( str(hex_value),16))[2:].zfill(8)
    return binary_value

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

def ASN1_parser( value ) -> dict : # make data to be tag+length+value
    data = {}
    object_byte, rest = getoneByte(value)
    # print(object_byte, rest)
    data['tag'] = object_byte
    
    ####### analyze tag
    # analyze one_data if its first bit is 1 or not
    object_byte_binary = calculate_hex(object_byte) # get binary of a byte ex: a1 -> 10100001
    # check first two bits
    data['tag_type'] = object_byte_binary[:2]
    if ( object_byte_binary[:2] == '00' ) : # universal
        pass
    elif ( object_byte_binary[:2] == '01' ) : # application
        pass
    elif ( object_byte_binary[:2] == '10' ) : # context-specific
        pass
    elif ( object_byte_binary[:2] == '11' ) : # Private
        pass
    # check third bit
    
    # check rest of 5 bits -> number
    
    ########
    
    ######## analyze length    
    data["length"], rest = ASN1_get_length( rest ) 
    ########
    
    
    ######## get the data of length    
    data['value'] = rest[:data["length"]*2]
    
    rest = rest[data["length"]*2:]
    ########
    return data, rest

def MMS_Parser( data : dict ) :
    if data['tag'] == 'a0' :
        confirmed_RequestPDU( data['value'] )
    elif data['tag'] == 'a1' :
        confirmed_ResponsePDU( data['value'] ) 
    
def ISO8823_Parser( data : dict ) :
    if data['tag'] == 'a0' :
        confirmed_RequestPDU( data['value'] )
    elif data['tag'] == 'a1' :
        confirmed_ResponsePDU( data['value'] ) 
    
    data['value']

def Parser( content : str ) -> list : 
    mms = []
    '''
    data = {
        tag : int,
        length : int,
        value : str
    }
    '''
    
    data, content = ASN1_parser(content)
    # Parser()
    # PDU MMS
    while( content != '' ) :
        data, content = ASN1_parser(content)
        # Parser()
    
    
    
    return mms

def confirmed_RequestPDU( content ) :
    data, rest = ASN1_parser(content)
    if ( data['tag'] == 'a0' ) :
        pass
    elif ( data['tag'] == '81' ) :
        pass
    
    pass

def confirmed_ResponsePDU( content ) :
    data = ASN1_parser(content)
    
    pass


# a = input()

print( ASN1_parser("a18102345678") )




