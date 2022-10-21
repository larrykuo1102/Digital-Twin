
from myParser import VariableAccessSpecification


a0 63(Confirmed-RequestPDU)
    02 02 0d 90(InvokeID : 0d90 =3472) 
    a5 5d (ConfirmedServiceRequest:Write)
        a0 2a (variableAccessSpecification) 
            30 28 (listOfVariable)
                a0 26 (ObjectName)
                    a1 24 (domain-specific)
                        1a 0b   41 51 46 32 35 35 52 65 6c 61 79 
                            1a 15   4f424a33435357493324434f24506f732453424f77                            
        a0 2f 
            a2 2d
                830100a214850103890f454c495053452d49454336313835308601069108000000000000000a83010084020600


a0 30 (confirmed_RequestPDU)
    02 02 06 2a (InvokeID)
        a4 2a (Read-Request)
            a1 28 (VariableAccessSpecification)
                a0 26 (listofVariable)
                    30 24 (VariableSpecification)
                        a0 22 (ObjectName)
                            a1 20 (domain-specific)
                                1a 0b (domainID)
                                    4b4f4331303443314c4430
                                1a 11 (itemID)
                                    4c4c4e3024425224526570436f6e463031


a0 82 01 22 (Confirmed-RequestPDU)    
    02 02 0d 8f (invokeID) 
    a4 82 01 1a (read-Request)        
        a1 82 01 16 (read Request)
            a0 82 01 12 (variableAccessSpecification)
                30 29 (listOfVariable)
                    a0 27 (ObjectName)
                        a1 25(domain-specific)
                            1a0b41514632353552656c61791a16456e657267794d4d54523124535424546f7457682474
                30 29 
                    a0 27(ObjectName)
                        a1251a0b41514632353552656c61791a16456e657267794d4d54523124535424546f7457682471
                30 2e
                    a0 2c(ObjectName)
                        a12a1a0b41514632353552656c61791a1b456e657267794d4d54523124535424546f7457682461637456616c
                30 2b
                    a0 29(ObjectName)
                        a1271a0b41514632353552656c61791a18456e657267794d4d54523124535424546f74564172682474302ba029a1271a0b41514632353552656c61791a18456e657267794d4d54523124535424546f745641726824713030a02ea12c1a0b41514632353552656c61791a1d456e657267794d4d54523124535424546f74564172682461637456616c



a3 5f (Unconfirmed-PDU)
    a0 5d (informationReport)
        a0 2a VariableAccessSpecification
            30 28 (listOfVariable)
                a0 26 (ObjectName)
                    a1 24 (domain-specific)
                        1a0b41514632353552656c61791a154f424a33435357493324434f24506f73244f706572
                a0 2f 
                    a2 2d (ObjectName)
                        83 01 00 a2 
                            14850103890f454c495053452d49454336313835308601069108000000000000000a83010084020600

