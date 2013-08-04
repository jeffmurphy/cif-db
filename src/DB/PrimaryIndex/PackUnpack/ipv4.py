import struct
from IPy import IP, intToIp

class PU_ipv4(object):
    """

    
    """
    def __init__ (self, debug):
        self.debug = debug

    @staticmethod
    def pack(unpacked):
        """
        Given an ipv4 string, pack it so that it can be included in a rowkey
        The rowkey packed format is: >I (big endian single integer)
        """
        ipv = IP(unpacked).version()
        
        if ipv != 4:
            raise Exception("not an ipv4 address")
        
        return struct.pack(">I", IP(unpacked).int())
    
    def unpack(packed):
        """
        The rowkey packed format is: >I (big endian single int)
        The unpacked format is: dot quad string, no leading zeros
        """
        
        if type(packed) != int:
            raise Exception("not an integer")
        
        return intToIp(unpack(">I", packed), 4)