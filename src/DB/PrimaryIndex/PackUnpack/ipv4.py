import struct
from IPy import IP, intToIp

class ipv4(object):
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
    
    @staticmethod
    def unpack(packed):
        """
        The rowkey packed format is: >I (big endian single int)
        The unpacked format is: dot quad string, no leading zeros
        """
        
        if len(packed) != 4:
            raise Exception("not a 4 byte buffer")
        
        return intToIp(unpack(">I", packed), 4)