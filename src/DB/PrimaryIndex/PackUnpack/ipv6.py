import struct
from IPy import IP, intToIp

class ipv6(object):
    """

    
    """
    def __init__ (self, debug):
        self.debug = debug

    @staticmethod
    def pack(unpacked):
        """
        Given an ipv6 string, pack it so that it can be included in a rowkey
        The rowkey packed format is: >IIII (big endian quad integer)
        """
        ip = IP(unpacked)
        
        if ip.version() != 6:
            raise Exception("not an ipv6 address")
        
        return struct.pack(">IIII", 
                           (i.int() >> 96) & 0xFFFFFFFF,
                           (i.int() >> 64) & 0xFFFFFFFF,
                           (i.int() >> 32) & 0xFFFFFFFF,
                           (i.int()        & 0xFFFFFFFF) )

    @staticmethod
    def unpack(packed):
        """
        The rowkey packed format is: >IIII (big endian quad int)
        The unpacked format is: std ipv6 colon separated format
        """
        
        if len(packed) != 16:
            raise Exception("not a 16 byte buffer")
        
        bb = unpack(">IIII", packed)
        i = (bb[0] << 96) | (bb[1] << 64) | (bb[2] << 32) | bb[3]
        
        return IP(i, 6)