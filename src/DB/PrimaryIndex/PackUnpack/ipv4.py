import struct
from IPy import IP

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
        return
    
    def unpack(packed):
        """
        The rowkey packed format is: >I (big endian single int)
        The unpacked format is: dot quad string, no leading zeros
        """
        return