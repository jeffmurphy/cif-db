import struct

class asn(object):
    """

    
    """
    def __init__ (self, debug):
        self.debug = debug

    @staticmethod
    def pack(unpacked):
        """
        Given an ASN (uint), pack it so that it can be included in a rowkey
        The rowkey packed format is: >I (big endian single integer)
        """
        
        if type(unpacked) != int:
            raise Exception("ASN not an int")
        
        return struct.pack(">I", unpacked)
    
    @staticmethod
    def unpack(packed):
        """
        The rowkey packed format is: >I (big endian single int)
        The unpacked format is: an integer
        """
        
        if len(packed) != 4:
            raise Exception("not a 4 byte buffer")
        
        return unpack(">I", packed)