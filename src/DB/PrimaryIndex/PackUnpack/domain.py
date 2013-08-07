import struct

class domain(object):
    """

    
    """
    def __init__ (self, debug):
        self.debug = debug

    @staticmethod
    def pack(unpacked):
        """
        Given an domain (string), pack it so that it can be included in a rowkey
        The rowkey packed format is: a reversed string
        """
        fqdn = unpacked[::-1]  # reversed
        #fmt = "%ds" % l
        #return struct.pack(fmt, str(fqdn)) 
        return str(fqdn)
    
    @staticmethod
    def unpack(packed):
        """
        The rowkey packed format is: a reversed string
        The unpacked format is: a string
        """
        
        return str(packed[::-1])
    