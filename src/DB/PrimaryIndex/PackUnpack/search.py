import struct

class search(object):
    """

    
    """
    def __init__ (self, debug):
        self.debug = debug

    @staticmethod
    def pack(unpacked):
        """
        Given an search (string), pack it so that it can be included in a rowkey
        The rowkey packed format is: a string
        """

        return str(unpacked)
    
    @staticmethod
    def unpack(packed):
        """
        The rowkey packed format is: a reversed string
        The unpacked format is: a string
        """
        
        return str(packed)
    