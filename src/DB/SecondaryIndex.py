import happybase
import struct
import re
import getopt
import sys

from DB.Registry import Registry

class SecondaryIndex(object):
    """
    The secondary index is the table name (index_botnet, index_malware) and 
    corresponds to the second part of the query string. 
    
    infrastructure/botnet
    
    pri = infrastructure (ipv4 and ipv6)
    sec = botnet
    """
    def __init__ (self, connectionPool, debug=0):
        self.debug = debug
        self.pool = connectionPool

        self.registry = Registry(connectionPool, debug)
        self.names_list = []
        self.names_dict = {}
        
        self.load_secondary_index_map()

    def exists(self, name):
        if name in self.names_dict:
            return True
        return False

    def names(self):
        return self.names_list

    def load_secondary_index_map(self):
        siv = self.registry.get('index.secondary')
        if siv != None:
            self.names_list = []
            self.names_dict = {}
            for i in re.split(',', siv):
                n = i.lstrip().rstrip()
                self.names_list.append(n)
                self.names_dict[n] = 1

        
