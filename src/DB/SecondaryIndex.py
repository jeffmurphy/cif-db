import happybase
import struct
import re
import getopt
import sys

from DB.Registry import Registry

class SecondaryIndex(object):
    def __init__ (self, hbhost, debug):
        self.debug = debug
        self.registry = Registry(hbhost, debug)
    	self.names_list = [] # name -> enum
    	
    	self.load_secondary_index_map()
    	
    def names(self):
    	return self.index_to_enum.keys()
    	
    def enum(self, name):
    	if name in self.index_to_enum:
    		return self.index_to_enum[name]
    	return None
    	
    def name(self, enum):
    	if enum in self.enum_to_index:
    		return self.enum_to_index[enum]
    	return None
    	
    def load_secondary_index_map(self):
    	siv = self.registry.get('index.secondary')
    	if siv != None:
    		siv_list = []
    		for i in re.split(',', siv):
    			siv_list.append(i.lstrip().rstrip())
		self.names_list = siv_list
	    
        