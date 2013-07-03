import happybase
import struct
import re
import getopt
import sys

from DB.Registry import Registry

class PrimaryIndex(object):
    def __init__ (self, hbhost, debug):
        self.debug = debug
        self.registry = Registry(hbhost, debug)
    	self.index_to_enum = {} # name -> enum
    	self.enum_to_index = {} # enum -> name
    	
    	self.load_primary_index_map()
    	
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
    			
    def load_primary_index_map():	    
	    for reg_key in self.registry.get():
	        reg_val = self.registry.get(reg_key)
	        if re.match('^index.primary.', reg_key):
	            if type(reg_val) is int:
	                x = re.split('\.', reg_key)
	                self.index_to_enum[x[2]] = reg_val
	                self.enum_to_index[reg_val] = x[2]
	    
        