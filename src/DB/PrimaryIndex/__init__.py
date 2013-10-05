import happybase
import struct
import re
import getopt
import sys

from DB.Registry import Registry

class PrimaryIndex(object):
	"""
	The primary index is the first part of the query string. Eg. "infrastructure" or "url".
	This corresponds to the third byte of the hbase rowkey. We allow for groups in the
	primary index. For example,
	
	ipv4 = 0
	ipv6 = 1
	infrastructure = ipv4,ipv6
	
	"""
	def __init__ (self, connectionPool, debug=0):
		self.debug = debug
		self.pool = connectionPool
		self.registry = Registry(connectionPool, debug)
		self.index_to_enum = {}  # name -> enum
		self.enum_to_index = {}  # enum -> name
    	
		self.load_primary_index_map()

	def names(self):
		"""
		Return all of the primary index names, including group names.
    	"""
		return self.index_to_enum.keys()

	def is_group(self, name):
		"""
		If the given name is a group, return True else False
		"""
		if name in self.index_to_enum:
			v = self.index_to_enum[name]
			if type(v) is not int:
				return True
		return False
	
	def reduce_group(self, name):
		"""
		If the given name is a group, return [group member names]
		else return [name]
		"""
		if name in self.index_to_enum:
			v = self.index_to_enum[name]
			if type(v) is int:
				return [name]

		rv = []

		for innername in re.split(',', self.index_to_enum[name]):
			rv.append(innername.lstrip().rstrip())
			
		return rv
	
	def enum(self, name):
		"""
		Return the enum value(s) for the given primary index name.
		This function returns a list. In the case where the given index name
		is a group, multiple enum values will be returned.
    	""" 
		enums = []
		if name in self.index_to_enum:
			v = self.index_to_enum[name]
			if type(v) is int:
				return v
			else:
				for innername in re.split(',', v):
					enums.append(self.enum(innername.lstrip().rstrip()))

		return enums

	def name(self, enum):
		"""
		Given an index enumeration value, return the name of the index
		"""
		if enum in self.enum_to_index:
			return self.enum_to_index[enum]
		return None

	def load_primary_index_map(self):	    
		for reg_key in self.registry.get():
			reg_val = self.registry.get(reg_key)
			if re.match('^index.primary.', reg_key):
				x = re.split('\.', reg_key)
				self.index_to_enum[x[2]] = reg_val
				if type(reg_val) is int:
					self.enum_to_index[reg_val] = x[2]

