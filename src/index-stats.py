#!/usr/bin/python
import happybase
import struct
import re
import getopt
import sys

from DB.Registry import Registry

def usage():
    print "index-stats.py [-h] [-H hbhostname]\n"

def HBConnection(host):
    c = happybase.Connection(host)
    return c

def load_primary_index_map(reg):
    km = {}
    for reg_key in reg.get():
        reg_val = reg.get(reg_key)
        if re.match('^index.primary.', reg_key):
            if type(reg_val) is int:
                x = re.split('\.', reg_key)
                km[reg_val] = x[2]
    return km

try:
    opts, args = getopt.getopt(sys.argv[1:], 'hH:')
except getopt.GetoptError, err:
    print str(err)
    usage()
    sys.exit(2)

hbhost = "localhost"

for o, a in opts:
    if o == "-h":
        usage()
        sys.exit(2)
    elif o == "-H":
        hbhost = a
        
c = HBConnection(hbhost)
registry = Registry(hbhost, False)
num_servers = registry.get('hadoop.num_servers')
if num_servers == None:
    num_servers = 1

primary_index_map = load_primary_index_map(registry)


for table in c.tables():
    if re.match('^index_', table):
        print "\nChecking: ", table
        
        index_entries_per_server = {}
        index_entries_per_primary_index = {}
        
        th = c.table(table)
        for key, value in th.scan():
            salt, dtype = struct.unpack('>HB', key[0:3])
            
            if not salt in index_entries_per_server:
                index_entries_per_server[salt] = 0
            if not primary_index_map[dtype] in index_entries_per_primary_index:
                index_entries_per_primary_index[primary_index_map[dtype]] = 0
                
            index_entries_per_server[salt] = index_entries_per_server[salt] + 1
            index_entries_per_primary_index[primary_index_map[dtype]] = index_entries_per_primary_index[primary_index_map[dtype]] + 1
            
        print "\tIndex entries per server:"
        for server in index_entries_per_server:
            s = server
            if s > num_servers:
                s = str(server) + "*"
            print "\t\tserver=", server, " entries=", index_entries_per_server[server]
        
        print "\tIndex entries per primary index:"
        for p_idx in index_entries_per_primary_index:
            print "\t\tprimary=", p_idx, " entries=", index_entries_per_primary_index[p_idx]
            