#!/usr/bin/python


import sys
import zmq
import random
import time
import os
import datetime
import json
import getopt
import socket
import happybase
import hashlib
import struct
import traceback
import re

# adjust to match your $PREFIX if you specified one
# default PREFIX = /usr/local
sys.path.append('/usr/local/lib/cif-protocol/pb-python/gen-py')

import msg_pb2
import feed_pb2
import control_pb2
import RFC5070_IODEF_v1_pb2
import MAEC_v2_pb2
import cifsupport

def HBConnection(host):
    c = happybase.Connection(host)
    t = c.tables()
    print "found tables: ", t
    if not "cif_idl" in t:
        raise Exception("missing cif_idl table")
    if not "cif_objs" in t:
        raise Exception("missing cif_objs table")
    return c

def tots(dt):
    if dt != None:
        return int(time.mktime(time.strptime(dt, "%Y-%m-%d-%H-%M-%S")))
    return 0
    
def usage():
    print "\
    db-scan.py [-s starttime] [-e endtime]\n\
        -s  start time YYYY-MM-DD-HH-MM-SS (def: start-5mins)\n\
        -e  start time YYYY-MM-DD-HH-MM-SS (def: now)\n\
    hour is in 24 hour format\n"
    
    
try:
    opts, args = getopt.getopt(sys.argv[1:], 's:e:D:h')
except getopt.GetoptError, err:
    print str(err)
    usage()
    sys.exit(2)
    
debug = 0
starttime = -1
endtime = -1


for o, a in opts:
    if o == "-s":
        starttime = tots(a)
    elif o == "-e":
        endtime = tots(a)
    elif o == "-h":
        usage()
        sys.exit(2)
    elif o == "-D":
        debug = a

if starttime == -1 and endtime != -1:
    starttime = endtime - 300
elif starttime != -1 and endtime == -1:
    endtime = starttime + 300
elif starttime == -1 and endtime == -1:
    endtime = time.time()
    starttime = endtime - 300
    
print "start=", starttime, " end=", endtime

salt = 0xFF00
srowid = struct.pack(">HIIIII", salt, starttime, 0,0,0,0)
erowid = struct.pack(">HIIIII", salt, endtime, 0,0,0,0)

print "start ", hex(salt), srowid.encode('hex') 
print "end   ", erowid.encode('hex')

connection = HBConnection('localhost')
tbl = connection.table('cif_objs')

print "Dumping cif_objs"

count = 0

for key, data in tbl.scan(row_start=srowid, row_stop=erowid):
    psalt, pts = struct.unpack(">HI", key[:6])
    print "entered on: ", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pts))
    contains = data.keys()[0]
    obj_data = data[contains]
    print "contains: ", contains
    count = count + 1

    if contains == "cf:RFC5070_IODEF_v1_pb2":
        iodef = RFC5070_IODEF_v1_pb2.IODEF_DocumentType()

        try:
            iodef.ParseFromString(obj_data)
            
            ii = iodef.Incident[0]
            table_type = ii.Assessment[0].Impact[0].content.content
            confidence = ii.Assessment[0].Confidence.content
            severity = ii.Assessment[0].Impact[0].severity
            addr_type = ii.EventData[0].Flow[0].System[0].Node.Address[0].category
            
            addr = ii.EventData[0].Flow[0].System[0].Node.Address[0].content
        
            prefix = 'na'
            asn = 'na'
            asn_desc = 'na'
            rir = 'na'
            cc = 'na'
            
            # addr_type == 5 then AddtData will contain asn, asn_desc, cc, rir, prefix
            if addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv4_addr:
                for i in ii.EventData[0].Flow[0].System[0].AdditionalData:
                    if i.meaning == 'prefix':
                        prefix = i.content
                    elif i.meaning == 'asn':
                        asn = i.content
                    elif i.meaning == 'asn_desc':
                        asn_desc = i.content
                    elif i.meaning == 'rir':
                        rir = i.content
                    elif i.meaning == 'cc':
                        cc = i.content

                            
            print "\ttype: ", table_type
            print "\tconfidence: ", confidence
            print "\tseverity: ", severity
            print "\taddr_type: ", addr_type
            print "\taddr: ", addr, prefix, asn, asn_desc, rir, cc
            

            
        except Exception as e:
            print "Failed to restore message to stated type: ", e

    
print count, " rows total."





