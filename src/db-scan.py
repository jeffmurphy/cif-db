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
    print time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pts))
    contains = data.keys()[0]
    obj_data = data[contains]
    print "\t", contains
    iodef = RFC5070_IODEF_v1_pb2.IODEF_DocumentType()
    iodef.ParseFromString(obj_data)
    print iodef
    ii = iodef.Incident
    print ii[0].IncidentID.name
    count = count + 1
    
    # Incident.Assessment.Impact.Content = botnet
    # Incident.Assessment.Confidence.content = 65.0
    # Incident.Assessment.Impact.severity = severity_type_high
    
    
print count, " rows total."





