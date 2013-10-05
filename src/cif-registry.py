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

from DB.Registry import Registry

def HBConnection(hbhost):
    pool = happybase.ConnectionPool(size=25, host=hbhost)
    return pool

    
def usage():
    print "cif-registry.py [-D #] [-h] [-d key] [-k key] [-t int|float|double|long|str] [-v value]\n\n"
    

def cast(t, v):
    if t in ["int"]:
        return int(v)
    if t in ["long"]:
        return long(v)
    if t in ["double", "float"]:
        return float(v)
    return str(v)
                
try:
    opts, args = getopt.getopt(sys.argv[1:], 't:v:k:d:D:H:h')
    
    debug = 0
    key_type = None
    key_value = None
    key_name = None
    del_name = None
    hbhost = "localhost"
    
    for o, a in opts:
        if o == "-t":
            key_type = a
        elif o == "-H":
            hbhost = a
        elif o == "-v":
            key_value = a
        elif o == "-k":
            key_name = a
        elif o == "-d":
            del_name = a
        elif o == "-h":
            usage()
            sys.exit(2)
        elif o == "-D":
            debug = a
    
    connectionPool = HBConnection(hbhost)
    reg = Registry(connectionPool, debug)
    
    if del_name != None:
        reg.delete(del_name)
        kv = reg.get(del_name)
        if kv != None:
            print "Failed to delete the key: it seems to still be in the database."
            
    elif key_name != None:
        if key_type != None and key_value != None:
            key_value = cast(key_type, key_value)
            reg.set(key_name, key_value)
            kv = reg.get(key_name)
            if kv == key_value:
                print key_name + " has been set to " + str(key_value)
            else:
                print "Failed? you gave me: " + str(key_value) + " but the database has " + str(kv)
        else:
            kv = reg.get(key_name)
            print key_name + " = " + str(kv) + " " + str(type(kv))

    else:
        kl = reg.get()
        print "Available keys: ", kl

    
except getopt.GetoptError as err:
    print str(err)
    usage()
    sys.exit(2)
except Exception as e:
    print e
    traceback.print_tb(sys.exc_info()[2])

    usage()
    sys.exit(2)
    


