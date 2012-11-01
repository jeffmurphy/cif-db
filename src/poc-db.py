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

sys.path.append('../../libcif/lib')
from CIF.CtrlCommands.Clients import *
from CIF.Foundation import Foundation
from DB.APIKeys import *

print "cif-db proof of concept"

"""
Two threads:

Attach to cif-router PUB:
    Subscribe to all message types
    Write all messages we receive to HBase

Attach to cif-router ROUTER:
    When we receive a query request:
        retrieve the requested information
        send it back to the requester
"""




    
def usage():
    print "\
    # poc-subscriber [-c 5656] [-r cif-router:5555] [-m name]\n\
    #     -c  control port (REQ - for inbound messages)\n\
    #     -r  cif-router hostname:port\n\
    #     -m  my name\n"
    

def HBConnection(host):
    c = happybase.Connection(host)
    t = c.tables()
    print "found tables: ", t
    if not "cif_idl" in t:
        raise Exception("missing cif_idl table")
    if not "cif_objs" in t:
        raise Exception("missing cif_objs table")
    return c

"""
Given a msg object, we want to record its IDL (for posterity)
to cif_idl if it hasn't been already. We then write the actual object
to cif_objs.

#     rowkey $salt$timestamp$hash   (eg "<2 byte salt><8 byte timestamp><16 byte md5>")
#     cf:$submsgtype     (eg cf:RFC5070-IODEF-v1=object)



"""

def saveIDL(cif_idl, sr):
    #bot = sr.baseObjectType;
    bot = re.sub('_', '-', sr.baseObjectType)
    fn = cifsupport.installBase() + "/" + bot + ".proto"
    print "IDL should be: " + fn
    
def writeToDb(cif_objs, cif_idl, sr):
    print "\tWrite message(s) to db: "  + str(sr.baseObjectType)
    ts = int(time.time()) # ignore fractional seconds
    md5 = hashlib.md5()
    md5.update(sr.SerializeToString())
    hash = md5.digest()
    colspec = "cf:" + str(sr.baseObjectType)
    salt = 0xFF00
    try:
        saveIDL(cif_idl, sr)
        rowid = struct.pack("II16s", salt, ts, hash)
        cif_objs.put(rowid, {colspec: sr.data})
        print "\tput: rowid:" + rowid.encode('hex') + " " + colspec + " "
    except struct.error, err:
        print "Failed to pack rowid: ", err

def controlMessageHandler(msg):
    print "controlMessageHandler: Got a control message: ", msg
    if msg.type == control_pb2.ControlType.COMMAND:
        if msg.command == control_pb2.ControlType.PING:
                c = Clients.makecontrolmsg(msg.dst, msg.src, msg.apikey)
                c.status = control_pb2.ControlType.SUCCESS
                c.type = control_pb2.ControlType.REPLY
                c.command = msg.command
                c.seq = msg.seq
                cf.sendmsg(c, None)
    
try:
    opts, args = getopt.getopt(sys.argv[1:], 'c:r:m:D:h')
except getopt.GetoptError, err:
    print str(err)
    usage()
    sys.exit(2)

controlport = "5656"
cifrouter = "sdev.nickelsoft.com:5555"
myid = "cif-db"
apikey = "a8fd97c3-9f8b-477b-b45b-ba06719a0088"
debug = 0

for o, a in opts:
    if o == "-c":
        controlport = a
    elif o == "-m":
        myid = a
    elif o == "-r":
        cifrouter = a
    elif o == "-h":
        usage()
        sys.exit(2)
    elif o == "-D":
        debug = a

myip = socket.gethostbyname(socket.gethostname()) # has caveats

global cf

try:
    print "Connect to HBase"
    connection = HBConnection('localhost')
    cif_objs = connection.table('cif_objs').batch(batch_size=5) # set very low for development, set to 1000+ for test/qa/prod
    cif_idl = connection.table('cif_idl')
    apikeys = APIKeys(connection, True)
    
    apikey = apikeys.get_by_alias(myid)
        
    cf = Foundation({'apikey' : apikey,
                     'myip'   : myip,
                     'cifrouter' : cifrouter,
                     'controlport' : controlport,
                     'myid' : myid,
                     'routerid' : "cif-router"
                     })


    cf.setdebug(debug)
    cf.setdefaultcallback(controlMessageHandler)
    
    print "Register with " + cifrouter + " (req->rep)"
    req = cf.ctrlsocket()

    # apikey, req, myip, myid, cifrouter
    (routerport, routerpubport) = cf.register()

    subscriber = cf.subscribersocket()
    
    time.sleep(1) # wait for router to connect, sort of lame but see this a lot in zmq code
    
    while True:
        msg = msg_pb2.MessageType()
        msg.ParseFromString(subscriber.recv())
        
        if apikeys.is_valid(msg.apikey):
            if msg.type == msg_pb2.MessageType.SUBMISSION and len(msg.submissionRequest) > 0:
                print "Got a SUBMISSION. Saving."
                for i in range(0, len(msg.submissionRequest)):
                    writeToDb(cif_objs, cif_idl, msg.submissionRequest[i])
            
            elif msg.type == msg_pb2.MessageType.QUERY and len(msg.queryRequest) > 0:
                print "Got a QUERY. Processing."
                for i in range(0, len(msg.submissionRequest)):
                    qreply = readFromDb(msg.queryRequest[0])
                    msg.reply.append(qreply)
                print "Gathered replies from DB. Sending back to requester. TODO"
            
            else:
                print "Wrong or empty message recvd on subscriber port. Expected submission or query (" + \
                    str(msg_pb2.MessageType.SUBMISSION) + " or " +                               \
                    str(msg_pb2.MessageType.QUERY) + ")  got " +                                 \
                    str(msg.type) + " number of parts (should be > 0) SR:" +                     \
                    str(len(msg.submissionRequest)) + " / QR:" + str(len(msg.queryRequest)) 
        else:
            print "message has an invalid apikey"
            
    cf.unregister()
    
except KeyboardInterrupt:
    cif_objs.send() # flush
    cf.ctrlc()
except IOError as e:
    print "I/O error({0}): {1}".format(e.errno, e.strerror)
except KeyError as e:
    print "PB KeyError: ", e
    traceback.print_exc(file=sys.stdout)
except Exception as inst:
    print "Unexpected error: ", sys.exc_info()[0], " ", sys.exc_info()[1], " "
    traceback.print_tb(sys.exc_info()[2])
except TTransportException as e:
    print "Can't connect to HBase"
    
