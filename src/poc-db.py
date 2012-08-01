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

# adjust to match your $PREFIX if you specified one
# default PREFIX = /usr/local
sys.path.append('/usr/local/lib/cif-protocol/pb-python/gen-py')

import msg_pb2
import feed_pb2
import control_pb2
import RFC5070_IODEF_v1_pb2
import MAEC_v2_pb2
import cifsupport

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



def ctrlsocket(myname, cifrouter):
    # Socket to talk to cif-router
    req = context.socket(zmq.REQ);
    req.setsockopt(zmq.IDENTITY, myname)
    req.connect('tcp://' + cifrouter)
    return req

def subscribersocket(publisher):
    # Socket to publish from
    print "Creating subscriber socket and connecting to " + publisher
    subscriber = context.socket(zmq.SUB)
    subscriber.connect('tcp://' + publisher)
    subscriber.setsockopt(zmq.SUBSCRIBE, '')
    return subscriber

def unregister(req, apikey, cifrouter, myid):
    print "Send UNREGISTER to cif-router (" + cifrouter + ")"
    
    msg = control_pb2.ControlType()
    msg.version = msg.version # required
    msg.apikey = apikey
    msg.type = control_pb2.ControlType.COMMAND
    msg.command = control_pb2.ControlType.UNREGISTER
    msg.dst = 'cif-router'
    msg.src = myid
    msg.apikey = apikey;
    
    req.send(msg.SerializeToString())
    
    reply = req.recv()
    msg.ParseFromString(reply)
    
    try:
        cifsupport.versionCheck(msg)
    except Exception as e:
        print "Received message was bad: ", e
    else:
        print "\tGot reply."
        if msg.status == control_pb2.ControlType.SUCCESS:
            print "\t\tunregistered successfully"
        else:
            print "\t\tnot sure? " + msg.status

def register(apikey, req, myip, myid, cifrouter):
    routerport = 0
    routerpubport = 0
    
    print "Send REGISTER to cif-router (" + cifrouter + ")"
    
    msg = control_pb2.ControlType()
    msg.version = msg.version # required
    msg.apikey = apikey
    msg.type = control_pb2.ControlType.COMMAND
    msg.command = control_pb2.ControlType.REGISTER
    msg.dst = 'cif-router'
    msg.src = myid
    print " Sending REGISTER: " #, msg
    
    req.send_multipart([msg.SerializeToString(), ''])
    reply = req.recv_multipart();

    print " REGISTER Got reply: " #, reply
    msg.ParseFromString(reply[0])

    #print " REGISTER decoded: ", msg
    routerport = msg.registerResponse.REQport
    routerpubport = msg.registerResponse.PUBport
    if msg.status == control_pb2.ControlType.SUCCESS:
        print "  registered successfully"
        return (routerport, routerpubport)
    elif msg.status == control_pb2.ControlType.DUPLICATE:
        print "  already registered?"
        return (routerport, routerpubport)
    else:
        print "  register failed."

    return (0,0)

def ctrlc(req, apikey, cifrouter, myid):
    print "Shutting down."
    unregister(req, apikey, cifrouter, myid)
    sys.exit(0)
    
def usage():
    print "\
    # poc-subscriber [-c 5656] [-r cif-router:5555] [-m name]\n\
    #     -c  control port (REQ - for inbound messages)\n\
    #     -r  cif-router hostname:port\n\
    #     -m  my name\n"
    
def ctrl(rep, controlport):
    print "Creating control socket on :" + controlport
    # Socket to accept control requests on
    rep = context.socket(zmq.REP);
    rep.bind('tcp://*:' + controlport);

def HBConnection(host):
    c = happybase.Connection(host)
    t = c.tables()
    print "found tables: ", t
    if not "cifidl" in t:
        print "missing cifidl table"
    if not "cifobjs" in t:
        print "missing cifobjs table"
        
def writeToDb(msg):
    print "Write message to db"
    
global req

try:
    opts, args = getopt.getopt(sys.argv[1:], 'c:r:m:h')
except getopt.GetoptError, err:
    print str(err)
    usage()
    sys.exit(2)

controlport = "5656"
cifrouter = "sdev.nickelsoft.com:5555"
myid = "poc-db"

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

myip = socket.gethostbyname(socket.gethostname()) # has caveats

print "ZMQ::Context"

context = zmq.Context()
myname = myip + ":" + controlport + "|" + myid

try:
    print "Connect to HBase"
    connection = HBConnection('localhost')
    
    print "Register with " + cifrouter + " (req->rep)"
    req = ctrlsocket(myname, cifrouter)
    (routerport, routerpubport) = register(req, cifrouter)
    routerhname = cifrouter.split(':')

    subscriber = subscribersocket(routerhname[0] + ":" + str(routerpubport))
    
    time.sleep(1) # wait for router to connect, sort of lame but see this a lot in zmq code
    
    while True:
        msg = msg_pb2.MessageType()
        msg.ParseFromString(subscriber.recv())
        if msg.type == msg_pb2.MessageType.SUBMISSION and len(msg.submissionRequest) > 0:
            print "Got msg with: ", msg.submissionRequest[0].baseObjectType
            writeToDb(msg)
        else:
            print "Wrong or empty message recvd on subscriber port. Expected submission ("  +
                str(msg_pb2.MessageType.SUBMISSION) + ") got " +
                str(msg.type) + " number of parts (should be > 0) " +
                str(len(msg.submissionRequest)) 
                 
    unregister(req, apikey, cifrouter, myid)
    
except KeyboardInterrupt:
    ctrlc(req, apikey, cifrouter, myid)
except IOError as e:
    print "I/O error({0}): {1}".format(e.errno, e.strerror)
except KeyError as e:
    print "PB KeyError: ", e
    traceback.print_exc(file=sys.stdout)
except Exception as inst:
    print "Unexpected error: ", sys.exc_info()[0]
     
    