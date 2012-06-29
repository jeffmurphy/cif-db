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

def unregister(req, cifrouter):
    print "Send UNREGISTER to cif-router (" + cifrouter + ")"
    req.send_multipart(["cif-router", "", "UNREGISTER"])
    reply = req.recv_multipart();
    print "Got reply: " , reply
    if reply[0] == 'UNREGISTERED':
        print "unregistered successfully"
    else:
        print "not sure? " + reply[0]

def register(req, cifrouter):
    routerport = 0
    routerpubport = 0
    
    print "Send REGISTER to cif-router (" + cifrouter + ")"
    req.send_multipart(["cif-router", "", "REGISTER"])
    reply = req.recv_multipart();
    print "Got reply: " , reply
    if reply[0] == 'REGISTERED':
        print "registered successfully"
        rv = json.loads(reply[2])
        routerport = rv['REQ']
        routerpubport = rv['PUB']
    elif reply[0] == 'ALREADY-REGISTERED':
        print "already registered?"

    return (routerport, routerpubport)
        
def ctrlc(req, cifrouter):
    print "Shutting down."
    unregister(req, cifrouter)
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
        print "Got msg: ", msg
        writeToDb(msg)
        
    unregister(req, cifrouter)
    
except KeyboardInterrupt:
    ctrlc(req, cifrouter)
except IOError as e:
    print "I/O error({0}): {1}".format(e.errno, e.strerror)
except KeyError as e:
    print "PB KeyError: ", e
    traceback.print_exc(file=sys.stdout)
except Exception as inst:
    print "Unexpected error: ", sys.exc_info()[0]
     
    