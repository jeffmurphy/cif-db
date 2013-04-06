import datetime
import time
import os
import threading
import zmq
import sys
import hashlib

sys.path.append('/usr/local/lib/cif-protocol/pb-python/gen-py')
import msg_pb2
import feed_pb2
import RFC5070_IODEF_v1_pb2
import MAEC_v2_pb2
import control_pb2
import cifsupport

"""
Accept a queryRequest, look inside of it and see what is being 
queried. Call the appropriate handler. Handler should return 
a queryResponse object 
"""

class Query(object):
    def __init__ (self, qr, limit, debug):
        self.debug = debug
        self.qr = qr
        self.limit = limit
 
    def L(self, msg):
       caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
       if self.debug != None:
           print caller + ": " + msg
       else:
           syslog.syslog(caller + ": " + msg)
           
    def setqr(self, qr):
        self.qr = qr
    
    def setlimit(self, limit):
        self.limit = limit

    """
    libcif hashes queries and only sends the hash and not the actual query text.
    for now, we do a switch/case on those hashes to process each query type
    
    we will fetch up to self.limit records matching the query, pack them into
    iodef documents, insert them into the QueryResponse and return that. 
    
    that object (the QR) will be placed back into the control message and sent
    back to the client from which it came.
    """
    def execqr(self):
        self.L("execute query")
        print "query is ", self.qr.query

        qrs = control_pb2.QueryResponse()
        
        if self.qr.query == "ca2d339a50fa8da9b894076ed04236041071a1f0":
            # infrastructure/botnet
            self.L("Query for infrastructure/botnet")
            

        print "return ", qrs
        return qrs