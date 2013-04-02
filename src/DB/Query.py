import datetime
import time
import os
import threading
import zmq
import sys
import hashlib

import socket
import happybase
import struct
import traceback

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
    def __init__ (self, hbhost, debug):
        self.debug = debug
        self.dbh = happybase.Connection(hbhost)

        try:
            self.tbl_ibn = self.dbh.table('infrastructure_botnet')
            self.tbl_co = self.dbh.table('cif_objs')
        except Exception as e:
            self.L("failed to open tables")
            raise
        
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
    we will fetch up to self.limit records matching the query, pack them into
    iodef documents, insert them into the QueryResponse and return that. 
    
    that object (the QR) will be placed back into the control message and sent
    back to the client from which it came.
    """
    def execqr(self):
        self.L("execute query")
        print "query is ", self.qr.query

        qrs = control_pb2.QueryResponse()
        
        if self.qr.query == "infrastructure/botnet":
            # infrastructure/botnet
            self.L("Query for infrastructure/botnet")
            # open the infrastructure_botnet table
            # foreach entry
            #   grab the iodef_rowkey value
            #   open the cif_objs table
            #   grab the row corresponding to the iodef_rowkey 
            #   save those all up in a list
            #   pack it into the queryresponse
            # return the queryresponse
            
            for key, value in self.tbl_ibn.scan():
                iodef_rowkey = value['b:iodef_rowkey']
                iodef_row = self.tbl_co.row(iodef_rowkey)
                _bot = (iodef_row.keys())[0]
                iodoc = iodef_row[_bot]
                bot = (_bot.split(":"))[1]
                print "VALUE ", bot, iodoc
                qrs.baseObjectType.append(bot)
                qrs.data.append(iodoc)
                
        qrs.description = "none"
        qrs.ReportTime = "2013-04-01 00:00:00"

        print "return ", qrs
        return qrs