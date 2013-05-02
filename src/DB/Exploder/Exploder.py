import syslog
from datetime import datetime
import time
import re
import sys
import threading
import socket
import happybase
import struct
import traceback

sys.path.append('/usr/local/lib/cif-protocol/pb-python/gen-py')

import msg_pb2
import feed_pb2
import control_pb2
import RFC5070_IODEF_v1_pb2
import MAEC_v2_pb2
import cifsupport

import Indexer
from DB.Salt import Salt
from DB.Registry import Registry

class Exploder(object):
    def __init__ (self, hbhost, debug):
        self.debug = debug
        self.dbh = happybase.Connection(hbhost)
        t = self.dbh.tables()

        self.table = self.dbh.table('infrastructure_botnet')
        self.kickit = threading.Semaphore(0)
        self.proc_thread = threading.Thread(target=self.run, name="Exploder daemon", args=())
        self.proc_thread.daemon = True
        self.proc_thread.start()
        
        self.registry = Registry(hbhost, debug)
        self.num_servers = self.registry.get('hadoop.num_servers')
        if self.num_servers == None:
            self.num_servers = 1

        self.index_handler = {} # Indexer.Indexer(self.dbh, "botnet", self.num_servers, self.debug)
        
        self.salt = Salt(self.num_servers, self.debug)
        
        
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            syslog.syslog(caller + ": " + msg)
    
    def do_some_work(self):
        self.kickit.release()
        
    def getcheckpoint(self):
        t = self.registry.get('exploder.checkpoint')
        if t != None:
            return t
        return 0
    
    def setcheckpoint(self, ts):
        self.registry.set('exploder.checkpoint', ts)
    
    def run(self):
        self.L("Exploder running")
        
        while True:
            self.L("waiting for work")
            self.kickit.acquire() # will block provided kickit is 0
            self.L("wakup")
            
            co = self.dbh.table('cif_objs')
            
            self.L("connected to cif_objs")
            
            startts = self.getcheckpoint()
            endts = int(time.time())
            processed = 0

            self.L("processing: " + str(startts) + " to " + str(endts))
            
            if startts == 0:
                startts = 1
                
            salt = 0xFF00  # FIX fix in poc-db at the same time (in writeToDb())
            srowid = struct.pack(">HIIIII", salt, startts-1, 0,0,0,0)
            erowid = struct.pack(">HIIIII", salt, endts, 0,0,0,0)

            for key, data in co.scan(row_start=srowid, row_stop=erowid):
                contains = data.keys()[0]
                obj_data = data[contains]
                
                if contains == "cf:RFC5070_IODEF_v1_pb2":
                    iodef = RFC5070_IODEF_v1_pb2.IODEF_DocumentType()
                    try:
                        iodef.ParseFromString(obj_data)

                        #print iodef
                        ii = iodef.Incident[0]
                        table_type = ii.Assessment[0].Impact[0].content.content
                        
                        self.L("\tIndexing: " + table_type)
                        
                        if table_type == "malware":
                            print ii
                
                        if not table_type in self.index_handler:
                            self.index_handler[table_type] = Indexer.Indexer(self.dbh, table_type, self.num_servers, self.debug)
                        
                        self.index_handler[table_type].extract(key, iodef)
                        #self.index_handler[table_type].commit()
                        

                    except Exception as e:
                        print "Failed to parse restored object: ", e
                        traceback.print_exc()

    
            self.setcheckpoint(endts)
            
