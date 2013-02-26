import syslog
from datetime import datetime
import time
import re
import sys
import threading
import happybase
import struct

sys.path.append('/usr/local/lib/cif-protocol/pb-python/gen-py')

import msg_pb2
import feed_pb2
import control_pb2
import RFC5070_IODEF_v1_pb2
import MAEC_v2_pb2
import cifsupport

class Exploder(object):
    def __init__ (self, connection, debug):
        self.debug = debug
        self.dbh = connection
        t = self.dbh.tables()
        
        if not "infrastructure_botnet" in t:
            raise Exception("missing infrastructure_botnet table")

        self.table = self.dbh.table('infrastructure_botnet')
        self.kickit = threading.Semaphore(0)
        self.proc_thread = threading.Thread(target=self.run, args=())
        self.proc_thread.start()

        
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            syslog.syslog(caller + ": " + msg)
    
    def do_some_work(self):
        self.kickit.release()
        
    def getcheckpoint(self):
        t = self.dbh.table('registry')
        c = t.row('exploder_checkpoint')
        if c != None and 'b:ts' in c:
            return c['b:ts']
        return 0
    
    def setcheckpoint(self, ts):
        t = self.dbh.table('registry')
        t.put('exploder_checkpoint', { 'b:ts': ts })
    
    def pack_rowkey_ipv4(self, salt, addr, hash):
        return None
    
    def pack_rowkey_ipv6(self, salt, addr, hash):
        return None
    
    def run(self):
        self.L("Exploder running")
        
        while True:
            self.L("waiting for work")
            self.kickit.acquire() # will block provided kickit is 0
            self.L("wakup")
            
            co = self.dbh.table('cif_objs')
            startts = self.getcheckpoint()
            endts = int(time.time())
            processed = 0

            self.L("processing: " + str(startts) + " to " + str(endts))
            
            salt = 0xFF00
            srowid = struct.pack(">HIIIII", salt, startts, 0,0,0,0)
            erowid = struct.pack(">HIIIII", salt, endts, 0,0,0,0)

            for key, data in co.scan(row_start=srowid, row_stop=erowid):
                contains = data.keys()[0]
                obj_data = data[contains]
                
                if contains == "cf:RFC5070_IODEF_v1_pb2":
                    iodef = RFC5070_IODEF_v1_pb2.IODEF_DocumentType()
                    try:
                        iodef.ParseFromString(obj_data)

                        print iodef
                        ii = iodef.Incident[0]
                        table_type = ii.Assessment[0].Impact[0].content.content
                        rowkey = None
                        
                        if table_type == "botnet":
                            confidence = ii.Assessment[0].Confidence.content
                            severity = ii.Assessment[0].Impact[0].severity
                            addr_type = ii.EventData[0].Flow[0].System[0].Node.Address[0].category
                            
                            if addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv4_addr or addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv4_net:
                                addr = ii.EventData[0].Flow[0].System[0].Node.Address[0].content
                                rowkey = self.pack_rowkey_ipv4(salt, addr, hash)
                            
                            elif addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv6_addr or addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv6_net:
                                addr = ii.EventData[0].Flow[0].System[0].Node.Address[0].content
                                rowkey = self.pack_rowkey_ipv6(salt, addr, hash)
                                
                        elif table_type == "malware":
                            print "malware"
                                
                    except Exception as e:
                        print "Failed to parse restored object: ", e

    
            #self.setcheckpoint(endts+1)
