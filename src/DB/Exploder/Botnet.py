import syslog
from datetime import datetime
import time
import re
import sys
import threading
import happybase
import struct
import hashlib

sys.path.append('/usr/local/lib/cif-protocol/pb-python/gen-py')

import msg_pb2
import feed_pb2
import control_pb2
import RFC5070_IODEF_v1_pb2
import MAEC_v2_pb2
import cifsupport

from DB.Salt import Salt

class Botnet(object):
    """
    tablename: infrastructure_botnet
    key: salt + address or salt + fqdn
         address is left padded with nulls into a 16 byte field
         fqdn is simply appended
    columns:
        b:prefix, asn, asn_desc, rir, cc, confidence, addr_type, port, ip_proto
    """
    def __init__ (self, connection, debug):
        self.debug = debug
        self.dbh = connection
        t = self.dbh.tables()
        
        if not "infrastructure_botnet" in t:
            raise Exception("missing infrastructure_botnet table")

        self.table = connection.table('infrastructure_botnet').batch(batch_size=5)
        
        self.reset()
        self.md5 = hashlib.md5()
        self.salt = Salt()
        
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            syslog.syslog(caller + ": " + msg)
            
    def pack_rowkey_ipv4(self, salt, addr):
        if re.match(r'^[0-9]\,[0-9]\.[0-9]\.[0-9]$', addr) != None:
            a = addr.split(".")
            b = int(a[0])<<24 | int(a[1])<<16 | int(a[2])<<8 | int(a[3])
            print "making rowkey for ", self.addr, " int=", b
            return struct.pack(">HIIII", self.salt.next(), 0, 0, 0, b) 
        else:
            raise Exception("Not an ipv4 addr: " + addr)
    def pack_rowkey_ipv6(self, salt, addr):
        return struct.pack(">HIIII", self.salt.next(), self.addr) 
    
    def pack_rowkey_fqdn(self, salt, fqdn):
        return None
    
    def reset(self):
        self.empty = True
        self.prefix = None
        self.asn = None
        self.asn_desc = None
        self.rir = None
        self.cc = None
        self.addr = None
        self.rowkey = None
        self.confidence = None
        self.addr_type = None
        self.port = None
        self.proto = None
        self.hash = None
    
    def commit(self):
        if self.empty == False:
            self.L("committing")
            try:
                self.table.put(self.rowkey, 
                               {
                                    'b:prefix': self.prefix,
                                    'b:asn': self.asn,
                                    'b:asn_desc': self.asn_desc,
                                    'b:rir': self.rir,
                                    'b:cc': self.cc,
                                    'b:confidence': self.confidence,
                                    'b:addr_type': self.addr_type,
                                    'b:port': self.port,
                                    'b:proto': self.proto
                                })
            except Exception as e:
                self.L("failed to put record to infra_botnet table: " + e.strerror)
        else:
            self.L("nothing to commit")
            
    def extract(self, iodef):
        self.reset()
        
        self.md5.update(iodef.SerializeToString())
        self.hash = self.md5.digest()
    
        ii = iodef.Incident[0]
        
        self.confidence = ii.Assessment[0].Confidence.content
        self.severity = ii.Assessment[0].Impact[0].severity
        self.addr_type = ii.EventData[0].Flow[0].System[0].Node.Address[0].category
        
        # ipv4 addresses and networks
        
        if self.addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv4_addr or self.addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv4_net:
            self.addr = ii.EventData[0].Flow[0].System[0].Node.Address[0].content
            self.rowkey = self.pack_rowkey_ipv4(self.salt.next(), self.addr)

            if 'Port' in ii.EventData[0].Flow[0].System[0].Service:
                self.port = ii.EventData[0].Flow[0].System[0].Service.Port
            if 'ip_proto' in ii.EventData[0].Flow[0].System[0].Service:
                self.proto = ii.EventData[0].Flow[0].System[0].Service.ip_protocol
                
            for i in ii.EventData[0].Flow[0].System[0].AdditionalData:
                    if i.meaning == 'prefix':
                        self.prefix = i.content
                    elif i.meaning == 'asn':
                        self.asn = i.content
                    elif i.meaning == 'asn_desc':
                        self.asn_desc = i.content
                    elif i.meaning == 'rir':
                        self.rir = i.content
                    elif i.meaning == 'cc':
                        self.cc = i.content
        
            self.empty = False
            
        # ipv6 addresses and networks
        
        elif self.addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv6_addr or self.addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv6_net:
            self.addr = ii.EventData[0].Flow[0].System[0].Node.Address[0].content
            self.rowkey = self.pack_rowkey_ipv6(self.salt.next(), self.addr)
            
            for i in ii.EventData[0].Flow[0].System[0].AdditionalData:
                    if i.meaning == 'prefix':
                        self.prefix = i.content
                    elif i.meaning == 'asn':
                        self.asn = i.content
                    elif i.meaning == 'asn_desc':
                        self.asn_desc = i.content
                    elif i.meaning == 'rir':
                        self.rir = i.content
                    elif i.meaning == 'cc':
                        self.cc = i.content
        
            self.empty = False
        