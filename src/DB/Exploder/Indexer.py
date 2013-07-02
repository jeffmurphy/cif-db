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

class Indexer(object):
    """
    feeds = infrastructure (addresses), domain, url, email, search, malware
    rowkey types:
        ipv4    = 0x0   (infrastructure/botnet)
        ipv6    = 0x1   (infrastructure/botnet)
        fqdn    = 0x2   (domain/botnet)
        url     = 0x3   (url/botnet)
        email   = 0x4   (email/botnet)
        search  = 0x5   (search/botnet)
        malware = 0x6   (maleware/botnet)
        asn     = 0x7   (asn/botnet)
        
    
    tablename: index_botnet
    key: salt + address or salt + fqdn
         address is left padded with nulls into a 16 byte field
         fqdn is simply appended
    columns:
        b:prefix, asn, asn_desc, rir, cc, confidence, addr_type, port, ip_proto
    """
    def __init__ (self, hbhost, index_type, num_servers = 1, debug = 0):
        self.debug = debug
        self.dbh = happybase.Connection(hbhost)

        self.num_servers = num_servers
        
        t = self.dbh.tables()
        
        self.table_name = "index_" + index_type
        
        if not self.table_name in t:
            self.dbh.create_table(self.table_name, {'b': {'COMPRESSION': 'SNAPPY'}})
            
        self.table = self.dbh.table(self.table_name).batch(batch_size=5) # FIX increase for prod
        
        self.reset()
        self.md5 = hashlib.md5()
        self.salt = Salt(self.num_servers, self.debug)
    
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            syslog.syslog(caller + ": " + msg)
            
    def pack_rowkey_ipv4(self, salt, addr):
        """
        rowkey: salt (2 bytes) + keytype(0x0=ipv4) + packedaddr(4 bytes)
        """
        if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', addr) != None:
            a = addr.split(".")
            b = int(a[0])<<24 | int(a[1])<<16 | int(a[2])<<8 | int(a[3])
            #print "making rowkey for ", self.addr, " int=", b
            return struct.pack(">HBI", self.salt.next(), self.TYPE_IPV4(), b) 
        else:
            raise Exception("Not an ipv4 addr: " + addr)
        
    def pack_rowkey_ipv6(self, salt, addr):
        """
        rowkey: salt (2 bytes) + keytype(0x1=ipv6) + packedaddr(16 bytes)
        """
        return struct.pack(">HBIIII", self.salt.next(), self.TYPE_IPV6(), self.addr) 
    
    def pack_rowkey_fqdn(self, salt, fqdn):
        """
        rowkey: salt (2 bytes) + keytype(0x2=fqdn) + string(first 10 chars)
        """
        l = len(str(fqdn))
        fqdn = fqdn[::-1]  # reversed
        fmt = ">HB%ds" % l
        return struct.pack(fmt, self.salt.next(), self.TYPE_FQDN(), str(fqdn)) 
    
    def pack_rowkey_url(self, salt, url):
        l = len(str(url))
        url = url[::-1]  # reversed
        fmt = ">HB%ds" % l
        return struct.pack(fmt, self.salt.next(), self.TYPE_URL(), str(url)) 

    
    def pack_rowkey_email(self, salt, email):
        l = len(str(email))
        email = email[::-1]  # reversed
        fmt = ">HB%ds" % l
        return struct.pack(fmt, self.salt.next(), self.TYPE_URL(), str(email)) 
    
    def pack_rowkey_search(self, salt, search):
        l = len(str(search))
        search = search[::-1]  # reversed
        fmt = ">HB%ds" % l
        return struct.pack(fmt, self.salt.next(), self.TYPE_SEARCH(), search) 
    
    def pack_rowkey_malware(self, salt, malware_hash):
        l = len(str(malware_hash))
        malware_hash = malware_hash[::-1]  # reversed
        fmt = ">HB%ds" % l
        return struct.pack(fmt, self.salt.next(), self.TYPE_MALWARE(), str(malware_hash)) 
    
    def pack_rowkey_asn(self, salt, asn):
        return struct.pack(">HBI", self.salt.next(), self.TYPE_ASN(), int(asn)) 
    
    def reset(self):
        self.empty = True
        self.addr = None
        self.rowkey = None
        self.confidence = None
        self.addr_type = None
        self.iodef_rowkey = None
    
    def commit(self):
        try:
            rowdict =      {
                                'b:confidence': str(self.confidence),
                                'b:addr_type': str(self.addr_type),
                                'b:iodef_rowkey': str(self.iodef_rowkey)
                            }
            
            self.table.put(self.rowkey, rowdict)
        except Exception as e:
            self.L("failed to put record to %s table: " % self.table_name)
            print e
        
        self.reset()

            
    def extract(self, iodef_rowkey, iodef):
        self.reset()

        self.iodef_rowkey = iodef_rowkey
        
        self.md5.update(iodef.SerializeToString())
        self.hash = self.md5.digest()
    
        ii = iodef.Incident[0]
        
        #print ii
        
        self.confidence = ii.Assessment[0].Confidence.content
        self.severity = ii.Assessment[0].Impact[0].severity
        
        # for malware hashes, they appear at the top level for now
        # iodef.incident[].additionaldata.meaning = "malware hash"
        # iodef.incident[].additionaldata.content = "[the hash]"
        
        if hasattr(ii, 'AdditionalData'):
            print "\tHas top level AdditionalData"
            for ed in ii.AdditionalData:
                #print "ED ", ed
                if ed.meaning == "malware hash":
                    self.L("\tIndexing for malware hash")
                    self.rowkey = self.pack_rowkey_malware(self.salt.next(), ed.content)
                    self.commit()
        
        # addresses and networks are in the EventData[].Flow[].System[] tree
        
        if len(ii.EventData) > 0 or hasattr(ii, 'EventData'):
            
            for ed in ii.EventData:
                for fl in ed.Flow:
                    for sy in fl.System:
                        for i in sy.Node.Address:
                            self.addr_type = i.category
                            
                            if self.addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv4_addr or self.addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv4_net:
                                self.addr = i.content
                                self.rowkey = self.pack_rowkey_ipv4(self.salt.next(), self.addr)
                                self.L("Indexing for ipv4")
                                
                                self.commit()
                                
                            # ipv6 addresses and networks
                            
                            elif self.addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv6_addr or self.addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ipv6_net:
                                self.addr = i.content
                                self.rowkey = self.pack_rowkey_ipv6(self.salt.next(), self.addr)
                                self.L("Indexing for ipv6")
                                
                                self.commit()
                            
                            elif self.addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_asn:
                                self.addr = i.content
                                self.rowkey = self.pack_rowkey_ipv6(self.salt.next(), self.addr)
                                self.L("Indexing for ASN")
                                
                                self.commit()
                            
                            elif self.addr_type == RFC5070_IODEF_v1_pb2.AddressType.Address_category_ext_value:
                                if i.ext_category == "fqdn":
                                    self.fqdn = i.content
                                    self.rowkey = self.pack_rowkey_fqdn(self.salt.next(), self.fqdn)
                                    self.L("Indexing for FQDDN")
                                    
                                    self.commit()
                                elif i.ext_category == "url":
                                    self.rowkey = self.pack_rowkey_url(self.salt.next(), i.content)
                                    self.L("Indexing for URL")
                                    
                                    self.commit()
                                    
                            else:
                                print "unhandled category: ", i
                    
    def TYPE_IPV4(self):
        return 0
    
    def TYPE_IPV6(self):
        return 1
    
    def TYPE_FQDN(self):
        return 2
    
    def TYPE_URL(self):
        return 3
    
    def TYPE_EMAIL(self):
        return 4
    
    def TYPE_SEARCH(self):
        return 5
    
    def TYPE_MALWARE(self):
        return 6
    
    def TYPE_ASN(self):
        return 7
    
    
    
