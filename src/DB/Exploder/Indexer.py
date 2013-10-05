import syslog
from datetime import datetime
import time
import re
import sys
import threading
import happybase
import struct
import hashlib
import base64

sys.path.append('/usr/local/lib/cif-protocol/pb-python/gen-py')

import msg_pb2
import feed_pb2
import control_pb2
import RFC5070_IODEF_v1_pb2
import MAEC_v2_pb2
import cifsupport

from DB.Salt import Salt
from DB.PrimaryIndex import PrimaryIndex
from DB.Log import Log

class Indexer(object):
    """


    """
    def __init__ (self, connectionPool, index_type, num_servers = 1, table_batch_size = 1000, debug = 0):
        self.debug = debug
        print "indexer connect"
        self.pool = connectionPool
        print "indexer load primary index map"
        self.primary_index = PrimaryIndex(connectionPool, debug)
        print "index init log"
        self.log = Log(connectionPool)
        
        self.num_servers = num_servers
        self.packers = {}
        
        for packer in self.primary_index.names():
            try:
                package='DB.PrimaryIndex.PackUnpack'
                self.L("loading packer " + package + "." + packer)
                __import__(package + "." + packer)
                pkg = sys.modules[package + "." + packer]
                self.packers[packer] = getattr(pkg, packer)
            except ImportError as e:
                self.L("warning: failed to load " + packer)
                    
        with self.pool.connection() as dbh:
            t = dbh.tables()
            
            self.table_name = "index_" + index_type
            
            if not self.table_name in t:
                self.L("index table %s doesnt exist, creating it" % (self.table_name))
                dbh.create_table(self.table_name, {'b': {'COMPRESSION': 'SNAPPY'}})
            
            table_batch_size = 5
            
            self.table = dbh.table(self.table_name).batch(batch_size=table_batch_size)
            self.co_table = dbh.table("cif_objs").batch(batch_size=table_batch_size)
            
            self.reset()
            self.md5 = hashlib.md5()
            self.salt = Salt(self.num_servers, self.debug)
    
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            self.log.L(caller + ": " + msg)
            
    def pack_rowkey_ipv4(self, salt, addr):
        return struct.pack(">HB", self.salt.next(), self.TYPE_IPV4()) + self.packers['ipv4'].pack(addr)

    def pack_rowkey_ipv6(self, salt, addr):
        return struct.pack(">HB", self.salt.next(), self.TYPE_IPV6()) + self.packers['ipv6'].pack(addr)
    
    def pack_rowkey_fqdn(self, salt, fqdn):
        return struct.pack(">HB", self.salt.next(), self.TYPE_FQDN()) + self.packers['domain'].pack(fqdn)
    
    def pack_rowkey_url(self, salt, url):
        return struct.pack(">HB", self.salt.next(), self.TYPE_URL()) + self.packers['url'].pack(url)

    def pack_rowkey_email(self, salt, email):
        return struct.pack(">HB", self.salt.next(), self.TYPE_URL()) + self.packers['email'].pack(email)
    
    def pack_rowkey_search(self, salt, search):
        return struct.pack(">HB", self.salt.next(), self.TYPE_SEARCH()) + self.packers['search'].pack(search) 
    
    def pack_rowkey_malware(self, salt, malware_hash):
        return struct.pack(">HB", self.salt.next(), self.TYPE_MALWARE()) + self.packers['malware'].pack(malware_hash) 
    
    def pack_rowkey_asn(self, salt, asn):
        return struct.pack(">HB", self.salt.next(), self.TYPE_ASN()) + self.packers['asn'].pack(asn) 
    
    def reset(self):
        self.empty = True
        self.addr = None
        self.rowkey = None
        self.confidence = None
        self.addr_type = None
        self.iodef_rowkey = None
    
    def commit(self):
        """
        Commit the record to the index_* table
        Update cif_objs(rowkey=self.iodef_rowkey) so that 'b:{self.table_name}_{self.rowkey}' = 1
        Purger will remove the reference when this feed record is purged.
        
        With hbase, you can put an addt'l cell value into a table/row without having to 
        merge. Existing cells won't be affected.
        """
        try:
            rowdict =      {
                                'b:confidence': str(self.confidence),
                                'b:addr_type': str(self.addr_type),
                                'b:iodef_rowkey': str(self.iodef_rowkey)
                            }
            
            self.table.put(self.rowkey, rowdict)
            fmt = "%ds" % (len(self.table_name) + 4)
            prk = struct.pack(fmt, "cf:" + str(self.table_name) + "_") + self.rowkey            
            self.co_table.put(self.iodef_rowkey, { prk: "1" })
            
        except Exception as e:
            self.L("failed to put record to %s table: " % self.table_name)
            print e
        
        self.reset()

            
    def extract(self, iodef_rowkey, iodef):
        """
        FIX atm this is iodef specific. ideally we will be able to index other document types
        """
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
                                    e = self.primary_index.enum(i.ext_category)
                                    if len(e) > 0:
                                        self.rowkey = struct.pack(">HB", self.salt.next(), e[0]) + self.packers[i.ext_category].pack(i.content) 
                                        self.commit()
                                    else:
                                        self.L("Unknown primary index given " + i.ext_category)
                                    
                            else:
                                print "unhandled category: ", i
                    
    def TYPE_IPV4(self):
        return self.primary_index.enum('ipv4')
    
    def TYPE_IPV6(self):
        return self.primary_index.enum('ipv6')
    
    def TYPE_FQDN(self):
        return self.primary_index.enum('domain')
    
    def TYPE_URL(self):
        return self.primary_index.enum('url')
    
    def TYPE_EMAIL(self):
        return self.primary_index.enum('email')
    
    def TYPE_SEARCH(self):
        return self.primary_index.enum('search')
    
    def TYPE_MALWARE(self):
        return self.primary_index.enum('malware')
    
    def TYPE_ASN(self):
        return self.primary_index.enum('asn')
    
    
    
