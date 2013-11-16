import datetime
import time
import os
import threading
import zmq
import sys, traceback
import hashlib
import re

import struct

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

from IPy import IP
from DB.Registry import Registry
from urlparse import urlparse

"""
Accept a queryRequest, look inside of it and see what is being 
queried. Call the appropriate handler. Handler should return 
a queryResponse object 
"""

class Query(object):
    def __init__ (self, connectionPool, p_index, s_index, debug):
        self.debug = debug
        self.primary_index = p_index
        self.secondary_index = s_index
        self.pool = connectionPool
        
        try:
            self.registry = Registry(connectionPool, debug)
            self.num_servers = self.registry.get('hadoop.num_servers')
            
            if self.num_servers == None:
                self.num_servers = 1

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
                self.tbl_co = dbh.table('cif_objs')
                self.available_tables = dbh.tables()
            
        except Exception as e:
            self.L("failed to open tables")
            print e
            raise

    def L(self, msg):
       caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
       if self.debug != None and self.debug > 0:
           print caller + ": " + msg
       else:
           syslog.syslog(caller + ": " + msg)
    
    def decode_query(self, qstring):
        """
        Given a query string, return a dictionary containing:
        
        { 'primary' : [INTEGER COUPLE],
          'prinames' : [STRING COUPLE],
          'secondary' : STRING,
          'limiter' : { 'type' : INTEGER, 
                        'value' : STR
                        }
        }
        
        eg: (infra = ipv4, ipv6 = 0, 1)
        
        infrastructure/botnet
        
        { 'primary' : [0,1], 'secondary' : 'botnet', 'limiter' : None }
        
        infrastructure/botnet,10.10.0.0/16
        
        { 'primary' : [0,1], 'secondary' : 'botnet', 'limiter' : { 'type' : 0, 'value' : '10.10.0.0/16' } }
        
        Where 'type', above, is a guess based on the types of things we expect to be queried for:
        IP addresses, domain names, email addresses, URLs
        
        What can we do with this? We can open the correct secondary index table. We can pack the rowkey
        based on the primary index. If the primary index is a couple, we set a start and stop rowkey. 
        If it's only a single value, we use it as a row prefix. If we have a limiter, we pack it based on 
        its type. 
        
        """
        
        rv = {}
        
        if re.match(r'^[a-z0-9]+/[a-z0-9]+$', qstring, flags=re.IGNORECASE):
            # "primary/secondary" only 
            
            indexparts = re.split('/', qstring)
            
            if len(indexparts) != 2:
                raise Exception("Query prefix not in the form of index1/index2")
            
            pi_enum = self.primary_index.enum(indexparts[0])
            
            if type(pi_enum) is int:
                pi_enum = [pi_enum]  # primary was not a group, so we only got a single enum back
                
            if len(pi_enum) > 0 and self.secondary_index.exists(indexparts[1]) == True:
                rv['primary'] = pi_enum
                rv['prinames'] = self.primary_index.reduce_group(indexparts[0])
                rv['secondary'] = indexparts[1]
                rv['limiter'] = { 'type' : None, 'value' : None }
            
        elif re.match(r'^[a-z0-9]+/[a-z0-9]+,', qstring, flags=re.IGNORECASE):
            # "primary/secondary,limiter" both specified

            qparts = re.split(',', qstring)
            
            if len(qparts) > 2:
                qparts[1] = qparts[1:].join('')
                del qparts[2:]
            
            indexparts = re.split('/', qparts[0])
            
            if len(indexparts) != 2:
                raise "Query prefix not in the form of index1/index2"
            
            pi_enum = self.primary_index.enum(indexparts[0])
            
            if type(pi_enum) is int:
                pi_enum = [pi_enum]  # primary was not a group, so we only got a single enum back
                
            limit_enum = self.guesstypeof(qparts[1])
            
            # make sure they didn't give us, eg, an email limiter for a ipv4 primary index
            
            if not limit_enum in pi_enum:
                raise Exception("Limiter mismatched with primary index")
        
            pi_enum = [limit_enum]
            
            if len(pi_enum) > 0 and self.secondary_index.exists(indexparts[1]) == True:
                rv['primary'] = pi_enum
                rv['prinames'] = self.primary_index.name(limit_enum)
                rv['secondary'] = indexparts[1]
                rv['limiter'] = { 'type' : self.guesstypeof(qparts[1]), 'value' : qparts[1] }
        
        else:
            # "limiter" only specified
            
            rv['primary'] = [self.guesstypeof(qstring)]
            rv['prinames'] = self.primary_index.name(self.guesstypeof(qstring))
            rv['secondary'] = None
            rv['limiter'] = { 'type' : self.guesstypeof(qstring), 'value' : qstring }
        
        return rv
    
    def guesstypeof(self, s):
        """
        Try to figure out which primary index apply to the given string.
        ipv4, ipv6, url, email, domain
        
        This information is useful when we get a limiter with no pri/sec hints. So 
        if the query is "10.10.0.0" we want to know that it's an ipv4 address so we can
        construct the start and stop rowkey appropriately.
        """

        try:
            ipv = IP(s).version()
            if ipv == 4:
                return self.primary_index.enum('ipv4')
            if ipv == 6:
                return self.primary_index.enum('ipv6')
        except ValueError as e:
            try:
                o = urlparse(s)

                # a hash, eg 10299abe93984f8e8d8e9f
                if o.scheme == '' and re.match(r'^[0-9a-f]+$', o.path, flags=re.IGNORECASE) != None:
                    return self.primary_index.enum('malware')
                
                # an email, blah@example.com
                if o.scheme == '' and re.search(r'@', o.path) != None:
                    return self.primary_index.enum('email')

                # a domainname
                if o.scheme == '' and re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$', o.path) != None:
                    return self.primary_index.enum('domain')
                
                # a url
                if o.scheme != '':
                    return self.primary_index.enum('url')
                
                # an asn
                if o.scheme == '' and re.match(r'^[\d+]$', o.path) != None:
                    return self.primary_index.enum('asn')
                
            except ValueError as e:
                return self.primary_index.enum('search')

        return self.primary_index.enum('search')
    
    def setqr(self, qr):
        self.qr = qr

    def ipv4_to_start_end_ints(self, v4):
        """
        Given (possibly) a cidr block, return the start addr and
        end addr (plus one) as ints. if no mask given, end = start
        """
        p = v4.split('/')
        octs = p[0].split('.')
        if len(octs) != 4:
            self.L ("ipv4_to_start_end_ints: Invalid parameter: " + str(v4))
            return 0

        for i in range(0,4):
            octs[i] = int(octs[i])

        start = octs[0] << 24 | octs[1] << 16 | octs[2] << 8 | octs[3]
        if len(p) == 2:
            maskbits = int(p[1])
            if int(maskbits) < 0 or int(maskbits) > 32:
                self.L ("ipv4_to_start_end_ints: Invalid bitmask: " + maskbits)
                return 0

            mask = 2**maskbits - 1
            end = start | mask
            end = end + 1
        else:
            end = start
        return [start, end]
        
    def setlimit(self, limit):
        self.limit = limit

    """
    we will fetch up to self.limit records matching the query, pack them into
    iodef documents, insert them into the QueryResponse and return that. 
    
    that object (the QR) will be placed back into the control message and sent
    back to the client from which it came.
    
    infra/botnet
    infra/malware
    infra/scan
    domain/botnet
    domain/malware
    url/botnet
    url/malware
    url/phishing
    
    <2 byte salt>
        ipv4    = 0x0   (infrastructure/botnet)
        ipv6    = 0x1   (infrastructure/botnet)
        fqdn    = 0x2   (domain/botnet)
        url     = 0x3   (url/botnet)
        email   = 0x4   (email/botnet)
        search  = 0x5   (search/botnet)
        malware = 0x6   (malware/botnet)
        asn     = 0x7   (asn/botnet)
    
    so to query for all infra_botnet, thread out for each salt (one thread per salt val) and 
    append 0x0 or 0x1 

    if they give a specific netblock or ip, append that as well

    
    for domain_botnet, one thread per salt and append 0x2, for a specific domain, append
    the length (2 bytes) and then the domain
    
    """
    def execqr(self):
        self.L("execute query: " + self.qr.query)

        try:
            decoded_query = self.decode_query(self.qr.query)

            # infrastructure/botnet,email@com.com   {'limiter': {'type': 4, 'value': u'email@com.com'}, 'primary': [0, 1], 'secondary': u'malware'}
            #     result: invalid/mismatched limiter/primary
            
            # infrastructure/botnet  {'limiter': {'type': None, 'value': None}, 'secondary': u'botnet', 'primary': [0, 1], 'prinames': ['ipv4', 'ipv6']}
            #     result: valid, query index_botnet for all ipv4/ipv6 rows
            
            # 10.10.0.0/16  {'limiter': {'type': 0, 'value': u'10.10.0.0/16'}, 'secondary': None, 'primary': None, 'prinames': None}
            #     result: valid, query all secondaries for primary type '0' and pack 10.10.0.0 onto the start and 10.10.255.255 onto the end rowkey
            
            # open table index_$secondary
            #
            # if len(primary) is 2:
            #     pack start rowkey using primary[0]
            #     pack stop rowkey using primary[1]
            # else
            #     pack rowprefix using primary[0]
            #
            # if we have a limiter, pack it into the end of the rowkey
            #   len(primary) must be 1 if we have a limiter
            
            # if stop rowkey != none then use scan(start=,stop=)
            # else use scan(rowprefix=)
            
            secondaries_to_scan = []
            if 'secondary' in decoded_query and decoded_query['secondary'] != None:
                secondaries_to_scan.append(decoded_query['secondary'])
            else:
                secondaries = self.registry.get('index.secondary')
                secondaries_to_scan = re.sub(r'\s*', r'', secondaries).split(',')
            
            qrs = control_pb2.QueryResponse()
            
            # TODO: spawn a thread for each secondary to scan, coalesce results
            # TODO: spawn a thread for each salt to scan, coalesce results
            
            qrs.ReportTime = datetime.datetime.now().isoformat(' ')
            qrs.description = self.qr.query
        
            with self.pool.connection() as dbh:
                for server in range(0, self.num_servers):
                    for secondary in secondaries_to_scan:
                        
                        table_name = "index_" + secondary
                        if not table_name in self.available_tables:
                            continue
                        table = dbh.table(table_name)
                        
                        if decoded_query['primary'] != None:
                            if len(decoded_query['primary']) == 1:
                                rowprefix = struct.pack('>HB', server, decoded_query['primary'][0])
    
                                # limiter/type and limiter/value are always present but may be None
                                if decoded_query['limiter']['type'] != None:
                                    packer = self.primary_index.name(decoded_query['limiter']['type']) # use 'prinames' instead of this lookup
                                    rowprefix = rowprefix + self.packers[packer].pack(decoded_query['limiter']['value'])
                                
                                for key, value in table.scan(row_prefix=rowprefix):
                                    iodef_rowkey = value['b:iodef_rowkey']
                                    iodef_row = self.tbl_co.row(iodef_rowkey)
                                    
                                    for key, value in iodef_row:
                                        if re.match(r'cf:index_', key) == None:
                                            bot = (key.split(":"))[1]
                                            qrs.baseObjectType.append(bot)
                                            qrs.data.append(value)
                                            break

                        
                            elif len(decoded_query['primary']) == 2:
                                
                                startrow = struct.pack('>HB', server, decoded_query['primary'][0])
                                stoprow = struct.pack('>HB', server, decoded_query['primary'][1])
    
                                if decoded_query['limiter']['type'] != None:
                                    print "limiter given of type " + self.primary_index.name(decoded_query['limiter']['type'])
                                    print "we shouldnt get here"
                                    
                                for key, value in table.scan(row_start=startrow, row_stop=stoprow):
                                    iodef_rowkey = value['b:iodef_rowkey']
                                    iodef_row = self.tbl_co.row(iodef_rowkey)
                                    
                                    for key, value in iodef_row:
                                        if re.match(r'cf:index_', key) == None:
                                            bot = (key.split(":"))[1]
                                            qrs.baseObjectType.append(bot)
                                            qrs.data.append(value)
                                            break
                                    
                        elif decoded_query['primary'] == None:
                                print "no primary given case"
                                print "we shouldnt get here"
                
            return qrs
        
        except Exception as e:
            print e
            traceback.print_exc(file=sys.stdout)
            raise e
