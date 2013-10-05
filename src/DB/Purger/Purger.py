import syslog
from datetime import datetime
import time
import re
import sys, traceback
import threading
import happybase
import struct
import hashlib
import socket

from DB.Salt import Salt
from DB.Registry import Registry
from DB.PrimaryIndex import PrimaryIndex
from DB.SecondaryIndex import SecondaryIndex
from DB.Log import Log

class Purger(object):
    """
    Eventually, this will submit map reduce jobs. Since we have to do 
    what amounts to full table scans, that's the best way to do it 
    using hadoop. For this POC, it doesn't use MR.
    
    outline:
    
    load index.* registry values
    index.purge_every tells us how long to sleep for between MR submissions
    index.primary.secondary.purge_after tells us the max age of records we'll keep
    index.purge_after is the default if no pri.sec is specified
    
    eg
    
    index.purge_every = 24h
    index.purge_after = 7d 
    index.infrastructure.botnet.purge_after = 10d 
    
    spawn a thread per server
    record them in threadtracker

    """
    def __init__(self, connectionPool, num_servers = 1, thread_tracker = None, debug = 0):
        self.debug = debug
        self.pool = connectionPool
        
        self.log = Log(connectionPool)
        
        self.L("cif-db Purger initializing")
        
        if thread_tracker == None:
            raise Exception("thread_tracker parameter can not be None")
        
        self.thread_tracker = thread_tracker
        self.registry = Registry(connectionPool, debug)
        
        self.primary_index = PrimaryIndex(connectionPool)
        self.secondary_index = SecondaryIndex(connectionPool)
        
        self.num_servers = self.registry.get('hadoop.num_servers')
        if self.num_servers == None:
            self.num_servers = 1 
            
        self.purge_every = self.expand_timespec(self.registry.get('index.purge_every'))
        if self.purge_every == None:
            self.purge_every = 24 * 60 * 60
        self.L("Purger will run every " + str(self.purge_every) + " seconds")
        
        self.prisecmap = []
        
        for i in self.registry.get():
            m = re.match(r'^index\.([^\.]+)\.([^\.]+)\.purge_after', i)
            if m != None:
                self.prisecmap[m.group(1)][m.group(2)] = self.expand_timespec(self.registry.get(i))
            
        self.workers = []
        for server in range(0, self.num_servers):
            thr_title = "Purger daemon %d of %d" % (server, self.num_servers-1)
            worker_thr = threading.Thread(target=self.run, name=thr_title, args=(server,))
            self.workers.append(worker_thr)
            worker_thr.daemon = True
            worker_thr.start()
            while not worker_thr.isAlive():
                self.log.L("waiting for purger/worker thread to become alive")
                time.sleep(1)
            self.L(thr_title)
            self.thread_tracker.add(id=worker_thr.ident, user='Purger', host=socket.gethostname(), state='Running', info=thr_title)
        
    def expand_timespec(self, tspec):
        """
        accepts: \d[dwh] and returns seconds
        """
        if tspec == None:
            return None
        m = re.match(r"^(\d+)([dwh])$", tspec)
        if m == None:
            self.L("invalid timespec: " + tspec)
            return None
        if m.group(2) == "d":
            return int(m.group(1)) * 24 * 60 * 60
        if m.group(2) == "w":
            return int(m.group(1)) * 7 * 24 * 60 * 60
        if m.group(2) == "h":
            return int(m.group(1)) * 60 * 60
        
    def remove_index_and_dereference(self, index_th, index_rowkey, co_tbl, index_table, document_rowkey):
        try:
            index_th.delete(index_rowkey)
            co_row = co_tbl.row(document_rowkey)
            fmt = "%ds" % (len(index_table) + 4)  # Also in Indexer
            prk = struct.pack(fmt, "cf:" + str(index_table) + "_") + document_rowkey
            if prk in co_row:
                co_tbl.delete(document_rowkey, columns=[prk])
        except Exception as e:
            self.L("Failed to delete reference and index: " + index_table + str(e) + traceback.format_exc(None))
            
    def run(self, server):
        """
        thread:
        
        forever:
            foreach sec: # eg botnet, phishing, whitelist
                foreach pri: # eg ipv4 ipv6 url
                    submit purge job(pri/sec)
                    record pri in a pri_list
                submit purge job(difference of the sets all_pris and pri_list / sec)
        """
        with self.pool.connection() as dbh:
            secondaries = set(self.secondary_index.names())
            primaries = set(self.primary_index.names())
    
            while True:
                pri_done = []
                for sec in secondaries:
                    for pri in primaries:
                        if self.primary_index.is_group(pri) == False:
                            self.submit_purge_job(dbh, pri, sec)
                        pri_done.append(pri)  # remove groups too
                    # pri_done is a subset of primaries
                    diff = primaries - set(pri_done)
                    if len(diff) > 0:
                        self.submit_purge_job(dbh, diff, sec)
                    
                time.sleep(self.purge_every)
                self.L("Purger awake after " + str(self.purge_every) + " seconds")
            
    def submit_purge_job(self, dbh, pri, sec):
        """
        future: submit a MR job
        current: just iterate
        
        FIX atm this is iodef specific, ideally we will handle other document types
        """
        self.L("begin purge of %s/%s" % (pri, sec))
        
        tables = dbh.tables()
        table_name = "index_" + sec
        
        if table_name in tables:
            tbl = dbh.table("index_" + sec)
            co_tbl = dbh.table("cif_objs")
            
            for i in range(0, self.num_servers):
                self.L("purging index_%s on server %d" %(sec, i))
                
                pri_enum = self.primary_index.enum(pri)
                if pri_enum != None:
                    rowpre = struct.pack(">HB", i, pri_enum)
                    oldest_allowed = self.lookup_max_lifespan(pri, sec)
                    for key, data in tbl.scan(row_prefix=rowpre, include_timestamp=True):

                        document_rowkey = None
                        data_age = None
                        if 'b:iodef_rowkey' in data:  # iodef handler
                            data_age = data['b:iodef_rowkey'][1]
                            document_rowkey = data['b:iodef_rowkey'][0]
                        #elif 'b:stiix_rowkey' in data: ... etc
                    
                        if time.time() - data_age < oldest_allowed:
                            # cif_objs.row(iodef_rowkey) will contain a column "cf:index_$sec_$thisrowkey" we want to delete that reference
                            self.remove_index_and_dereference(tbl, key, co_tbl, table_name, document_rowkey)
    
    def lookup_max_lifespan(self, pri, sec):
        return 86400
        if pri != None and sec != None:
            # index.$pri.$sec.purge_after
            rkey = "index.%s.%s.purge_after" % (pri, sec)
            rv = self.registry.get(rkey)
            if rv != None:
                return self.expand_timespec(rv)
            else:
                rv = self.registry.get("index.purge_after") # global fallback
                if rv != None:
                    return self.expand_timespec(rv)
        return self.expand_timespec("270d")  # hardcoded default
    
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            self.log.L(caller + ": " + msg)