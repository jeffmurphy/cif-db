import syslog
from datetime import datetime
import time
import re
import sys
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
    def __init__(self, hbhost, num_servers = 1, thread_tracker = None, debug = 0):
        self.debug = debug
        self.hbhost = hbhost
        
        self.log = Log(hbhost)
        
        self.log.L("cif-db Purger initializing")
        
        if thread_tracker == None:
            raise Exception("thread_tracker parameter can not be None")
        
        self.thread_tracker = thread_tracker
        self.registry = Registry(hbhost, debug)

        self.primary_index = PrimaryIndex(hbhost)
        self.secondary_index = SecondaryIndex(hbhost)
        
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
            worker_thr = threading.Thread(target=self.run, name=thr_title, args=(hbhost, server))
            self.workers.append(worker_thr)
            worker_thr.daemon = True
            worker_thr.start()
            while not worker_thr.isAlive():
                print "waiting for purger/worker thread to become alive"
                time.sleep(1)
            self.L(thr_title)
            self.thread_tracker.add(id=worker_thr.ident, user='Purger', host=socket.gethostname(), state='Running', info=thr_title)
        
    def expand_timespec(self, tspec):
        """
        accepts: \d[dwh] and returns seconds
        """
        print "tspec ", tspec
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
        
    def run(self, hbhost, server):
        """
        thread:
        
        forever:
            foreach sec: # eg botnet, phishing, whitelist
                foreach pri: # eg ipv4 ipv6 url
                    submit purge job(pri/sec)
                    record pri in a pri_list
                submit purge job(difference of the sets all_pris and pri_list / sec)
        """
        dbh = happybase.Connection(hbhost)
        secondaries = set(self.secondary_index.names())
        primaries = set(self.primary_index.names())
        
        while True:
            pri_done = []
            for sec in secondaries:
                for pri in primaries:
                    self.submit_purge_job(pri, sec)
                    pri_done.append(pri)
                # pri_done is a subset of primaries
                diff = primaries - set(pri_done)
                if len(diff) > 0:
                    self.submit_purge_job(diff, sec)
                
            time.sleep(self.purge_every)
            self.L("Purger awake after " + str(self.purge_every) + " seconds")
            
    def submit_purge_job(self, pri, sec):
        """
        future: submit a MR job
        current: just iterate
        """
        print "submit purge: pri=%s sec=%s" % (pri, sec)
        
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            self.log.L(caller + ": " + msg)