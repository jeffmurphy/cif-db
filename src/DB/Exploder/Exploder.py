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
import socket

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
    def __init__ (self, connectionPool, thread_tracker, debug):
        self.debug = debug
        self.pool = connectionPool
        
        if thread_tracker == None:
            raise Exception("thread_tracker parameter can not be None")
        
        self.thread_tracker = thread_tracker
        
        self.registry = Registry(connectionPool, debug)
        self.num_servers = self.registry.get('hadoop.num_servers')
        if self.num_servers == None:
            self.num_servers = 1
        
        self.batch_size = self.registry.get('hbase.batch_size')
        if self.batch_size == None:
            self.batch_size = 1000
            
        """
        We create one exploder thread per hbase server. Each thread has its own
        hbase connection.  
        
        foreach server (1 .. numservers)
            spawn_exploder_thread(server)
        """
        
        self.workers = []
        for server in range(0, self.num_servers):
            thr_title = "Exploder daemon %d of %d" % (server, self.num_servers-1)
            worker_thr = threading.Thread(target=self.run, name=thr_title, args=(server,))
            self.workers.append(worker_thr)
            worker_thr.daemon = True
            worker_thr.start()
            while not worker_thr.isAlive():
                print "waiting for exploder/worker thread to become alive"
                time.sleep(1)
            self.thread_tracker.add(id=worker_thr.ident, user='Exploder', host=socket.gethostname(), state='Running', info=thr_title)
        

    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            syslog.syslog(caller + ": " + msg)
    
    def do_some_work(self):
        self.kickit.release()
        
    def getcheckpoint(self, salt):
        t = self.registry.get('exploder.checkpoint.' + str(salt))
        if t != None:
            return t
        return 0
    
    def setcheckpoint(self, salt, ts):
        self.registry.set('exploder.checkpoint.' + str(salt), ts)
    
    def run(self, salt):
        """
        run(salt)
        
        this routine scans the cif_obj db for rows starting at
          "salt" + last checkpoint timestamp
        and ending at row
          "salt" + now()
        
        each row read in is passed to the Indexer for indexing.
        """
        
        self.L("Exploder thread running for salt: " + str(salt))
        
        with self.pool.connection() as dbh:
    
            index_handler = {} # Indexer.Indexer(self.dbh, "botnet", self.num_servers, self.debug)
            
            while True:
                co = dbh.table('cif_objs')
                
                startts = self.getcheckpoint(salt)
                endts = int(time.time())
                processed = 0
    
                #self.L("processing: " + str(startts) + " to " + str(endts))
                
                if startts == 0:
                    startts = 1
                    
                srowid = struct.pack(">HIIIII", salt, startts-1, 0,0,0,0)
                erowid = struct.pack(">HIIIII", salt, endts, 0,0,0,0)
    
                for key, data in co.scan(row_start=srowid, row_stop=erowid):
                    contains = data.keys()[0]
                    obj_data = data[contains]
                    
                    if contains == "cf:RFC5070_IODEF_v1_pb2":
                        iodef = RFC5070_IODEF_v1_pb2.IODEF_DocumentType()
                        try:
                            iodef.ParseFromString(obj_data)
    
                            #print "IODEF: ", iodef
                            ii = iodef.Incident[0]
                            table_type = ii.Assessment[0].Impact[0].content.content
                            
                            self.L("\tIndexing: " + table_type)
                    
                            # check to make sure table_name is in index.secondary
                            #   index.secondary contains a list of configured/permitted secondary index types
                            
                            if not table_type in index_handler:
                                self.L("index handler for table type %s doesnt exist, creating a new handler thread" % (table_type))
                                index_handler[table_type] = Indexer.Indexer(self.pool, table_type, self.num_servers, self.batch_size, self.debug)
                            
                            index_handler[table_type].extract(key, iodef)
                            processed = processed + 1
    
                        except Exception as e:
                            print "Failed to parse restored object: ", e
                            traceback.print_exc()
                    else:
                        print "Contains an unsupported object type: ", contains
                    
                time.sleep(5)
                if processed > 0:
                    self.setcheckpoint(salt, endts)
            
