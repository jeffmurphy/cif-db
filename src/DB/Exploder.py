import syslog
from datetime import datetime
import time
import re
import sys
import threading
import happybase

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
        t.put('exploder_checkpoint', { 'b:ts', ts })
        
    def run(self):
        self.L("Exploder running")
        
        while True:
            self.L("waiting for work")
            self.kickit.acquire() # will block provided kickit is 0
            self.L("wakup")
            
            co = connection.table('cif_objs')
            starts = self.getcheckpoint()
            endts = int(time.time())
            processed = 0
            
            salt = 0xFF00
            srowid = struct.pack(">HIIIII", salt, startts, 0,0,0,0)
            erowid = struct.pack(">HIIIII", salt, endts, 0,0,0,0)

            for key, data in tbl.scan(row_start=srowid, row_stop=erowid):
                contains = data.keys()[0]
                obj_data = data[contains]
                
            self.setcheckpoint(endts+1)
