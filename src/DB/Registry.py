import syslog
from datetime import datetime
import time
import re
import sys
import threading
import happybase

class Registry(object):
    def __init__ (self, connection, debug):
        self.debug = debug
        self.lock = threading.RLock()
        self.dbh = connection
        t = self.dbh.tables()
        if not "registry" in t:
            raise Exception("missing registry table")

        self.table = connection.table('registry').batch(batch_size=5)
        
        
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            syslog.syslog(caller + ": " + msg)
    
    def get(self, k):
        """
        rowkey = k
        b:type = type
        b:val  = val
        """
        return True
    
    def set(self, k, v):
        if type(v) is int:
            print 'set int'
        elif type(v) is str:
            print 'set str'
        elif type(v) is float:
            print 'set float'
        elif type(v) is long:
            print 'set long'
        elif type(v) is double:
            print 'set double'  