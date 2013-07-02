import syslog
from datetime import datetime
import time
import re
import sys
import threading

class Salt(object):
    def __init__ (self, nsrvs=10, debug=0):
        self.debug   = debug
        self.salt    = 0x0000
        self.servers = nsrvs
        self.lock = threading.RLock()
        
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            syslog.syslog(caller + ": " + msg)
    
    def range(self):
        return self.servers
            
    def next(self):
        self.lock.acquire()
        self.salt = self.salt + 1
        if self.salt >= self.servers:
            self.salt = 0x0000
        self.lock.release()
        return self.salt