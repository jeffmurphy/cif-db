import syslog
from datetime import datetime
import time
import re
import sys
import threading
import socket
import happybase

class Registry(object):
    def __init__ (self, hbhost, debug):
        self.debug = debug
        self.lock = threading.RLock()
        self.dbh = happybase.Connection(hbhost)

        t = self.dbh.tables()
        if not "registry" in t:
            raise Exception("missing registry table")

        self.table = self.dbh.table('registry')
        
        
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            syslog.syslog(caller + ": " + msg)
    
    def get(self, k = None):
        """
        rowkey = k
        b:type = type
        b:value  = val
        
        if k is not None: return the value or None if it doesnt exist
        if k is None: return a list of all registry keys (list may be empty)
        """
        if k != None:
            r = self.table.row(k)
            if r != None:
                if 'b:type' in r and 'b:value' in r:
                    if r['b:type'] in ["int"]:
                        return int(r['b:value'])
                    if r['b:type'] in ["long"]:
                        return long(r['b:value'])
                    if r['b:type'] in ["double", "float"]:
                        return float(r['b:value'])
                    return str(r['b:value'])
                return None
        else:
            r = self.table.scan()
            rv = []
            for tk, tv in r:
                rv.append(tk)
            return rv
        
    def delete(self, k):
        self.table.delete(k)
        
    def set(self, k, v):
        at = None
        av = str(v)
        if type(v) is int:
            at = "int"
        elif type(v) is str:
            at = "str"
        elif type(v) is float:
            at = "float"
        elif type(v) is long:
            at = "long"
        elif type(v) is double:
            at = "double"
        
        self.table.put(k, {"b:type": at, "b:value": av})
         