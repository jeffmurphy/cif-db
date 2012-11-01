import syslog
from datetime import datetime
import time

class APIKeys(object):
    def __init__ (self, dbh, debug):
        self.dbh = dbh
        self.debug = debug
        self.table = self.dbh.table('apikeys')
    
    def L(self, msg):
        if self.debug != None:
            print msg
        else:
            syslog.syslog(msg)
    
    def totimestamp(dt, epoch=datetime(1970,1,1)):
        td = dt - epoch
        return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6
    
    def is_valid (self, apikey):
        """
        If the given key is found in the table, and is not expired or revoked, return true.
        
        b:revoked 'f'
        b:expires is either 'never' or < current time
        """
        R = str(__name__)
        
        if apikey != None:
            row = self.table.row(apikey, columns = ['b:expires', 'b:revoked'])
            if row != {}:
                if row['b:revoked'] == None or row['b:revoked'] == "f":
                    if row['b:expires'] == "never" or row['b:expires'] > time.time():
                        return True
                    else:
                        self.L(R + ": " + apikey + " is expired")
                else:
                    self.L(R + ": " + apikey + " is revoked")
            else:
                self.L(R + ": " + apikey + " not found ")
        else:
            self.L(R + ": no key given")
        return False
    
    def get_by_alias(self, alias):
        """
        lookup where rowkey = alias, return column b:key or None
        """
        R = str(__name__)
        if alias != None:
            row = self.table.row(alias, columns = ['b:key'])
            if row != {}:
                return row['b:key']
            else:
                self.L(R, ": no key for alias " + alias)
        return None
    