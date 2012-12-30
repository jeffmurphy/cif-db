import syslog
from datetime import datetime
import time
import re

class APIKeys(object):
    def __init__ (self, dbh, debug):
        self.dbh = dbh
        self.debug = debug
        self.table = self.dbh.table('apikeys')
        self.currow = None
    
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
    
    def is_revoked(self):
        if self.exists() == True:
            if 'b:revoked' in self.currow:
                if self.currow['b:revoked'] == 'f':
                    return False
        return False

    def is_expired(self):
        if self.exists() == True:
            if 'b:expires' in self.currow:
                if self.currow['b:expires'] == 'never':
                    return True
                if int(self.currow['b:expires']) > time.time():
                    return True
        return False
    
    def exists(self):
        if currow == None or currow == {}:
            return False
        return True
    
    def get_by_alias(self, alias):
        """
        lookup where rowkey = alias, returns a string column b:key (the key itself) or None
        use get_by_key() to retrieve full key details
        """
        R = str(__name__)
        if alias != None:
            row = self.table.row(alias, columns = ['b:key'])
            if row != {}:
                return row['b:key']
            else:
                self.L(R + ": no key for alias " + alias)
        return None
    
    def get_by_key(self, apikey):
        """
        lookup where rowkey = key, return a dictionary of all columns:values
        or an empty dict
        """
        R = str(__name__)
        self.L(R + " : " + apikey)
        rv = {}
        if apikey != None:
            row = self.table.row(apikey)
            rv = self.row_to_rv(row)
            if rv != {}:
                self.currow = row
            else:
                self.L(R + ": no key " + apikey)
                self.currow = {}
        return rv
    
    def get_groups_by_key(self, apikey):
        """
        lookup the record matching apikey, return a list of groups the key is a member of
        to find the default group, use get_by_key()
        returns an empty list on fail
        """
        R = str(__name__)
        self.L(R + " : " + apikey)
        rv = []
        if apikey != None:
            row = self.table.row(apikey)
            if row != {}:
                self.currow = row
                for key, value in row.iteritems():
                    m = re.match('grp:(.*)', key)
                    if m != None:
                        rv.append(m.group(1))
        return rv

    def row_to_rv(self, row):
        """ 
        given a row from the db, translate its values into something standardized we can
        stuff into a protocol buffer. eg hbase values are typeless, we want to type (some of) them.
        """
        rv = {}
        if row != {}:
            
            if 'b:alias' in row:
                rv['alias'] = row['b:alias']
            else:
                rv['alias'] = ''
                
            if 'b:description' in row:
                rv['description'] = row['b:description']
            else:
                rv['description'] = ''
                
            if 'b:default' in row:
                rv['default'] = row['b:default']
            else:
                rv['default'] = ''
                
            if 'b:expires' not in row or row['b:expires'] == "never":
                rv['expires'] = 0
            else:
                rv['expires'] = row['b:expires']

            if 'b:write' not in row or row['b:write'] == 'f':
                rv['write'] = False
            else:
                rv['write'] = True
                
            if 'b:restricted_access' not in row or row['b:restricted_access'] == 'f':
                rv['restricted_access'] = False
            else:
                rv['restricted_access'] = True
                                    
            if 'b:revoked' not in row or row['b:revoked'] == 'f':
                rv['revoked'] = False
            else:
                rv['revoked'] = True
                
            if 'b:parent' in row:
                rv['parent'] = row['b:parent']
            else:
                rv['parent'] = ''
                
            if 'b:created' in row:
                rv['created'] = row['b:created']
            else:
                rv['created'] = 0

            rv['groups'] = {}
            
            for k in row:
                if k.startswith("grp:"):
                    rv['groups'][k.replace("grp:", "")] = row[k]
                    
        return rv
            
    def list_by_key(self, apikey_pattern):
        """
        lookup where rowkey =~ apikey_pattern, return a dict of all matches 
        will also return aliases (since they appear in the rowkey)
        
        returns an empty dict on fail/no matches
        """
        R = str(__name__)
        self.L(R + " : " + apikey_pattern)
        rv = {}
        if apikey_pattern != None:
            for key, data in self.table.scan():  #filter="FirstKeyOnlyFilter"):
                match = re.search(apikey_pattern, key)
                if match != None:
                    rv[key] = self.row_to_rv(data)
        return rv
    
    def add_key(self, apikey_params):
        """
        Given a key, add it to the database. If the key exists, returns False, else True on success
        
        add_key({
            apikey: ...,
            alias: ...,
            restrictedAccess: t|f,
            writeAccess: t|f,
            description: ...,
            expires: int...,
            revoked: t|f,
            groupsList: {groupname, groupid, isdefault=t|f},
            restrictionsList: {restrname, restrid},
            parent: ...
        })
        """
        return True
    
    def update_key(self, apikey_params):
        """
        Given a key, update it in the database. If the key does not exist, returns False, else True on success
        
        All of the fields, except the 'apikey' field, are optional. The specified fields will be merged
        into the existing database record. To "unset" a field like parent or description, set it to ""
        
        add_key({
            apikey: ...,
            alias: ...,
            restrictedAccess: t|f,
            writeAccess: t|f,
            description: ...,
            expires: int...,
            revoked: t|f,
            groupsList: {groupname, groupid, isdefault=t|f},
            restrictionsList: {restrname, restrid},
            parent: ...
        })
        """
        return True
    
    def remove_key(self, apikey):
        """
        Remove the given key from the database.
        """
        return True
    
