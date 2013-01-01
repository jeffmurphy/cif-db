import syslog
from datetime import datetime
import time
import re
import sys


class APIKeys(object):
    def __init__ (self, dbh, debug):
        self.dbh = dbh
        self.debug = debug
        self.table = self.dbh.table('apikeys')
        self.currow = None
        self.updateable_row_names = ['alias', 'restrictedAccess', 'writeAccess', 'description', 'expires', 'revoked', 'parent']
        
    def L(self, msg):
        caller =  ".".join([str(__name__), sys._getframe(1).f_code.co_name])
        if self.debug != None:
            print caller + ": " + msg
        else:
            syslog.syslog(caller + ": " + msg)
    
    def totimestamp(dt, epoch=datetime(1970,1,1)):
        td = dt - epoch
        return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6
    
    def is_valid (self, apikey):
        """
        If the given key is found in the table, and is not expired or revoked, return true.
        
        b:revoked 'f'
        b:expires is either 'never' or < current time
        """
        
        if apikey != None:
            row = self.table.row(apikey, columns = ['b:expires', 'b:revoked'])
            if row != {}:
                if row['b:revoked'] == None or row['b:revoked'] == "f":
                    if row['b:expires'] == "never" or row['b:expires'] > time.time():
                        return True
                    else:
                        self.L(apikey + " is expired")
                else:
                    self.L(apikey + " is revoked")
            else:
                self.L(apikey + " not found ")
        else:
            self.L("no key given")
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
        lookup where rowkey = alias, returns a string column b:apikey (the key itself) or None
        use get_by_key() to retrieve full key details
        """
        if alias != None:
            row = self.table.row(alias, columns = ['b:apikey'])
            if row != {}:
                return row['b:apikey']
            else:
                self.L("no key for alias " + alias)
        return None
    
    def get_by_key(self, apikey):
        """
        lookup where rowkey = key, return a dictionary of all columns:values
        or an empty dict
        """
        self.L(apikey)
        rv = {}
        if apikey != None:
            row = self.table.row(apikey)
            rv = self.row_to_rv(row)
            if rv != {}:
                self.currow = row
            else:
                self.L("no key " + apikey)
                self.currow = {}
        return rv
    
    def get_groups_by_key(self, apikey):
        """
        lookup the record matching apikey, return a list of groups the key is a member of
        to find the default group, use get_by_key()
        returns an empty list on fail
        """
        self.L(apikey)
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
                
            if 'b:defaultGroup' in row:
                rv['defaultGroup'] = row['b:defaultGroup']
            else:
                rv['defaultGroup'] = ''
                
            if 'b:expires' not in row or row['b:expires'] == "never":
                rv['expires'] = 0
            else:
                rv['expires'] = int(row['b:expires'])

            if 'b:writeAccess' not in row or row['b:writeAccess'] == 'f':
                rv['writeAccess'] = False
            else:
                rv['writeAccess'] = True
                
            if 'b:restrictedAccess' not in row or row['b:restrictedAccess'] == 'f':
                rv['restrictedAccess'] = False
            else:
                rv['restrictedAccess'] = True
                                    
            if 'b:revoked' not in row or row['b:revoked'] == 'f':
                rv['revoked'] = False
            else:
                rv['revoked'] = True
                
            if 'b:parent' in row:
                rv['parent'] = row['b:parent']
            else:
                rv['parent'] = ''
                
            if 'b:created' in row:
                rv['created'] = int(row['b:created'])
            else:
                rv['created'] = 0

            rv['groups'] = {}
            
            rv['restrictions'] = {}

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
        self.L(apikey_pattern)
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

        apikey = apikey_params.apikey
        self.L(apikey)
        
        kr = self.get_by_key(apikey)
        if kr != {}:
            return False # key already exists

        ka = self.get_by_alias(apikey_params.alias)
        if ka != None:
            return False # alias already exists
        
        self.L("key/alias dont exist, looks ok to add")
        
        for fn in self.updateable_row_names:
            dbcol = "b:" + fn
            val = str(getattr(apikey_params, fn))
            kr[dbcol] = str(getattr(apikey_params, fn))
            
        try:
            self.table.put(apikey, kr)
        except TypeError as e:
            print e
            self.L("add of main record failed for " + apikey)
            return False
        except:
            self.table.delete(apikey)
            self.L("add failed, unknown error: " + str(sys.exc_info()[0]))
            return False
            
        try:
            if apikey_params.alias != "":
                self.table.put(apikey_params.alias, {'b:apikey': apikey})
        except TypeError as e:
            self.table.delete(apikey) # rollback
            self.L("add of alias record failed for " + apikey + " (rolled back main)")
            return False
        except:
            self.table.delete(apikey)
            self.L("add failed, unknown error: " + str(sys.exc_info()[0]))
            return False
        
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
        apikey = apikey_params.apikey
        self.L(apikey)

        kr = self.table.row(apikey)
        if kr != {}:
            try:
                prev_alias = kr['b:alias']
                
                for fn in self.updateable_row_names:
                    dbcol = "b:" + fn
                    kr[dbcol] = str(getattr(apikey_params, fn))
                
                self.table.put(apikey, kr)
                
                if prev_alias != apikey_params.alias:
                    self.table.put(apikey_params.alias, {'b:apikey': apikey})
                    self.table.delete(prev_alias)

                return True
            except:
                self.L("update failed, unknown error: " + str(sys.exc_info()[0]))
                return False
        
        return False
    
    def remove_by_key(self, apikey):
        """
        Remove the given key from the database.
        """
        self.L(apikey)
        kr = self.get_by_key(apikey)
        if kr != {}:
            try:
                if 'alias' in kr and kr['alias'] != '':
                    print "delete the alias record"
                    # delete the alias record
                    self.table.delete(kr['alias'])
                else:
                    print "no alias rec to delete ", kr
                self.table.delete(apikey)
                return True
            except:
                self.L("remove failed, unknown error: " + str(sys.exc_info()[0]))
                return False
        return True # if the key doesnt even exist, then we return True
    
    def remove_by_alias(self, apikey_alias):
        """
        Remove the given key from the database.
        """
        self.L(apikey_alias)
        apikey = self.get_by_alias(apikey_alias)
        if apikey != None:
            return self.remove_by_key(apikey)
        return True # if the alias doesnt exist, we return True
    