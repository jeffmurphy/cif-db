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
                if row['b:revoked'] == None or row['b:revoked'] == "False":
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
                if self.currow['b:revoked'] == 'False':
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

            if 'b:writeAccess' not in row or row['b:writeAccess'] == 'False':
                rv['writeAccess'] = False
            else:
                rv['writeAccess'] = True
                
            if 'b:restrictedAccess' not in row or row['b:restrictedAccess'] == 'False':
                rv['restrictedAccess'] = False
            else:
                rv['restrictedAccess'] = True
                                    
            if 'b:revoked' not in row or row['b:revoked'] == 'False':
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
        will NOT return aliases (even tho we store them in the rowkey)
        
        returns an empty dict on fail/no matches
        """
        self.L(apikey_pattern)
        rv = {}
        if apikey_pattern != None:
            for key, data in self.table.scan():  #filter="FirstKeyOnlyFilter"):
                match = re.search(apikey_pattern, key)
                if match != None and 'b:apikey' not in data:
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
            raise Exception("Key already exists")

        ka = self.get_by_alias(apikey_params.alias)
        if ka != None:
            raise Exception("Alias already exists")
        
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
            raise Exception("Failed to add key to database")
        except:
            self.table.delete(apikey)
            self.L("add failed, unknown error: " + str(sys.exc_info()[0]))
            raise Exception("Failed to add key to database: " +  str(sys.exc_info()[0]))
            
        try:
            if apikey_params.alias != "":
                self.table.put(apikey_params.alias, {'b:apikey': apikey})
        except TypeError as e:
            self.table.delete(apikey) # rollback
            self.L("add of alias record failed for " + apikey + " (rolled back main)")
            raise Exception("Add of alias to database failed")
        except:
            self.table.delete(apikey)
            self.L("add failed, unknown error: " + str(sys.exc_info()[0]))
            raise Exception("Add of alias failed: " + str(sys.exc_info()[0]))
    
    def update_key(self, apikey_params):
        """
        Given a key, update it in the database. 
        
        All of the fields, except the 'apikey' field, are optional. The specified fields will be merged
        into the existing database record. 
        
        
        add_key({
            apikey: ...,
            alias: ...,
            restrictedAccess: t|f,
            writeAccess: t|f,
            description: ...,
            expires: int...,
            revoked: t|f,
            groupsList: [ {groupname: name, groupid: id, default: t|f} ],
            restrictionsList: [ {restrname: name, restrid: id} ],
            parent: ...
        })
                
        """
        apikey = apikey_params.apikey
        self.L(apikey)
        
        kr = self.table.row(apikey)
        if kr != {}:
            try:

                if apikey_params.HasField("alias"):
                    prev_alias = kr['b:alias']
                    if apikey_params.alias != "" and prev_alias != apikey_params.alias: # if you want to change the alias
                        ka = self.get_by_alias(alias)
                        if ka != None:
                            raise Exception("Alias already taken")
                        self.table.put(apikey_params.alias, {'b:apikey': apikey})
                        self.table.delete(prev_alias)
                    
                for fn in self.updateable_row_names:
                    if apikey_params.HasField(fn):
                        dbcol = "b:" + fn
                        colval = str(getattr(apikey_params, fn))
                        kr[dbcol] = colval
                
                self.table.put(apikey, kr)
                
                if apikey_params.HasField('groupsList'):
                    self.update_groups(apikey, apikey_params.groupsList)
                
                if apikey_params.HasField('restrictionsList'):
                    self.update_restrictions(apikey, apikey_params.restrictionsList)
                
            except:
                self.L("update failed, unknown error: " + str(sys.exc_info()[0]))
                raise Exception("Unknown error: " + str(sys.exc_info()[0]))
        
        raise Exception("Key doesn't exist: " + apikey)
    
    def update_groups(self, apikey, groupsList):
        """
        Given a groups list like this: groupsList = [ {groupname: name, groupid: id, default: t|f} ]
        add the group name/id to the specified apikey. If the groupid is empty (or unspecified) but 
        the name is given, we will remove the group from the given apikey.
        
        The group must exist in the groups table before we take any action, otherwise we return 
        false.
        
        The groupid that the client passes is ignored, and instead we lookup the groupid in the
        groups table using the groupname they give us. 
        """
        
        if apikey != None and 'groupname' in groupsList:
            groupid = self.get_group_by_name(groupsList['groupname'])
            if groupid != None:
                akr = self.table.get('apikeys', apikey)
                if akr != {}: 
                    if 'groupid' in groupsList:
                        self.table.put('apikeys', apikey, 'grp:' + groupid, groupsList['groupname'])
                    else:
                        self.table.delete('apikeys', apikey, 'grp:' + groupid)
                else:
                    raise Exception("Key doesn't exist")
    
    def update_restrictions(self, apikey, restrictionsList):
        return True
    
    def create_group(self, groupname, groupid):
        if groupname != None and groupid != None:
            self.table.put('groups', groupname, 'b:uuid', groupid)
            self.table.put('groups', groupid, 'b:name', groupname)

        raise Exception("Invalid parameters")
    
    def remove_group(self, groupname, groupid):
        if groupname != None and groupid != None:
            self.table.delete('groups', groupname)
            self.table.delete('groups', groupid)
            
        raise Exception("Invalid parameters")
    
    def get_group_by_name(self, groupName):
        if groupName != None:
            row = self.table.get('groups', groupName, 'b:uuid')
            if row != {} and 'b:uuid' in row:
                return row['b:uuid']
        return None
    
    def get_group_by_id(self, groupid):
        if groupid != None:
            row = self.table.get('groups', groupid, 'b:name')
            if row != {} and 'b:name' in row:
                return row['b:name']
        return None
    
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
            except:
                self.L("remove failed, unknown error: " + str(sys.exc_info()[0]))
                raise Exception("Remove failed: " + str(sys.exc_info()[0]))
    
    def remove_by_alias(self, apikey_alias):
        """
        Remove the given key from the database.
        """
        self.L(apikey_alias)
        apikey = self.get_by_alias(apikey_alias)
        if apikey != None:
            self.remove_by_key(apikey)
    