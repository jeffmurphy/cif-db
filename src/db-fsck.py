#!/usr/bin/python

import sys
import zmq
import random
import time
import os
import datetime
import json
import getopt
import socket
import happybase
import hashlib
import struct
import traceback
import re

# adjust to match your $PREFIX if you specified one
# default PREFIX = /usr/local
sys.path.append('/usr/local/lib/cif-protocol/pb-python/gen-py')

def usage():
    print "db-fsck [-v] [-f] [-H host] [-D 0-9] [-h]\n\t-v verbose\n\t-f fix (default: report dont fix)\n\t-H hbase host\n\t-D debug level\n\t-h this message"
    sys.exit()
    
def HBConnection(host):
    c = happybase.Connection(host)
    t = c.tables()
    if not "cif_idl" in t:
        raise Exception("missing cif_idl table")
    if not "cif_objs" in t:
        raise Exception("missing cif_objs table")
    return c

def document_is_indexed(c, tbl, rkey):
    """
    open table, make sure rkey exists. 
    """
    t = c.table(tbl)
    r = t.row(rkey)
    if r == None:
        return False
    return True

def index_refers_to_valid_document(c, rkey, doc_type):
    try:
        t = c.table("cif_objs")
        r = t.row(rkey)
        if r != None:
            if "cf:" + doc_type in r:
                return True
        return False
    except Exception as e:
        print "Failed to lookup document in cif_objs"
        print e

def validate_index(c, tbl, fix=False):
    """
    index_* tables contain rows that have b:iodef_rowkey column
    the iodef_rowkey value should correspond to an existing cif_objs document
    containing a column cf:RFC5070_IODEF_v1_pb2
    
    if new document types are supported as indexable, then this routine
    should be modified to check those too
    
    fix=True: if the index points to a document that doesn't exist the fix is to
    delete the index entry.
    """
    try:
        invalid_index = 0
        
        t = c.table(tbl)
        if t != None:
            for key, data in t.scan():
                if 'b:iodef_rowkey' in data:
                    if index_refers_to_valid_document(c, data['b:iodef_rowkey'], 'RFC5070_IODEF_v1_pb2') == False:
                        invalid_index = invalid_index + 1
                        if fix == True:
                            t.delete(key)
        
        print "\tIndex", tbl, "contains", invalid_index, "invalid entries."
        
    except Exception as e:
        print "Failed to validate ", tbl
        print e


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'vfH:D:h')
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(2)
    
    """
    foreach row in cif_objs
        if one of the columns =~ cf:(index_.*)_(.*)
            table = $1
            rowkey = $2
            make sure the reference is good (rowkey exists in $1)
    """
    
    hbhost = "127.0.0.1"
    fixit = False
    
    for o, a in opts:
        if o == "-h":
            usage()
        elif o == "-H":
            hbhost = a
        elif o == "-v":
            verbose = True
        elif o == "-D":
            debug = a
        elif o == "-f":
            fixit = True
    
    print "Connecting to HBase on " + hbhost
    c = HBConnection(hbhost)
    print "Opening cif_objs"
    t = c.table('cif_objs')
    
    print "Validating cif_objs"
    
    try:
        count = 0
        unindexed_documents = 0
        
        for key, data in t.scan():
            for col in data:
                m = re.match(r'cf:(index_[a-z]+)_(.*)', col)
                if m != None:
                    sub_table = m.group(1)
                    sub_rowkey = m.group(2)
                    count = count + 1
                    if (count % 1000 == 0):
                        print count, " ",
                        
                    if document_is_indexed(c, sub_table, sub_rowkey) == False:
                        # the fix for unindexed documents is to reset exploder.checkpoint
                        # and restart cif-db
                        unindexed_documents = unindexed_documents + 1
        
        print "cif_objs:\n\t%d/%d unindexed documents\n" % (unindexed_documents, count)
        if unindexed_documents > 0 and fixit == True:
            print "\tto fix: change the registry values for exploder.checkpoint to zero and restart cif-db"
            
        for index_table in c.tables():
            if re.match(r'^index_', index_table):
                print "Validating " + index_table
                validate_index(c, index_table, fixit)
    
    except Exception as e:
        print "Something bad happened:", e
        
if __name__ == '__main__':
    main()
    
    