import datetime
import time
import os
import threading
import zmq
import sys, traceback
import hashlib
import re

import struct

import socket
import happybase
import struct
import traceback

from DB.Salt import Salt
from DB.Registry import Registry

class Log(object):
    def __init__ (self, hbhost, myhost, debug):
        self.debug = debug
        self.myhost = myhost
        self.registry = Registry(hbhost, debug)
        self.num_servers = self.registry.get('hadoop.num_servers')

        if self.num_servers == None:
            self.num_servers = 1
            
        self.dbh = happybase.Connection(hbhost)
        self.table = self.dbh.table('log')
        
        self.salt = Salt(self.num_servers, self.debug)
    
    def L(self, msg):
         self.salt.next()
         try:
            rowkey = struct.pack(">HI", self.salt.next(), int(time.time()))
            rowdict =      {
                                'b:hostname': str(self.myhost),
                                'b:msg': str(msg)
                            }
            
            self.table.put(rowkey, rowdict)
         except Exception as e:
            print "failed to put record to 'log' table: "
            print "rk ", rowkey
            print e
            