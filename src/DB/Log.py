import datetime
import time
import os
import threading
import zmq
import sys, traceback
import hashlib
import re

import socket
import happybase
import struct
import traceback

from DB.Salt import Salt
from DB.Registry import Registry

class Log(object):
    def __init__ (self, connectionPool, myhost = None, debug = 0):
        self.debug = debug
        self.pool = connectionPool
        
        if myhost != None:
            self.myhost = myhost
        else:
            self.myhost = socket.gethostname()
        
        self.registry = Registry(connectionPool, debug)
        self.num_servers = self.registry.get('hadoop.num_servers')

        if self.num_servers == None:
            self.num_servers = 1
        
        self.salt = Salt(self.num_servers, self.debug)
    
    def L(self, msg):
         self.salt.next()
         try:
            rowkey = struct.pack(">HI", self.salt.next(), int(time.time()))
            rowdict =      {
                                'b:hostname': str(self.myhost),
                                'b:msg': str(msg)
                            }
            with self.pool.connection() as connection:
                connection.table('log').put(rowkey, rowdict)
         except Exception as e:
            print "failed to put record to 'log' table: ", rowdict

            