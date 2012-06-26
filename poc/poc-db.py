#!/usr/bin/python

import sys

# adjust to match your $PREFIX if you specified one
# default PREFIX = /usr/local
sys.path.append('/usr/local/lib/cif-protocol/pb-python/gen-py')

import msg_pb2
import feed_pb2
import RFC5070_IODEF_v1_pb2
import MAEC_v2_pb2
import cifsupport

print "cif-db proof of concept"

"""
Two threads:

Attach to cif-router PUB:
    Subscribe to all message types
    Write all messages we receive to HBase

Attach to cif-router ROUTER:
    When we receive a query request:
        retrieve the requested information
        send it back to the requester
"""

