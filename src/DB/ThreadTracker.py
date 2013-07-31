import struct
import sys, time
import threading

class ThreadTracker(object):
    """ ID, User, Host, Command, Time, State, Info
    """

    def __init__(self, _debug):
        self.track = {}
        self.debug = _debug
        self.lock = threading.Lock()
    
    def add(self, id=None, user=None, host=None, command=None, state=None, info=None):
        self.lock.acquire()
        self.track[id] = { user: user, host: host, command: command, state: state, info: info, time: time.time() }
        self.lock.release()
    
    def update(self, id=None, state=None, info=None):
        self.lock.acquire()
        if id in self.track:
            self.track[id][state] = state
            self.track[id][info] = info
        self.lock.release()
        
    def remove(self, _id):
        self.lock.acquire()
        del self.track[_id]
        self.lock.release()
    
    def list(self):
        self.lock.acquire()
        rv = []
        for _id in self.track:
            rv.append(_id)
        self.lock.release()
        return rv
    
    def get(self, _id):
        self.lock.acquire()
        rv = None
        if _id in self.track:
            rv = self.track[_id]
        self.lock.release()
        return rv
    