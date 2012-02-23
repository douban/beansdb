#!/usr/bin/python

import os.path, re, sys
import time
from random import shuffle

try:
    from cmemcached import Client
except:
    from memcache import Client

def fnv1a(s):
    prime = 0x01000193
    h = 0x811c9dc5
    for c in s:
        h ^= ord(c)
        h = (h * prime) & 0xffffffff
    return h

class MCStore(object):
    def __init__(self, server):
        self.server = server
        self.mc = Client([server])

    def __repr__(self):
        return '<MCStore(server=%s)>' % repr(self.server)

    def __str__(self):
        return self.server

    def set(self, key, data, rev=0):
        return bool(self.mc.set(key, data, rev))

    def get(self, key):
        return self.mc.get(key)

    def get_multi(self, keys):
        return self.mc.get_multi(keys)

    def delete(self, key):
        return bool(self.mc.delete(key))


class WriteFailedError(Exception):
    def __init__(self, key):
        self.key = key
    def __repr__(self):
        return 'write %s failed' % self.key


class Beansdb(object):
    hash_space = 1<<32
    cached = True
    def __init__(self, servers, buckets_count=16, N=3, W=1, R=1):
        self.buckets_count = buckets_count
        self.bucket_size = self.hash_space / buckets_count
        self.servers = {}
        self.server_buckets = {}
        self.buckets = [[] for i in range(buckets_count)]
        for s,bs in servers.items():
            server = MCStore(s)
            self.servers[s] = server
            self.server_buckets[s] = bs
            for b in bs:
                self.buckets[b].append(server)
        for b in range(self.buckets_count):
            self.buckets[b].sort(key=lambda x:fnv1a("%d:%s:%d"%(b,x,b)))
        self.N = N
        self.W = W
        self.R = R

    def print_buckets(self):
        for i,ss in enumerate(self.buckets):
            print i,','.join(str(s) for s in ss)
        for s,bs in self.server_buckets.items():
            print s,len(bs)

    def _get_servers(self, key):
        hash = fnv1a(key)
        b = hash / self.bucket_size
        return self.buckets[b]

    def get(self, key):
        ss = self._get_servers(key)
        for i,s in enumerate(ss):
            r = s.get(key)
            if r is not None:
                # self heal
                for k in range(i):
                    ss[k].set(key, r)
                return r

    def get_multi(self, keys):
        rs = {}
        ss = self.servers.values()
        shuffle(ss)
        for s in ss:
            rs.update(s.get_multi([k for k in keys if k not in rs and s in self._get_servers(k)]))
        return rs

    def delete(self, key):
        rs = [s.delete(key) for s in self._get_servers(key)]
        return rs.count(True) >= self.W

    def set(self, key, value):
        rs = [s.set(key, value) for s in self._get_servers(key)]
        if not rs.count(True) >= self.W:
            # try to get, it will return False when set same content into db
            if self.get(key) != value:
                raise WriteFailedError(key)
        return True


BEANSDBCFG = {
    "localhost:7901": range(16),
    "localhost:7902": range(16),
    "localhost:7903": range(16),
}

db = Beansdb(BEANSDBCFG, 16)

def _test():
    u = "/test"
    data = "teatdata" * 100
    assert db.set(u, data)
    #assert db.exists(u)
    assert db.get(u) == data
    assert db.get_multi([u]) == {u:data}
    assert db.delete(u)
    assert db.get(u) is None

if __name__ == '__main__':
    _test()
    pass

