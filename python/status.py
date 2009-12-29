#!/usr/bin/python

import os,os.path
import time
import sys
import math

from dbclient import Beansdb, db

def stat(s):
    st = {}
    for i in range(16):
        for d,h,c in [line.split(' ') for line in (s.get('@%x'%i) or '').split('\n') if line]:
            if not d.endswith('/') or len(d) != 2: continue
            st[i*16+int(d[0],16)] = int(c)
    return st

def status(db):
    st = {}
    for s in db.servers.values():
        st[str(s)] = stat(s)
        print '\t',s,
    print
    scale = 256/db.buckets_count
    for b in range(db.buckets_count):
        print '%x' % b, 
        for s in db.servers.values():
            print '\t',
            if s in db.buckets[b]:
                print '\x1b[01;32m%8d\x1b[0m' % sum(st[str(s)].get(b*scale+i,0) for i in range(scale)),
            else:
                print '%8d' % sum(st[str(s)].get(b*scale,0) for i in range(scale)),
        print 

if __name__ == '__main__':
    status(db)
