#!/usr/bin/python

import sys, os, os.path
from dbclient import Beansdb, db

def get_dir(s, dir):
    def parse(line):
        p,h,c = line.split(' ')
        return p, (int(h), int(c))
    return dict(parse(line) for line in 
                filter(None, (s.get(dir) or '').split('\n')))

def is_dir(d):
    return len(d) == 16 and len([k for k in d if k.endswith('/')]) == 16

def mirror(src, dst, path):
    s = get_dir(src, path)
    d = get_dir(dst, path)
    if s == d:
        print path, src, dst, 'skipped'
        return
    if is_dir(s):
        for k in sorted(s):
            if s[k] != d.get(k):
                #print path+k[0], 'mirror ', s[k], d.get(k)
                mirror(src, dst, path+k[0])
    elif is_dir(d):
        for k in sorted(d):
            mirror(dst, src, path+k[0])
    elif not is_dir(s) and not is_dir(d):
        sync_files(src, dst, path, s, d)
        sync_files(dst, src, path, d, s)
    else:
        print path, src, '=>', dst, 'skipped'

def sync_files(src, dst, path, s, d):
    for k in sorted(s.keys()):
        if k not in d:
            data = src.get(k)
            if data is not None:
                print path, k, s[k], d.get(k,(0,0)), src, "=>", dst, dst.set(k, data, s[k][1])
            else:
                print path, src, k, 'is None', src.delete(k)
        elif s[k][0] != d[k][0]:
            if s[k][1] > d[k][1]:
                data = src.get(k)
                if data is not None:
                    print path, k, s[k], d.get(k,(0,0)), src, "=>", dst, dst.set(k, data, s[k][1])
                else:
                    print path, src, k, 'is None', src.delete(k)
            elif s[k][1] == d[k][1]:
                m1 = int((src.get('?'+k) or '0').split(' ')[-1])
                m2 = int((dst.get('?'+k) or '0').split(' ')[-1])
                print path, src, k, 'is broken', s[k], m1, d[k], m2
                if m1 > m2:
                    dst.set(k, src.get(k))
                elif m2 >= m1:
                    src.set(k, dst.get(k))
                
def stat(s):
    st = {}
    for d,h,c in [line.split(' ') for line in (s.get('@') or '').split('\n') if line]:
        if len(d) != 2 and not d.endswith('/'): 
            return {}
        try:
            st[int(d[0],16)] = (h,int(c))
        except:
            pass
    return st

def almost(a,b):
    return abs(a-b) < 0.2*(abs(a)+abs(b))

def sync(db, start=0):
    stats = {}
    for n,s in db.servers.items():
        stats[str(s)] = stat(s)
    for b in range(start, db.buckets_count):
        N = len(db.buckets[b])
        for s in range(N)[::-1]:
            src = db.buckets[b][s]
            dst = db.buckets[b][(s+1)%N]
            if not stats[str(src)] or not stats[str(dst)]:
                continue
            ss = stats[str(src)].get(b, (0,0))
            ds = stats[str(dst)].get(b, (0,0))
            if ss != ds:
                print '%02x'%b,src,ss, dst, ds
                mirror(src, dst, "@%0x"%b)

def lock(fd):
    import fcntl, errno
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
    except IOError, e:
        if e.errno in (errno.EACCES, errno.EAGAIN):
            print "There is an instance of", sys.argv[0], "running. Quit"
            sys.exit(0)
        else:
            raise

def main():
    import os
    lock_file_path = '/tmp/lsync.lock'
    fd = os.open(lock_file_path, os.O_CREAT|os.O_RDWR, 0660)
    try:
        lock(fd)
        if len(sys.argv)>1:
            sync(db, int(sys.argv[1]))
        else:
            sync(db)
    finally:
        os.close(fd)
    
if __name__ == "__main__":
    main()
