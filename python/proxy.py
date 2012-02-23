#!/usr/bin/env python

import time, math
import logging
import sys
from eventlet import api, greenio, coros, util, tpool

def fnv1a(s):
    prime = 0x01000193
    h = 0x811c9dc5
    for c in s:
        h ^= ord(c)
        h = (h * prime) & 0xffffffff
    return h

class Client(object):
    hash_space = 1<<32
    def __init__(self, servers={}, buckets_count=16, N=3, R=1, W=1):
        self.socks = dict((addr, []) for addr in servers)
        self.N = N
        self.R = R
        self.W = W
        self.buckets_count = buckets_count
        self.bucket_size = self.hash_space / buckets_count
        self.servers = {}
        self.server_buckets = {}
        self.buckets = [[] for i in range(buckets_count)]
        for s,bs in servers.items():
            for b in bs:
                self.buckets[b].append(s)
        for b in range(self.buckets_count):
            self.buckets[b].sort(key=lambda x:hash("%x::%s"%(b,x) * 2))

    def pop_connection(self, addr):
        try:
            sock = self.socks[addr].pop()
        except IndexError:
            sock = None
        if sock is None:
            sock = greenio.socket.socket()
            if ':' in addr:
                addr, port = addr.split(":")
            else:
                port = 11211
            try:
                sock.connect((addr, int(port)))
            except greenio.socket.error:
                print >>sys.stderr, "connect to %s:%s failed" % (addr, port)
                return
        return sock

    def push_connection(self, addr, sock):
        self.socks[addr].append(sock)

    def get_hosts_by_key(self, key):
        hash = fnv1a(key)
        b = hash / self.bucket_size
        return self.buckets[b] 

    def _get(self, addr, key):
        sock = self.pop_connection(addr)
        if not sock:
            return
        try:
            sock.send("get %s\r\n" % key)
            reader = sock.makefile('r')
            line = reader.readline()
            r  = None
            if line.startswith("VALUE"):
                _, key, flag, length = line.split(' ')
                value = reader.read(int(length))
                r = value, int(flag)
                reader.read(2) # \r\n
                line = reader.readline() # END\r\n
            reader.close()
            self.push_connection(addr, sock)
            return r
        except:
            raise

    def get(self, key):
        for addr in self.get_hosts_by_key(key):
            r = self._get(addr, key)
            if r is not None:
                return r

    def _set(self, addr, key, value, flag, results=[]):
        sock = self.pop_connection(addr)
        if not sock:
            return
        reader = sock.makefile('r')
        writer = sock.makefile('w')
        writer.write("set %s %d %d %d\r\n" % (key, flag, 0, len(value)))
        writer.write(value)
        writer.write("\r\n")
        writer.flush()
        line = reader.readline()
        r = line.startswith("STORED")
        reader.close()
        writer.close()
        self.push_connection(addr, sock)
        return r

    def set(self, key, value, flag=0, rev=0):
        rs = [self._set(addr, key, value, flag) 
                for addr in self.get_hosts_by_key(key)]
        return rs.count(True) > 0

    def delete(self, key):
        pass

def test():
    c = Client({"localhost:7901":range(16),
                "localhost:7902":range(16),
                "localhost:7903":range(16)})
    print c.set('a', 'aaaa', 0)
    print c.get('a')

def handler(store, sock):
    reader = sock.makefile('r')
    writer = sock.makefile('w')

    def writeline(line):
        writer.write(line)
        writer.write('\r\n')

    while True:
        x = reader.readline()
        if not x: break

        args = x.split()
        cmd = args[0]

        st = time.time()
        if cmd == 'get':
            for key in args[1:]:
                v = store.get(key)
                if v is not None:
                    value, flag = v
                    writeline("VALUE %s %d %d" % (key, flag, len(value)))
                    writeline(value)
                    del value, v
            writeline('END')
            
        elif cmd == 'set':
            key, flag, rev, bytes = args[1:5]
            flag, rev, bytes = int(flag), int(rev), int(bytes)

            buf = reader.read(bytes)
            while len(buf) < bytes:
                buf += reader.read(bytes - len(buf))
            reader.read(2)
            if store.set(key, buf, flag, rev):
                writeline('STORED')
            else:
                writeline('NOT_STORED')
            del buf

        elif cmd == 'delete':
            key = args[1]
            v = store.delete(key)
            noreply = len(args) > 3 and int(args[3]) or False
            if not noreply:
                writeline(v and 'DELETED' or 'NOT_FOUND')

        elif cmd == 'stat':
            writeline('END')

        elif cmd == 'quit':
            break

        else:
            writeline('CLIENT_ERROR')
        
        t = time.time() - st
        if t > 0.001:
            logging.info(args)
            print t, args
        
        writer.flush()
        api.sleep()
        
    reader.close()
    writer.close()
    sock.close()


def main():
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-l", "--listen", dest="host", default="0.0.0.0",
            help="the ip interface to bind")
    parser.add_option("-p", "--port", default=7902, type=int,
            help="which port to listen")
    parser.add_option("-d", "--daemon", action="store_true", 
            help="run in daemon", default=False)

    (options, args) = parser.parse_args()

    cfg = {"localhost:7901":range(16),
            "localhost:7902":range(16),
            "localhost:7903":range(16)}
    store = Client(cfg, 16)

    print "server listening on %s:%s" % (options.host, options.port)
    server = api.tcp_listener((options.host, options.port))
    util.set_reuse_addr(server)

    while True:
        try:
            new_sock, address = server.accept()
        except KeyboardInterrupt:
            break
        api.spawn(handler, store, new_sock) 

    print 'close listener ...'
    server.close()
    
if __name__ == '__main__':
    main()
