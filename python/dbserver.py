#!/usr/bin/env python

import time, math
import logging
from eventlet import api, util, tpool
#from tcstore import TCStore, MultiTCStore
from store import HStore

quit = False

def flush(store):
    while not quit:
        store.flush(30)
        api.sleep(1)

def handler(store, sock, reader, writer):
    
    def writeline(line):
        writer.write(line)
        writer.write('\r\n')

    while not quit:
        # pass through every non-eof line
        x = reader.readline()
        if not x: break

        args = x.split()
        cmd = args[0]
        #print args

        st = time.time()
        if cmd == 'get':
            def do():
                for key in args[1:]:
                    v = store.get(key)
                    if v is not None:
                        writeline("VALUE %s %d %d" % (key, 0, len(v)))
                        writeline(v)
                        del v
                writeline('END')
                t = time.time() - st
                if t > 0.1:
                    print t, args
                writer.flush()
            tpool.execute(do)
            
        elif cmd == 'set':
            def do():
                key, flag, rev, bytes = args[1:5]
                flag, rev, bytes = int(flag), int(rev), int(bytes)

                buf = reader.read(bytes)
                while len(buf) < bytes:
                    buf += reader.read(bytes - len(buf))
                reader.read(2)
                if store.set(key, buf, rev):
                    writeline('STORED')
                else:
                    writeline('NOT_STORED')
                del buf
                t = time.time() - st
                if t > 0.1:
                    print t, args
                writer.flush()
            tpool.execute(do)

        elif cmd == 'delete':
            def do():
                key = args[1]
                v = store.delete(key)
                noreply = len(args) > 3 and int(args[3]) or False
                if not noreply:
                    writeline(v and 'DELETED' or 'NOT_FOUND')
                t = time.time() - st
                if t > 0.1:
                    print t, args
                writer.flush()
            tpool.execute(do)

        elif cmd == 'stat':
            writeline('END')
            writer.flush()

        elif cmd == 'quit':
            break

        else:
            writeline('CLIENT_ERROR')
        
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
#    parser.add_option("-d", "--daemon", action="store_true", 
#            help="run in daemon", default=False)
    parser.add_option("-H", "--home", default="beansdb",
            help="the database path")
    parser.add_option("-c", "--count", default=16, type=int,
            help="number of db file, power of 16")
    parser.add_option("-s", "--start", default=0, type=int,
            help="start index of db file")
    parser.add_option("-e", "--end", default=-1, type=int,
            help="last end of db file, -1 means no limit")
    parser.add_option("-n", "--limit", default=100, type=int, 
            help="diffs limit to do db scan")
    parser.add_option("-t", "--threads", type=int, default=20,
            help="number of IO threads")


    (options, args) = parser.parse_args()

    store = (HStore(options.home, 
                int(math.log(options.count, 16)),
                options.start, options.end))
    #store.check(options.limit, nonblocking=True)
    api.spawn(tpool.execute, store.check, options.limit) # check in thread pool
    api.spawn(tpool.execute, flush, store)

    print "server listening on %s:%s" % (options.host, options.port)
    server = api.tcp_listener((options.host, options.port))
    util.set_reuse_addr(server)

    while True:
        try:
            new_sock, address = server.accept()
        except KeyboardInterrupt:
            break
        api.spawn(handler, store, new_sock, 
            new_sock.makefile('r'), new_sock.makefile('w'))

    global quit
    quit = True
    
    print 'close listener ...'
    server.close()
    
    print 'stop checker thread ...'
    store.stop_check()

    print 'stop worker threads ...'
    tpool.killall()

    print 'close store...'
    store.close()

if __name__ == '__main__':
    main()
