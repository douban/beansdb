#!/usr/bin/python
# encoding:utf-8

import sys
import os
import re
import web

from dbclient import Beansdb

fs = Beansdb({"localhost:7900": range(16)}, 16)

class File:
    def GET(self, path):
        data = fs.get(path)
        if data:
            sys.stdout.write(data)
        else:
            web.notfound()

urls = (
   "(/.*)", "File",
)

def runfcgi_multiprocess(func, addr=('localhost', 8000)): 
    import flup.server.fcgi as flups 
    return flups.WSGIServer(func, multithreaded=False, 
                multiprocess=True, bindAddress=addr).run() 

web.wsgi.runfcgi = runfcgi_multiprocess 

if __name__ == '__main__':
    if hasattr(web, 'run'):
        # web.py 0.2
        web.run(urls, globals())
    else:
        app = web.application(urls, globals())
        app.run()
