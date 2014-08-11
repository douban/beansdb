#!/usr/bin/env python
# coding:utf-8

import unittest
import subprocess
import shlex
import time
import os
import sys
import string
import random
import shutil
from os.path import dirname

sys.path.insert(0, os.path.join(dirname(dirname(__file__)), "python"))
from dbclient import MCStore # in  "python" dir

def start_svc(cmd):
    print "start", cmd
    p = subprocess.Popen(isinstance(cmd, (tuple, list,)) and cmd or shlex.split(cmd) , close_fds=True)
    time.sleep(0.2)
    if p.poll() is not None:
        raise Exception("cannot start %s" % (cmd))
    return p

def stop_svc(popen):
    if popen.poll() is not None:
        return
    popen.terminate()
    popen.wait()


class BeansdbInstance:

    def __init__(self, base_path, port):
        self.port = port
        self.popen = None
        self.db_home = os.path.join(base_path, "beansdb_%s" % (self.port))
        if not os.path.exists(self.db_home):
            os.makedirs(self.db_home)
        top_dir = dirname(dirname(os.path.abspath(__file__)))
        beansdb = os.path.join(top_dir, "src/beansdb")
        conf = os.path.join(dirname(os.path.abspath(__file__)), "test_log.conf")
        self.cmd = "%s -p %s -H %s -T 1 -L %s" % (beansdb, self.port, self.db_home, conf)


    def start(self):
        assert self.popen is None
        self.popen = start_svc(self.cmd)
        store = MCStore("127.0.0.1:%s" % (self.port))
        while True:
            try:
                store.get("@")
                return
            except IOError:
                time.sleep(0.5)
                continue

    def stop(self):
        print "stop", self.cmd
        if self.popen:
            stop_svc(self.popen)
            self.popen = None

    def clean(self):
        if self.popen:
            self.stop()
        if os.path.exists(self.db_home):
            shutil.rmtree(self.db_home)


class TestBeansdbBase(unittest.TestCase):

    data_base_path = os.path.join("/tmp", "beansdb_test")
    code_base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    #NOTE: should override accesslog in tests
#    accesslog = os.path.join(self.data_base_path, 'beansproxy.log')
#    errorlog = os.path.join(self.data_base_path, 'beansproxy.log')


    def _init_dir(self):
        if not os.path.exists(self.data_base_path):
            os.makedirs(self.data_base_path)

    def _clear_dir(self):
        if os.path.exists(self.data_base_path):
            shutil.rmtree(self.data_base_path)





#
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
