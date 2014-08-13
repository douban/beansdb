#!/usr/bin/env python
# coding:utf-8

import os
import sys
import time
from base import BeansdbInstance, TestBeansdbBase, MCStore, check_data_hint_integrity
import unittest


class TestGenerateData(TestBeansdbBase):

    proxy_addr = 'localhost:7905'
    backend1_addr = 'localhost:57901'
    
    def setUp(self):
        self._clear_dir()
        self._init_dir()
        self.backend1 = BeansdbInstance(self.data_base_path, 57901)
 
    def test_gen_data(self):
        self.backend1.start()
        store = MCStore(self.backend1_addr)
        loop_num = 10 * 1024
        for i in xrange(loop_num):
            key = "test%s" % (i)
            if not store.set(key, 1):
                print "failed to set %s" % (key)
                return self.fail("fail")
            if not store.set(key, 2):
                print "failed to set %s" % (key)
                return self.fail("fail")
        print "done set"
        for i in xrange(loop_num):
            key = "test%s" % (i)
            try:
                self.assertEqual(store.get(key), 2)
            except Exception, e:
                print key, "error", e
                return self.fail("fail")
        print "done get"
        self.backend1.stop()
        print "stopped"
        self.backend1.start()
        print "started"
        store = MCStore(self.backend1_addr)
        for i in xrange(loop_num):
            key = "test%s" % (i)
            try:
                self.assertEqual(store.get(key), 2)
            except Exception, e:
                print key, "error", e
                return self.fail("fail")
        print "done get"
        check_data_hint_integrity(self.backend1.db_home, 1)


    def tearDown(self):
        self.backend1.stop()


if __name__ == '__main__':
    unittest.main()

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
