#!/usr/bin/env python
# coding:utf-8

import os
import sys
import time
from base import BeansdbInstance, TestBeansdbBase, MCStore
from base import locate_key_iterate, locate_key_with_hint, get_hash, check_data_hint_integrity
import unittest
import telnetlib
import glob
import quicklz
import struct
import re
from gc_simple import TestGCBase



class TestBroken(TestGCBase):

    def setUp(self):
        self._clear_dir()
        self._init_dir()
        self.backend1 = BeansdbInstance(self.data_base_path, 57901, db_depth=0)

    def _check_data(self, data, prefix='', loop_num=10 * 1024):
        store = MCStore(self.backend1_addr)
        for key in self.backend1.generate_key(prefix=prefix, count=loop_num):
            try:
                if key != 'test1':
                    self.assertEqual(store.get(key), data)
                else:
                    self.assertEqual(store.get(key), None)
            except Exception, e:
                return self.fail("fail to check key %s: %s" % (key, str(e)))

    def test_broken(self):
        self.backend1.start()

        self._gen_data(1)
        print "done set data to 1"
        time.sleep(10)
        self.assertEqual(self.backend1.item_count(), 10240)
        self.backend1.stop()
        
        hintpath = os.path.join(self.backend1.db_home, '000.hint.qlz')
        datapath = os.path.join(self.backend1.db_home, '000.data')
        f = open(datapath, "r+")
        f.seek(256 + 24 + len('test0'))
        f.write('x')
        f.close()
        os.remove(hintpath)
        
        self.backend1.start()
        self.assertEqual(self.backend1.item_count(), 10240 - 1)
        self._check_data(1)
        
        self.backend1.stop()

class TestBrokenGC(TestBroken):
    def test_broken(self):
        self.backend1.start()

        self._gen_data(1)
        print "done set data to 1"
        time.sleep(10)
        self.assertEqual(self.backend1.item_count(), 10240)

        self.backend1.stop()
        self.backend1.start()

        datapath = os.path.join(self.backend1.db_home, '000.data')
        f = open(datapath, "r+")
        f.seek(256 + 24 + len('test0'))
        f.write('x')
        f.close()
        
        

        self._start_gc(0)
        print "gc started"
        while True:
            status = self._gc_status()
            if status.find('running') >= 0:
                time.sleep(1)
                continue
            elif status == 'success':
                print "done gc"
                break
            elif status == 'fail':
                return self.fail("optimize_stat = fail")
            else:
                self.fail(status)
        self.assertEqual(self.backend1.item_count(), 10240 - 1)
        self._check_data(1)

        self.backend1.stop()


if __name__ == '__main__':
    unittest.main()


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
