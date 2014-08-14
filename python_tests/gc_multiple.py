#!/usr/bin/env python
# coding:utf-8

import os
import sys
import unittest
from gc_simple import TestGCBase
import glob
import time
from base import BeansdbInstance, TestBeansdbBase, MCStore, check_data_with_key,check_data_hint_integrity

class TestGCMultiple(TestGCBase):

    def setUp(self):
        self._clear_dir()
        self._init_dir()
        self.backend1 = BeansdbInstance(self.data_base_path, 57901, accesslog=False, max_data_size=10) 
        # buffer size is 4m, max_data_size set to 10m for data file better reach above 6m
        # turn off accesslog to speed up write

    # only generate keys in sector0
    def _gen_data(self, data, prefix='', loop_num=10 * 1024):
        store = MCStore(self.backend1_addr)
        for key in self.backend1.generate_key(prefix=prefix, count=loop_num, sector=0):
            if not store.set(key, data):
                return self.fail("fail to set %s" % (key))

    def _delete_data(self, prefix='', loop_num=10 * 1024):
        store = MCStore(self.backend1_addr)
        for key in self.backend1.generate_key(prefix=prefix, count=loop_num, sector=0):
            if not store.delete(key):
                return self.fail("fail to delete %s" % (key))


    def _check_data(self, data, prefix='', loop_num=10 * 1024):
        store = MCStore(self.backend1_addr)
        for key in self.backend1.generate_key(prefix=prefix, count=loop_num, sector=0):
            try:
                self.assertEqual(store.get(key), data)
            except Exception, e:
                return self.fail("fail to check key %s: %s" % (key, str(e)))


    def test_gc_multiple_files_and_limit(self):
        self.backend1.start()
        self._gen_data(1, prefix='group1_', loop_num=16 * 1024)
        #5M data file 1
        self._gen_data(2, prefix='group1_', loop_num=16 * 1024)
        print 'group1'
        
        self.backend1.stop()
        self.backend1.start()
        print "restarted"

        self._gen_data(1, prefix='group2_', loop_num=16 * 1024)
        self._gen_data(2, prefix='group2_', loop_num=16 * 1024)

        self.backend1.stop()
        self.backend1.start()
        print "restarted"


        #5M data file 2
        # data file 3
        self._gen_data(1, prefix='group3_', loop_num=512)
        self._gen_data(2, prefix='group3_', loop_num=512)
        self.assertEqual(self.backend1.item_count(), 32 * 1024 + 512)

        sector0_exp = os.path.join(self.backend1.db_home, "0/*.data")

        print "sector0 files", len(glob.glob(sector0_exp))
        self.assert_(len(glob.glob(sector0_exp)) >= 2)

        time.sleep(1)
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

        self.assertEqual(self.backend1.item_count(), 32 * 1024 + 512)
        self._check_data(2, prefix='group1_', loop_num=8 * 1024)
        self._check_data(2, prefix='group2_', loop_num=512)
        self._check_data(2, prefix='group3_', loop_num=512)
        for key in self.backend1.generate_key(prefix="group1_", count=2, sector=0):
            print key
            self.assert_(not check_data_with_key(os.path.join(self.backend1.db_home, "0/000.data"), key, ver_=1))
            self.assert_(check_data_with_key(os.path.join(self.backend1.db_home, "0/000.data"), key, ver_=2))
        print "group2 should be not in 000.data, but in 001.data"
        for key in self.backend1.generate_key(prefix="group2_", count=2, sector=0):
            print key
            self.assert_(not check_data_with_key(os.path.join(self.backend1.db_home, "0/000.data"), key))
            self.assert_(check_data_with_key(os.path.join(self.backend1.db_home, "0/001.data"), key, ver_=2))

        print "check data& hint"
        check_data_hint_integrity(self.backend1.db_home, db_depth=self.backend1.db_depth)

if __name__ == '__main__':
    unittest.main()



# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
