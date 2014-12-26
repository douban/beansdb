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

class TestBucketTxt(TestBeansdbBase):

    proxy_addr = 'localhost:7905'
    backend1_addr = 'localhost:57901'

    def setUp(self):
        self._clear_dir()
        self._init_dir()
        self.backend1 = BeansdbInstance(self.data_base_path, 57901)

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


    def test_buckets_txt(self):
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

        self._gen_data(1, prefix='group3_', loop_num=16 * 1024)
        self._gen_data(2, prefix='group3_', loop_num=16 * 1024)

        self.backend1.stop()
        sector0_exp = os.path.join(self.backend1.db_home, "0/*.data")
        print "sector0 files", len(glob.glob(sector0_exp))
        self.assertEqual(len(glob.glob(sector0_exp)), 3)

        buckets_txt = os.path.join(self.backend1.db_home, "0/buckets.txt")
        self.assert_(os.path.exists(buckets_txt))

        print "delete the last file will start fail"
        data2 = os.path.join(self.backend1.db_home, "0/002.data")
        hint2 = os.path.join(self.backend1.db_home, "0/002.hint.qlz")
        print "rm", data2
        print "rm", hint2
        os.remove(data2)
        os.remove(hint2)
        with self.assertRaisesRegexp(Exception, '^cannot start'):
            self.backend1.start()


    def test_buckets_txt2(self):
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

        self._gen_data(1, prefix='group3_', loop_num=16 * 1024)
        self._gen_data(2, prefix='group3_', loop_num=16 * 1024)

        self.assertEqual(self.backend1.item_count(), 16 * 3 * 1024)
        self.backend1.stop()
        sector0_exp = os.path.join(self.backend1.db_home, "0/*.data")
        print "sector0 files", len(glob.glob(sector0_exp))
        self.assertEqual(len(glob.glob(sector0_exp)), 3)

        buckets_txt = os.path.join(self.backend1.db_home, "0/buckets.txt")
        with open(buckets_txt, 'r') as f:
            bucket_data = f.read()
        print bucket_data
        bucket_arr = bucket_data.split("\n")
        for i in xrange(len(bucket_arr)):
            if bucket_arr[i] and bucket_arr[i][0] == '2':
                bucket_arr[i] = "2 1024"  # size have to be multiply of 256
                break
        with open(buckets_txt, 'w') as f:
            f.write("\n".join(bucket_arr))
        print "changed the buckets.txt with last file size, can be tolerated"
        with open(buckets_txt, 'r') as f:
            bucket_data = f.read()
            print bucket_data

        self.backend1.start()
        self.assertEqual(self.backend1.item_count(), 16 * 3 * 1024)
        print "test item count ok"

    def test_buckets_txt3(self):
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
        self.assertEqual(self.backend1.item_count(), 16 * 2 * 1024)

        self.backend1.stop()


        self.backend1.stop()
        sector0_exp = os.path.join(self.backend1.db_home, "0/*.data")
        print "sector0 files", len(glob.glob(sector0_exp))
        self.assertEqual(len(glob.glob(sector0_exp)), 2)

        buckets_txt = os.path.join(self.backend1.db_home, "0/buckets.txt")
        with open(buckets_txt, 'r') as f:
            bucket_data = f.read()
        print bucket_data
        bucket_arr = bucket_data.split("\n")
        for i in xrange(len(bucket_arr)):
            if bucket_arr[i] and bucket_arr[i][0] == '0':
                size = int(bucket_arr[i].split()[1])
                size += 1024
                bucket_arr[i] = "1 %s" % (size)  # size have to be multiply of 256
                break
        with open(buckets_txt, 'w') as f:
            f.write("\n".join(bucket_arr))
        print "changed the buckets.txt file size which not the last, shouldnot start"
        with open(buckets_txt, 'r') as f:
            bucket_data = f.read()
            print bucket_data

        with self.assertRaisesRegexp(Exception, '^cannot start'):
            self.backend1.start()

    def test_buckets_txt4(self):
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
        buckets_txt = os.path.join(self.backend1.db_home, "0/buckets.txt")
        if os.path.exists(buckets_txt):
            print "rm", buckets_txt
            os.remove(buckets_txt)
        self.backend1.start()




    def tearDown(self):
        self.backend1.stop()



if __name__ == '__main__':
    unittest.main()



# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
