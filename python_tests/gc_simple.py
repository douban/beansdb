#!/usr/bin/env python
# coding:utf-8

import time
import string
import itertools
from base import BeansdbInstance, TestBeansdbBase, MCStore
from base import locate_key_iterate, locate_key_with_hint, check_data_hint_integrity
import unittest
import telnetlib


class TestGCBase(TestBeansdbBase):

    proxy_addr = 'localhost:7905'
    backend1_addr = 'localhost:57901'

    def setUp(self):
        self._clear_dir()
        self._init_dir()
        self.backend1 = BeansdbInstance(self.data_base_path, 57901)

    def _start_gc(self, bucket='', start_fid=0, end_fid=None):
        """ bucket must be in 0 or 00 string """
        if bucket:
            assert isinstance(bucket, basestring) and len(bucket) <= 2

        t = telnetlib.Telnet("127.0.0.1", self.backend1.port)
        tree = '@%s' % bucket
        if end_fid is None:
            t.write('gc {} {}\n'.format(tree, start_fid))
        else:
            t.write('gc {} {} {}\n' % (tree, start_fid, end_fid))
        t.read_until('OK')
        t.write('quit\n')
        t.close()

    def _start_gc_all(self):
        height = self.backend1.db_depth
        hex_digits = string.digits + 'abcdef'
        buckets_iter = itertools.product(*[hex_digits for _ in range(height)])
        buckets = [''.join(i) for i in buckets_iter]

        for b in buckets:
            self._start_gc(bucket=b)
            while True:
                status = self._gc_status()
                if status.find('running') >= 0:
                    continue
                elif status == 'success':
                    print "bucket %s gc done" % b
                    break
                elif status == 'fail':
                    return self.fail("optimize_stat = fail")
                else:
                    self.fail(status)

    def _gc_status(self):
        t = telnetlib.Telnet("127.0.0.1", self.backend1.port)
        t.write('optimize_stat\n')
        out = t.read_until('\n')
        t.write('quit\n')
        t.close()
        return out.strip("\r\n")

    def _gen_data(self, data, prefix='', loop_num=10 * 1024):
        store = MCStore(self.backend1_addr)
        for key in self.backend1.generate_key(prefix=prefix, count=loop_num):
            if not store.set(key, data):
                return self.fail("fail to set %s" % (key))

    def _delete_data(self, prefix='', loop_num=10 * 1024):
        store = MCStore(self.backend1_addr)
        for key in self.backend1.generate_key(prefix=prefix, count=loop_num):
            if not store.delete(key):
                return self.fail("fail to delete %s" % (key))

    def _check_data(self, data, prefix='', loop_num=10 * 1024):
        store = MCStore(self.backend1_addr)
        for key in self.backend1.generate_key(prefix=prefix, count=loop_num):
            try:
                self.assertEqual(store.get(key), data)
            except Exception, e:
                return self.fail("fail to check key %s: %s" % (key, str(e)))

    def tearDown(self):
        self.backend1.stop()


class TestGCSimple(TestGCBase):

    def test_gc(self):
        self.backend1.start()
        store = MCStore(self.backend1_addr)
        ver_key = 'test_version_key'
        store.set(ver_key, 1)
        store.set(ver_key, 1, rev=3)  # will only raise version in htree
        self.assertEqual(self._get_version(store, ver_key), 3)

        self._gen_data(1)
        print "done set data to 1"
        time.sleep(10)
        self._gen_data(2)
        self._gen_data(1, prefix='delete_group')
        time.sleep(2)
        self.assertEqual(self.backend1.item_count(), 20481)
        self._delete_data(prefix='delete_group')
        self.assertEqual(self.backend1.item_count(), 10241)
        self.assert_(not store.delete('key not exists'))
        self.assertEqual(self.backend1.item_count(), 10241)

        print "stop beansdb to rotate data file and produce hint"
        self.backend1.stop()
        self.backend1.start()

        print "deleted key should exists in data"
        assert locate_key_iterate(self.backend1.db_home, db_depth=self.backend1.db_depth, key="delete_group" + "test0", ver_=1)
        assert locate_key_with_hint(self.backend1.db_home, db_depth=self.backend1.db_depth, key="delete_group" + "test0", ver_=-2)
        print "done set data to 2"
        self._start_gc_all()
        print "gc started"
        while True:
            status = self._gc_status()
            if status.find('running') >= 0:
                self._check_data(2)
                continue
            elif status == 'success':
                print "done gc"
                break
            elif status == 'fail':
                return self.fail("optimize_stat = fail")
            else:
                self.fail(status)
        self._check_data(2)
        store = MCStore(self.backend1_addr)
        self.assertEqual(self._get_version(store, ver_key), 3)  # version 3 should be in data
        print "check test key version, old version should not exist"
        assert locate_key_with_hint(self.backend1.db_home, db_depth=self.backend1.db_depth, key=ver_key, ver_=3)
        assert not locate_key_iterate(self.backend1.db_home, db_depth=self.backend1.db_depth, key=ver_key, ver_=1)
        print "check data & hint"
        check_data_hint_integrity(self.backend1.db_home, db_depth=self.backend1.db_depth)

        print "deleted key got deleted from data file during gc"
        assert not locate_key_iterate(self.backend1.db_home, db_depth=self.backend1.db_depth, key="delete_group" + "test0")
        self.assertEqual(self.backend1.item_count(), 10241)

        self.backend1.stop()


class TestGCSimple2(TestGCSimple):

    def setUp(self):
        self._clear_dir()
        self._init_dir()
        self.backend1 = BeansdbInstance(self.data_base_path, 57901, db_depth=2)

if __name__ == '__main__':
    unittest.main()


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
