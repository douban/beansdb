#!/usr/bin/env python
# coding:utf-8

from base import BeansdbInstance, MCStore
from base import random_string, delete_hint_and_htree, temper_with_key_value
import unittest
from gc_simple import TestGCBase


string_large = random_string(10*1024*1024)


class TestBrokenBase(TestGCBase):
    proxy_addr = 'localhost:7905'
    backend1_addr = 'localhost:57901'

    def setUp(self):
        self._clear_dir()
        self._init_dir()
        self.backend1 = BeansdbInstance(self.data_base_path, 57901, db_depth=1)

    # only generate keys in sector0
    def _gen_data(self, data, prefix='', loop_num=10 * 1024, sector=0):
        store = MCStore(self.backend1_addr)
        for key in self.backend1.generate_key(prefix=prefix, count=loop_num, sector=sector):
            if not store.set(key, data):
                return self.fail("fail to set %s" % (key))
        store.close()

    def _check_data(self, data, prefix='', loop_num=10 * 1024, sector=0):
        store = MCStore(self.backend1_addr)
        for key in self.backend1.generate_key(prefix=prefix, count=loop_num, sector=sector):
            try:
                self.assertEqual(store.get(key), data)
            except Exception, e:
                return self.fail("fail to check key %s: %s" % (key, str(e)))
        store.close()


class TestBitCaseScanBroken(TestBrokenBase):

    def test_bc_scan(self):
        print ""
        print "test bc scan broken data"
        self.backend1.start()
        self._gen_data("some value", prefix='test1', loop_num=1024, sector=0)
        tempered_key = None
        for key in self.backend1.generate_key(prefix="test2", count=1, sector=0):
            tempered_key = key
            store = MCStore(self.backend1_addr)
            store.set(tempered_key, string_large)
            store.close()
        self._gen_data("other value", prefix='test3', loop_num=1024, sector=0)
        self.assertEqual(self.backend1.item_count(), 2049)
        self.backend1.stop()

        #make sure we produce a crc error
        assert temper_with_key_value(self.backend1.db_home, self.backend1.db_depth, tempered_key, delete_hint=True)
        delete_hint_and_htree(self.backend1.db_home, self.backend1.db_depth)

        self.backend1.start()
        self.assertEqual(self.backend1.item_count(), 2048)
        self._check_data("some value", prefix="test1", loop_num=1024, sector=0)
        self._check_data("other value", prefix="test3", loop_num=1024, sector=0)
        self.backend1.stop()


class TestOnlineBroken(TestBrokenBase):

    def test_get_broken(self):
        print
        print "test get broken data"
        self.backend1.start()

        self._gen_data("some value", prefix='test1', loop_num=1024, sector=0)
        tempered_key = None
        for key in self.backend1.generate_key(prefix="test2", count=1, sector=0):
            tempered_key = key
            store = MCStore(self.backend1_addr)
            store.set(tempered_key, string_large)
            store.close()
        self._gen_data("other value", prefix='test3', loop_num=1024, sector=0)
        self.assertEqual(self.backend1.item_count(), 2049)

        # flush hint
        self.backend1.stop()
        self.backend1.start()

        #make sure we produce a crc error
        temper_with_key_value(self.backend1.db_home, self.backend1.db_depth, tempered_key, delete_hint=False)
        self.assertEqual(self.backend1.item_count(), 2049)
        print "when beansdb encounter broken data when reading, it should delete it from htree"
        store = MCStore(self.backend1_addr)
        store.get(tempered_key) is None
        store.close()
        self.assertEqual(self.backend1.item_count(), 2048)
        self._check_data("some value", prefix="test1", loop_num=1024, sector=0)
        self._check_data("other value", prefix="test3", loop_num=1024, sector=0)
        self.backend1.stop()


class TestGCBroken(TestBrokenBase):

    def test_gc_broken(self):

        print
        print "test gc broken data"
        self.backend1.start()
        self._gen_data("some value", prefix='test1', loop_num=1024, sector=0)
        tempered_key = None
        for key in self.backend1.generate_key(prefix="test2", count=1, sector=0):
            tempered_key = key
            store = MCStore(self.backend1_addr)
            store.set(tempered_key, string_large)
            store.close()
        self._gen_data("other value", prefix='test1', loop_num=1024, sector=0)
        self.assertEqual(self.backend1.item_count(), 1025)
        # flush hint
        self.backend1.stop()
        self.backend1.start()

        #make sure we produce a crc error
        temper_with_key_value(self.backend1.db_home, self.backend1.db_depth, tempered_key, delete_hint=False)

        self._start_gc_all()
        while True:
            status = self._gc_status()
            if status == 'success':
                print "done gc"
                break
            elif status == 'fail':
                return self.fail("optimize_stat = fail")

        self.assertEqual(self.backend1.item_count(), 1024)
        self._check_data("other value", prefix="test1", loop_num=1024, sector=0)


if __name__ == '__main__':
    unittest.main()


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
