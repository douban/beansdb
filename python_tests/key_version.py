#!/usr/bin/env python
# coding:utf-8

import os
import sys
import time
from base import BeansdbInstance, TestBeansdbBase, MCStore
import unittest


class TestKeyVersion(TestBeansdbBase):

    proxy_addr = 'localhost:7905'
    backend1_addr = 'localhost:57901'


    def _get_version(self, store, key):
        meta = store.get("?" + key)
        if meta:
            return int(meta.split()[0])

    def setUp(self):
        self._clear_dir()
        self._init_dir()
        self.backend1 = BeansdbInstance(self.data_base_path, 57901)

    def test_set_verion(self):
        self.backend1.start()
        store = MCStore(self.backend1_addr)
        key = "key1"
        store.set(key, "aaa")
        self.assertEqual(store.get(key), "aaa")
        self.assertEqual(self._get_version(store, key), 1)
        store.set_raw(key, "bbb", rev=3)
        self.assertEqual(self._get_version(store, key), 3)
        store.set_raw(key, "bbb", rev=4)
        self.assertEqual(self._get_version(store, key), 4) # current behavior will raise version
        store.set_raw(key, "ccc", rev=2)
        self.assertEqual(store.get(key), "bbb")
        self.assertEqual(self._get_version(store, key), 4) # current behavior will raise version

    def test_delete_version(self):
        self.backend1.start()
        store = MCStore(self.backend1_addr)
        key = "key2"
        store.set(key, "aaa")
        self.assertEqual(self._get_version(store, key), 1)
        store.delete(key)
        self.assertEqual(self._get_version(store, key), None)
        store.set(key, "bbb")
        self.assertEqual(store.get(key), 'bbb')
        self.assertEqual(self._get_version(store, key), 3)


    def tearDown(self):
        self.backend1.stop()

if __name__ == '__main__':
    unittest.main()


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
