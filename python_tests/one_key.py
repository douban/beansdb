#!/usr/bin/env python
# coding:utf-8

from base import BeansdbInstance, TestBeansdbBase, MCStore, random_string
import unittest

import zlib
import string


class TestKeyVersion(TestBeansdbBase):

    proxy_addr = 'localhost:7905'
    backend1_addr = 'localhost:57901'

    def _get_meta(self, store, key):
        meta = store.get("??" + key)
        if meta:
            meta = meta.split()
            assert(len(meta) == 7)
            return tuple([int(meta[i]) for i in [0, -2, -1]])

    def setUp(self):
        self._clear_dir()
        self._init_dir()
        self.backend1 = BeansdbInstance(self.data_base_path, 57901)

        self.last_pos = 0
        self.last_size = 0

    def append(self, size):
        self.last_pos += self.last_size
        self.last_size = size

    def test_set_verion(self):
        self.backend1.start()
        store = MCStore(self.backend1_addr)
        key = "key1"
        store.set(key, "aaa")
        self.append(256)
        self.assertEqual(store.get(key), "aaa")
        self.assertEqual(self._get_meta(store, key), (1, 0, self.last_pos))
        store.set_raw(key, "bbb", rev=3)
        self.append(256)
        self.assertEqual(self._get_meta(store, key), (3, 0, self.last_pos))
        store.set_raw(key, "bbb", rev=4)
        self.assertEqual(self._get_meta(store, key), (4, 0, self.last_pos)) # current behavior will raise version
        store.set_raw(key, "ccc", rev=2)
        self.assertEqual(store.get(key), "bbb")
        self.assertEqual(self._get_meta(store, key), (4, 0, self.last_pos)) # current behavior will raise version

    def test_delete_version(self):
        self.backend1.start()
        store = MCStore(self.backend1_addr)
        key = "key1"

        store.set(key, "aaa")
        self.append(256)
        self.assertEqual(self._get_meta(store, key), (1, 0, self.last_pos))

        store.delete(key)
        self.append(256)
        self.assertEqual(self._get_meta(store, key), (-2, 0, self.last_pos))

        store.set(key, "bbb")
        self.append(256)
        self.assertEqual(store.get(key), 'bbb')
        self.assertEqual(self._get_meta(store, key), (3, 0, self.last_pos))

    def _test_compress(self, overflow):
        self.backend1.start()
        value =  string.letters
        store = MCStore(self.backend1_addr)
        compressed_value = zlib.compress(value, 0)
        key = 'k' * (256 - len(compressed_value) - 24 + (1 if overflow else 0))

        value_easy_compress = 'v'* len(compressed_value)

        assert(store.set(key, value_easy_compress))
        assert(store.get(key) == value_easy_compress)
        self.append(256)
        self.assertEqual(self._get_meta(store, key), (1, 0, self.last_pos))

        assert(store.set_raw(key, compressed_value, flag = 0x00000010))
        assert(store.get(key) == value)
        self.append(512 if overflow else 256)
        self.assertEqual(self._get_meta(store, key), (2, 0, self.last_pos))

        assert(store.set(key, 'aaa'))
        self.append(256)
        self.assertEqual(self._get_meta(store, key), (3, 0, self.last_pos))

    def test_compress_257(self):
        self._test_compress(True)

    def test_compress_256(self):
        self._test_compress(False)

    def test_special_key(self):
        self.backend1.start()
        kvs = [('a'*250, 1), ("a", range(1000))]
        store = MCStore(self.backend1_addr)
        for k,v in kvs:
            assert(store.set(k, v))
            assert(v == store.get(k))
        self.backend1.stop()
        self.backend1.start()
        store = MCStore(self.backend1_addr)
        for (k,v) in kvs:
            assert(v == store.get(k))

    def test_big_value(self):
        self.backend1.start()
        store = MCStore(self.backend1_addr)

        key = "largekey"
        size = 10 * 1024 * 1024
        rsize = (((size + len(key) + 24) >> 8) + 1) << 8
        string_large = random_string(size)
        assert(store.set(key, string_large))
        assert(store.get(key) == string_large)
        self.append(rsize)
        self.assertEqual(self._get_meta(store, key), (1, 0, self.last_pos))

        assert(store.set(key, 'aaa'))
        self.append(256)
        self.assertEqual(self._get_meta(store, key), (2, 0, self.last_pos))


    def test_restart(self):
        pass

    def tearDown(self):
        self.backend1.stop()

if __name__ == '__main__':
    unittest.main()


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
