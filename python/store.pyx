"""
  Beansdb - A high available distributed key-value storage system:

      http://beansdb.googlecode.com

  Copyright 2009 Douban Inc.  All rights reserved.

  Use and distribution licensed under the BSD license.  See
  the LICENSE file for full text.
"""

__authors__ = ["Davies Liu <davies.liu@gmail.com>"]
__version__ = "0.3.0"

import os

cdef extern from "Python.h":
    object PyString_FromString(char *s)
    object PyString_FromStringAndSize(char *s, Py_ssize_t len)
    ctypedef struct PyThreadState:
        pass
    PyThreadState *PyEval_SaveThread()
    void PyEval_RestoreThread(PyThreadState *_save)

cdef extern from "stdlib.h":
    void free(void *ptr)

cdef extern from "stdint.h":
    ctypedef unsigned int uint32_t

cdef extern from "stdbool.h":
    ctypedef int bool

cdef extern from "../htree.h":
    ctypedef struct C_HTree "HTree":
        pass
    C_HTree*   ht_open(char *path, int depth) except NULL
    void     ht_close(C_HTree *tree)
    void     ht_clear(C_HTree *tree)
    void     ht_flush(C_HTree *tree)
    void     ht_add(C_HTree *tree, char *name, 
                int ver, uint32_t hash, bool update)
    void     ht_remove(C_HTree *tree, char *name, bool update)
    uint32_t ht_get_hash(C_HTree *tree, char *key, int *count)
    char*    ht_list(C_HTree *tree, char *dir) except NULL

cdef extern from "../hstore.h":
    ctypedef struct C_HStore "HStore":
        pass
    C_HStore* hs_open(char* path, int height, int start, int end)
    void hs_clear(C_HStore *store)
    void hs_check(C_HStore *store, int scan_limit)
    void hs_stop_check(C_HStore *store)
    void hs_flush(C_HStore *store, int limit)
    void hs_close(C_HStore *store)
    bool hs_set(C_HStore *store, char *key, char* value, 
                int vlen, int ver, uint32_t flag)
    char *hs_get(C_HStore *store, char *key, int *vlen, uint32_t *flag)
    bool  hs_delete(C_HStore *store, char *key)


cdef class HTree(object):

    cdef C_HTree *tree
    cdef readonly object path
    cdef readonly int depth

    def __init__(self, char* path, int depth):
        self.path = path
        self.depth = depth
        self.tree = ht_open(path, depth)

        if not self.tree:
            raise Exception, 'open %s failed' % path

    def close(self):
        if self.tree:
            ht_close(self.tree)
            self.tree = NULL

    def flush(self):
        ht_flush(self.tree)

    def clear(self):
        ht_clear(self.tree)

    def add(self, char* key, int ver, int hash=0, bool update=1):
        ht_add(self.tree, key, ver, hash, update)

    def remove(self, char* key, bool update=0):
        ht_remove(self.tree, key, update)

    def get_hash(self, object key):
        cdef int count = 0
        cdef int hash
        hash = ht_get_hash(self.tree, key, &count)
        return (hash, count)

    def list(self, object dir):
        cdef char *rs = ht_list(self.tree, dir)
        cdef object r = PyString_FromString(rs)
        free(rs)
        return r

    def __hash__(self):
        cdef int count = 0
        return ht_get_hash(self.tree, "@", &count)

    def __len__(self):
        cdef int count = 0
        ht_get_hash(self.tree, "@", &count)
        return count
        

cdef class HStore(object):

    cdef C_HStore *store
    cdef readonly object path
    cdef readonly int height

    def __init__(self, char* path, int height=0, int start=0, int end=-1):
        cdef PyThreadState *_save
        self.path = path
        self.height = height
        if not os.path.exists(path):
            os.makedirs(path)
        if height > 1:
            end = 1 << (height * 4) if end == -1 else end
            for i in range(start/16, end/16):
                d = os.path.join(path, ("%%0%dx" % (height - 1)) % i)
                if not os.path.exists(d):
                    os.makedirs(d)

        self.store = hs_open(path, height, start, end)
        if not self.store:
            raise Exception, 'open %s failed' % path

    def check(self, int limit=0):
        cdef PyThreadState *_save
        if self.store:
            _save = PyEval_SaveThread()
            hs_check(self.store, limit)
            PyEval_RestoreThread(_save)

    def stop_check(self):
        cdef PyThreadState *_save
        if self.store:
            _save = PyEval_SaveThread()
            hs_stop_check(self.store)
            PyEval_RestoreThread(_save)

    def flush(self, int limit=64):
        cdef PyThreadState *_save
        if self.store:
            _save = PyEval_SaveThread()
            hs_flush(self.store, limit)
            PyEval_RestoreThread(_save)

    def clear(self):
        if self.store:
            hs_clear(self.store)

    def close(self):
        cdef PyThreadState *_save
        if self.store:
            _save = PyEval_SaveThread()
            hs_close(self.store)
            PyEval_RestoreThread(_save)
        self.store = NULL

    def set(self, key, value, int ver=0, int flag=0):
        cdef PyThreadState *_save
        cdef bool r
        if self.store:
            _save = PyEval_SaveThread()
            r = hs_set(self.store, key, value, len(value), ver, flag)
            PyEval_RestoreThread(_save)
            return r

    def get(self, key):

        if not self.store:
            return
        cdef PyThreadState *_save
        cdef int len = 0
        cdef uint32_t flag = 0
        cdef char *value

        _save = PyEval_SaveThread()
        try:
            value = hs_get(self.store, key, &len, &flag)
        finally:
            PyEval_RestoreThread(_save)

        if value:
            r = PyString_FromStringAndSize(value, len)
            free(value)
            return r
        
    def delete(self, char *key):

        cdef PyThreadState *_save
        cdef bool r

        if self.store:
            _save = PyEval_SaveThread()
            r = hs_delete(self.store, key) 
            PyEval_RestoreThread(_save)
            return r
