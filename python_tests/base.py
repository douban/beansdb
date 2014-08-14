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
import fnv1a # douban-fnv1a
import glob
import quicklz
import struct
import re
import collections
import binascii
from nose.tools import eq_
import memcache # for stat interface

sys.path.insert(0, os.path.join(dirname(dirname(__file__)), "python"))
from dbclient import MCStore # in  "python" dir

def start_svc(cmd):
    print "start", cmd
    p = subprocess.Popen(cmd if isinstance(cmd, (tuple, list,)) else shlex.split(cmd), close_fds=True)
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

    def __init__(self, base_path, port, accesslog=True, db_depth=1, max_data_size=None):
        self.port = port
        self.popen = None
        self.db_depth = db_depth
        self.db_home = os.path.join(base_path, "beansdb_%s" % (self.port))
        if not os.path.exists(self.db_home):
            os.makedirs(self.db_home)
        top_dir = dirname(dirname(os.path.abspath(__file__)))
        beansdb = os.path.join(top_dir, "src/beansdb")
        conf = os.path.join(dirname(os.path.abspath(__file__)), "test_log.conf" if accesslog else 'test_nolog.conf')
        self.cmd = "%s -C -p %s -H %s -T %s -L %s" % (beansdb, self.port, self.db_home, self.db_depth, conf)
        if max_data_size:
            self.cmd += " -F %s" % (max_data_size)


    def start(self):
        """ max_data_size is MB """
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

    def stat(self):
    #    mc = MCStore(server)  libmemcached not supported
        mc = memcache.Client(["127.0.0.1:%s" % (self.port)])
        try:
            result_dict = mc.get_stats()[0][1]
        except IndexError:
            result_dict = None
        return result_dict

    def item_count(self):
        s = self.stat()
        assert s is not None
        return int(s['total_items'])


    def generate_key(self, prefix='', count=16 * 1024, sector=None):
        i = 0
        j = 0
        while j < count: 
            key = prefix + "test%s" % (i)
            if sector is not None:
                if sector == get_key_sector(key, self.db_depth):
                    j += 1
                    yield key
            else:
                j += 1
                yield key
            i += 1 
                

def get_key_sector(key, db_depth):
    hash_ = get_hash(key)
    if db_depth == 1:
        return (hash_ >> 28) & 0xf
    elif db_depth == 2:
        sector1 = (hash_ >> 28) & 0xf
        sector2 = (hash_ >> 24) & 0xf
        return (sector1, sector2)
    else:
        raise NotImplementedError()

def get_hash(data):
    _hash = fnv1a.get_hash_beansdb(data)
    _hash = _hash & 0xffffffff
    return _hash

def get_data_hash(data):
    l = len(data)
    uint32_max = 2 ** 32 - 1
    hash_ = (l * 97) & uint32_max
    if len(data) <= 1024:
        hash_ += get_hash(data)
        hash_ &= uint32_max
    else:
        hash_ += get_hash(data[0:512])
        hash_ &= uint32_max
        hash_ *= 97
        hash_ &= uint32_max
        hash_ += get_hash(data[l-512:l])
        hash_ &= uint32_max
    hash_ &= 0xffff
    return hash_


PADDING = 256
FLAG_COMPRESS = 0x00010000 # by beansdb


def delete_hint_and_htree(db_homes, db_depth):

    if not isinstance(db_homes, (list, tuple)):
        db_homes = [db_homes]
    for db_home in db_homes:
        if db_depth == 1:
            g = glob.glob(os.path.join(db_home, "*", "*.hint.qlz"))
        elif db_depth == 2:
            g = glob.glob(os.path.join(db_home, "*/*", "*.hint.qlz"))
        else:
            raise NotImplementedError()
        for file_ in g:
            print "rm", file_
            os.remove(file_)
        if db_depth == 1:
            g = glob.glob(os.path.join(db_home, "*", "*.htree"))
        elif db_depth == 2:
            g = glob.glob(os.path.join(db_home, "*/*", "*.htree"))
        for file_ in g:
            print "rm", file_
            os.remove(file_)
    



def locate_key_with_hint(db_homes, db_depth, key, ver_=None):
    """ assume disk0 already have link,
        if key exists and valid return True, if key not exist return False
    """
    if isinstance(db_homes, (list, tuple)):
        db_home = db_homes[0]
    else:
        db_home = db_homes
    key_hash = get_hash(key)
    if db_depth == 1:
        sector = (key_hash >> 28) & 0xf
        sector_path = "%x" % (sector)
        g = glob.glob(os.path.join(db_home, sector_path, "*.hint.qlz"))
    elif db_depth == 2:
        sector1 = (key_hash >> 28) & 0xf
        sector2 = (key_hash >> 24) & 0xf
        sector_path = "%x/%x" % (sector1, sector2)
        g = glob.glob(os.path.join(db_home, sector_path, "*.hint.qlz"))
    else:
        raise NotImplementedError()
    for hint_file in g:
        r = _check_hint_with_key(hint_file, key)
        if r is not None:
            pos, ver, hash_ = r
            data_file = re.sub(r'(.+)\.hint.qlz', r'\1.data', os.path.basename(hint_file))
            data_file = os.path.join(db_home, sector_path, data_file)
            print "file", data_file, "pos", pos, "ver", ver
            if ver_ is not None and ver != ver_:
                continue
            check_data_with_key(data_file, key, ver_=ver, hash_=hash_ if ver_ > 0 else None, pos=pos)
            return True
    return False

def locate_key_iterate(db_homes, db_depth, key, ver_=None):
    """ assume disk0 already have link,
        if key exists and valid return True, if key not exist return False
    """
    if isinstance(db_homes, (list, tuple)):
        db_home = db_homes[0]
    else:
        db_home = db_homes
    key_hash = get_hash(key)
    if db_depth == 1:
        sector = (key_hash >> 28) & 0xf
        sector_path = "%x" % (sector)
        g = glob.glob(os.path.join(db_home, sector_path, "*.data"))
    elif db_depth == 2:
        sector1 = (key_hash >> 28) & 0xf
        sector2 = (key_hash >> 24) & 0xf
        sector_path = "%x/%x" % (sector1, sector2)
        g = glob.glob(os.path.join(db_home, sector_path, "*.data"))
    else:
        raise NotImplementedError()
    for data_file in g:
        print data_file
        if check_data_with_key(data_file, key, ver_=ver_):
            return True
    return False



def check_data_with_key(file_path, key, ver_=None, hash_=None, pos=None):
    """ if pos is None, iterate data file to match key and ver_,
        otherwise seek to pos and check key and ver_ and hash_
    """
    with open(file_path, 'r') as f:
        while True:
            if pos is not None:
                f.seek(pos, 0)
            block = f.read(PADDING)
            if not block:
                if pos is not None:
                    raise Exception("no data at pos %s" % (pos))
                return False
            crc, tstamp, flag, ver, ksz, vsz = struct.unpack("IiiiII", block[:24])
            if not (0 < ksz < 255 and 0 <= vsz < (50<<20)):
                raise ValueError('%s header out of bound, ksz %s, vsz %s, offset %s' % (file_path, ksz, vsz, f.tell()))
            rsize = 24 + ksz
            if rsize > PADDING:
                block += f.read(rsize-PADDING)
            crc32 = binascii.crc32(block[4:24 + ksz + vsz]) & 0xffffffff
            if crc != crc32:
                raise ValueError('%s crc wrong' % (file_path))
            key_ = block[24:24+ksz]
            if pos is not None:
                eq_(key, key_)
                if ver_ is not None and ver_ != ver:
                    raise ValueError('%s key %s expect ver %s != %s', file_path, key, ver_, ver)
            else:
                if key != key_:
                    continue
                if ver_ is not None and ver_ != ver:
                    continue

            value = block[24+ksz:24+ksz+vsz]
            if flag & FLAG_COMPRESS:
                value = quicklz.decompress(value)
                print "decompress"
            _hash = get_data_hash(value)
            if hash_ is not None and _hash != hash_:
                raise ValueError("%s key %s expect hash 0x%x != 0x%x" % (file_path, key, hash_, _hash))
            return True
    return False


def _check_hint_with_key(file_path, key):
    with open(file_path, 'r') as f:
        hint_data = f.read()
    if file_path.endswith('.qlz'):
        hint_data = quicklz.decompress(hint_data)
    hint_len = len(hint_data)
    off_s = 0
    while off_s < hint_len:
        header = hint_data[off_s:off_s + 10]
        if not header:
            raise ValueError('%s error' % (file_path))
        pos, ver, hash_ = struct.unpack('IiH', header)
        off_s += 10
        ksz = pos & 0xff
        key_ = hint_data[off_s:off_s + ksz]
        if key_ == key:
            return pos & 0xffffff00, ver, hash_
        off_s += ksz + 1
    return None

def _build_key_list_from_hint(file_path):
    with open(file_path, 'r') as f:
        hint_data = f.read()
    if file_path.endswith('.qlz'):
        hint_data = quicklz.decompress(hint_data)
    key_list = list()
    hint_len = len(hint_data)
    off_s = 0
    while off_s < hint_len:
        header = hint_data[off_s:off_s + 10]
        if not header:
            raise ValueError('%s error' % (file_path))
        pos, ver, hash_ = struct.unpack('IiH', header)
        off_s += 10
        ksz = pos & 0xff
        key = hint_data[off_s:off_s + ksz]
        key_list.append((pos & 0xffffff00, key, ver, hash_))
        off_s += ksz + 1
    key_list.sort(cmp=lambda a, b: cmp(a[0], b[0]))
    return key_list




def _check_data_with_hint(data_file, hint_file):
    hint_keys = _build_key_list_from_hint(hint_file)
    j = 0
    pos = 0
    with open(data_file, 'r') as f:
        while True:
            block = f.read(PADDING)
            _pos = PADDING
            if not block:
                if j < len(hint_keys):
                    raise Exception("data is less than hint: %s" % (data_file))
                print j
                return
            crc, tstamp, flag, ver, ksz, vsz = struct.unpack("IiiiII", block[:24])
            if not (0 < ksz < 255 and 0 <= vsz < (50<<20)):
                raise ValueError('%s header out of bound, ksz %s, vsz %s, offset %s' % (data_file, ksz, vsz, f.tell()))

            rsize = 24 + ksz
            if rsize > PADDING:
                block += f.read(rsize-PADDING)
                _pos += rsize - PADDING
            crc32 = binascii.crc32(block[4:24 + ksz + vsz]) & 0xffffffff
            if crc != crc32:
                raise ValueError('%s crc wrong, pos=%s' % (data_file, pos))
            key = block[24:24+ksz]
            value = block[24+ksz:24+ksz+vsz]
            hint_key = hint_keys[j]
            if pos < hint_key[0]:
                pos += _pos
                continue
            elif pos > hint_key[0]:
                raise Exception('%s pos %s > hint pos %s' % (data_file, pos, hint_key[0]))
            eq_(hint_key[1], key, data_file)
            eq_(hint_key[2], ver, data_file)

            if flag & FLAG_COMPRESS:
                value = quicklz.decompress(value)
                print "decompress"
            _hash = get_data_hash(value)
            eq_(hint_key[3], _hash, data_file)
            pos += _pos
            j += 1

def check_data_hint_integrity(db_homes, db_depth):
    index = _get_all_files_index(db_homes, db_depth)
    for bucket, num_ext_dict in index.iteritems():
        nums = map(lambda x: x[0], num_ext_dict.keys())
        max_num = max(nums)
        print "bucket", bucket, "max_num", max_num
        for i in xrange(max_num + 1):
            data_file = num_ext_dict.get((i, 'data'))
            hint_file = num_ext_dict.get((i, 'hint.qlz'))
            if data_file and hint_file:
                print data_file, hint_file
                _check_data_with_hint(data_file, hint_file)




def _parse_bucket_from_path(db_depth, file_path):
    bucket = []
    path = os.path.dirname(file_path)
    regx = re.compile(r'^[0-9a-fA-F]$')
    for i in xrange(db_depth):
        bucket_level = os.path.basename(path)
        if not regx.match(bucket_level):
            raise Exception("%s in %s does not seam to be a bucket" % (bucket_level, file_path))
        bucket.insert(0, bucket_level)
        path = os.path.dirname(path)
    return tuple(bucket)

def _parse_file_no_form_path(filepath):
    filename = os.path.basename(filepath)
    om = re.match(r'^(\d+)\..+$', filename)
    if not om:
        raise Exception('invalid path %s' % (filepath))
    number = int(om.group(1), 10)
    return number

def _get_all_files_index(db_homes, db_depth):
    file_index = dict()
    if isinstance(db_homes, basestring):
        db_homes = [db_homes]
    for db_home in db_homes:
        for root, dirs, names in os.walk(db_home):
            for file_name in names:
                file_path = os.path.join(root, file_name)
                if os.path.islink(file_path):
                    if not os.path.exists(file_path):
                        raise Exception("bad link", file_path)
                    target = os.readlink(file_path)
                    if os.path.islink(target):
                        raise Exception("double link %s -> %s" % (file_path, target))
                    continue
                elif file_path.endswith('.hint.qlz') or file_path.endswith('.data'):
                    ext = file_path[file_path.index('.') + 1:]
                    try:
                        bucket = _parse_bucket_from_path(db_depth, file_path)
                    except Exception, e:
                        print str(e)
                        continue
                    bucket = tuple(map(lambda x: int(x, 16), bucket))
                    number = _parse_file_no_form_path(file_path)
                    if not file_index.has_key(bucket):
                        file_index[bucket] = dict()
                    if file_index[bucket].has_key((number, ext)):
                        raise Exception('double file %s' % (file_path))
                    file_index[bucket][(number, ext)] = file_path
    return file_index




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

    def _get_version(self, store, key):
        meta = store.get("?" + key)
        if meta:
            return int(meta.split()[0])

#
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
