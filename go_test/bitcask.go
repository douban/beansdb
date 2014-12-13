package btest

// #cgo CFLAGS:  -I ../src -I ../third-party/zlog-1.2/
// #cgo LDFLAGS: -L ../third-party/zlog-1.2/ -lzlog -L .  -lbeansdb
// #include <stdlib.h>
// #include "record.h"
// #include "hint.h"
// #include "bitcask.h"
import "C"
import "unsafe"
import (
	"errors"
	"time"
)

type Record struct {
	Key     string
	Value   []byte
	Flag    int32
	Hash    uint32
	Version int32
	Tstamp  int32
	pos     uint32
}

func NewRecord(key string, value []byte, flag int32, version int32) *Record {
	r := &Record{Key: key, Value: value, Flag: flag, Version: version}
	r.Tstamp = int32(time.Now().Unix())
	r.GenHash()
	return r
}

const PRIME = 0x01000193

func Fnv1a(buf []byte) (h uint32) {
	h = 0x811c9dc5
	for _, b := range buf {
		h ^= uint32(int8(b))
		h *= PRIME
	}
	return h
}

func (r *Record) GenHash() {
	if r.Version < 0 {
		if len(r.Value) == 0 {
			r.Hash = 0
			return
		} else {
			println("invalid record: ver:", r.Version, " size:", len(r.Value))
		}
	}
	hash := uint32(len(r.Value)) * 97
	if len(r.Value) <= 1024 {
		hash += Fnv1a(r.Value)
	} else {
		hash += Fnv1a(r.Value[:512])
		hash *= 97
		hash += Fnv1a(r.Value[len(r.Value)-512:])
	}
	r.Hash = hash & 0xffff
}

var MAX_BUCKET_SIZE = int64(1024 * 1024 * 1024 * 2)
var MERGE_LIMIT = 1024 * 20

type Bitcask struct {
	path string
	bc   *C.Bitcask
}

func NewBitcask(dirpath string, depth, pos int, before int64) (b *Bitcask, err error) {
	b = new(Bitcask)
	b.path = dirpath

	cpath := C.CString(dirpath)
	defer C.free(unsafe.Pointer(cpath))
	b.bc = C.bc_open(cpath, C.int(depth), C.int(pos), C.time_t(before))

	if b.bc == nil {
		return nil, errors.New("open bitcask failed" + dirpath)
	}
	return
}

func (b *Bitcask) Flush() {
	C.bc_flush(b.bc, 0, 0)
}

func (b *Bitcask) Close() {
	C.bc_close(b.bc)
	b.bc = nil
}

func (b *Bitcask) Merge() {
	C.bc_optimize(b.bc, 0)
}

func (b *Bitcask) GetRecord(key string) *Record {
	var ret_pos C.uint32_t
	var ret_ver C.int
	c_key := C.CString(key)
	defer C.free(unsafe.Pointer(c_key))
	dr := C.bc_get(b.bc, c_key, &ret_pos, &ret_ver)
	if dr == nil {
		return nil
	}
	defer C.free_record(dr)

	r := new(Record)
	r.Key = key
	r.Value = []byte(C.GoStringN(dr.value, _Ctype_int(dr.vsz)))
	r.Flag = int32(dr.flag)
	r.Version = int32(dr.version)
	r.Tstamp = int32(dr.tstamp)
	r.GenHash()
	return r
}

func (b *Bitcask) Get(key string) ([]byte, int32) {
	r := b.GetRecord(key)
	if r != nil {
		return r.Value, r.Flag
	}
	return nil, 0
}

func (b *Bitcask) Set(key string, value []byte, flag, version int32) error {
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	cv := C.CString(string(value))
	defer C.free(unsafe.Pointer(cv))
	if !(0 != (C.bc_set(b.bc, ckey, cv, C.size_t(len(value)),
		C.int(flag), C.int(version)))) {
		return errors.New("set failed")
	}
	return nil
}

func (b *Bitcask) Delete(key string) error {
	return b.Set(key, nil, 0, -1)
}

func (b *Bitcask) Hash() uint16 {
	c_key := C.CString("@")
	defer C.free(unsafe.Pointer(c_key))
	return uint16(C.bc_get_hash(b.bc, c_key, (*C.uint)(nil)))
}

func (b *Bitcask) Len() int {
	c_key := C.CString("@")
	defer C.free(unsafe.Pointer(c_key))
	var cnt C.uint
	C.bc_get_hash(b.bc, c_key, &cnt)
	return int(cnt)
}

func (b *Bitcask) List(dir string) string {
	c_key := C.CString(dir)
	defer C.free(unsafe.Pointer(c_key))
	cstr, _ := C.bc_list(b.bc, c_key, nil)
	if cstr == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(cstr))
	return C.GoString(cstr)
}

func (b *Bitcask) ListPrefix(dir, prefix string) string {
	c_key := C.CString(dir)
	defer C.free(unsafe.Pointer(c_key))
	c_prefix := C.CString(prefix)
	defer C.free(unsafe.Pointer(c_prefix))
	cstr, _ := C.bc_list(b.bc, c_key, c_prefix)
	if cstr == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(cstr))
	return C.GoString(cstr)
}
