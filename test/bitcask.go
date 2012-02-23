package btest

// #include <stdlib.h>
// #include "../hint.h"
// #include "../record.h"
// #include "../bitcask.h"
import "C"
import "unsafe"
import (
    "os"
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
    r.Tstamp = int32(time.Seconds())
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

func NewBitcask(dirpath string, depth,pos int, before int64) (b *Bitcask, err os.Error) {
    b = new(Bitcask)
    b.path = dirpath

    cpath := C.CString(dirpath)
    defer C.free(unsafe.Pointer(cpath))
    b.bc = C.bc_open(cpath, (_Ctype_int)(depth), (_Ctype_int)(pos), (_Ctypedef_time_t)(before))

    if b.bc == nil {
        return nil, os.NewError("open bitcask failed" + dirpath)
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
    c_key := C.CString(key)
    defer C.free(unsafe.Pointer(c_key))
    dr := C.bc_get(b.bc, c_key)
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

func (b *Bitcask) Set(key string, value []byte, flag, version int32) os.Error {
    ckey := C.CString(key)
    defer C.free(unsafe.Pointer(ckey))
    cv := C.CString(string(value))
    defer C.free(unsafe.Pointer(cv))
    if !bool(C.bc_set(b.bc, ckey, cv, _Ctype_int(len(value)),
        _Ctype_int(flag), _Ctype_int(version))) {
        return os.NewError("set failed")
    }
    return nil
}

func (b *Bitcask) Delete(key string) os.Error {
    return b.Set(key, nil, 0, -1)
}

func (b *Bitcask) Hash() uint16 {
    c_key := C.CString("@")
    defer C.free(unsafe.Pointer(c_key))
    return uint16(C.bc_get_hash(b.bc, c_key, (*_Ctype_int)(nil)))
}

func (b *Bitcask) Len() int {
    c_key := C.CString("@")
    defer C.free(unsafe.Pointer(c_key))
    var cnt _Ctype_int
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
