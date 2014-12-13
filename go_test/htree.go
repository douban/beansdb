package btest

// #cgo CFLAGS:  -I ../src -I ../third-party/zlog-1.2/
// #cgo LDFLAGS: -L ../third-party/zlog-1.2/ -lzlog -L .  -lbeansdb
// #include <stdlib.h>
// #include "record.h"
// #include "htree.h"
// #include "hint.h"
// #include "record.h"
import "C"
import "unsafe"

type Item struct {
	Bucket  int
	Pos     uint32
	Hash    uint32
	Version int32
}

type HashTree struct {
	tree *C.HTree
}

func NewHTree(depth, pos int) *HashTree {
	t := C.ht_new(C.int(depth), C.int(pos), C.bool(false))
	return &HashTree{tree: t}
}

func (t *HashTree) Add(key string, item *Item) {
	p := C.CString(key)
	defer C.free(unsafe.Pointer(p))
	pos := (uint32(item.Bucket)) + uint32(item.Pos)
	C.ht_add(t.tree, p,
		C.uint32_t(pos),
		C.uint16_t(item.Hash),
		C.int32_t(item.Version))
}

func (t *HashTree) Remove(key string) {
	p := C.CString(key)
	defer C.free(unsafe.Pointer(p))
	C.ht_remove(t.tree, p)
}

func (t *HashTree) Clear() {
	C.ht_destroy(t.tree)
	t.tree = nil
}

func (t *HashTree) ScanHintFile(bucket int, path string) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	C.scanHintFile(t.tree, (_Ctype_int)(bucket), p, nil)
}

func (t *HashTree) Get(key string) *Item {
	c_key := C.CString(key)
	defer C.free(unsafe.Pointer(c_key))
	citem, _ := C.ht_get(t.tree, c_key)
	if citem == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(citem))

	return &Item{Bucket: int(uint32(citem.pos) & 0xff),
		Pos:     uint32(citem.pos) & 0xffffff00,
		Hash:    uint32(citem.hash),
		Version: int32(citem.ver)}
}

func (t *HashTree) Hash() uint16 {
	c_key := C.CString("@")
	defer C.free(unsafe.Pointer(c_key))
	return uint16(C.ht_get_hash(t.tree, c_key, (*C.uint)(nil)))
}

func (t *HashTree) Len() int {
	c_key := C.CString("@")
	defer C.free(unsafe.Pointer(c_key))
	var cnt C.uint
	C.ht_get_hash(t.tree, c_key, &cnt)
	return int(cnt)
}

func (t *HashTree) List(pos, prefix string) string {
	c_key := C.CString(pos)
	defer C.free(unsafe.Pointer(c_key))
	c_prefix := C.CString(prefix)
	defer C.free(unsafe.Pointer(c_prefix))
	cstr, _ := C.ht_list(t.tree, c_key, c_prefix)
	if cstr == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(cstr))
	return C.GoString(cstr)
}
