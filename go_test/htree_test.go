package btest

import (
	"fmt"
	"reflect"
	"testing"
)

func fnv1a(buf []byte) (h uint32) {
	PRIME := uint32(0x01000193)
	h = 0x811c9dc5
	for _, b := range buf {
		h ^= uint32(int8(b))
		h = (h * PRIME)
	}
	return h
}

func TestHash(t *testing.T) {
	h := fnv1a([]byte("test"))
	if h != uint32(2949673445) {
		t.Error("hash error", h)
	}
}

func TestHTree(t *testing.T) {
	tree := NewHTree(0, 0)
	if tree.Hash() != 0 || tree.Len() != 0 {
		t.Error("emtpy tree", tree.Hash(), tree.Len())
	}
	item := &Item{Bucket: 3, Pos: 1024, Hash: 3, Version: 10}
	tree.Add("test", item)
	h := fnv1a([]byte("test")) * 3
	if tree.Hash() != uint16(h) {
		t.Error("hash error", tree.Hash())
	}

	tree.Add("test0", &Item{Hash: 5, Version: -1})
	if tree.Hash() != uint16(h) {
		t.Error("hash error", tree.Hash())
	}

	tree.Add("test2", &Item{Hash: 5, Version: 1})
	h += fnv1a([]byte("test2")) * 5
	if tree.Hash() != uint16(h) {
		t.Error("hash error", tree.Hash())
	}

	tree.Add("test2", &Item{Hash: 7, Version: -2})
	h -= fnv1a([]byte("test2")) * 5
	if tree.Hash() != uint16(h) {
		t.Error("hash error", tree.Hash())
	}

	tree.Add("test2", &Item{Hash: 5, Version: 3})
	h += fnv1a([]byte("test2")) * 5
	if tree.Hash() != uint16(h) {
		t.Error("hash error", tree.Hash())
	}

	l := tree.List("", "")
	if l != "test 3 10\ntest0 5 -1\ntest2 5 3\n" {
		t.Error("list error", l)
	}

	l = tree.List("", "test2")
	if l != "test2 5 3\n" {
		t.Error("list with prefix error", l)
	}

	r := tree.Get("test")
	if !reflect.DeepEqual(r, item) {
		t.Error("get failed", r, item)
	}

	tree.Remove("test")
	if tree.Len() != 1 {
		t.Error("remove failed", tree.Len())
	}

	r = tree.Get("test")
	if r != nil {
		t.Error("remove failed")
	}
}

func TestSplitMerge(t *testing.T) {
	tree := NewHTree(0, 0)
	N := 254
	key := "test"
	tree.Add(key, &Item{Hash: 3, Version: 1})
	child_hash := make([]uint32, 16, 16)
	child_count := make([]uint32, 16, 16)

	keyhash := fnv1a([]byte(key))
	b := uint8(keyhash>>28) & 0xf
	h0 := keyhash * 3
	child_hash[b] += h0 //21935
	child_count[b] += 1

	for i := 0; i < N; i++ {
		key := fmt.Sprintf("a%d", i)
		tree.Add(key, &Item{Hash: uint32(i), Version: int32(i + 1)})

		keyhash = fnv1a([]byte(key))
		b = uint8(keyhash>>28) & 0xf
		child_hash[b] += keyhash * uint32(i)
		child_count[b] += 1
	}
	h := uint32(0)
	for i := 0; i < 16; i++ {
		if N+1 > 64*4 {
			h *= 97
		}
		h += child_hash[i]
	}
	if tree.Len() != N+1 || tree.Hash() != uint16(h) {
		t.Error("split failed", tree.Len(), tree.Hash(), uint16(h), "\n",
			tree.List("", ""))

	}

	for i := 0; i < N; i++ {
		key := fmt.Sprintf("a%d", i)
		tree.Remove(key)
	}
	if tree.Len() != 1 || tree.Hash() != uint16(h0) {
		t.Error("remove many failed", tree.Len(), tree.Hash())
	}
}
