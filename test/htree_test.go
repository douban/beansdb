package btest

import (
    "fmt"
    "testing"
    "reflect"
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
    //Hello("davies")

    tree := NewHTree(0, 0)
    if tree.Hash() != 0 || tree.Len() != 0 {
        t.Error("emtpy tree", tree.Hash(), tree.Len())
    }

    //key := "hello"
    item := &Item{Bucket: 3, Pos: 1024, Hash: 3, Version: 10}
    tree.Add("test", item)
    //h := fnv1a([]byte(key)) * 75
    if tree.Hash() != 21935 {
        t.Error("hash error", tree.Hash())
    }

    tree.Add("test0", &Item{Hash: 5, Version: -1})
    if tree.Hash() != 21935 {
        t.Error("hash error", tree.Hash())
    }

    tree.Add("test2", &Item{Hash: 5, Version: 1})
    if tree.Hash() != 24824 {
        t.Error("hash error", tree.Hash())
    }

    tree.Add("test2", &Item{Hash: 7, Version: -2})
    if tree.Hash() != 21935 {
        t.Error("hash error", tree.Hash())
    }

    tree.Add("test2", &Item{Hash: 5, Version: 3})
    if tree.Hash() != 24824 {
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
    N := 200
    key := "test"
    tree.Add(key, &Item{Hash: 3, Version: 1})
    for i := 0; i < N; i++ {
        key := fmt.Sprintf("a%d", i)
        tree.Add(key, &Item{Hash: uint32(i), Version: int32(i + 1)})
    }
    if tree.Len() != N+1 || tree.Hash() != 53137 {
        t.Error("split failed", tree.Len(), tree.Hash(),
            tree.List("", ""))

    }

    for i := 0; i < N; i++ {
        key := fmt.Sprintf("a%d", i)
        tree.Remove(key)
    }
    if tree.Len() != 1 || tree.Hash() != 21935 {
        t.Error("remove many failed", tree.Len(), tree.Hash())
    }
}
