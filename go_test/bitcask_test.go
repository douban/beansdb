package btest

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

func clear(dirpath string) {
	dir, err := os.Open(dirpath)
	if err != nil {
		return
	}
	defer dir.Close()
	names, _ := dir.Readdirnames(-1)
	for _, name := range names {
		os.Remove(path.Join(dirpath, name))
	}
}

func testRecord(t *testing.T, b *Bitcask, r *Record) {
	err := b.Set(r.Key, r.Value, r.Flag, r.Version)
	if err != nil {
		t.Error("Set failed", r.Key, r)
	}

	value, flag := b.Get(r.Key)
	if string(value) != string(r.Value) {
		t.Error("Get failed", r.Key, string(value), flag)
	}
	rr := b.GetRecord(r.Key)
	if rr == nil {
		t.Error("GetRecord() failed", r.Key)
		return
	}
	if r.Version == 0 {
		r.Version = 1
	}
	info := fmt.Sprintf("%d %d %d %d", r.Version, uint16(r.Hash), r.Flag, len(r.Value))
	info2 := fmt.Sprintf("%d %d %d %d", rr.Version, uint16(rr.Hash), rr.Flag, len(rr.Value))
	if info != info2 {
		t.Error("Get info failed", r.Key, info2, info)
	}

	line := fmt.Sprintf("%s %d %d\n", r.Key, uint16(r.Hash), r.Version)
	if strings.Index(b.List(""), line) < 0 {
		t.Error("List1 failed", r.Key, b.List(""), " but expected ", line)
	}
}

func TestBitcask(t *testing.T) {
	clear("test/")

	b, err := NewBitcask("test/", 0, 0, 0)
	if err != nil || b == nil {
		t.Error("open failed", err)
		return
	}

	testRecord(t, b, NewRecord("test", []byte("test"), 13, 1))
	testRecord(t, b, NewRecord("hello", []byte("world"), 2, 5))
	testRecord(t, b, NewRecord("test2", []byte("test22"), 13, 0))
	testRecord(t, b, NewRecord("empty", []byte(""), 13, 19))
	testRecord(t, b, NewRecord("big", make([]byte, 1024*100), 13, 19))

	b.Close()

	b, err = NewBitcask("test/", 0, 0, 0)
	if err != nil {
		t.Error("open failed", err)
		return
	}

	value, flag := b.Get("test")
	if string(value) != "test" {
		t.Error("Get from datafile failed", string(value), flag)
	}

	keys := b.List("")
	if strings.Index(keys, "test 29545 1\n") < 0 {
		t.Error("List from datafile failed", keys)
	}

	b.Close()

	b, err = NewBitcask("test/", 0, 0, 0)
	if err != nil {
		t.Error("open failed", err)
		return
	}

	value, flag = b.Get("test")
	if string(value) != "test" {
		t.Error("Get from hint failed", string(value), flag)
	}

	keys = b.List("")
	if strings.Index(keys, "test 29545 1\n") < 0 {
		t.Error("List from hint failed", keys)
	}

	b.Delete("test")

	value, flag = b.Get("test")
	if len(value) != 0 {
		t.Error("delete failed", string(value), flag)
	}

	keys = b.List("")
	if strings.Index(keys, "test 29545 1\n") >= 0 {
		t.Error("List after delete failed", keys)
	}

	b.Close()
	b, err = NewBitcask("test/", 0, 0, 0)

	value, flag = b.Get("test")
	if len(value) != 0 {
		t.Error("delete after close failed", string(value), flag)
	}

	keys = b.List("")
	if strings.Index(keys, "test 29545 1\n") >= 0 {
		t.Error("List after delete failed", keys)
	}

	b.Close()
}

func TestVersion(t *testing.T) {
	clear("test/")

	b, err := NewBitcask("test/", 0, 0, 0)
	if err != nil {
		t.Error("open failed", err)
		return
	}

	key := "ver_test"
	data := []byte("data")
	if b.Set(key, data, 0, 0) != nil {
		t.Error("set fail")
	}
	if b.GetRecord(key).Version != 1 {
		t.Error("version wrong")
	}
	if b.Set(key, data, 0, 0) != nil {
		t.Error("repeat set should not fail")
	}
	if b.Set(key, data, 0, 1) == nil {
		t.Error("set should fail with same ver")
	}
	if b.Set(key, data, 0, 5) != nil {
		t.Error("sync should not fail")
	}
	if b.Delete(key) != nil {
		t.Error("delete failed")
	}
	if b.GetRecord(key) != nil {
		t.Error("delete failed get")
	}
	if b.Delete(key) == nil {
		t.Error("delete not exist")
	}
	if b.Set(key, data, 0, 6) == nil {
		t.Error("set should fail")
	}
	if b.Set(key, data, 0, 0) != nil {
		t.Error("set fail")
	}
	if b.GetRecord(key).Version != 1 {
		t.Error("ver wrong")
	}
	// if b.Set(key, data, 0, -8) != nil {
	//     t.Error("sync failed")
	// }
}

func TestRotate(t *testing.T) {
	clear("test/")

	MAX_BUCKET_SIZE = 1024
	N := 100
	b, err := NewBitcask("test/", 0, 0, 0)
	if err != nil {
		t.Error("open failed", err)
		return
	}

	for i := 0; i < N; i++ {
		key := fmt.Sprintf("test_%d", i)
		r := b.Set(key, make([]byte, 1024*10), 13, 0)
		if r != nil {
			t.Error("Set failed", key, r)
			break
		}
	}
	b.Close()

	b, _ = NewBitcask("test/", 0, 0, 0)
	for i := 0; i < N; i++ {
		key := fmt.Sprintf("test_%d", i)
		r := b.Set(key, make([]byte, 1024*11), 13, 0)
		if r != nil {
			t.Error("Set2 failed", key, r)
			break
		}
	}

	for i := 0; i < N; i++ {
		key := fmt.Sprintf("test_%d", i)
		r, _ := b.Get(key)
		if len(r) != 1024*11 {
			t.Error("Get before merge failed", key, r, len(r))
			break
		}
	}
	b.Merge()

	for i := 0; i < N; i++ {
		key := fmt.Sprintf("test_%d", i)
		r, _ := b.Get(key)
		if len(r) != 1024*11 {
			t.Error("Get after merge failed", key, r, len(r))
			break
		}
	}

	b.Close()

	b, err = NewBitcask("test/", 0, 0, 0)
	if err != nil {
		t.Error("open failed", err)
		return
	}

	for i := 0; i < N; i++ {
		key := fmt.Sprintf("test_%d", i)
		r, _ := b.Get(key)
		if len(r) != 1024*11 {
			t.Error("Get failed", key, r, len(r))
			break
		}
	}
	b.Close()
}

func TestRecover(t *testing.T) {
	clear("test/")

	b, _ := NewBitcask("test/", 0, 0, 0)
	key := "ver_test"
	data := []byte("hello")
	if b.Set(key, data, 0, 0) != nil {
		t.Error("set fail")
	}
	r, _ := b.Get(key)
	if !bytes.Equal(r, data) {
		t.Error("get fail")
	}

	time.Sleep(1e9)
	before := time.Now().Unix()

	data2 := []byte("world")
	if b.Set(key, data2, 0, 0) != nil {
		t.Error("set fail")
	}
	r, _ = b.Get(key)
	if !bytes.Equal(r, data2) {
		t.Error("get fail 2")
	}
	b.Flush()

	// test before close
	b2, _ := NewBitcask("test/", 0, 0, before)
	r, _ = b2.Get(key)
	if !bytes.Equal(r, data) {
		t.Error("recover data before close failed", string(r))
	}
	b2.Close()

	b.Close()

	// test after close
	b2, _ = NewBitcask("test/", 0, 0, before)
	r, _ = b2.Get(key)
	if !bytes.Equal(r, data) {
		t.Error("recover data after close failed", string(r))
	}
	b2.Close()
}
