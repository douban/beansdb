package btest

// #cgo CFLAGS:  -I ../src -I ../third-party/zlog-1.2/
// #cgo LDFLAGS: -L ../third-party/zlog-1.2/ -lzlog -L .  -lbeansdb
// #include "codec.h"
import "C"

const BUFSIZE = 256

func init() {
	logConfPath := C.CString("./beansdb_log.conf")
	C.log_init(logConfPath)
}

type Codec struct {
	cdc  *C.Codec
	buf  *C.char
	buf2 *C.char
}

func NewCodec() *Codec {
	dc := new(Codec)
	dc.cdc = C.dc_new()
	dc.buf = (*C.char)(C.malloc(BUFSIZE))
	return dc
}

func (dc *Codec) Encode(src string) (dst string, idx int) {
	var cdc *C.Codec = dc.cdc
	n := C.dc_encode(cdc, dc.buf, BUFSIZE, C.CString(src), C.int(len(src)))
	return C.GoStringN(dc.buf, n), 1
}

func (dc *Codec) Decode(src string) (dst string, idx int) {
	n := C.dc_decode(dc.cdc, dc.buf, BUFSIZE, C.CString(src), C.int(len(src)))
	return C.GoStringN(dc.buf, n), 1
}
