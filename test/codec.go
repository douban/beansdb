package btest

// #include <stdlib.h>
// #include "../codec.h"
import "C"
import "unsafe"

func init() {
    C.dc_init()
}

func DCEncode(s string) string {
    cs := C.CString(s)
    defer C.free(unsafe.Pointer(cs))

    buf := C.malloc(255)
    defer C.free(buf)
    n := C.dc_encode((*_Ctype_char)(buf), cs, (_Ctype_int)(len(s)))
    if n > 0 {
        return C.GoStringN((*_Ctype_char)(buf), n)
    }
    return s
}

func DCDecode(s string) string {
    cs := C.CString(s)
    defer C.free(unsafe.Pointer(cs))

    buf := C.malloc(255)
    defer C.free(buf)

    n := C.dc_decode((*_Ctype_char)(buf), cs, (_Ctype_int)(len(s)))
    if n > 0 {
        return C.GoStringN((*_Ctype_char)(buf), n)
    }
    return s
}
