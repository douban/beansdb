package btest

import (
    "testing"
)

type dcCase struct {
    s string
    l int
}

var dcCases = []dcCase {
    {"/hello", 6},
    {"/hello/5464", 5},
    {"/hello/3fe989", 5},
    {"/hello/3fe989f3adefaefc", 9},
    {"/v/v32", 6},
//    {"中文12312", 5},
//    {"你好/v/v3552", 14},
    {"/你好/v/v3552", 5},
    {"1231@gmail.com", 14},
    {"/status/raw/1Fp3da", 5},
    {"/status/mediam/2fffff", 5},
    {"files/file-131470845.jp", 5},
    {"files/file-5314708453.jp", 5},
    {"/epic/5957/8158.jpg", 9},
    {"/photo/thumb/SG94-EpQ_p866859435", 32},
    {"/note/small/24795790-1", 5},
    {"/anduin/urlgrabcontent/4paFkh", 5},
}

func TestDC(t *testing.T) {
    for _, c := range dcCases {
        b := DCEncode(c.s)
        if len(b) != c.l {
            t.Error("length not match", c.s, c.l, len(b))
        }else{
            ss := DCDecode(b)
            if ss != c.s {
                t.Error("decode fail", c.s, ss)
            }
        }
    }
}
