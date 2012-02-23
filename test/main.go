package main

import (
    "net"
    "time"
    "io"
    "bufio"
)

const N = 1024 * 1024 * 10

func main() {
    addr, _ := net.ResolveTCPAddr("0.0.0.0:9009")
    go func() {
        l, _ := net.ListenTCP("tcp", addr)
        conn, _ := l.AcceptTCP()
        println("accepted")
        go func(c io.ReadWriter) {
            buf := make([]byte, N)
            b := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
            if n, e := b.Read(buf); e != nil || n < N {
                println("read", n, e.String())
                return
            }
            if n, e := b.Write(buf); n < N || e != nil {
                println("write", n, e.String())
            }
            b.Flush()
            time.Sleep(1)
        }(conn)
    }()
    time.Sleep(1e9)
    c, _ := net.DialTCP("tcp", nil, addr)
    println("connected")
    f := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
    b := make([]byte, N)
    if n, e := f.Write(b); n < N || e != nil {
        panic("write failed")
    }
    f.Flush()
    if n, e := f.Read(b); e != nil || n < N {
        println("read 2", n, e.String())
    }
}
