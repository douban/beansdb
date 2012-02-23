package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "runtime"
    "http"
    "http/pprof"
    "strings"
    "path"
    "bytes"
    "time"
    "memcache"
    "htree"
    "sync"
    "strconv"
)

type BitcaskStore struct {
    depth  int
    before int64
    bc     []*htree.Bitcask
    locks  []sync.Mutex
}

func NewStore(dir string, depth int, before int64) *BitcaskStore {
    p := new(BitcaskStore)
    p.depth = depth
    p.before = before
    p.locks = make([]sync.Mutex, 97)

    count := 1 << uint32(depth*4)
    p.bc = make([]*htree.Bitcask, count)
    for i := 0; i < count; i++ {
        subdir := ""
        if depth > 0 {
            sf := fmt.Sprintf("%%0%dx", depth)
            subdir = fmt.Sprintf(sf, i)
            subdir = strings.Join(strings.Split(subdir, ""), "/")
        }
        dbpath := path.Join(dir, subdir)
        os.MkdirAll(dbpath, 0755)
        var err os.Error
        p.bc[i], err = htree.NewBitcask(dbpath, depth, before)
        if err != nil {
            panic(os.NewError("Can not open db:" + dbpath + err.String()))
        }
    }

    return p
}

func (p *BitcaskStore) Close() {
    for _, bc := range p.bc {
        bc.Close()
    }
    log.Print("All bitcask were closed.")
}

func hextoi(s string) (n int, err os.Error) {
    n = 0
    for _, c := range s {
        n <<= 4
        switch {
        case c >= 'a' && c <= 'f':
            n += c - 'a' + 10
        case c >= 'A' && c <= 'F':
            n += c - 'A' + 10
        case c >= '0' && c <= '9':
            n += c - '0'
        default:
            return 0, os.NewError("invalid hex:" + string(c))
        }
    }
    return n, nil
}

func (p *BitcaskStore) getByKey(key string) *htree.Bitcask {
    h := htree.Fnv1a([]byte(key))
    i := h >> (uint32(8-p.depth) * 4)
    return p.bc[i]
}

func (p *BitcaskStore) getHash(pos string) (uint16, int) {
    if len(pos) >= p.depth {
        i, _ := hextoi(pos[:p.depth])
        return p.bc[i].Hash(), p.bc[i].Len()
    }
    hash, cnt := uint16(0), 0
    for i := 0; i < 16; i++ {
        h, c := p.getHash(fmt.Sprintf("%s%x", pos, i))
        hash *= 97
        hash += h
        cnt += c
    }
    return hash, cnt
}

func (p *BitcaskStore) Get(key string) (*memcache.Item, os.Error) {
    if strings.HasPrefix(key, "@") {
        if len(key) > p.depth {
            index := key[1 : 1+p.depth]
            i, err := hextoi(index)
            if err != nil {
                log.Print("error of ", index)
                return nil, os.NewError("invalid position")
            }
            l := p.bc[i].List(key[1+p.depth:])
            return &memcache.Item{Body: []byte(l), Flag: 0}, nil
        } else {
            buf := bytes.NewBuffer(nil)
            for i := 0; i < 16; i++ {
                h, c := p.getHash(key[1:] + fmt.Sprintf("%x", i))
                s := fmt.Sprintf("%x/ %d %d\n", i, h, c)
                buf.WriteString(s)
            }
            return &memcache.Item{Body: buf.Bytes(), Flag: 0}, nil
        }
    }

    info := false
    if strings.HasPrefix(key, "?") {
        key = key[1:]
        info = true
    }

    bc := p.getByKey(key)
    r := bc.GetRecord(key)
    if r != nil {
        if info {
            info := fmt.Sprintf("%d %d %d %d %d", r.Version, uint16(r.Hash), r.Flag,
                len(r.Value), r.Tstamp)
            return &memcache.Item{Body: []byte(info), Flag: 0}, nil
        }
        return &memcache.Item{Body: r.Value, Flag: int(r.Flag)}, nil
    }
    return nil, nil
}

func (p *BitcaskStore) GetMulti(keys []string) (map[string]*memcache.Item, os.Error) {
    rs := make(map[string]*memcache.Item, len(keys))
    for _, key := range keys {
        r, err := p.Get(key)
        if err != nil {
            return nil, err
        }
        if r != nil {
            rs[key] = r
        }
    }
    return rs, nil
}

func (p *BitcaskStore) Set(key string, item *memcache.Item, noreply bool) (bool, os.Error) {
    if p.before > 0 {
        return false, nil
    }
    bc := p.getByKey(key)
    err := bc.Set(key, item.Body, int32(item.Flag), int32(item.Exptime))
    return err == nil, err
}

func (p *BitcaskStore) Append(key string, value []byte) (bool, os.Error) {
    if p.before > 0 {
        return false, nil
    }

    i := htree.Fnv1a([]byte(key)) % uint32(len(p.locks))
    p.locks[i].Lock()
    defer p.locks[i].Unlock()

    bc := p.getByKey(key)
    r, flag := bc.Get(key)
    if flag != 0 {
        log.Print("append %s, but flag !=0", key)
        return false, os.NewError("bad flag")
    }
    r = append(r, value...)
    bc.Set(key, r, flag, 0) // use timestamp later

    return true, nil
}

func (p *BitcaskStore) Incr(key string, value int) (int, os.Error) {
    if p.before > 0 {
        return 0, nil
    }

    i := htree.Fnv1a([]byte(key)) % uint32(len(p.locks))
    p.locks[i].Lock()
    defer p.locks[i].Unlock()

    r, _ := p.Get(key)
    n := 0
    if r != nil {
        var e os.Error
        n, e = strconv.Atoi(string(r.Body))
        if e != nil {
            log.Printf("invalid number %s, %s", key, string(r.Body))
            return 0, os.NewError("invalid number")
        }
    }
    n += value
    p.Set(key, &memcache.Item{Body: []byte(strconv.Itoa(n)), Flag: 0x4}, false) // use timestamp later

    return n, nil
}

func (p *BitcaskStore) Delete(key string) (bool, os.Error) {
    if p.before > 0 {
        return false, nil
    }
    bc := p.getByKey(key)
    err := bc.Delete(key)
    return err == nil, err
}

func (p *BitcaskStore) Len() int {
    n := 0
    for _, bc := range p.bc {
        n += bc.Len()
    }
    return n
}

var listen *string = flag.String("listen", "0.0.0.0", "address to listen")
var port *int = flag.Int("port", 7900, "proxy port")
var dbpath *string = flag.String("dbpath", "testdb", "config path")
var dbdepth *int = flag.Int("depth", 1, "depth of db")
var accesslog *string = flag.String("accesslog", "", "access log path")
var debug *bool = flag.Bool("debug", false, "debug info")
var before *string = flag.String("before", "", "serve data only modified before some time")
var threads *int = flag.Int("threads", 8, "number of threads")
var memlimit *int = flag.Int("memlimit", 1024*2, "limit memory used by go heap (M)")

func main() {
    flag.Parse()
    runtime.GOMAXPROCS(*threads)

    http.Handle("/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
    http.Handle("/pprof/heap", http.HandlerFunc(pprof.Heap))
    http.Handle("/pprof/symbol", http.HandlerFunc(pprof.Symbol))
    go func() {
        http.ListenAndServe("0.0.0.0:6060", nil)
    }()

    if *accesslog != "" {
        logf, err := os.OpenFile(*accesslog, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
        if err != nil {
            log.Print("open " + *accesslog + " failed")
            return
        }
        memcache.AccessLog = log.New(logf, "", log.Ldate|log.Ltime)
    } else if *debug {
        memcache.AccessLog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
    }

    tbefore := int64(0)
    if *before != "" {
        t, err := time.Parse(time.RFC3339[:len(*before)], *before)
        if err != nil {
            log.Print("parse time error", err.String())
            return
        }
        t.ZoneOffset = 8 * 60 * 60
        tbefore = t.Seconds()
        log.Print("load data before", t.Format(time.RFC3339))
    }

    log.Print("start to open db ", *dbpath)
    store := NewStore(*dbpath, *dbdepth, tbefore)
    defer store.Close()

    addr := fmt.Sprintf("%s:%d", *listen, *port)
    s := memcache.NewServer(store)
    e := s.Listen(addr)
    if e != nil {
        log.Print("Listen at ", *listen, "failed")
        return
    }

    // monitor mem usage
    go func() {
        ul := uint64(*memlimit) * 1024 * 1024
        for runtime.MemStats.HeapSys < ul {
            time.Sleep(1e9)
        }
        log.Print("Mem used by Go is over limitation ", runtime.MemStats.HeapSys/1024/1024, *memlimit)
        s.Shutdown()
    }()

    s.Serve()
    log.Print("shut down gracefully.")
}
