
# What is Beansdb?

Beansdb is a distributed key-value storage system designed for large scale
online system, aiming for high avaliablility and easy management. It took
the ideas from Amazon's Dynamo, then made some simplify to Keep It Simple
Stupid (KISS).

The clients write to N Beansdb node, then read from R of them (solving
conflict). Data in different nodes is synced through hash tree, in cronjob.

It conforms to memcache protocol (not fully supported, see below), so any
memcached client can interactive with it without any modification.

Beansdb is heavy used in http://www.douban.com/, is used to stored images,
mp3,  text fields and so on, see benchmark below.

Any suggestion or feedback is welcomed.


# Features

* High availability data storage with multi readable and writable repications

* Soft state and final consistency, synced with hash tree

* Easy Scaling out without interrupting online service

* High performance read/write for a key-value based object

* Configurable availability/consistency by N,W,R

* Memcache protocol compatibility

## Supported memcache commands

* get
* set(with version support)
* append
* incr
* delete
* stats
* gc

## Private commands

* get @xxx, list the content of hash tree, such as @0f
* get ?xxx, get the meta data of key.

# Python Example
```
from dbclient import Beansdb

# three beansdb nodes on localhost
BEANSDBCFG = {
    "localhost:7901": range(16),
    "localhost:7902": range(16),
    "localhost:7903": range(16),
}

db = Beansdb(BEANSDBCFG, 16)

db.set('hello', 'world')
db.get('hello')
db.delete('hello')
```

# Benchmark
```
　$ beansdb -d
　$ memstorm -s localhost:7900 -n 1000000 -k 10 -l 100
　　
　　----
　　Num of Records : 1000000
　　Non-Blocking IO : 0
　　TCP No-Delay : 0
　　
　　Successful [SET] : 1000000
　　Failed [SET] : 0
　　Total Time [SET] : 51.77594s
　　Average Time [SET] : 0.00005s
　　
　　Successful [GET] : 1000000
　　Failed [GET] : 0
　　Total Time [GET] : 40.93667s
　　Average Time [GET] : 0.00004s
```

# Real performance in production

* cluster 1: 1.1B records, 55TB data, 48 nodes, 1100 get/25 set per seconds,
             med/avg/90%/99% time is 12/20/37/186 ms.
* cluster 2: 3.3B records, 3.5TB data, 15 nodes, 1000 get/500 set per seconds,
             med/avg/90%/99% time is 1/11/15/123 ms.

