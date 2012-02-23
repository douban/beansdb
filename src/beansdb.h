/*
 *  Beansdb - A high available distributed key-value storage system:
 *
 *      http://beansdb.googlecode.com
 *
 *  The source code of Beansdb is most based on Memcachedb and Memcached:
 *
 *      http://memcachedb.org/
 *      http://danga.com/memcached/
 *
 *  Copyright 2009 Douban Inc.  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      Davies Liu <davies.liu@gmail.com>
 *
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#define DATA_BUFFER_SIZE 2048
#define MAX_PAYLOAD_SIZE 1400
#define MAX_SENDBUF_SIZE (256 * 1024 * 1024)
/* I'm told the max legnth of a 64-bit num converted to string is 20 bytes.
 * Plus a few for spaces, \r\n, \0 */
#define SUFFIX_SIZE 24
#define INCR_MAX_STORAGE_LEN 24

/** Initial size of list of items being returned by "get". */
#define ITEM_LIST_INITIAL 200

/** Initial size of the sendmsg() scatter/gather array. */
#define IOV_LIST_INITIAL 400

/** Initial number of sendmsg() argument structures to allocate. */
#define MSG_LIST_INITIAL 10

/** High water marks for buffer shrinking */
#define READ_BUFFER_HIGHWAT 8192
#define ITEM_LIST_HIGHWAT 400
#define IOV_LIST_HIGHWAT 600
#define MSG_LIST_HIGHWAT 100

#define MAX_REP_PRIORITY 1000000
#define MAX_REP_ACK_POLICY 6
#define MAX_REP_NSITES 1000


#define RGET_MAX_ITEMS 100

/* Get a consistent bool type */
#if HAVE_STDBOOL_H
# include <stdbool.h>
#else
  typedef enum {false = 0, true = 1} bool;
#endif

#if HAVE_STDINT_H
# include <stdint.h>
#else
 typedef unsigned char             uint8_t;
#endif

/* unistd.h is here */
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

/* 64-bit Portable printf */
/* printf macros for size_t, in the style of inttypes.h */
#ifdef _LP64
#define __PRIS_PREFIX "z"
#else
#define __PRIS_PREFIX
#endif

#define AE_SETSIZE (1024*60)    /* Max number of fd supported */

#define AE_OK 0
#define AE_ERR -1

#define AE_NONE 0
#define AE_READABLE 1
#define AE_WRITABLE 2

/* Use these macros after a % in a printf format string
   to get correct 32/64 bit behavior, like this:
   size_t size = records.size();
   printf("%"PRIuS"\n", size); */

#define PRIdS __PRIS_PREFIX "d"
#define PRIxS __PRIS_PREFIX "x"
#define PRIuS __PRIS_PREFIX "u"
#define PRIXS __PRIS_PREFIX "X"
#define PRIoS __PRIS_PREFIX "o"

struct stats {
    uint32_t      curr_conns;
    uint32_t      total_conns;
    uint32_t      conn_structs;
    uint64_t      get_cmds;
    uint64_t      set_cmds;
    uint64_t      delete_cmds;
    uint64_t      slow_cmds;
    uint64_t      get_hits;
    uint64_t      get_misses;
    time_t        started;          /* when the process was started */
    uint64_t      bytes_read;
    uint64_t      bytes_written;
};

#define MAX_VERBOSITY_LEVEL 2

struct settings {
    size_t item_buf_size;
    int maxconns;
    int port;
    char *inter;
    int verbose;
    float slow_cmd_time;
    int flush_period;
    int flush_limit;
    int num_threads;        /* number of libevent threads to run */
};

extern struct stats stats;
extern struct settings settings;

typedef struct _stritem {
    int             ver;        /* version of item */
    uint32_t        flag;        /* flag of item */
    int             nbytes;     /* size of data */
    uint8_t         nsuffix;    /* length of flags-and-length string */
    uint8_t         nkey;       /* key length, w/terminating null and padding */
    void * end[];
    /* then null-terminated key */
    /* then " flags length\r\n" (no terminating null) */
    /* then data with terminating \r\n (no terminating null; it's binary!) */
} item;

#define ITEM_key(item) ((char*)&((item)->end[0]))

/* warning: don't use these macros with a function, as it evals its arg twice */
#define ITEM_suffix(item) ((char*) &((item)->end[0]) + (item)->nkey + 1)
#define ITEM_data(item) ((char*) &((item)->end[0]) + (item)->nkey + 1 + (item)->nsuffix)
#define ITEM_ntotal(item) (sizeof(struct _stritem) + (item)->nkey + 1 + (item)->nsuffix + (item)->nbytes)

enum conn_states {
    conn_listening,  /** the socket which listens for connections */
    conn_read,       /** reading in a command line */
    conn_write,      /** writing out a simple response */
    conn_nread,      /** reading in a fixed number of bytes */
    conn_swallow,    /** swallowing unnecessary bytes w/o storing */
    conn_closing,    /** closing this connection */
    conn_mwrite,     /** writing out many items sequentially */
};

#define NREAD_ADD 1
#define NREAD_SET 2
#define NREAD_REPLACE 3
#define NREAD_APPEND 4
#define NREAD_PREPEND 5

typedef struct conn conn;
struct conn {
    int    sfd;
    int    state;
    short  ev_flags;

    char   *rbuf;   /** buffer to read commands into */
    char   *rcurr;  /** but if we parsed some already, this is where we stopped */
    int    rsize;   /** total allocated size of rbuf */
    int    rbytes;  /** how much data, starting from rcur, do we have unparsed */

    char   *wbuf;
    char   *wcurr;
    int    wsize;
    int    wbytes;
    int    write_and_go; /** which state to go into after finishing current write */
    void   *write_and_free; /** free this memory after finishing writing */
    bool   noreply;   /* True if the reply should not be sent. */

    char   *ritem;  /** when we read in an item's value, it goes here */
    int    rlbytes;

    /* data for the nread state */

    /**
     * item is used to hold an item structure created after reading the command
     * line of set/add/replace commands, but before we finished reading the actual
     * data. The data is read into ITEM_data(item) to avoid extra copying.
     */

    void   *item;     /* for commands set/add/replace  */
    int    item_comm; /* which one is it: set/add/replace */

    /* data for the swallow state */
    int    sbytes;    /* how many bytes to swallow */

    /* data for the mwrite state */
    struct iovec *iov;
    int    iovsize;   /* number of elements allocated in iov[] */
    int    iovused;   /* number of elements used in iov[] */

    struct msghdr *msglist;
    int    msgsize;   /* number of elements allocated in msglist[] */
    int    msgused;   /* number of elements used in msglist[] */
    int    msgcurr;   /* element in msglist[] being transmitted now */
    int    msgbytes;  /* number of bytes in current msg */

    item   **ilist;   /* list of items to write out */
    int    isize;
    item   **icurr;
    int    ileft;

    conn   *next;     /* Used for generating a list of conn structures */
};

/*
 * Functions
 */

/* item management */
void item_init(void);
item *do_item_from_freelist(void);
int do_item_add_to_freelist(item *it);
item *item_alloc1(char *key, const size_t nkey, const int flags, const int nbytes);
int item_free(item *it);
item *item_get(char *key, size_t nkey);

/* conn management */
conn *do_conn_from_freelist();
bool do_conn_add_to_freelist(conn *c);
conn *conn_new(const int sfd, const int init_state, const int read_buffer_size);

int add_delta(char *key, size_t nkey, int64_t delta, char *buf);
int store_item(item *item, int comm);

void thread_init(int nthreads);
int add_event(int fd, int mask, conn *c);
void loop_run(int nthreads);

void drive_machine(conn *c);

/* Lock wrappers for cache functions that are called from main loop. */
conn *mt_conn_from_freelist(void);
bool mt_conn_add_to_freelist(conn *c);
item *mt_item_from_freelist(void);
int mt_item_add_to_freelist(item *it);
void  mt_stats_lock(void);
void  mt_stats_unlock(void);

# define conn_from_freelist()        mt_conn_from_freelist()
# define conn_add_to_freelist(x)     mt_conn_add_to_freelist(x)
# define item_from_freelist()        mt_item_from_freelist()
# define item_add_to_freelist(x)     mt_item_add_to_freelist(x)
# define STATS_LOCK()                mt_stats_lock()
# define STATS_UNLOCK()              mt_stats_unlock()

extern int daemon_quit;
