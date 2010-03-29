/*
 *  Beansdb - A high available distributed key-value storage system:
 *
 *      http://beansdb.googlecode.com
 *
 *  Copyright 2009 Douban Inc.  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      Davies Liu <davies.liu@gmail.com>
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>

#include <tcutil.h>
#include <tchdb.h>

#include "htree.h"
#include "hstore.h"
#include "fnv1a.h"

const int NUM_OF_MUTEX = 97;

typedef struct t_meta {
    int32_t  version;
    uint32_t hash;
    uint32_t flag;
    time_t   modified;
} Meta;

struct t_hstore {
    int height;
    int start;
    int end;
    bool stop_scan;
    bool *scanning;
    TCHDB **db;
    HTree **tree;
    pthread_mutex_t *mutex;
    TCMDB **cache;
};

static uint32_t gen_hash(void *buf, int len)
{
    assert(buf);
    uint32_t hash = len * 97;
    if (len <= 1024){
        hash += fnv1a(buf, len);
    }else{
        hash += fnv1a(buf, 512);
        hash *= 97;
        hash += fnv1a(buf + len - 512, 512);
    }
    return hash;
}

inline int get_index(HStore *store, char *key)
{
    if (store->height == 0) return 0;
    uint32_t h = fnv1a(key, strlen(key));
    return h >> ((8 - store->height) * 4);
}

inline pthread_mutex_t *get_mutex(HStore *store, char *key)
{
    uint32_t h = fnv1a(key, strlen(key));
    return store->mutex + h % NUM_OF_MUTEX;
}

HStore* hs_open(char *path, int height, int start, int end)
{
    if (NULL == path) return NULL;
    if (height < 0 || height > 4) {
        fprintf(stderr, "invalid db height: %d\n", height);
        return NULL; 
    }
    int i, j, count = 1 << (height * 4);
    if (end == -1 || end > count) end = count;
    if (start < 0) start = 0;

    HStore *store = (HStore*) malloc(sizeof(HStore));
    assert(store);
    store->height = height;
    store->start = start;
    store->end = end;
    store->stop_scan = false;

    store->scanning = (bool*) malloc(sizeof(bool) * count);
    memset(store->scanning, 0, sizeof(bool) * count);
    store->db = (TCHDB**) malloc(sizeof(TCHDB*) * count);
    memset(store->db, 0, sizeof(TCHDB*) * count);
    store->cache = (TCMDB**) malloc(sizeof(TCMDB*) * count);
    memset(store->cache, 0, sizeof(TCMDB*) * count);
    store->tree = (HTree**) malloc(sizeof(HTree*) * count);
    memset(store->tree, 0, sizeof(HTree*) * count);
  
    char format[255], buf[255], format2[255], buf2[255];
    if (height > 1){
        sprintf(format, "%%s/%%0%dx/%%0%dx.tch", height-1, height);
        sprintf(format2, "%%s/%%0%dx/.%%0%dx.index", height-1, height);
    }else{
        sprintf(format, "%%s/%%0%dx.tch", height);
        sprintf(format2, "%%s/.%%0%dx.index", height);
    }
    if (0 != access(path, F_OK) && 0 != mkdir(path, 0750)){
        fprintf(stderr, "mkdir %s failed\n", path);
        return NULL;
    }
    for (i=start; i<end; i++){
        if (height > 1){
            snprintf(buf, 255, format, path, i/16, i);
            char dp[255], df[255];
            sprintf(df, "%%s/%%0%dx", height-1);
            sprintf(dp, df, path, i/16);
            if (0 != access(dp, F_OK) && 0 != mkdir(dp, 0750)){
                fprintf(stderr, "mkdir %s failed\n", dp);
                return NULL;
            }
        }else{
            snprintf(buf, 255, format, path, i);
        }
        
        TCHDB *db = tchdbnew();
        assert(db);
        tchdbtune(db, 64 * 1024, 4, -1, 0);
        tchdbsetxmsiz(db, 64 * 4 * 1024);

        if(!tchdbopen(db, buf, HDBOCREAT | HDBOREADER | HDBOWRITER)){
            printf("HDB: open %s failed.\n", buf);
            tchdbdel(db);
            for (j=start; j<i; j++){
                tchdbclose(store->db[j]);
                tchdbdel(store->db[j]);
                ht_close(store->tree[j]);
            }
            free(store->tree);
            free(store->cache);
            free(store->db);
            return NULL;
        }
        store->db[i] = db;

        store->cache[i] = tcmdbnew();

        if (height > 1){
            snprintf(buf2, 255, format2, path, i/16, i);
        }else{
            snprintf(buf2, 255, format2, path, i);
        }
        HTree *tree = ht_open(buf2, height);
        if(!tree){
            tchdbclose(db);
            tchdbdel(db);
            for (j=start; j<i; j++){
                tchdbclose(store->db[j]);
                tchdbdel(store->db[j]);
                ht_close(store->tree[j]);
            }
            free(store->tree);
            free(store->cache);
            free(store->db);
            return NULL;
        }
        ht_get_hash(tree, "@", NULL); // warn up
        store->tree[i] = tree;
    }

    store->mutex =  malloc(sizeof(pthread_mutex_t) * NUM_OF_MUTEX);
    for (i=0; i<NUM_OF_MUTEX; i++){
        pthread_mutex_init(&store->mutex[i], NULL);
    }

    return store;
}

static void do_flush(HStore *store, int i)
{
    TCMDB *cache = store->cache[i];
    char *key, *value = NULL;
    int klen, vlen;
    tcmdbiterinit(cache);
    while (key = tcmdbiternext(cache, &klen)){
        pthread_mutex_t *mutex = get_mutex(store, key);
        pthread_mutex_lock(mutex);
        value = tcmdbget(cache, key, klen, &vlen);
        if (value){
            if(!tchdbput(store->db[i], key, klen, value, vlen)){
	        printf("tchdbput %s into %x.tch failed: %s\n", 
			key, i, tcerrmsg(tchdbecode(store->db[i])));
		tchdbout(store->db[i], key, klen);
		ht_remove(store->tree[i], key, false);
	    }
            tcmdbout(cache, key, klen);
            free(value);
        }
        pthread_mutex_unlock(mutex);

        free(key);
        tcmdbiterinit(cache);
    }
    ht_flush(store->tree[i]);
}

void hs_flush(HStore *store, int limit)
{
    int i;
    for (i=store->start; i<store->end; i++){
        if (tcmdbrnum(store->cache[i]) < limit || 
            store->scanning[i] && limit > 0){
            continue;
        }
        do_flush(store, i);
    }
}

void hs_close(HStore *store)
{
    assert(store);
    int i;

    hs_flush(store, 0);

    for (i=0; i<NUM_OF_MUTEX; i++){
        pthread_mutex_lock(store->mutex + i);
    }

    for (i=store->start; i < store->end; i++){
        tchdbclose(store->db[i]);
        tchdbdel(store->db[i]);
        ht_close(store->tree[i]);
        tcmdbdel(store->cache[i]);
    }

    free(store->db);
    free(store->cache);
    free(store->tree);
    store->end = 0;
    store->db = NULL;
    store->tree = NULL;

    for (i=NUM_OF_MUTEX-1; i>=0; i--){
        pthread_mutex_unlock(store->mutex + i);
        pthread_mutex_destroy(store->mutex + i);
    }
    free(store->mutex);
    store->mutex = NULL;
}

static void do_scan(HStore *store, int i)
{
    TCHDB *db = store->db[i];
    HTree *tree = store->tree[i];

    tchdbiterinit(db);
    TCXSTR *key = tcxstrnew(), *value = tcxstrnew();
    while (!store->stop_scan && tchdbiternext3(db, key, value)){
        char *v = (char*)tcxstrptr(value);
        int vsize = tcxstrsize(value);
        vsize -= sizeof(Meta);
        uint32_t h = gen_hash(v, vsize);
        Meta *meta = (Meta*)(v + vsize); 
        if (meta->hash == h || meta->hash == 0){
            ht_add(tree, (char*)tcxstrptr(key), meta->version, h, false);
        }else{
            fprintf(stderr, "corrupted record %s: %x != %x", 
                (char*)tcxstrptr(key), h, meta->hash);
        }
        tcxstrclear(key);
        tcxstrclear(value);
    }
    tcxstrdel(key);
    tcxstrdel(value);

    do_flush(store, i);
}

void hs_check(HStore *store, int scan_limit)
{
    int i;
    for (i=store->start; i<store->end; i++){
        store->scanning[i] = true;
	do_flush(store, i);
        int cnt, rnum = tchdbrnum(store->db[i]);
        ht_get_hash(store->tree[i], "@", &cnt);
        if (abs(rnum - cnt) > 0){
            printf("check %x.tch: %d in db, %d(%d) in htree\n", 
                    i, rnum, cnt, cnt - rnum);
            if (abs(rnum - cnt) > scan_limit){
                printf("start scanning ...\n");
                if (cnt > rnum){
                    printf("clear index of %x.tch\n", i);
                    ht_clear(store->tree[i]);
                }
                do_scan(store, i);
                ht_get_hash(store->tree[i], "@", &cnt);
                rnum = tchdbrnum(store->db[i]);
                printf("scan complete with %d(%d)\n", cnt, cnt-rnum);
                if (abs(rnum - cnt) > scan_limit){
                    fprintf(stderr, "rnum %d may be wrong, optimize it\n", rnum);
                }
            }
        }
        store->scanning[i] = false;
        if (store->stop_scan) {
            printf("scan canceled due to close\n");
            break;
        }
    }
}

void hs_stop_check(HStore *store)
{
    int i;
    store->stop_scan = true;
    for (i=store->start; i<store->end; i++){
        while (store->scanning[i]) {
		sleep(1);
    		store->stop_scan = true;
	}
    }
}

void hs_clear(HStore *store)
{
    int i;
    for (i=0; i<NUM_OF_MUTEX; i++){
        pthread_mutex_lock(store->mutex + i);
    }

    for (i=store->start; i < store->end; i++){
        tchdbvanish(store->db[i]);
        ht_clear(store->tree[i]);
    }
    
    for (i=NUM_OF_MUTEX-1; i>=0; i--){
        pthread_mutex_unlock(store->mutex + i);
    }
}

bool hs_set(HStore *store, char *key, char* value,
        int vlen, int ver, uint32_t flag)
{
    if (!key || key[0] == '@') return false;

    int index = get_index(store, key);
    if (index < store->start || index >= store->end) return false;

    pthread_mutex_t *mutex = get_mutex(store, key);
    pthread_mutex_lock(mutex);

    int siz, old_ver = 0;
    uint32_t old_hash = ht_get_hash(store->tree[index], key, &old_ver);
    if (ver > 0 && ver <= old_ver){
        pthread_mutex_unlock(mutex);
        return false;
    }

    if (ver == 0){
        ver = old_ver + 1;
    }

    bool changed = true;
    uint32_t hash = gen_hash((void*)value, vlen);
    if (hash == old_hash){
        int size;
        char *oldv = tcmdbget(store->cache[index], key, strlen(key), &size);
        if (!oldv){
            oldv = tchdbget(store->db[index], key, strlen(key), &size);
        }
        if (oldv){
            if (size==vlen && strncmp(oldv, value, vlen) == 0){
                changed = false;
            }
            free(oldv);
        }
    }
    if (changed){
        char* newbuf = malloc(vlen + sizeof(Meta));
        if (!newbuf){
            pthread_mutex_unlock(mutex);
            return false;
        }
        memcpy(newbuf, value, vlen);
        Meta *meta = (Meta*)(newbuf + vlen);
        meta->version = ver;
        meta->hash = hash;
        meta->flag = flag;
        meta->modified = time(0);
        tcmdbput(store->cache[index], key, strlen(key), newbuf, vlen + sizeof(Meta));
        free(newbuf);
    }
    ht_add(store->tree[index], key, ver, hash, false);
    pthread_mutex_unlock(mutex);
    return changed;
}

static int hextoi(char *s, int len)
{
    int n = 0;
    char *p = s, *end = s + len;
    while (p < end){
        n *= 16;
        if ('a' <= *p && *p <= 'f'){
            n += *p - 'a' + 10;
        }else if ('0' <= *p && *p <= '9'){
            n += *p - '0';
        }
        p++;
    }
    return n ;
}

static int hs_get_hash(HStore *store, char *pos, int *count)
{
    if (strlen(pos) >= store->height){
        assert(strlen(pos) == store->height);
        int index = hextoi(pos, store->height);
        if (index < store->start || index >= store->end){
            *count = 0;
            return 0;
        }
        return ht_get_hash(store->tree[index], "@", count);
    }else{
        int i, hash=0;
        *count = 0;
        for (i=0; i<16; i++){
            int h,c;
            char pos_buf[255];
            sprintf(pos_buf, "%s%x", pos, i);
            h = hs_get_hash(store, pos_buf, &c);
            hash *= 97;
            hash += h;
            *count += c;
        }
        return hash;
    }
}

static char* hs_list(HStore *store, char *key)
{
    int pos = strlen(key);
    if (pos >= store->height){
        int index = hextoi(key, store->height);
        if (index < store->start || index >= store->end){
            return NULL;
        }
        return ht_list(store->tree[index], key + store->height);
    }else{
        int i, bsize = 1024, used = 0;
        char *buf = malloc(bsize);
        for (i=0; i < 16; i++) {
            char pos_buf[255];
            if (strlen(key)){
                sprintf(pos_buf, "%s%x", key, i);
            }else{
                sprintf(pos_buf, "%x", i);
            }
            int hash, count;
            hash = hs_get_hash(store, pos_buf, &count);
            used += snprintf(buf + used, bsize - used, "%x/ %u %u\n", i, hash & 0xffff, count);
        }
        return buf;
    }
}

char *hs_get(HStore *store, char *key, int *vlen, uint32_t *flag)
{
    if (!key) return NULL;

    char *r = NULL;
    if (key[0] == '@'){
        r = hs_list(store, key+1);
        if (r) *vlen = strlen(r);
	*flag = 0;
    }else if (key[0] == '?'){
        key ++;
        int index = get_index(store, key);
        if (index < store->start || index >= store->end) return NULL;
        
        char *v = tcmdbget(store->cache[index], key, strlen(key), vlen);
        if (!v){
            v = tchdbget(store->db[index], key, strlen(key), vlen);
        }
        if (v){
            Meta *meta = (Meta*)(v + *vlen - sizeof(Meta));
            r = malloc(256);
            *vlen = snprintf(r, 255, "%d %d %d %d", meta->version, 
                    meta->hash, meta->flag, meta->modified);
            *flag = 0;
            free(v);
        }
    }else{
        int index = get_index(store, key);
        if (index < store->start || index >= store->end) return NULL;

        r = tcmdbget(store->cache[index], key, strlen(key), vlen);
        if (!r){
            r = tchdbget(store->db[index], key, strlen(key), vlen);
        }
        if(r){
            *vlen -= sizeof(Meta);
            Meta *meta = (Meta*)(r + *vlen);
            *flag = meta->flag;
        }
    }
    return r;
}

bool hs_delete(HStore *store, char *key)
{
    if (!key) return false;

    assert(store);
    int index = get_index(store, key);
    if (index < store->start || index >= store->end) return false;

    if (store->scanning[index]) return false;
    
    pthread_mutex_t *mutex = get_mutex(store, key);
    pthread_mutex_lock(mutex);

    ht_remove(store->tree[index], key, false);
    bool r = tcmdbout2(store->cache[index], key);
    r = tchdbout2(store->db[index], key) || r;
    
    pthread_mutex_unlock(mutex);

    return r;
}
