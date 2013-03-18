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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>
#include <time.h>

#include "htree.h"
#include "hstore.h"
#include "bitcask.h"
#include "diskmgr.h"

#define NUM_OF_MUTEX 37
#define MAX_PATHS 20
const int APPEND_FLAG  = 0x00000100;
const int INCR_FLAG    = 0x00000204;

struct t_hstore {
    int height, count;
    time_t before;
    int scan_threads;
    int op_start, op_end, op_limit; // for optimization
    Mgr* mgr;
    pthread_mutex_t locks[NUM_OF_MUTEX];
    Bitcask* bitcasks[];
};

inline int get_index(HStore *store, char *key)
{
    if (store->height == 0) return 0;
    uint32_t h = fnv1a(key, strlen(key));
    return h >> ((8 - store->height) * 4);
}

inline pthread_mutex_t* get_mutex(HStore *store, char *key)
{
    uint32_t i = fnv1a(key, strlen(key)) % NUM_OF_MUTEX;
    return &store->locks[i];
}


// scan
static int scan_completed = 0;
static pthread_mutex_t scan_lock;
static pthread_cond_t  scan_cond;

typedef void (*BC_FUNC)(Bitcask *bc);

struct scan_args {
    HStore *store;
    int index;
    BC_FUNC func;
};

static void* scan_thread(void *_args)
{
    struct scan_args *args = _args; 
    HStore *store = args->store;
    int i, index = args->index;
    for (i=0; i<store->count; i++) {
        if (i % store->scan_threads == index) {
            args->func(store->bitcasks[i]);
        }
    }

    pthread_mutex_lock(&scan_lock);
    scan_completed ++;
    pthread_cond_signal(&scan_cond);
    pthread_mutex_unlock(&scan_lock);

//    fprintf(stderr, "thread %d completed\n", index);
    return NULL;
}

static void parallelize(HStore *store, BC_FUNC func) {
    scan_completed = 0;
    pthread_mutex_init(&scan_lock, NULL);
    pthread_cond_init(&scan_cond, NULL);

    pthread_attr_t attr;
    pthread_attr_init(&attr);

    int i, ret;
    pthread_t *thread_ids = malloc(sizeof(pthread_t) * store->scan_threads);
    struct scan_args *args = (struct scan_args *) malloc(sizeof(struct scan_args) * store->scan_threads);
    for (i=0; i<store->scan_threads; i++) {
        args[i].store = store;
        args[i].index = i;
        args[i].func = func;
        if ((ret = pthread_create(thread_ids + i, &attr, scan_thread, args + i)) != 0) {
            fprintf(stderr, "Can't create thread: %s\n", strerror(ret));
            exit(1);
        }
    }

    pthread_mutex_lock(&scan_lock);
    while (scan_completed < store->scan_threads) {
        pthread_cond_wait(&scan_cond, &scan_lock);
    }
    pthread_mutex_unlock(&scan_lock);

    for (i=0; i<store->scan_threads; i++) {
        pthread_join(thread_ids[i], NULL);
        pthread_detach(thread_ids[i]);
    }
    free(thread_ids);
    free(args);
}

HStore* hs_open(char *path, int height, time_t before, int scan_threads)
{
    if (NULL == path) return NULL;
    if (height < 0 || height > 3) {
        fprintf(stderr, "invalid db height: %d\n", height);
        return NULL; 
    }
    if (before != 0){
        if (before<0) {
            fprintf(stderr, "invalid time:%ld\n", before);
            return NULL;
        }else{
            fprintf(stderr, "serve data modified before %s\n", ctime(&before));
        }
    }
    
    char *paths[20], *rpath = path;
    int npath = 0;
    while ((paths[npath] = strsep(&rpath, ",:;")) != NULL) {
        if (npath >= MAX_PATHS) return NULL; 
        path = paths[npath];
        if (0 != access(path, F_OK) && 0 != mkdir(path, 0755)){
            fprintf(stderr, "mkdir %s failed\n", path);
            return NULL;
        }
        if (height > 1){
            // try to mkdir
            HStore *s = hs_open(path, height - 1, 0, 0);
            if (s == NULL){
                return NULL;
            }
            hs_close(s);
        }
        
        npath ++;
    }

    int i, j, count = 1 << (height * 4);
    HStore *store = (HStore*) malloc(sizeof(HStore) + sizeof(Bitcask*) * count);
    if (!store) return NULL;
    memset(store, 0, sizeof(HStore) + sizeof(Bitcask*) * count);
    store->height = height;
    store->count = count;
    store->before = before;
    store->scan_threads = scan_threads;
    store->op_start = 0;
    store->op_end = 0;
    store->op_limit = 0;
    store->mgr = mgr_create((const char**)paths, npath);
    if (store->mgr == NULL) {
        free(store);
        return NULL;
    }
    for (i=0; i<NUM_OF_MUTEX; i++) {
        pthread_mutex_init(&store->locks[i], NULL);
    }

    char *buf[20] = {0};
    for (i=0;i<npath;i++) {
        buf[i] = malloc(255);
    }
    for (i=0; i<count; i++){
        for (j=0; j<npath; j++) {
            path = paths[j];
            switch(height){
                case 0: sprintf(buf[j], "%s", path); break;
                case 1: sprintf(buf[j], "%s/%x", path, i); break;
                case 2: sprintf(buf[j], "%s/%x/%x", path, i>>4, i & 0xf); break;
                case 3: sprintf(buf[j], "%s/%x/%x/%x", path, i>>8, (i>>4)&0xf, i&0xf); break;
            }
        }
        Mgr *mgr = mgr_create((const char**)buf, npath);
        if (mgr == NULL) return NULL;
        store->bitcasks[i] = bc_open2(mgr, height, i, before);
    }
    for (i=0;i<npath;i++) {
        free(buf[i]);
    }
   
    if (store->scan_threads > 1 && count > 1) {
        parallelize(store, bc_scan);
    }else{
        for (i=0; i<count; i++) {
            bc_scan(store->bitcasks[i]);
        }
    }

    return store;
}

void hs_flush(HStore *store, int limit, int period)
{
    if (!store) return;
    if (store->before > 0) return;
    int i;
    for (i=0; i<store->count; i++){
        bc_flush(store->bitcasks[i], limit, period);
    }
}

void hs_close(HStore *store)
{
    int i;
    if (!store) return;
    // stop optimizing
    store->op_start = store->op_end = 0;
    
    if (store->scan_threads > 1 && store->count > 1) {
        parallelize(store, bc_close);
    } else {
        for (i=0; i<store->count; i++){
            bc_close(store->bitcasks[i]);
        }
    }
    mgr_destroy(store->mgr);
    free(store);
}

static uint16_t hs_get_hash(HStore *store, char *pos, uint32_t *count)
{
    if (strlen(pos) >= store->height){
        pos[store->height] = 0;
        int index = strtol(pos, NULL, 16);
        return bc_get_hash(store->bitcasks[index], "@", count);
    }else{
        uint16_t i, hash=0;
        *count = 0;
        char pos_buf[255];
        for (i=0; i<16; i++){
            int h,c;
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
    char *prefix = NULL;
    int p = 0, pos = strlen(key);
    while (p < pos) {
        if (key[p] == ':'){
            prefix = &key[p+1];
            break;
        }
        p++;
    }
    if (p > 8) return NULL;

    if (p >= store->height){
        char buf[20] = {0};
        memcpy(buf, key, store->height);
        int index = strtol(buf, NULL, 16);
        memcpy(buf, key, p);
        return bc_list(store->bitcasks[index], buf + store->height, prefix);
    }else{
        int i, bsize = 1024, used = 0;
        char *buf = malloc(bsize);
        if (!buf) return NULL;
        for (i=0; i < 16; i++) {
            char pos_buf[255];
            memcpy(pos_buf, key, p);
            sprintf(pos_buf + p, "%x", i);
            uint32_t hash, count;
            hash = hs_get_hash(store, pos_buf, &count);
            used += snprintf(buf + used, bsize - used, "%x/ %u %u\n", i, hash & 0xffff, count);
        }
        return buf;
    }
}

char *hs_get(HStore *store, char *key, int *vlen, uint32_t *flag)
{
    if (!key || !store) return NULL;

    if (key[0] == '@'){
        char *r = hs_list(store, key+1);
        if (r) *vlen = strlen(r);
        *flag = 0;
        return r;
    }
    
    bool info = false;
    if (key[0] == '?'){
        info = true;
        key ++;
    }
    int index = get_index(store, key);
    DataRecord *r = bc_get(store->bitcasks[index], key);
    if (r == NULL){
        return NULL;
    }
    
    char *res = NULL;
    if (info){
        res = malloc(256);
        if (!res) {
            free_record(r);
            return NULL;
        }
        uint16_t hash = 0;
        if (r->version > 0){
            hash = gen_hash(r->value, r->vsz);
        }
        *vlen = snprintf(res, 255, "%d %u %u %u %u", r->version, 
            hash, r->flag, r->vsz, r->tstamp);
        *flag = 0;
    }else if (r->version > 0){
        res = record_value(r);
        r->value = NULL;
        *vlen = r->vsz;
        *flag = r->flag;
    }
    free_record(r);
    return res;
}

bool hs_set(HStore *store, char *key, char* value, int vlen, uint32_t flag, int ver)
{
    if (!store || !key || key[0] == '@') return false;
    if (store->before > 0) return false;
    
    int index = get_index(store, key);
    return bc_set(store->bitcasks[index], key, value, vlen, flag, ver);
}

bool hs_append(HStore *store, char *key, char* value, int vlen)
{
    if (!store || !key || key[0] == '@') return false;
    if (store->before > 0) return false;
    
    pthread_mutex_t *lock = get_mutex(store, key);
    pthread_mutex_lock(lock);

    int suc = false;
    int rlen = 0, flag = APPEND_FLAG;
    char *body = hs_get(store, key, &rlen, &flag);
    if (body != NULL && flag != APPEND_FLAG) {
        fprintf(stderr, "try to append %s with flag=%x\n", key, flag);
        goto APPEND_END;
    }
    body = realloc(body, rlen + vlen);
    memcpy(body + rlen, value, vlen);
    suc = hs_set(store, key, body, rlen + vlen, flag, 0); // TODO: use timestamp
    
APPEND_END:    
    if (body != NULL) free(body);
    pthread_mutex_unlock(lock);
    return suc;
}

int64_t hs_incr(HStore *store, char *key, int64_t value)
{
    if (!store || !key || key[0] == '@') return 0;
    if (store->before > 0) return 0;
    
    pthread_mutex_t *lock = get_mutex(store, key);
    pthread_mutex_lock(lock);

    int64_t result = 0;
    int rlen = 0, flag = INCR_FLAG;
    char buf[25];
    char *body = hs_get(store, key, &rlen, &flag);
    
    if (body != NULL) {
        if (flag != INCR_FLAG || rlen > 22) {
            fprintf(stderr, "try to incr %s but flag=0x%x, len=%d", key, flag, rlen);
            goto INCR_END; 
        }
        result = strtoll(body, NULL, 10);
        if (result == 0 && errno == EINVAL) {
            fprintf(stderr, "incr %s failed: %s\n", key, buf);
            goto INCR_END;
        }
    }

    result += value;
    if (result < 0) result = 0;
    rlen = sprintf(buf, "%lld", (long long int) result); 
    if (!hs_set(store, key, buf, rlen, INCR_FLAG, 0)) { // use timestamp later
        result = 0; // set failed
    }

INCR_END:
    pthread_mutex_unlock(lock);
    if (body != NULL) free(body);
    return result;
}

void* do_optimize(void *arg)
{
    HStore *store = (HStore *) arg;
    time_t st = time(NULL);
    fprintf(stderr, "start to optimize from %d to %d\n", 
        store->op_start, store->op_end);
    for (; store->op_start < store->op_end; store->op_start ++) {
        bc_optimize(store->bitcasks[store->op_start], store->op_limit);
    }
    store->op_start = store->op_end = 0;
    fprintf(stderr, "optimization completed in %lld seconds\n", 
            (long long)(time(NULL) - st));
    return NULL;
}

bool hs_optimize(HStore *store, int limit)
{
    if (store->before > 0) return false;
    bool processing = store->op_start < store->op_end;
    if (processing) {
        store->op_start = store->op_end = 0;
    }else{
        pthread_t id;
        store->op_limit = limit;
        store->op_start = 0;
        store->op_end = 1 << (store->height * 4);
        pthread_create(&id, NULL, do_optimize, store);
    }
    
    return true;
}

bool hs_delete(HStore *store, char *key)
{
    if (!key || !store) return false;
    if (store->before > 0) return false;

    int index = get_index(store, key);
    return bc_delete(store->bitcasks[index], key);
}

uint64_t hs_count(HStore *store, uint64_t *curr)
{
    uint64_t total = 0, curr_total = 0;
    int i;
    for (i=0; i<store->count; i++) {
        uint32_t curr = 0;
        total += bc_count(store->bitcasks[i], &curr);
        curr_total += curr;
    }
    
    if (NULL != curr)  *curr = curr_total;
    return total;
}

void    hs_stat(HStore *store, uint64_t *total, uint64_t *avail)
{
    uint64_t used = 0;
    *total = 0;
    int i;
    for (i=0; i<store->count; i++) {
        bc_stat(store->bitcasks[i], &used);
        *total += used; 
    }
     
    uint64_t total_space;
    mgr_stat(store->mgr, &total_space, avail);
}
