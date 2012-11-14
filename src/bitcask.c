/*
 *  Beansdb - A high available distributed key-value storage system:
 *
 *      http://beansdb.googlecode.com
 *
 *  Copyright 2010 Douban Inc.  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      Davies Liu <davies.liu@gmail.com>
 *
 */
 
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <time.h>

#include "bitcask.h"
#include "htree.h"
#include "record.h"
#include "diskmgr.h"

#define MAX_BUCKET_COUNT 256

const uint32_t MAX_RECORD_SIZE = 50 << 20; // 50M
const uint32_t MAX_BUCKET_SIZE = (uint32_t)4 << 30; // 2G
const uint32_t WRITE_BUFFER_SIZE = 2 << 20; // 2M

const int SAVE_HTREE_LIMIT = 1;

const char DATA_FILE[] = "%03d.data";
const char HINT_FILE[] = "%03d.hint.qlz";
const char HTREE_FILE[] = "%03d.htree";

struct bitcask_t {
    uint32_t depth, pos;
    time_t before;
    Mgr    *mgr;
    HTree  *tree, *curr_tree;
    int    last_snapshot;
    uint64_t bytes, curr_bytes;
    uint32_t curr;
    char   *write_buffer;
    time_t last_flush_time;
    uint32_t    wbuf_size, wbuf_start_pos, wbuf_curr_pos;
    pthread_mutex_t flush_lock, buffer_lock, write_lock;
};

Bitcask* bc_open(const char* path, int depth, int pos, time_t before)
{
    if (path == NULL || depth > 4) return NULL;
    if (0 != access(path, F_OK) && 0 != mkdir(path, 0750)){
        fprintf(stderr, "mkdir %s failed\n", path);
        return NULL;
    }
    const char* t[] = {path};
    Mgr *mgr = mgr_create(t, 1);
    if (mgr == NULL) return NULL;

    Bitcask* bc = bc_open2(mgr, depth, pos, before);
    if (bc != NULL) bc_scan(bc);
    return bc;
}

Bitcask* bc_open2(Mgr *mgr, int depth, int pos, time_t before)
{
    Bitcask* bc = (Bitcask*)malloc(sizeof(Bitcask));
    if (bc == NULL) return NULL;

    memset(bc, 0, sizeof(Bitcask));    
    bc->mgr = mgr;
    bc->depth = depth;
    bc->pos = pos;
    bc->before = before;
    bc->bytes = 0;
    bc->curr_bytes = 0;
    bc->tree = NULL;
    bc->last_snapshot = -1;
    bc->curr_tree = ht_new(depth, pos);
    bc->wbuf_size = 1024 * 4;
    bc->write_buffer = malloc(bc->wbuf_size);
    bc->last_flush_time = time(NULL);
    pthread_mutex_init(&bc->buffer_lock, NULL);
    pthread_mutex_init(&bc->write_lock, NULL);
    pthread_mutex_init(&bc->flush_lock, NULL);
    return bc;
}

void bc_scan(Bitcask* bc)
{
    const char* path = mgr_base(bc->mgr);
    char dname[20], hname[20], datapath[255], hintpath[255];
    int i=0;
    struct stat st;
    // load snapshot of htree
    for (i=MAX_BUCKET_COUNT-1; i>=0; i--) {
        sprintf(dname, HTREE_FILE, i);
        sprintf(datapath, "%s/%s", path, dname);
        if (stat(datapath, &st) == 0) {
            bc->tree = ht_open(bc->depth, bc->pos, datapath);
            if (bc->tree != NULL) {
                bc->last_snapshot = i;
                break;
            } else {
                fprintf(stderr, "open HTree from %s failed\n", datapath);
                unlink(datapath);
            }
        }
    }
    if (bc->tree == NULL) {
        bc->tree = ht_new(bc->depth, bc->pos);
    }

    i ++;
    for (; i<MAX_BUCKET_COUNT; i++) {
        sprintf(dname, DATA_FILE, i);
        sprintf(datapath, "%s/%s", path, dname);
        if (stat(datapath, &st) != 0) {
            break;
        }
        bc->bytes += st.st_size;

        sprintf(hname, HINT_FILE, i);
        sprintf(hintpath, "%s/%s", path, hname);
        if (bc->before == 0){
            if (0 == stat(hintpath, &st)){
                scanHintFile(bc->tree, i, hintpath, NULL);
            }else{
                sprintf(hintpath, "%s/%s", mgr_alloc(bc->mgr, hname), hname);
                scanDataFile(bc->tree, i, datapath, hintpath);                
            }
        }else{
            if (0 == stat(hintpath, &st) && 
                (st.st_mtime < bc->before || 0 == stat(datapath, &st) && st.st_mtime < bc->before)){
                scanHintFile(bc->tree, i, hintpath, NULL); 
            }else{
                scanDataFileBefore(bc->tree, i, datapath, bc->before);
            }
        }
    }

    if (i - bc->last_snapshot > SAVE_HTREE_LIMIT) {
        sprintf(dname, HTREE_FILE, i-1);
        sprintf(datapath, "%s/%s.tmp", path, dname);
        if (ht_save(bc->tree, datapath) == 0) {
            sprintf(hintpath, "%s/%s", path, dname);
            rename(datapath, hintpath);

            sprintf(dname, HTREE_FILE, bc->last_snapshot);
            sprintf(datapath, "%s/%s.tmp", path, dname);
            unlink(datapath);

            bc->last_snapshot = i-1;
        } else {
            fprintf(stderr, "save HTree to %s failed\n", datapath);
        }
    }
    
    bc->curr = i;
}

/*
 * bc_close() is not thread safe, should stop other threads before call it.
 * */
void bc_close(Bitcask *bc)
{
    int i=0;
    char dname[20], hname[20], datapath[255], hintpath[255];
    
    pthread_mutex_lock(&bc->write_lock);
    
    bc_flush(bc, 0, 0);
    
    if (NULL != bc->curr_tree) {
        if (bc->curr_bytes > 0) {
            char name[255], buf[255];
            sprintf(name, HINT_FILE, bc->curr);
            sprintf(buf, "%s/%s", mgr_alloc(bc->mgr, name), name);
            build_hint(bc->curr_tree, buf);
        }else{
            ht_destroy(bc->curr_tree);
        }
        bc->curr_tree = NULL;
    }

    if (bc->curr_bytes == 0) bc->curr --;
    if (bc->curr - bc->last_snapshot >= SAVE_HTREE_LIMIT) {
        const char* path = mgr_base(bc->mgr);
        sprintf(dname, HTREE_FILE, bc->curr);
        sprintf(datapath, "%s/%s.tmp", path, dname);
        if (ht_save(bc->tree, datapath) == 0) {
            sprintf(hintpath, "%s/%s", path, dname);
            rename(datapath, hintpath);

            sprintf(dname, HTREE_FILE, bc->last_snapshot);
            sprintf(datapath, "%s/%s.tmp", path, dname);
            unlink(datapath);
        } else {
            fprintf(stderr, "save HTree to %s failed\n", datapath);
        }
    }
    ht_destroy(bc->tree);

    mgr_destroy(bc->mgr);
    free(bc->write_buffer);
    free(bc);
}

void update_items(Item *it, void *args)
{
    HTree *tree = (HTree*) args;
    Item *p = ht_get(tree, it->key);
    if (!p) {
        fprintf(stderr, "Bug, item missed after optimized\n");
        return;
    }
    if (it->pos != p->pos && (it->pos & 0xff) == (p->pos & 0xff) ) {
        ht_add(tree, p->key, it->pos, p->hash, p->ver);
    }
    free(p);
}

void bc_optimize(Bitcask *bc, int limit)
{
    int i;
    for (i=0; i < bc->curr; i++) {
        char data[20], hint[20], datapath[255], hintpath[255];
        sprintf(data, DATA_FILE, i);
        sprintf(hint, HINT_FILE, i);
        sprintf(datapath, "%s/%s", mgr_alloc(bc->mgr, data), data);
        sprintf(hintpath, "%s/%s", mgr_alloc(bc->mgr, hint), hint);
        
        uint32_t recoverd = 0;
        HTree *cur_tree = optimizeDataFile(bc->tree, i, datapath, hintpath, limit, &recoverd);
        if (NULL == cur_tree) continue;
        pthread_mutex_lock(&bc->buffer_lock);
        bc->bytes -= recoverd;
        pthread_mutex_unlock(&bc->buffer_lock);

        pthread_mutex_lock(&bc->write_lock);
        ht_visit(cur_tree, update_items, bc->tree);
        pthread_mutex_unlock(&bc->write_lock);

        build_hint(cur_tree, hintpath);
    }
}

DataRecord* bc_get(Bitcask *bc, const char* key)
{
    Item *item = ht_get(bc->tree, key);
    if (NULL == item) return NULL;
    if (item->ver < 0){
        free(item);
        return NULL;
    }
    
    uint32_t bucket = item->pos & 0xff;
    uint32_t pos = item->pos & 0xffffff00;
    if (bucket > bc->curr) {
        fprintf(stderr, "BUG: invalid bucket %d > %d\n", bucket, bc->curr);
        ht_remove(bc->tree, key);
        free(item);
        return NULL;
    }

    DataRecord* r = NULL;
    if (bucket == bc->curr) {
        pthread_mutex_lock(&bc->buffer_lock);
        if (bucket == bc->curr && pos >= bc->wbuf_start_pos){
            uint32_t p = pos - bc->wbuf_start_pos;
            r = decode_record(bc->write_buffer + p, bc->wbuf_curr_pos - p, true);
        }
        pthread_mutex_unlock(&bc->buffer_lock);
        
        if (r != NULL){
            free(item);
            return r;
        }
    }
        
    char fname[20], data[255];
    const char * path = mgr_base(bc->mgr);
    sprintf(fname, DATA_FILE, bucket);
    sprintf(data, "%s/%s", path, fname);
    int fd = open(data, O_RDONLY);
    if (-1 == fd){
        goto GET_END;
    }
    
    r = fast_read_record(fd, pos, true);
    if (NULL == r){
        fprintf(stderr, "Bug: get %s failed in %s %d %d\n", key, path, bucket, pos); 
    }else{
         // check key
        if (strcmp(key, r->key) != 0){
            fprintf(stderr, "Bug: record %s is not expected %s in %u @ %u\n", r->key, key, bucket, pos);
            free_record(r);
            r = NULL;
        } 
    }
GET_END:
    if (NULL == r)
        ht_remove(bc->tree, key);
    if (fd != -1) close(fd);
    free(item);
    return r;
}

struct build_thread_args {
    HTree *tree;
    char *path;
};

void* build_thread(void *param)
{
    struct build_thread_args *args = (struct build_thread_args*) param;
    build_hint(args->tree, args->path);
    free(args->path);
    free(param);
    return NULL;
}

void bc_rotate(Bitcask *bc) {
    // build in new thread
    char hname[20], hintpath[255];
    sprintf(hname, HINT_FILE, bc->curr);
    sprintf(hintpath, "%s/%s", mgr_alloc(bc->mgr, hname), hname);
    struct build_thread_args *args = (struct build_thread_args*)malloc(
            sizeof(struct build_thread_args));
    args->tree = bc->curr_tree;
    args->path = strdup(hintpath);
    pthread_t build_ptid;
    pthread_create(&build_ptid, NULL, build_thread, args);
    // next bucket
    bc->curr ++;
    bc->curr_tree = ht_new(bc->depth, bc->pos);
    bc->wbuf_start_pos = 0;
}

void bc_flush(Bitcask *bc, int limit, int flush_period)
{
    if (bc->curr >= MAX_BUCKET_COUNT) {
        fprintf(stderr, "reach max bucket count\n");
        exit(1);
    }
    
    pthread_mutex_lock(&bc->flush_lock);

    time_t now = time(NULL);
    if (bc->wbuf_curr_pos > limit * 1024 || 
        now > bc->last_flush_time + flush_period && bc->wbuf_curr_pos > 0) {
        char name[20], buf[255];
        sprintf(name, DATA_FILE, bc->curr);
        sprintf(buf, "%s/%s", mgr_alloc(bc->mgr, name), name);

        FILE *f = fopen(buf, "ab");
        if (f == NULL) {
            fprintf(stderr, "open file %s for flushing failed.\n", buf);
            exit(1);
        }
        // check file size
        uint64_t last_pos = ftell(f);
        if (last_pos > 0 && last_pos != bc->wbuf_start_pos) {
            fprintf(stderr, "last pos not match: %llu != %d\n", last_pos, bc->wbuf_start_pos);
            exit(1);
        }
      
        pthread_mutex_lock(&bc->buffer_lock);
        int size = bc->wbuf_curr_pos;
        char * tmp = (char*) malloc(size);
        memcpy(tmp, bc->write_buffer, size);
        pthread_mutex_unlock(&bc->buffer_lock);
        
        int n = fwrite(tmp, 1, size, f);
        if (n <= 0) {
            fprintf(stderr, "write failed: return %d\n", n);
            exit(1);
        }
        free(tmp);
        fclose(f);
        bc->last_flush_time = now;

        pthread_mutex_lock(&bc->buffer_lock);
        bc->bytes += n;
        bc->curr_bytes += n;
        if (n < bc->wbuf_curr_pos) {
            memmove(bc->write_buffer, bc->write_buffer + n, bc->wbuf_curr_pos - n);
        }
        bc->wbuf_start_pos += n;
        bc->wbuf_curr_pos -= n;
        if (bc->wbuf_curr_pos == 0) {
            if (bc->wbuf_size < WRITE_BUFFER_SIZE) {
                bc->wbuf_size *= 2;
                free(bc->write_buffer);
                bc->write_buffer = malloc(bc->wbuf_size);
            } else if (bc->wbuf_size > WRITE_BUFFER_SIZE * 2) {
                bc->wbuf_size = WRITE_BUFFER_SIZE;
                free(bc->write_buffer);
                bc->write_buffer = malloc(bc->wbuf_size);
            }
        }
        
        if (bc->wbuf_start_pos + bc->wbuf_size > MAX_BUCKET_SIZE) {
            bc_rotate(bc);
        }
        pthread_mutex_unlock(&bc->buffer_lock);
    }
    pthread_mutex_unlock(&bc->flush_lock);
}

bool bc_set(Bitcask *bc, const char* key, char* value, int vlen, int flag, int version)
{
    if (version < 0 && vlen > 0 || vlen > MAX_RECORD_SIZE){
        fprintf(stderr, "invalid set cmd \n");
        return false;
    }

    bool suc = false;
    pthread_mutex_lock(&bc->write_lock);
    
    int oldv = 0, ver = version;
    Item *it = ht_get(bc->tree, key);
    if (it != NULL) {
        oldv = it->ver;
    }
    
    if (version == 0 && oldv > 0){ // replace
        ver = oldv + 1;
    } else if (version == 0 && oldv <= 0){ // add
        ver = -oldv + 1;
    } else if (version < 0 && oldv <= 0) { // delete, not exist
        goto SET_FAIL;
    } else if (version == -1) { // delete
        ver = - abs(oldv) - 1;
    } else if (abs(version) <= abs(oldv)) { // sync
        goto SET_FAIL;
    } else { // sync
        ver = version;
    }
    
    uint16_t hash = gen_hash(value, vlen);
    if (ver < 0) hash = 0;

    if (NULL != it && hash == it->hash) {
        DataRecord *r = bc_get(bc, key);
        if (r != NULL && r->flag == flag && vlen  == r->vsz
             && memcmp(value, r->value, vlen) == 0) {
            if (version != 0){
                // update version
                ht_add(bc->tree, key, it->pos, it->hash, ver);
                if (it->pos & 0xff == bc->curr){
                    if (bc->curr_tree == NULL) {
                        fprintf(stderr, "BUG: curr_tree should not be NULL\n");
                    }else{
                        ht_add(bc->curr_tree, key, it->pos, it->hash, ver);
                    }
                }
            }
            suc = true;
            free_record(r);
            goto SET_FAIL;
        }
        if (r != NULL) free_record(r);
    }
    
    int klen = strlen(key);
    DataRecord *r = malloc(sizeof(DataRecord) + klen);
    r->ksz = klen;
    memcpy(r->key, key, klen);
    r->vsz = vlen;
    r->value = value;
    r->free_value = false;
    r->flag = flag;
    r->version = ver;
    r->tstamp = time(NULL);

    int rlen;
    char *rbuf = encode_record(r, &rlen);
    if (rbuf == NULL || (rlen & 0xff) != 0){
        fprintf(stderr, "encode_record() failed with %d\n", rlen);
        if (rbuf != NULL) free(rbuf);
        goto SET_FAIL; 
    }

    pthread_mutex_lock(&bc->buffer_lock);
    // record maybe larger than buffer
    if (bc->wbuf_curr_pos + rlen > bc->wbuf_size) {
        pthread_mutex_unlock(&bc->buffer_lock);
        bc_flush(bc, 0, 0);
        pthread_mutex_lock(&bc->buffer_lock);
        
        while (rlen > bc->wbuf_size) {
            bc->wbuf_size *= 2;
            free(bc->write_buffer);
            bc->write_buffer = malloc(bc->wbuf_size);
        }
        if (bc->wbuf_start_pos + bc->wbuf_size > MAX_BUCKET_SIZE) {
            bc_rotate(bc);
        }
    }
    memcpy(bc->write_buffer + bc->wbuf_curr_pos, rbuf, rlen);
    int pos = (bc->wbuf_start_pos + bc->wbuf_curr_pos) | bc->curr;
    bc->wbuf_curr_pos += rlen;
    pthread_mutex_unlock(&bc->buffer_lock);
   
    ht_add(bc->tree, key, pos, hash, ver);
    ht_add(bc->curr_tree, key, pos, hash, ver);
    suc = true;
    free(rbuf);
    free_record(r);

SET_FAIL:
    pthread_mutex_unlock(&bc->write_lock);
    if (it != NULL) free(it);
    return suc;
}

bool bc_delete(Bitcask *bc, const char* key)
{
    return bc_set(bc, key, "", 0, 0, -1);
}

uint16_t bc_get_hash(Bitcask *bc, const char * pos, int *count)
{
    return ht_get_hash(bc->tree, pos, count);
}

char* bc_list(Bitcask *bc, const char* pos, const char* prefix)
{
    return ht_list(bc->tree, pos, prefix);
}

uint32_t   bc_count(Bitcask *bc, uint32_t* curr)
{
    uint32_t total = 0;
    ht_get_hash(bc->tree, "@", &total);
    if (NULL != curr && NULL != bc->curr_tree) {
        ht_get_hash(bc->curr_tree, "@", curr);
    }
    return total;
}

void bc_stat(Bitcask *bc, uint64_t *bytes)
{
    if (bytes != NULL) {
        *bytes = bc->bytes;
    }
}
