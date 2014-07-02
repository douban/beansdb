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
 *      Hurricane Lee <hurricane1026@gmail.com>
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
#include <math.h>
#include <time.h>
#include <inttypes.h>

#include "bitcask.h"
#include "htree.h"
#include "record.h"
#include "diskmgr.h"
#include "hint.h"
#include "const.h"
#include "log.h"

/* unistd.h is here */
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#define MAX_BUCKET_COUNT 256

const uint32_t MAX_RECORD_SIZE = 50 << 20; // 50M
const uint32_t MAX_BUCKET_SIZE = (uint32_t)(4000 << 20); // 4G
const uint32_t WRITE_BUFFER_SIZE = 2 << 20; // 2M

const int SAVE_HTREE_LIMIT = 5;

const char DATA_FILE[] = "%03d.data";
const char HINT_FILE[] = "%03d.hint.qlz";
const char HTREE_FILE[] = "%03d.htree";

struct bitcask_t
{
    uint32_t depth, pos;
    time_t before;
    Mgr    *mgr;
    HTree  *tree, *curr_tree;
    int    last_snapshot;
    int    curr;
    uint64_t bytes, curr_bytes;
    char   *write_buffer;
    time_t last_flush_time;
    uint32_t    wbuf_size, wbuf_start_pos, wbuf_curr_pos;
    pthread_mutex_t flush_lock, buffer_lock, write_lock;
    int    optimize_flag;
};

Bitcask* bc_open(const char* path, int depth, int pos, time_t before)
{
    if (path == NULL || depth > 4) return NULL;
    if (0 != access(path, F_OK) && 0 != mkdir(path, 0750))
    {
        log_error("mkdir %s failed", path);
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
    Bitcask* bc = (Bitcask*)safe_malloc(sizeof(Bitcask));
    /*if (bc == NULL) return NULL;*/

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
    bc->write_buffer = (char*)safe_malloc(bc->wbuf_size);
    bc->last_flush_time = time(NULL);
    pthread_mutex_init(&bc->buffer_lock, NULL);
    pthread_mutex_init(&bc->write_lock, NULL);
    pthread_mutex_init(&bc->flush_lock, NULL);
    return bc;
}

static inline bool file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static inline char *gen_path(char *dst, int dst_size, const char *base, const char *fmt, int i)
{
    char name[16];
    safe_snprintf(name, 16, fmt, i);
    safe_snprintf(dst, dst_size , "%s/%s",  base, name);
    return dst;
}

static inline char *new_path(char *dst, int dst_size, Mgr *mgr, const char *fmt, int i)
{
    char *path = gen_path(dst, dst_size, mgr_base(mgr), fmt, i);
    if (!file_exists(dst))
    {
        char name[16];
        safe_snprintf(name, 16, fmt, i);
        safe_snprintf(path, dst_size, "%s/%s",  mgr_alloc(mgr, name), name);
        log_notice("mgr_alloc %s", path);
    }
    return path;
}

static void skip_empty_file(Bitcask* bc)
{
    int i, last=0;
    char opath[MAX_PATH_LEN], npath[MAX_PATH_LEN];

    const char* base = mgr_base(bc->mgr);
    for (i=0; i<MAX_BUCKET_COUNT; i++)
    {
        if (file_exists(gen_path(opath, MAX_PATH_LEN, base, DATA_FILE, i)))
        {
            if (i != last)
            {
                mgr_rename(opath, gen_path(npath, MAX_PATH_LEN, base, DATA_FILE, last));

                if (file_exists(gen_path(opath, MAX_PATH_LEN, base, HINT_FILE, i)))
                {
                    mgr_rename(opath, gen_path(npath, MAX_PATH_LEN, base, HINT_FILE, last));
                }

                mgr_unlink(gen_path(opath, MAX_PATH_LEN, base, HTREE_FILE, i));
            }
            ++last;
        }
    }
}

void bc_scan(Bitcask* bc)
{
    char datapath[MAX_PATH_LEN], hintpath[MAX_PATH_LEN];
    int i = 0;
    struct stat st, hst;

    skip_empty_file(bc);

    const char* base = mgr_base(bc->mgr);
    // load snapshot of htree
    for (i = MAX_BUCKET_COUNT - 1; i >= 0; --i)
    {
        if (stat(gen_path(datapath, MAX_PATH_LEN, base, HTREE_FILE, i), &st) == 0
                && stat(gen_path(hintpath, MAX_PATH_LEN, base, HINT_FILE, i), &hst) == 0
                && st.st_mtime >= hst.st_mtime
                && (bc->before == 0 || st.st_mtime < bc->before))
        {
            bc->tree = ht_open(bc->depth, bc->pos, datapath);
            if (bc->tree != NULL)
            {
                bc->last_snapshot = i;
                break;
            }
            else
            {
                log_error("open HTree from %s failed", datapath);
                mgr_unlink(datapath);
            }
        }
    }
    if (bc->tree == NULL)
    {
        bc->tree = ht_new(bc->depth, bc->pos);
    }

    for (i=0; i<MAX_BUCKET_COUNT; i++)
    {
        if (stat(gen_path(datapath, MAX_PATH_LEN, base, DATA_FILE, i), &st) != 0)
        {
            break;
        }
        bc->bytes += st.st_size;
        if (i <= bc->last_snapshot) continue;

        gen_path(hintpath, MAX_PATH_LEN, base, HINT_FILE, i);
        if (bc->before == 0)
        {
            if (0 == stat(hintpath, &st))
            {
                scanHintFile(bc->tree, i, hintpath, NULL);
            }
            else
            {
                scanDataFile(bc->tree, i, datapath,
                             new_path(hintpath, MAX_PATH_LEN, bc->mgr, HINT_FILE, i));
            }
        }
        else
        {
            if (0 == stat(hintpath, &st) &&
                    (st.st_mtime < bc->before || (0 == stat(datapath, &st) && st.st_mtime < bc->before)))
            {
                scanHintFile(bc->tree, i, hintpath, NULL);
            }
            else
            {
                scanDataFileBefore(bc->tree, i, datapath, bc->before);
            }
        }
    }

    if (i - bc->last_snapshot > SAVE_HTREE_LIMIT)
    {
        if (ht_save(bc->tree, new_path(datapath, MAX_PATH_LEN, bc->mgr, HTREE_FILE, i-1)) == 0)
        {
            char htreepath_tmp[MAX_PATH_LEN];
            mgr_unlink(gen_path(htreepath_tmp, MAX_PATH_LEN, base, HTREE_FILE, bc->last_snapshot));
            bc->last_snapshot = i-1;
        }
        else
        {
            log_error("save HTree to %s failed", datapath);
        }
    }

    bc->curr = i;
    if (i > 0)
    {
        log_notice("bitcask %x loaded, curr = %d", bc->pos , i);
    }
}

/*
 * bc_close() is not thread safe, should stop other threads before call it.
 * */
void bc_close(Bitcask *bc)
{
    char datapath[MAX_PATH_LEN], hintpath[MAX_PATH_LEN];

    if (bc->optimize_flag > 0)
    {
        bc->optimize_flag = 2;
        while (bc->optimize_flag > 0)
        {
            sleep(1);
        }
    }

    pthread_mutex_lock(&bc->write_lock);

    bc_flush(bc, 0, 0);

    if (NULL != bc->curr_tree)
    {
        if (bc->curr_bytes > 0)
        {
            build_hint(bc->curr_tree, new_path(hintpath, MAX_PATH_LEN, bc->mgr, HINT_FILE, bc->curr));
        }
        else
        {
            ht_destroy(bc->curr_tree);
        }
        bc->curr_tree = NULL;
    }

    if (bc->curr_bytes == 0) --(bc->curr);
    if (bc->curr - bc->last_snapshot >= SAVE_HTREE_LIMIT)
    {
        if (ht_save(bc->tree, new_path(datapath, MAX_PATH_LEN, bc->mgr, HTREE_FILE, bc->curr)) == 0)
        {
            mgr_unlink(gen_path(datapath, MAX_PATH_LEN, mgr_base(bc->mgr), HTREE_FILE, bc->last_snapshot));
        }
        else
        {
            log_error("save HTree to %s failed", datapath);
        }
    }
    ht_destroy(bc->tree);

    mgr_destroy(bc->mgr);
    free(bc->write_buffer);
    free(bc);
}

uint64_t data_file_size(Bitcask *bc, int bucket)
{
    struct stat st;
    char path[MAX_PATH_LEN];
    gen_path(path, MAX_PATH_LEN, mgr_base(bc->mgr), DATA_FILE, bucket);
    if (stat(path, &st) != 0) return 0;
    return st.st_size;
}


// update pos in HTree
struct update_args
{
    HTree *tree;
    uint32_t index;
};

static void update_item_pos(Item *it, void *_args)
{
    struct update_args *args = (struct update_args*)_args;
    HTree *tree = (HTree*) args->tree;
    Item *p = ht_get(tree, it->key);
    if (p)
    {
        if (it->pos == p->pos)
        {
            uint32_t npos = (it->pos & 0xffffff00) | args->index;
            ht_add(tree, p->key, npos, p->hash, p->ver);
        }
        free(p);
    }
}

int bc_optimize(Bitcask *bc, int limit)
{
    int i, total, last = -1;
    bc->optimize_flag = 1;
    const char *base = mgr_base(bc->mgr);
    char htreepath_tmp[MAX_PATH_LEN];
    // remove htree
    for (i=0; i < bc->curr; ++i)
    {
        mgr_unlink(gen_path(htreepath_tmp, MAX_PATH_LEN, base, HTREE_FILE, i));
    }
    bc->last_snapshot = -1;

    time_t limit_time = 0;
    if (limit > 3600 * 24 * 365 * 10)   // more than 10 years
    {
        limit_time = limit; // absolute time
    }
    else
    {
        limit_time = time(NULL) - limit; // relative time
    }

    struct stat st;
    bool skipped = false;
    for (i=0; i < bc->curr && bc->optimize_flag == 1; ++i)
    {
        char datapath[MAX_PATH_LEN], hintpath[MAX_PATH_LEN];
        gen_path(datapath, MAX_PATH_LEN, base, DATA_FILE, i);
        gen_path(hintpath, MAX_PATH_LEN, base, HINT_FILE, i);
        if (stat(datapath, &st) != 0)
        {
            continue; // skip empty file
        }
        // skip recent modified file
        if (st.st_mtime > limit_time)
        {
            skipped = true;

            ++last;
            if (last != i)   // rotate data file
            {
                char npath[MAX_PATH_LEN];
                gen_path(npath, MAX_PATH_LEN, base, DATA_FILE, last);
                if (symlink(datapath, npath) != 0)
                {
                    log_error("symlink failed: %s -> %s", datapath, npath);
                    last = i;
                    continue;
                }

                // update HTree to use new index
                if (stat(hintpath, &st) != 0)
                {
                    log_error("no hint file: %s, skip it", hintpath);
                    last = i;
                    continue;
                }
                HTree *tree = ht_new(bc->depth, bc->pos);
                scanHintFile(tree, i, hintpath, NULL);
                struct update_args args;
                args.tree = bc->tree;
                args.index = last;
                ht_visit(tree, update_item_pos, &args);
                ht_destroy(tree);

                unlink(npath);
                mgr_rename(datapath, npath);
                mgr_rename(hintpath, gen_path(npath, MAX_PATH_LEN, base, HINT_FILE, last));
            }
            continue;
        }

        int deleted = count_deleted_record(bc->tree, i, hintpath, &total);
        uint64_t curr_size = data_file_size(bc, i) * (total - deleted/2) / (total+1); // guess
        uint64_t last_size = last >= 0 ? data_file_size(bc, last) : -1;

        // last data file size
        uint32_t recoverd = 0;
        if (last == -1 || last_size + curr_size > MAX_BUCKET_SIZE)
        {
            ++last;
        }
        while (last < i)
        {
            char ldpath[MAX_PATH_LEN], lhpath[MAX_PATH_LEN];
            new_path(ldpath, MAX_PATH_LEN, bc->mgr, DATA_FILE, last);
            new_path(lhpath, MAX_PATH_LEN, bc->mgr, HINT_FILE, last);
            recoverd = optimizeDataFile(bc->tree, i, datapath, hintpath,
                                        skipped, MAX_BUCKET_SIZE, last, ldpath, lhpath);
            if (recoverd == 0)
            {
                ++last;
            }
            else
            {
                break;
            }
        }
        if (recoverd == 0)
        {
            // last == i
            recoverd = optimizeDataFile(bc->tree, i, datapath, hintpath,
                                        skipped, MAX_BUCKET_SIZE, last, NULL, NULL);
        }

        pthread_mutex_lock(&bc->buffer_lock);
        bc->bytes -= recoverd;
        pthread_mutex_unlock(&bc->buffer_lock);
    }

    // update pos of items in curr_tree
    pthread_mutex_lock(&bc->write_lock);
    pthread_mutex_lock(&bc->flush_lock);
    if (i == bc->curr && ++last < bc->curr)
    {
        char opath[MAX_PATH_LEN], npath[MAX_PATH_LEN];
        gen_path(opath, MAX_PATH_LEN, base, DATA_FILE, bc->curr);

        if (file_exists(opath))
        {
            gen_path(npath, MAX_PATH_LEN, base, DATA_FILE, last);
            if (symlink(opath, npath) != 0)
                log_error("symlink failed: %s -> %s", opath, npath);

            struct update_args args;
            args.tree = bc->tree;
            args.index = last;
            ht_visit(bc->curr_tree, update_item_pos, &args);

            unlink(npath);
            mgr_rename(opath, npath);
        }

        bc->curr = last;
    }
    pthread_mutex_unlock(&bc->flush_lock);
    pthread_mutex_unlock(&bc->write_lock);
    log_notice("bitcask %x optimization done, curr = %d", bc->pos, bc->curr);
    bc->optimize_flag = 0;
    return 0;
}

DataRecord* bc_get(Bitcask *bc, const char* key)
{
    Item *item = ht_get(bc->tree, key);
    if (NULL == item) return NULL;
    if (item->ver < 0)
    {
        free(item);
        return NULL;
    }

    uint32_t bucket = item->pos & 0xff;
    uint32_t pos = item->pos & 0xffffff00;
    if (bucket > (uint32_t)(bc->curr))
    {
        log_error("Bug: invalid bucket %d > %d, bitcask %x, key = %s", bucket, bc->curr, bc->pos, key);
        ht_remove(bc->tree, key);
        free(item);
        return NULL;
    }

    DataRecord* r = NULL;
    if (bucket == (uint32_t)(bc->curr))
    {
        pthread_mutex_lock(&bc->buffer_lock);
        if (bucket == (uint32_t)(bc->curr) && pos >= bc->wbuf_start_pos)
        {
            uint32_t p = pos - bc->wbuf_start_pos;
            r = decode_record(bc->write_buffer + p, bc->wbuf_curr_pos - p, true);
        }
        pthread_mutex_unlock(&bc->buffer_lock);

        if (r != NULL)
        {
            free(item);
            return r;
        }
    }

    char datapath[MAX_PATH_LEN];
    const char * base= mgr_base(bc->mgr);
    gen_path(datapath, MAX_PATH_LEN, base,  DATA_FILE, bucket);
    int fd = open(datapath, O_RDONLY);
    if (-1 == fd)
    {
        goto GET_END;
    }

    r = fast_read_record(fd, pos, true);
    if (NULL == r)
    {
        if (bc->optimize_flag == 0)
            log_error("Bug: get %s failed in %s %u %u", key, base, bucket, pos);
    }
    else
    {
        // check key
        if (strcmp(key, r->key) != 0)
        {
            if (bc->optimize_flag == 0)
                log_error("Bug: record %s is not expected %s in %u @ %u", r->key, key, bucket, pos);
            free_record(r);
            r = NULL;
        }
    }
GET_END:
    if (NULL == r && bc->optimize_flag == 0)
        ht_remove(bc->tree, key);
    if (fd != -1) close(fd);
    free(item);
    return r;
}

struct build_thread_args
{
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

void bc_rotate(Bitcask *bc)
{
    // build in new thread
    char hintpath[MAX_PATH_LEN];
    new_path(hintpath, MAX_PATH_LEN, bc->mgr, HINT_FILE, bc->curr);
    struct build_thread_args *args = (struct build_thread_args*)safe_malloc(
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

void bc_flush(Bitcask *bc, unsigned int limit, int flush_period)
{
    if (bc->curr >= MAX_BUCKET_COUNT)
    {
        log_error("reach max bucket count");
        exit(1);
    }

    pthread_mutex_lock(&bc->flush_lock);
    pthread_mutex_lock(&bc->buffer_lock);

    time_t now = time(NULL);
    if (bc->wbuf_curr_pos > limit * 1024 ||
            (now > bc->last_flush_time + flush_period && bc->wbuf_curr_pos > 0))
    {
        uint32_t size = bc->wbuf_curr_pos;
        char * tmp = (char*)safe_malloc(size);
        memcpy(tmp, bc->write_buffer, size); // safe
        pthread_mutex_unlock(&bc->buffer_lock);

        char buf[MAX_PATH_LEN];
        new_path(buf, MAX_PATH_LEN, bc->mgr, DATA_FILE, bc->curr);

        FILE *f = fopen(buf, "ab");
        if (f == NULL)
        {
            log_error("open file %s for flushing failed. exit!", buf);
            exit(1);
        }
        // check file size
        uint64_t last_pos = ftello(f);
        if (last_pos > 0 && last_pos != bc->wbuf_start_pos)
        {
            log_error("last pos not match: %"PRIu64" != %d in %s. exit!", last_pos, bc->wbuf_start_pos, buf);
            exit(1);
        }

        size_t n = fwrite(tmp, 1, size, f);
        if (n < size)
        {
            log_error("write failed: return %zu. exit!", n);
            exit(1);
        }
        free(tmp);
        fclose(f);
        bc->last_flush_time = now;

        pthread_mutex_lock(&bc->buffer_lock);
        bc->bytes += n;
        bc->curr_bytes += n;
        if (n < bc->wbuf_curr_pos)
        {
            memmove(bc->write_buffer, bc->write_buffer + n, bc->wbuf_curr_pos - n);
        }
        bc->wbuf_start_pos += n;
        bc->wbuf_curr_pos -= n;
        if (bc->wbuf_curr_pos == 0)
        {
            if (bc->wbuf_size < WRITE_BUFFER_SIZE)
            {
                bc->wbuf_size *= 2;
                free(bc->write_buffer);
                bc->write_buffer = (char*)safe_malloc(bc->wbuf_size);
            }
            else if (bc->wbuf_size > WRITE_BUFFER_SIZE * 2)
            {
                bc->wbuf_size = WRITE_BUFFER_SIZE;
                free(bc->write_buffer);
                bc->write_buffer = (char*)safe_malloc(bc->wbuf_size);
            }
        }

        if (bc->wbuf_start_pos + bc->wbuf_size > MAX_BUCKET_SIZE)
        {
            bc_rotate(bc);
        }
    }

    pthread_mutex_unlock(&bc->buffer_lock);
    pthread_mutex_unlock(&bc->flush_lock);
}

bool bc_set(Bitcask *bc, const char* key, char* value, size_t vlen, int flag, int version)
{
    if ((version < 0 && vlen > 0) || vlen > MAX_RECORD_SIZE)
    {
        log_error("invalid set cmd");
        return false;
    }

    bool suc = false;
    pthread_mutex_lock(&bc->write_lock);

    int oldv = 0, ver = version;
    Item *it = ht_get(bc->tree, key);
    if (it != NULL)
    {
        oldv = it->ver;
    }

    if (version == 0 && oldv > 0)  // replace
    {
        ver = oldv + 1;
    }
    else if (version == 0 && oldv <= 0)    // add
    {
        ver = -oldv + 1;
    }
    else if (version < 0 && oldv <= 0)     // delete, not exist
    {
        goto SET_FAIL;
    }
    else if (version == -1)     // delete
    {
        ver = - abs(oldv) - 1;
    }
    else if (abs(version) <= abs(oldv))     // sync
    {
        goto SET_FAIL;
    }
    else     // sync
    {
        ver = version;
    }

    uint16_t hash = 0;
    if (ver > 0) 
        gen_hash(value, vlen);

    if (NULL != it && hash == it->hash)
    {
        DataRecord *r = bc_get(bc, key);
        if (r != NULL && r->flag == flag && vlen  == r->vsz
                && memcmp(value, r->value, vlen) == 0)
        {
            if (version != 0)
            {
                // update version
                if ((it->pos & 0xff) == bc->curr)
                {
                    ht_add(bc->curr_tree, key, it->pos, it->hash, ver);
                }
                ht_add(bc->tree, key, it->pos, it->hash, ver);
            }
            suc = true;
            free_record(r);
            goto SET_FAIL;
        }
        if (r != NULL) free_record(r);
    }

    int klen = strlen(key);
    DataRecord *r = (DataRecord*)safe_malloc(sizeof(DataRecord) + klen);
    r->ksz = klen;
    memcpy(r->key, key, klen); // safe
    r->vsz = vlen;
    r->value = value;
    r->free_value = false;
    r->flag = flag;
    r->version = ver;
    r->tstamp = time(NULL);

    unsigned int rlen;
    char *rbuf = encode_record(r, &rlen);
    if (rbuf == NULL || (rlen & 0xff) != 0)
    {
        log_error("encode_record() failed with %d", rlen);
        if (rbuf != NULL) free(rbuf);
        goto SET_FAIL;
    }

    pthread_mutex_lock(&bc->buffer_lock);
    // record maybe larger than buffer
    if (bc->wbuf_curr_pos + rlen > bc->wbuf_size)
    {
        pthread_mutex_unlock(&bc->buffer_lock);
        bc_flush(bc, 0, 0);
        pthread_mutex_lock(&bc->buffer_lock);

        while (rlen > bc->wbuf_size)
        {
            bc->wbuf_size *= 2;
            free(bc->write_buffer);
            bc->write_buffer = (char*)safe_malloc(bc->wbuf_size);
        }
        if (bc->wbuf_start_pos + bc->wbuf_size > MAX_BUCKET_SIZE)
        {
            bc_rotate(bc);
        }
    }
    memcpy(bc->write_buffer + bc->wbuf_curr_pos, rbuf, rlen); // safe
    int pos = (bc->wbuf_start_pos + bc->wbuf_curr_pos) | bc->curr;
    bc->wbuf_curr_pos += rlen;
    pthread_mutex_unlock(&bc->buffer_lock);

    ht_add(bc->curr_tree, key, pos, hash, ver);
    ht_add(bc->tree, key, pos, hash, ver);
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

uint16_t bc_get_hash(Bitcask *bc, const char * pos, unsigned int *count)
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
    if (NULL != curr && NULL != bc->curr_tree)
    {
        ht_get_hash(bc->curr_tree, "@", curr);
    }
    return total;
}

void bc_stat(Bitcask *bc, uint64_t *bytes)
{
    if (bytes != NULL)
    {
        *bytes = bc->bytes;
    }
}
