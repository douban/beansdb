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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "record.h"
#include "hint.h"
#include "crc32.c"
#include "diskmgr.h"
#include "quicklz.h"
#include "fnv1a.h"

#include "mfile.h"
#include "util.h"
#include "const.h"
#include "log.h"
#include "time.h"
#ifndef CLOCK_MONOTONIC
#include "clock_gettime_stub.c"
#endif


const int PADDING = 256;
const int32_t COMPRESS_FLAG = 0x00010000;
const int32_t CLIENT_COMPRESS_FLAG = 0x00000010;
const float COMPRESS_RATIO_LIMIT = 0.7;
const int TRY_COMPRESS_SIZE = 1024 * 10;

static inline bool bad_kv_size(uint32_t ksz, uint32_t vsz)
{
    return ((ksz == 0 || ksz > MAX_KEY_LEN)|| vsz > MAX_VALUE_LEN);
}

uint32_t gen_hash(char *buf, int len)
{
    uint32_t hash = len * 97;
    if (len <= 1024)
    {
        hash += fnv1a(buf, len);
    }
    else
    {
        hash += fnv1a(buf, 512);
        hash *= 97;
        hash += fnv1a(buf + len - 512, 512);
    }
    return hash;
}

int record_length(DataRecord *r)
{
    size_t n = sizeof(DataRecord) - sizeof(char*) + r->ksz + r->vsz;
    /*
    if (n % PADDING != 0)
    {
        n += PADDING - (n % PADDING);
    }
    */
    return (n / PADDING + (int)!!(n % PADDING)) * PADDING;
}

char* record_value(DataRecord *r)
{
    char *res = r->value;
    if (res == r->key + r->ksz + 1)
    {
        // value was alloced in record
        res = (char*)safe_malloc(r->vsz);
        memcpy(res, r->value, r->vsz); // safe
    }
    return res;
}

void free_record(DataRecord *r)
{
    if (r == NULL) return;
    if (r->value != NULL && r->free_value) free(r->value);
    free(r);
}

void compress_record(DataRecord *r)
{
    if (r->flag & COMPRESS_FLAG) return;
    int ksz = r->ksz, vsz = r->vsz;
    int n = sizeof(DataRecord) - sizeof(char*) + ksz + vsz;
    if (n > PADDING && (r->flag & (COMPRESS_FLAG|CLIENT_COMPRESS_FLAG)) == 0)
    {
        char *wbuf = (char*)try_malloc(QLZ_SCRATCH_COMPRESS);
        char *v = (char*)try_malloc(vsz + 400);
        if (wbuf == NULL || v == NULL) return ;
        int try_size = vsz > TRY_COMPRESS_SIZE ? TRY_COMPRESS_SIZE : vsz;
        int vsize = qlz_compress(r->value, v, try_size, wbuf);
        if (try_size < vsz && vsize < try_size * COMPRESS_RATIO_LIMIT)
        {
            try_size = vsz;
            vsize = qlz_compress(r->value, v, try_size, wbuf);
        }
        free(wbuf);

        if (vsize > try_size * COMPRESS_RATIO_LIMIT || try_size < vsz)
        {
            free(v);
            return;
        }

        if (r->free_value)
        {
            free(r->value);
        }
        r->value = v;
        r->free_value = true;
        r->vsz = vsize;
        r->flag |= COMPRESS_FLAG;
    }
}

DataRecord* decompress_record(DataRecord *r)
{
    if (r->flag & COMPRESS_FLAG)
    {
        char scratch[QLZ_SCRATCH_DECOMPRESS];
        unsigned int csize = qlz_size_compressed(r->value);
        if (csize != r->vsz)
        {
            log_error("broken compressed data: %d != %d, flag=%x", csize, r->vsz, r->flag);
            goto DECOMP_END;
        }
        unsigned int size = qlz_size_decompressed(r->value);
        char *v = (char*)safe_malloc(size);
        unsigned int ret = qlz_decompress(r->value, v, scratch);
        if (ret != size)
        {
            log_error("decompress %s failed: %d != %d", r->key, ret, size);
            goto DECOMP_END;
        }
        if (r->free_value)
        {
            free(r->value);
        }
        r->value = v;
        r->free_value = true;
        r->vsz = size;
        r->flag &= ~COMPRESS_FLAG;
    }
    return r;

DECOMP_END:
    free_record(r);
    return NULL;
}

DataRecord* decode_record(char* buf, uint32_t size, bool decomp, const char* path, uint32_t pos, const char* key)
{
    DataRecord *r = (DataRecord *) (buf - sizeof(char*));
    uint32_t ksz = r->ksz, vsz = r->vsz;
    if (bad_kv_size(ksz, vsz))
    {
        log_error("invalid ksz=%u, vsz=%u, %s @%u, key = (%s)", ksz, vsz, path, pos, key);
        return NULL;
    }


    unsigned int need = sizeof(DataRecord) - sizeof(char*) + ksz + vsz;
    if (size < need)
    {
        log_error("not enough data in buffer %d < %d, %s @%u,  key = (%s) ", size, need, path, pos, key);
        return NULL;
    }
    uint32_t crc = crc32(0, (unsigned char*)buf + sizeof(uint32_t),  need - sizeof(uint32_t));
    if (r->crc != crc)
    {
        log_error("CHECKSUM %u != %u, %s @%u, get (%s) got (%s)", crc, r->crc,  path, pos, key, r->key);
        return NULL;
    }

    DataRecord *r2 = (DataRecord *)safe_malloc(need + 1 + sizeof(char*));
    memcpy(&r2->crc, &r->crc, sizeof(DataRecord) - sizeof(char*) + ksz); // safe
    r2->key[ksz] = 0; // c str
    r2->free_value = false;
    r2->value = r2->key + ksz + 1;
    memcpy(r2->value, r->key + ksz, vsz); // safe

    if (decomp)
    {
        r2 = decompress_record(r2);
    }
    return r2;
}

static inline DataRecord* scan_record(char* begin, char* end,  char** curr,
        const char* path, int* num_broken_total)
{
    int num_broken_curr = 0;
    while (*curr <  end)
    {
        char *p = *curr;
        DataRecord *r = decode_record(p, end-p, false,  path, p - begin, "nokey");
        if (r != NULL)
        {
            if (num_broken_curr > 0)
            {
                log_error("END_BROKEN in %s after %d PADDING, total %d", path, num_broken_curr, *num_broken_total);
                num_broken_curr = 0;
            }
            return r;
        }
        else
        {
            if (num_broken_curr == 0)
            {
                log_error("START_BROKEN in %s at %ld", path, p - begin);
            }

            num_broken_curr++;
            (*num_broken_total)++;
            if (num_broken_curr > 40960)   // 10M
            {
                // TODO: delete broken keys from htree
                log_error("GIVEUP_BROKEN in %s after %d PADDING, total %d", path, num_broken_curr, *num_broken_total);
                break;
            }
            *curr += PADDING;
        }
    }
    if (*curr >= end && num_broken_curr > 0)
    {
        log_error("FILE_END_BROKEN in %s after %d PADDING, total %d", path, num_broken_curr, *num_broken_total);
    }
    return NULL;
}



DataRecord* read_record(FILE *f, bool decomp, const char* path, const char* key)
{
    DataRecord *r = (DataRecord*) safe_malloc(PADDING + sizeof(char*));
    r->value = NULL;

    if (fread(&r->crc, 1, PADDING, f) != PADDING)
    {
        log_error("read file fail, %s @%lld, key = (%s)",  path, (long long int)ftello(f), key);
        goto READ_END;
    }

    uint32_t ksz = r->ksz, vsz = r->vsz;

    if (bad_kv_size(ksz, vsz))
    {
        goto READ_END;
    }

    uint32_t crc_old = r->crc;
    int read_size = PADDING - (sizeof(DataRecord) - sizeof(char*)) - ksz;
    if (vsz < read_size)
    {
        r->value = r->key + ksz + 1;
        r->free_value = false;
        memmove(r->value, r->key + ksz, vsz);
    }
    else
    {
        r->value = (char*)safe_malloc(vsz);
        r->free_value = true;
        safe_memcpy(r->value, vsz, r->key + ksz, read_size);
        int need = vsz - read_size;
        int ret = 0;
        if (need > 0 && need != (ret=fread(r->value + read_size, 1, need, f)))
        {
            r->key[ksz] = 0; // c str
            log_error("PREAD %d < %d, %s @%lld, key = (%s)", ret, need, path, (long long int)ftello(f), key);
            goto READ_END;
        }
    }
    r->key[ksz] = 0; // c str

    uint32_t crc = crc32(0, (unsigned char*)(&r->tstamp),
                         sizeof(DataRecord) - sizeof(char*) - sizeof(uint32_t) + ksz);
    crc = crc32(crc, (unsigned char*)r->value, vsz);
    if (crc != crc_old)
    {
        log_error("CHECKSUM %u != %u, %s @%lld, get key (%s) got(%s)", crc, r->crc, path, (long long int)ftello(f), key, r->key);
        goto READ_END;
    }

    if (decomp)
    {
        r = decompress_record(r);
    }
    return r;

READ_END:
    free_record(r);
    return NULL;
}

DataRecord* fast_read_record(int fd, off_t offset, bool decomp, const char* path, const char* key)
{
    DataRecord *r = (DataRecord*) safe_malloc(PADDING + sizeof(char*));
    r->value = NULL;

    if (pread(fd, &r->crc, PADDING, offset) != PADDING)
    {
        log_error("read file fail, %s @%lld, file size = %lld, key = %s",  path, (long long)offset, (long long)lseek(fd, 0L, SEEK_END), key);
        goto READ_END;
    }

    uint32_t ksz = r->ksz, vsz = r->vsz;

    if (bad_kv_size(ksz, vsz))
    {
        log_error("invalid ksz=%u, vsz=%u, %s @%lld, key = (%s)", ksz, vsz, path, (long long)offset, key);
        goto READ_END;
    }

    uint32_t crc_old = r->crc;
    int read_size = PADDING - (sizeof(DataRecord) - sizeof(char*)) - ksz;
    if (vsz < read_size)
    {
        r->value = r->key + ksz + 1;
        r->free_value = false;
        memmove(r->value, r->key + ksz, vsz);
    }
    else
    {
        r->value = (char*)safe_malloc(vsz);
        r->free_value = true;
        safe_memcpy(r->value, vsz, r->key + ksz, read_size);
        int need = vsz - read_size;
        int ret = 0;
        if (need > 0 && need != (ret=pread(fd, r->value + read_size, need, offset+PADDING)))
        {
            r->key[ksz] = 0; // c str
            log_error("PREAD %d < %d, %s @%lld, get key (%s) got(%s)", ret, need, path, (long long int) offset, key, r->key);
            goto READ_END;
        }
    }
    r->key[ksz] = 0; // c str

    uint32_t crc = crc32(0, (unsigned char*)(&r->tstamp),
                         sizeof(DataRecord) - sizeof(char*) - sizeof(uint32_t) + ksz);
    crc = crc32(crc, (unsigned char*)r->value, vsz);
    if (crc != crc_old)
    {
        log_error("CHECKSUM %u != %u, %s @%lld, get key (%s) got(%s)", crc, r->crc, path, (long long int)offset, key, r->key);
        goto READ_END;
    }

    if (decomp)
    {
        r = decompress_record(r);
    }
    return r;

READ_END:
    free_record(r);
    return NULL;
}

char* encode_record(DataRecord *r, unsigned int *size)
{
    compress_record(r);

    unsigned int m, n;
    int ksz = r->ksz, vsz = r->vsz;
    int hs = sizeof(char*); // over header
    m = n = sizeof(DataRecord) - hs + ksz + vsz;
    if (n % PADDING != 0)
    {
        m += PADDING - (n % PADDING);
    }

    char *buf = (char*)safe_malloc(m);

    DataRecord *data = (DataRecord*)(buf - hs);
    memcpy(&data->crc, &r->crc, sizeof(DataRecord) - hs); // safe
    memcpy(data->key, r->key, ksz); // safe
    memcpy(data->key + ksz, r->value, vsz); // safe
    memset(buf + n, 0, m - n);
    data->crc = crc32(0, (unsigned char*)&data->tstamp, n - sizeof(uint32_t));

    *size = m;
    return buf;
}

int write_record(FILE *f, DataRecord *r)
{
    unsigned int size;
    char *data = encode_record(r, &size);
    if (fwrite(data, 1, size, f) < size)
    {
        log_error("write %d byte failed", size);
        free(data);
        return -1;
    }
    free(data);
    return 0;
}


void scanDataFile(HTree* tree, int bucket, const char* path, const char* hintpath)
{
    MFile *f = open_mfile(path);
    if (f == NULL) return;

    log_warn("scan datafile %s", path);
    HTree *cur_tree = ht_new(0, 0);
    char *p = f->addr, *end = f->addr + f->size;
    int num_broken_total = 0;
    size_t last_advise = 0;
    while (p < end)
    {
        DataRecord *r = scan_record(f->addr, end, &p, path, &num_broken_total);
        if (r == NULL)
            break;
        uint32_t pos = p - f->addr;
        p += record_length(r);
        r = decompress_record(r);
        if (r == NULL)
        {
            log_error("decompress_record fail, %s @%u size = %ld", path, pos, p - (pos + f->addr));
            continue;
        }
        uint16_t hash = gen_hash(r->value, r->vsz);
        if (r->version > 0)
        {
            ht_add2(tree, r->key, r->ksz, pos | bucket, hash, r->version);
        }
        else
        {
            ht_remove2(tree, r->key, r->ksz);
        }
        ht_add2(cur_tree, r->key, r->ksz, pos | bucket, hash, r->version);
        free_record(r);
        mfile_dontneed(f, p - f->addr, &last_advise);
    }
    close_mfile(f);
    build_hint(cur_tree, hintpath);
}

void scanDataFileBefore(HTree* tree, int bucket, const char* path, time_t before)
{
    MFile *f = open_mfile(path);
    if (f == NULL) return;

    log_error("scan datafile %s before %ld", path, before);
    char *p = f->addr, *end = f->addr + f->size;
    int num_broken_total = 0;
    size_t last_advise = 0;
    while (p < end)
    {
        DataRecord *r = scan_record(f->addr, end, &p, path, &num_broken_total);
        if (r == NULL)
            break;
        if (r->tstamp >= before)
            break;
        uint32_t pos = p - f->addr;
        p += record_length(r);
        r = decompress_record(r);
        if (r == NULL)
        {
            log_error("decompress_record fail, %s @%u size = %ld", path, pos, p - (pos + f->addr));
            continue;
        }
        /*uint16_t hash = gen_hash(r->value, r->vsz);*/
        if (r->version > 0)
        {
            uint16_t hash = gen_hash(r->value, r->vsz);
            ht_add2(tree, r->key, r->ksz, pos | bucket, hash, r->version);
        }
        else
        {
            ht_remove2(tree, r->key, r->ksz);
        }
        free_record(r);
        mfile_dontneed(f, p - f->addr, &last_advise);
    }
    close_mfile(f);
}

// update pos in HTree
void update_items(Item *it, void *args)
{
    HTree *tree = (HTree*) args;
    Item *p = ht_get(tree, it->key);
    if (p)
    {
        if (it->pos != p->pos && it->ver == p->ver)
        {
            if (it->ver > 0)
            {
                ht_add(tree, p->key, it->pos, p->hash, p->ver);
            }
            else
            {
                ht_remove(tree, p->key);
            }
        }
        free(p);
    }
    else
    {
        ht_add(tree, it->key, it->pos, it->hash, it->ver);
    }
}
int optimizeDataFile(HTree* tree, Mgr* mgr, int bucket, const char* path, const char* hintpath, 
        int last_bucket, const char *lastdata, const char *lasthint_real, uint32_t max_data_size, 
        bool skipped, bool use_tmp, uint32_t *deleted_bytes)
{

    struct timespec opt_start, opt_end, update_start, update_end;
    clock_gettime(CLOCK_MONOTONIC, &opt_start);

    int err = -1; 
    log_notice("begin optimize %s -> %s, use_tmp= %s", path, lastdata, use_tmp?"true":"false");

//to destroy:
    FILE *new_df = NULL;
    HTree *cur_tree = NULL;
    char *hintdata = NULL;
    MFile *f = open_mfile(path);
    if (f == NULL) 
    {
          err = -1;
          goto  OPT_FAIL;
    }

    uint32_t old_srcdata_size = f->size;
    uint32_t new_df_orig_size =  0;
    char tmp[MAX_PATH_LEN] = "";
    uint32_t hint_used = 0, hint_size = 0;

    if (!use_tmp)
    {
        new_df = fopen(lastdata, "ab");
        new_df_orig_size = ftello(new_df);

        int end = new_df_orig_size % 256;
        if (end != 0)
        {
            char bytes[256];
            int size = 256 - end;
            log_warn("size of %s is 0x%llx, add padding", lastdata, (long long)new_df_orig_size);
            if (fwrite(bytes, 1, size, new_df) < size)
            {
                log_error("write error when padding %s", lastdata);
                goto  OPT_FAIL;
            }
        }

        if (new_df_orig_size > 0)
        {
            HintFile *hint = open_hint(lasthint_real, NULL);
            if (hint == NULL)
            {
                log_error("open last hint file %s failed", lasthint_real);
                err = 1;
                goto  OPT_FAIL;
            }
            hint_size = hint->size * 2;
            if (hint_size < 4096) hint_size = 4096;
            hintdata = (char*)safe_malloc(hint_size);
            memcpy(hintdata, hint->buf, hint->size); // safe
            hint_used = hint->size;
            close_hint(hint);
        }
    }
    else
    {
        strcpy(tmp, lastdata);
        strcat(tmp, ".tmp");
        mgr_alloc(mgr, simple_basename(tmp));

        new_df = fopen(tmp, "wb");
        if (new_df == NULL)
        {
            log_error("open tmp datafile failed, %s", tmp);
            goto  OPT_FAIL;
        }
    }
    if (hintdata == NULL)
    {
        hint_size = 1<<20;
        hintdata = (char*)safe_malloc(hint_size);
    }

    cur_tree = ht_new(0, 0);
    int nrecord = 0, deleted = 0, broken = 0, released = 0;
    char *p = f->addr, *end = f->addr + f->size;
    char *newp = p;
    size_t last_advise = 0;
    while (p < end)
    {
        DataRecord *r = scan_record(f->addr, end, &p, path, &broken);
        if (r == NULL)
        {
            if (p < end)
                goto  OPT_FAIL;
            break;
        }

        newp = p + record_length(r);
        nrecord++;
        Item *it = ht_get2(tree, r->key, r->ksz);
        uint32_t pos = p - f->addr;
        if (it && it->pos  == (pos | bucket) && (it->ver > 0 || skipped))
        {
            uint32_t new_pos = ftello(new_df);
            if (new_pos + record_length(r) > max_data_size)
            {
                if (use_tmp)
                {
                    log_warn("Bug: optimize %s into tmp %s overflow", path, tmp);
                }
                else 
                {
                    log_warn("optimize %s into %s overflow, ftruncate to %u", path, lastdata, new_df_orig_size);
                    fflush(new_df);  
                    if ( 0 != ftruncate(fileno(new_df), new_df_orig_size))
                    {
                        log_error("ftruncate failed for  %s old size = %u", path, new_df_orig_size);
                    }
                    rewind(new_df);
                }
                err = 1;
                goto  OPT_FAIL;
            }

            uint16_t hash = it->hash;
            ht_add2(cur_tree, r->key, r->ksz, new_pos | last_bucket, hash, it->ver);
            // append record to hint file
            int hsize = sizeof(HintRecord) - NAME_IN_RECORD + r->ksz + 1;
            if (hint_used + hsize > hint_size)
            {
                hint_size *= 2;
                hintdata = (char*)safe_realloc(hintdata, hint_size);
            }
            HintRecord *hr = (HintRecord*)(hintdata + hint_used);
            hr->ksize = r->ksz;
            hr->pos = new_pos >> 8;
            hr->version = it->ver;
            hr->hash = hash;
            safe_memcpy(hr->key, hint_size - sizeof(uint32_t) -
                    sizeof(int32_t) - sizeof(uint16_t), r->key, r->ksz + 1);
            hint_used += hsize;

            r->version = it->ver;
            if (write_record(new_df, r) != 0)
            {
                log_error("write error: %s -> %d", path, last_bucket);
                free(it);
                free_record(r);
                goto  OPT_FAIL;
            }
        }
        else
        {
            if (it && it->pos == (pos | bucket) && it->ver < 0)
            {
                deleted ++;
                ht_add2(cur_tree, r->key, r->ksz, 0, it->hash, it->ver);
            }
            released++;
        }
        if (it) free(it);
        p = newp;
        free_record(r);

        mfile_dontneed(f, pos, &last_advise);
    }
    fseeko(new_df, 0L, SEEK_END);
    *deleted_bytes = f->size - (ftello(new_df) - new_df_orig_size);

    close_mfile(f);
    fclose(new_df);

    clock_gettime(CLOCK_MONOTONIC, &update_start);
    if (bucket == last_bucket)
    {
        ht_set_updating_bucket(tree, bucket, cur_tree);
        ht_visit2(cur_tree, update_items, tree);
        mgr_unlink(lastdata);
        mgr_rename(tmp, lastdata);
        ht_set_updating_bucket(tree, -1, NULL);
    }
    else 
    {
        if (use_tmp)
            mgr_rename(tmp, lastdata);
        ht_visit(cur_tree, update_items, tree);
        mgr_unlink(path);
    }
    clock_gettime(CLOCK_MONOTONIC, &update_end);

    ht_destroy(cur_tree);

    if (last_bucket != bucket)
        mgr_unlink(hintpath);
    write_hint_file(hintdata, hint_used, lasthint_real);
    free(hintdata);


    clock_gettime(CLOCK_MONOTONIC, &opt_end);
    float update_secs = (update_end.tv_sec - update_start.tv_sec) + (update_end.tv_nsec - update_start.tv_nsec) / 1e9;
    float opt_secs = (opt_end.tv_sec - opt_start.tv_sec) + (opt_end.tv_nsec - opt_start.tv_nsec) / 1e9;
    log_notice("optimize %s -> %d (%u B) complete, %d/%d records released, %d deleted, %u/%u bytes released, %d bytes broken, use %fs/%fs",
            path, last_bucket, (last_bucket == bucket) ? old_srcdata_size : new_df_orig_size, released, nrecord, deleted, *deleted_bytes, old_srcdata_size, broken, update_secs, opt_secs);
    return 0;

OPT_FAIL:
    log_notice("optimize %s -> %d (%u B) failed,   %d/%d records released, %d deleted, %u/%u bytes released, %d bytes broken, use %fs/%fs, err = %d",
            path, last_bucket, (last_bucket == bucket) ? old_srcdata_size : new_df_orig_size, released, nrecord, deleted, *deleted_bytes, old_srcdata_size, broken, update_secs, opt_secs, err);
    if (hintdata) free(hintdata);
    if (cur_tree)  ht_destroy(cur_tree);
    if (f) close_mfile(f);
    if (new_df) fclose(new_df);
    if (use_tmp) mgr_unlink(tmp);
    return err;
}
