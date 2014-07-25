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


const int PADDING = 256;
const int32_t COMPRESS_FLAG = 0x00010000;
const int32_t CLIENT_COMPRESS_FLAG = 0x00000010;
const float COMPRESS_RATIO_LIMIT = 0.7;
const int TRY_COMPRESS_SIZE = 1024 * 10;

static inline bool bad_kv_size(int ksz, int vsz)
{
    if (ksz < 0 || ksz > MAX_KEY_LEN || vsz < 0 || vsz > 50 * 1024 * 1024)
    {
        log_error("invalid ksz=: %d, vsz=%d", ksz, vsz);
        return true;
    }
    return false; 
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

DataRecord* decode_record(char* buf, uint32_t size, bool decomp)
{
    DataRecord *r = (DataRecord *) (buf - sizeof(char*));
    int ksz = r->ksz, vsz = r->vsz;
    if (bad_kv_size(ksz, vsz))
        return NULL;

    unsigned int need = sizeof(DataRecord) - sizeof(char*) + ksz + vsz;
    if (size < need)
    {
        log_error("not enough data in buffer: %d < %d", size, need);
        return NULL;
    }
    uint32_t crc = crc32(0, (unsigned char*)buf + sizeof(uint32_t),  need - sizeof(uint32_t));
    if (r->crc != crc)
    {
        log_error("CRC checksum failed");
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


DataRecord* read_record(FILE *f, bool decomp)
{
    DataRecord *r = (DataRecord*) safe_malloc(PADDING + sizeof(char*));
    r->value = NULL;

    if (fread(&r->crc, 1, PADDING, f) != PADDING)
    {
        log_error("read record faied");
        goto READ_END;
    }

    int ksz = r->ksz, vsz = r->vsz;

    if (bad_kv_size(ksz, vsz))
        goto READ_END;

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
            log_error("read record %s faied: %d < %d @%lld", r->key, ret, need, (long long int)ftello(f));
            goto READ_END;
        }
    }
    r->key[ksz] = 0; // c str

    uint32_t crc = crc32(0, (unsigned char*)(&r->tstamp),
                         sizeof(DataRecord) - sizeof(char*) - sizeof(uint32_t) + ksz);
    crc = crc32(crc, (unsigned char*)r->value, vsz);
    if (crc != crc_old)
    {
        log_error("%s @%lld crc32 check failed %d != %d", r->key, (long long int)ftello(f), crc, r->crc);
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

DataRecord* fast_read_record(int fd, off_t offset, bool decomp)
{
    DataRecord *r = (DataRecord*) safe_malloc(PADDING + sizeof(char*));
    r->value = NULL;

    if (pread(fd, &r->crc, PADDING, offset) != PADDING)
    {
        log_error("read record faied");
        goto READ_END;
    }

    int ksz = r->ksz, vsz = r->vsz;

    if (bad_kv_size(ksz, vsz))
        goto READ_END;

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
            log_error("read record %s faied: %d < %d @%lld", r->key, ret, need,(long long int) offset);
            goto READ_END;
        }
    }
    r->key[ksz] = 0; // c str

    uint32_t crc = crc32(0, (unsigned char*)(&r->tstamp),
                         sizeof(DataRecord) - sizeof(char*) - sizeof(uint32_t) + ksz);
    crc = crc32(crc, (unsigned char*)r->value, vsz);
    if (crc != crc_old)
    {
        log_error("%s @%lld crc32 check failed %d != %d", r->key, (long long int)offset, crc, r->crc);
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
    int broken = 0;
    size_t last_advise = 0;
    while (p < end)
    {
        DataRecord *r = decode_record(p, end-p, false);

        if (r != NULL)
        {
            uint32_t pos = p - f->addr;
            p += record_length(r);
            r = decompress_record(r);
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
        }
        else
        {
            broken ++;
            if (broken > 40960)   // 10M
            {
                log_error("unexpected broken data in %s at %ld", path, p - f->addr - broken * PADDING);
                break;
            }
            p += PADDING;
        }
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
    int broken = 0;
    size_t last_advise = 0;
    while (p < end)
    {
        DataRecord *r = decode_record(p, end-p, false);
        if (r != NULL)
        {
            if (r->tstamp >= before )
            {
                break;
            }
            uint32_t pos = p - f->addr;
            p += record_length(r);
            r = decompress_record(r);
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
        }
        else
        {
            broken ++;
            if (broken > 40960)   // 10M
            {
                log_error("unexpected broken data in %s at %ld", path, p - f->addr - broken * PADDING);
                break;
            }
            p += PADDING;
        }
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
        bool skipped, bool isnewfile, uint32_t *deleted_bytes)
{
    int err = -1; 

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

    uint32_t old_srcdata_size = f->size, old_dstdata_size = 0;
    char tmp[MAX_PATH_LEN] = "";
    uint32_t hint_used = 0, hint_size = 0;
    if (!isnewfile)
    {
        new_df = fopen(lastdata, "ab");
        old_dstdata_size = ftello(new_df);

        if (old_dstdata_size > 0)
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
    int nrecord = 0, deleted = 0, broken = 0;
    char *p = f->addr, *end = f->addr + f->size;
    size_t last_advise = 0;
    while (p < end)
    {
        DataRecord *r = decode_record(p, end-p, false);
        if (r == NULL)
        {
            broken ++;
            if (broken > 40960)   // 10M
            {
                // TODO: delete broken keys from htree
                log_error("unexpected broken data in %s at %ld", path, p - f->addr - broken * PADDING);
                break;
            }
            p += PADDING;
            continue;
        }
        nrecord++;
        Item *it = ht_get2(tree, r->key, r->ksz);
        uint32_t pos = p - f->addr;
        if (it && it->pos  == (pos | bucket) && (it->ver > 0 || skipped))
        {
            uint32_t new_pos = ftello(new_df);
            if (new_pos + record_length(r) > max_data_size)
            {
                if (last_bucket == bucket)
                {
                    log_warn("Bug: optimize %s into  tmp %s overflow, delete it!", path, tmp);
                }
                else 
                {
                    log_warn("optimize %s into %s overflow, ftruncate to %u", path, lastdata, old_dstdata_size);
                    fflush(new_df);  
                    if ( 0 != ftruncate(fileno(new_df), old_dstdata_size))
                    {
                        log_error("ftruncate failed for  %s old size = %u", path, old_dstdata_size);
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

            if (write_record(new_df, r) != 0)
            {
                log_error("write error: %s -> %d, old dst data size = %u", path, last_bucket, old_dstdata_size);
                free(it);
                free_record(r);
                goto  OPT_FAIL;
            }
        }
        else
        {
            if (it && it->pos == (pos | bucket) && it->ver < 0)
                ht_add2(cur_tree, r->key, r->ksz, 0, it->hash, it->ver);
            deleted ++;
        }
        if (it) free(it);
        p += record_length(r);
        free_record(r);

        mfile_dontneed(f, pos, &last_advise);
    }
    fseeko(new_df, 0L, SEEK_END);
    *deleted_bytes = f->size - (ftello(new_df) - old_dstdata_size);

    close_mfile(f);
    fclose(new_df);

    ht_visit(cur_tree, update_items, tree);
    ht_destroy(cur_tree);

    mgr_unlink(path);
    if (isnewfile)
        mgr_rename(tmp, lastdata);

    if (last_bucket != bucket)
        mgr_unlink(hintpath);
    write_hint_file(hintdata, hint_used, lasthint_real);
    free(hintdata);

    log_notice("optimize %s -> %d (%u B) complete, %d/%d records deleted, %u/%u bytes released, %d broken",
                       path,  last_bucket, old_dstdata_size, deleted, nrecord, *deleted_bytes, old_srcdata_size, broken);
    return 0;

OPT_FAIL:
    log_notice("optimize %s -> %d (%u B) failed,  %d/%d records deleted,  %u/%u bytes released, %d broken, err = %d",
            path, last_bucket, old_dstdata_size, deleted, nrecord, *deleted_bytes, old_srcdata_size, broken, err);
    if (hintdata) free(hintdata);
    if (cur_tree)  ht_destroy(cur_tree);
    if (f) close_mfile(f);
    if (new_df) fclose(new_df);
    if (isnewfile) mgr_unlink(tmp);
    return err;
}
