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

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "record.h"
#include "hint.h"
#include "crc32.c"
#include "diskmgr.h"
#include "quicklz.h"
#include "fnv1a.h"

const int PADDING = 256;
const int32_t COMPRESS_FLAG = 0x00010000;
const int32_t CLIENT_COMPRESS_FLAG = 0x00000010;
const float COMPRESS_RATIO_LIMIT = 0.7;
const int TRY_COMPRESS_SIZE = 1024 * 10;

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
    if (n % PADDING != 0)
    {
        n += PADDING - (n % PADDING);
    }
    return n;
}

char* record_value(DataRecord *r)
{
    char *res = r->value;
    if (res == r->key + r->ksz + 1)
    {
        // value was alloced in record
        res = (char*)malloc(r->vsz);
        memcpy(res, r->value, r->vsz);
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
        char *wbuf = (char*)malloc(QLZ_SCRATCH_COMPRESS);
        char *v = (char*)malloc(vsz + 400);
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
        int csize = qlz_size_compressed(r->value);
        if (csize != r->vsz)
        {
            fprintf(stderr, "broken compressed data: %d != %d, flag=%x\n", csize, r->vsz, r->flag);
            goto DECOMP_END;
        }
        int size = qlz_size_decompressed(r->value);
        char *v = (char*)malloc(size);
        if (v == NULL)
        {
            fprintf(stderr, "malloc(%d)\n", size);
            goto DECOMP_END;
        }
        int ret = qlz_decompress(r->value, v, scratch);
        if (ret != size)
        {
            fprintf(stderr, "decompress %s failed: %d != %d\n", r->key, ret, size);
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
    if (ksz < 0 || ksz > 200 || vsz < 0 || vsz > 100 * 1024 * 1024)
    {
        //fprintf(stderr, "invalid ksz=: %d, vsz=%d\n", ksz, vsz);
        return NULL;
    }
    int need = sizeof(DataRecord) - sizeof(char*) + ksz + vsz;
    if (size < need)
    {
        fprintf(stderr, "not enough data in buffer: %d < %d\n", size, need);
        return NULL;
    }
    uint32_t crc = crc32(0, buf + sizeof(uint32_t),  need - sizeof(uint32_t));
    if (r->crc != crc)
    {
        fprintf(stderr, "CRC checksum failed\n");
        return NULL;
    }

    DataRecord *r2 = (DataRecord *) malloc(need + 1 + sizeof(char*));
    memcpy(&r2->crc, &r->crc, sizeof(DataRecord) - sizeof(char*) + ksz);
    r2->key[ksz] = 0; // c str
    r2->free_value = false;
    r2->value = r2->key + ksz + 1;
    memcpy(r2->value, r->key + ksz, vsz);

    if (decomp)
    {
        r2 = decompress_record(r2);
    }
    return r2;
}


DataRecord* read_record(FILE *f, bool decomp)
{
    DataRecord *r = (DataRecord*) malloc(PADDING + sizeof(char*));
    r->value = NULL;

    if (fread(&r->crc, 1, PADDING, f) != PADDING)
    {
        fprintf(stderr, "read record faied\n");
        goto READ_END;
    }

    int ksz = r->ksz, vsz = r->vsz;
    if (ksz < 0 || ksz > 200 || vsz < 0 || vsz > 100 * 1024 * 1024)
    {
        fprintf(stderr, "invalid ksz=: %d, vsz=%d\n", ksz, vsz);
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
        r->value = (char*)malloc(vsz);
        r->free_value = true;
        memcpy(r->value, r->key + ksz, read_size);
        int need = vsz - read_size;
        int ret = 0;
        if (need > 0 && need != (ret=fread(r->value + read_size, 1, need, f)))
        {
            r->key[ksz] = 0; // c str
            fprintf(stderr, "read record %s faied: %d < %d @%lld\n", r->key, ret, need, ftello(f));
            goto READ_END;
        }
    }
    r->key[ksz] = 0; // c str

    uint32_t crc = crc32(0, (char*)(&r->tstamp),
                         sizeof(DataRecord) - sizeof(char*) - sizeof(uint32_t) + ksz);
    crc = crc32(crc, r->value, vsz);
    if (crc != crc_old)
    {
        fprintf(stderr, "%s @%lld crc32 check failed %d != %d\n", r->key, ftello(f), crc, r->crc);
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
    DataRecord *r = (DataRecord*) malloc(PADDING + sizeof(char*));
    r->value = NULL;

    if (pread(fd, &r->crc, PADDING, offset) != PADDING)
    {
        fprintf(stderr, "read record faied\n");
        goto READ_END;
    }

    int ksz = r->ksz, vsz = r->vsz;
    if (ksz < 0 || ksz > 200 || vsz < 0 || vsz > 100 * 1024 * 1024)
    {
        fprintf(stderr, "invalid ksz=: %d, vsz=%d\n", ksz, vsz);
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
        r->value = (char*)malloc(vsz);
        r->free_value = true;
        memcpy(r->value, r->key + ksz, read_size);
        int need = vsz - read_size;
        int ret = 0;
        if (need > 0 && need != (ret=pread(fd, r->value + read_size, need, offset+PADDING)))
        {
            r->key[ksz] = 0; // c str
            fprintf(stderr, "read record %s faied: %d < %d @%lld\n", r->key, ret, need, offset);
            goto READ_END;
        }
    }
    r->key[ksz] = 0; // c str

    uint32_t crc = crc32(0, (char*)(&r->tstamp),
                         sizeof(DataRecord) - sizeof(char*) - sizeof(uint32_t) + ksz);
    crc = crc32(crc, r->value, vsz);
    if (crc != crc_old)
    {
        fprintf(stderr, "%s @%lld crc32 check failed %d != %d\n", r->key, offset, crc, r->crc);
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

char* encode_record(DataRecord *r, int *size)
{
    compress_record(r);

    int m, n;
    int ksz = r->ksz, vsz = r->vsz;
    int hs = sizeof(char*); // over header
    m = n = sizeof(DataRecord) - hs + ksz + vsz;
    if (n % PADDING != 0)
    {
        m += PADDING - (n % PADDING);
    }

    char *buf = (char*)malloc(m);

    DataRecord *data = (DataRecord*)(buf - hs);
    memcpy(&data->crc, &r->crc, sizeof(DataRecord)-hs);
    memcpy(data->key, r->key, ksz);
    memcpy(data->key + ksz, r->value, vsz);
    data->crc = crc32(0, (char*)&data->tstamp, n - sizeof(uint32_t));

    *size = m;
    return buf;
}

int write_record(FILE *f, DataRecord *r)
{
    int size;
    char *data = encode_record(r, &size);
    if (fwrite(data, 1, size, f) < size)
    {
        fprintf(stderr, "write %d byte failed\n", size);
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

    fprintf(stderr, "scan datafile %s\n", path);
    HTree *cur_tree = ht_new(0,0);
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
                fprintf(stderr, "unexpected broken data in %s at %ld\n", path, p - f->addr - broken * PADDING);
                break;
            }
            p += PADDING;
        }
        size_t pos = p - f->addr;
        if (pos - last_advise > (64<<20))
        {
            madvise(f->addr, pos, MADV_DONTNEED);
#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
            posix_fadvise(f->fd, 0, pos, POSIX_FADV_DONTNEED);
#endif
            last_advise = pos;
        }
    }

    close_mfile(f);
    build_hint(cur_tree, hintpath);
}

void scanDataFileBefore(HTree* tree, int bucket, const char* path, time_t before)
{
    MFile *f = open_mfile(path);
    if (f == NULL) return;

    fprintf(stderr, "scan datafile %s before %ld\n", path, before);
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
            uint16_t hash = gen_hash(r->value, r->vsz);
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
                fprintf(stderr, "unexpected broken data in %s at %ld\n", path, p - f->addr - broken * PADDING);
                break;
            }
            p += PADDING;
        }
        size_t pos = p - f->addr;
        if (pos - last_advise > (64<<20))
        {
            madvise(f->addr, pos, MADV_DONTNEED);
#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
            posix_fadvise(f->fd, 0, pos, POSIX_FADV_DONTNEED);
#endif
            last_advise = pos;
        }
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

uint32_t optimizeDataFile(HTree* tree, int bucket, const char* path, const char* hintpath,
                          bool skipped, uint32_t max_data_size, int last_bucket, const char *lastdata, const char *lasthint)
{
    MFile *f = open_mfile(path);
    if (f == NULL) return -1;

    FILE *new_df = NULL;
    char tmp[255], *hintdata = NULL;
    uint32_t hint_used=0, hint_size = 0, old_data_size=0;
    if (lastdata != NULL)
    {
        new_df = fopen(lastdata, "ab");
        old_data_size = ftello(new_df);

        if (old_data_size > 0)
        {
            HintFile *hint = open_hint(lasthint, NULL);
            if (hint == NULL)
            {
                fprintf(stderr, "open last hint file %s failed\n", lasthint);
                close_mfile(f);
                return 0;
            }
            hint_size = hint->size * 2;
            if (hint_size < 4096) hint_size = 4096;
            hintdata = (char*)malloc(hint_size);
            memcpy(hintdata, hint->buf, hint->size);
            hint_used = hint->size;
            close_hint(hint);
        }
        else
        {
            hint_size = 4096;
            hintdata = (char*)malloc(hint_size);
            hint_used = 0;
        }
    }
    else
    {
        sprintf(tmp, "%s.tmp", path);
        new_df = fopen(tmp, "wb");
        hintdata = (char*)malloc(1<<20);
        hint_size = 1<<20;
    }
    if (new_df == NULL)
    {
        fprintf(stderr, "open new datafile failed\n");
        close_mfile(f);
        return -1;
    }

    HTree *cur_tree = ht_new(0,0);
    int deleted = 0, broken = 0;
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
                fprintf(stderr, "unexpected broken data in %s at %ld\n", path, p - f->addr - broken * PADDING);
                break;
            }
            p += PADDING;
            continue;
        }
        Item *it = ht_get2(tree, r->key, r->ksz);
        uint32_t pos = p - f->addr;
        if (it && it->pos  == (pos | bucket) && (it->ver > 0 || skipped))
        {
            uint32_t new_pos = ftello(new_df);
            if (new_pos + record_length(r) > max_data_size)
            {
                fprintf(stderr, "optimize %s into %s failed\n", path, lastdata);
                free(hintdata);
                ht_destroy(cur_tree);
                close_mfile(f);
                ftruncate(new_df, old_data_size);
                fclose(new_df);
                return 0; // overflow
            }

            uint16_t hash = it->hash;
            ht_add2(cur_tree, r->key, r->ksz, new_pos | last_bucket, hash, it->ver);
            // append record to hint file
            int hsize = sizeof(HintRecord) - NAME_IN_RECORD + r->ksz + 1;
            if (hint_used + hsize > hint_size)
            {
                hint_size *= 2;
                hintdata = (char*)realloc(hintdata, hint_size);
            }
            HintRecord *hr = (HintRecord*)(hintdata + hint_used);
            hr->ksize = r->ksz;
            hr->pos = new_pos >> 8;
            hr->version = it->ver;
            hr->hash = hash;
            memcpy(hr->key, r->key, r->ksz + 1);
            hint_used += hsize;

            if (write_record(new_df, r) != 0)
            {
                fprintf(stderr, "write error: %s\n", path);
                free(hintdata);
                ht_destroy(cur_tree);
                close_mfile(f);
                fclose(new_df);
                return -1;
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

        if (pos - last_advise > (64<<20))
        {
            madvise(f->addr, pos, MADV_DONTNEED);
#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
            posix_fadvise(f->fd, 0, pos, POSIX_FADV_DONTNEED);
#endif
            last_advise = pos;
        }
    }
    uint32_t deleted_bytes = f->size - (ftello(new_df) - old_data_size);

    close_mfile(f);
    fclose(new_df);

    ht_visit(cur_tree, update_items, tree);
    ht_destroy(cur_tree);

    mgr_unlink(path);
    if (lastdata == NULL)
        mgr_rename(tmp, path);

    mgr_unlink(hintpath);
    write_hint_file(hintdata, hint_used, lasthint ? lasthint : hintpath);
    free(hintdata);

    fprintf(stderr, "optimize %s complete, %d records deleted, %u bytes came back\n",
            path, deleted, deleted_bytes);
    return deleted_bytes;
}
