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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "record.h"
#include "hint.h"
#include "crc32.c"
#include "quicklz.h"
//#include "fnv1a.h"

const int PADDING = 256;
const int32_t COMPRESS_FLAG = 0x00010000;
const int32_t CLIENT_COMPRESS_FLAG = 0x00000010;
const float COMPRESS_RATIO_LIMIT = 0.7;
const int TRY_COMPRESS_SIZE = 1024 * 10;

uint32_t gen_hash(char *buf, int len)
{
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

int record_length(DataRecord *r)
{
    size_t n = sizeof(DataRecord) - sizeof(char*) + r->ksz + r->vsz;
    if (n % PADDING != 0) {
        n += PADDING - (n % PADDING);
    }
    return n;
}

char* record_value(DataRecord *r)
{
    char *res = r->value;
    if (res == r->key + r->ksz + 1) {
        // value was alloced in record
        res = malloc(r->vsz);
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
    if (n > PADDING && (r->flag & (COMPRESS_FLAG|CLIENT_COMPRESS_FLAG)) == 0) {
        char *wbuf = malloc(QLZ_SCRATCH_COMPRESS);
        char *v = malloc(vsz + 400);
        if (wbuf == NULL || v == NULL) return ;
        int try_size = vsz > TRY_COMPRESS_SIZE ? TRY_COMPRESS_SIZE : vsz; 
        int vsize = qlz_compress(r->value, v, try_size, wbuf);
        if (try_size < vsz && vsize < try_size * COMPRESS_RATIO_LIMIT){
            try_size = vsz;
            vsize = qlz_compress(r->value, v, try_size, wbuf);
        }
        free(wbuf);
        
        if (vsize > try_size * COMPRESS_RATIO_LIMIT || try_size < vsz) {
            free(v);
            return;
        }
        
        if (r->free_value) {
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
    if (r->flag & COMPRESS_FLAG) {
        char scratch[QLZ_SCRATCH_DECOMPRESS];
        int csize = qlz_size_compressed(r->value);
        if (csize != r->vsz) {
            fprintf(stderr, "broken compressed data: %d != %d, flag=%x\n", csize, r->vsz, r->flag);
            goto DECOMP_END;
        }
        int size = qlz_size_decompressed(r->value);
        char *v = malloc(size);
        if (v == NULL) {
            fprintf(stderr, "malloc(%d)\n", size);
            goto DECOMP_END;
        }
        int ret = qlz_decompress(r->value, v, scratch);
        if (ret < size) {
            fprintf(stderr, "decompress %s failed: %d < %d\n", r->key, ret, size);
            goto DECOMP_END;
        }
        if (r->free_value) {
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
    if (ksz < 0 || ksz > 200 || vsz < 0 || vsz > 100 * 1024 * 1024){
        fprintf(stderr, "invalid ksz=: %d, vsz=%d\n", ksz, vsz);
        return NULL;
    }
    int need = sizeof(DataRecord) - sizeof(char*) + ksz + vsz;
    if (size < need) {
        fprintf(stderr, "not enough data in buffer: %d < %d\n", size, need);
        return NULL;
    }
    // CRC check ?

    DataRecord *r2 = (DataRecord *) malloc(need + 1 + sizeof(char*));
    memcpy(&r2->crc, &r->crc, sizeof(DataRecord) - sizeof(char*) + ksz);
    r2->key[ksz] = 0; // c str    
    r2->free_value = false;
    r2->value = r2->key + ksz + 1;
    memcpy(r2->value, r->key + ksz, vsz);
       
    if (decomp) {
        r2 = decompress_record(r2);
    }
    return r2;
}


DataRecord* read_record(FILE *f, bool decomp)
{
    DataRecord *r = (DataRecord*) malloc(PADDING + sizeof(char*));
    r->value = NULL;
   
    if (fread(&r->crc, 1, PADDING, f) != PADDING) {
        fprintf(stderr, "read record faied\n");         
        goto READ_END;
    }

    int ksz = r->ksz, vsz = r->vsz;
    if (ksz < 0 || ksz > 200 || vsz < 0 || vsz > 100 * 1024 * 1024){
        fprintf(stderr, "invalid ksz=: %d, vsz=%d\n", ksz, vsz);
        goto READ_END;
    }
  
    uint32_t crc_old = r->crc;
    int read_size = PADDING - (sizeof(DataRecord) - sizeof(char*)) - ksz;
    if (vsz < read_size) {
        r->value = r->key + ksz + 1;
        r->free_value = false;
        memmove(r->value, r->key + ksz, vsz);
    }else{
        r->value = malloc(vsz);
        r->free_value = true;
        memcpy(r->value, r->key + ksz, read_size);
        int need = vsz - read_size;
        int ret = 0;
        if (need > 0 && need != (ret=fread(r->value + read_size, 1, need, f))) {
            r->key[ksz] = 0; // c str    
            fprintf(stderr, "read record %s faied: %d < %d @%ld\n", r->key, ret, need, ftell(f)); 
            goto READ_END;
        }
    }
    r->key[ksz] = 0; // c str    

    uint32_t crc = crc32(0, (char*)(&r->tstamp), 
                    sizeof(DataRecord) - sizeof(char*) - sizeof(uint32_t) + ksz);
    crc = crc32(crc, r->value, vsz);
    if (crc != crc_old){
        fprintf(stderr, "%s @%ld crc32 check failed %d != %d\n", r->key, ftell(f), crc, r->crc);
        goto READ_END;
    }

    if (decomp) {
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
   
    if (pread(fd, &r->crc, PADDING, offset) != PADDING) {
        fprintf(stderr, "read record faied\n");         
        goto READ_END;
    }

    int ksz = r->ksz, vsz = r->vsz;
    if (ksz < 0 || ksz > 200 || vsz < 0 || vsz > 100 * 1024 * 1024){
        fprintf(stderr, "invalid ksz=: %d, vsz=%d\n", ksz, vsz);
        goto READ_END;
    }
  
    uint32_t crc_old = r->crc;
    int read_size = PADDING - (sizeof(DataRecord) - sizeof(char*)) - ksz;
    if (vsz < read_size) {
        r->value = r->key + ksz + 1;
        r->free_value = false;
        memmove(r->value, r->key + ksz, vsz);
    }else{
        r->value = malloc(vsz);
        r->free_value = true;
        memcpy(r->value, r->key + ksz, read_size);
        int need = vsz - read_size;
        int ret = 0;
        if (need > 0 && need != (ret=pread(fd, r->value + read_size, need, offset+PADDING))) {
            r->key[ksz] = 0; // c str    
            fprintf(stderr, "read record %s faied: %d < %d @%ld\n", r->key, ret, need, offset); 
            goto READ_END;
        }
    }
    r->key[ksz] = 0; // c str    

    uint32_t crc = crc32(0, (char*)(&r->tstamp), 
                    sizeof(DataRecord) - sizeof(char*) - sizeof(uint32_t) + ksz);
    crc = crc32(crc, r->value, vsz);
    if (crc != crc_old){
        fprintf(stderr, "%s @%ld crc32 check failed %d != %d\n", r->key, offset, crc, r->crc);
        goto READ_END;
    }

    if (decomp) {
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
    if (n % PADDING != 0) {
        m += PADDING - (n % PADDING);
    }

    char *buf = malloc(m);

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
    if (fwrite(data, 1, size, f) < size){
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
    while (p < end) {
        DataRecord *r = decode_record(p, end-p, false);
        if (r != NULL) {
            uint32_t pos = p - f->addr;
            p += record_length(r); 
            r = decompress_record(r);
            uint16_t hash = gen_hash(r->value, r->vsz);
            if (r->version > 0){
                ht_add2(tree, r->key, r->ksz, pos | bucket, hash, r->version);            
            }else{
                ht_remove2(tree, r->key, r->ksz);
            }
            ht_add2(cur_tree, r->key, r->ksz, pos | bucket, hash, r->version);
            free_record(r);
        } else {
            p += PADDING;
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
    while (p < end) {
        DataRecord *r = decode_record(p, end-p, false);
        if (r != NULL) {
            if (r->tstamp >= before ){
                break;
            }
            uint32_t pos = p - f->addr;
            p += record_length(r); 
            r = decompress_record(r);
            uint16_t hash = gen_hash(r->value, r->vsz);
            if (r->version > 0){
                uint16_t hash = gen_hash(r->value, r->vsz);
                ht_add2(tree, r->key, r->ksz, pos | bucket, hash, r->version);            
            }else{
                ht_remove2(tree, r->key, r->ksz);
            }
            free_record(r);
        } else {
            p += PADDING;
        }
    }

    close_mfile(f);
}

HTree* optimizeDataFile(HTree* tree, int bucket, const char* path, const char* hintpath,
    int limit, uint32_t *recovered) 
{
    int all = 0;
    int deleted = count_deleted_record(tree, bucket, hintpath, &all);
    if (deleted <= all * 0.1 && deleted <= limit) {
        fprintf(stderr, "only %d records deleted in %d, skip %s\n", deleted, all, path);
        return NULL;
    }

    MFile *f = open_mfile(path);
    if (f == NULL) return;
    
    char tmp[255];
    sprintf(tmp, "%s.tmp", path);
    FILE *new_df = fopen(tmp, "wb");
    if (NULL==new_df){
        fprintf(stderr, "open %s failed\n", tmp);
        close_mfile(f);
        return NULL;
    }
    
    HTree *cur_tree = ht_new(0,0);
    deleted = 0;
    char *p = f->addr, *end = f->addr + f->size;
    while (p < end) {
        DataRecord *r = decode_record(p, end-p, false);
        if (r == NULL) {
            fprintf(stderr, "read data failed: %s\n", path);
            ht_destroy(cur_tree);
            close_mfile(f);
            fclose(new_df);
            return NULL;
        }
        Item *it = ht_get2(tree, r->key, r->ksz);
        uint32_t pos = p - f->addr;
        if (it && it->pos  == (pos | bucket) && it->ver > 0) {
            uint32_t new_pos = ftell(new_df);
            uint16_t hash = it->hash;
            ht_add2(cur_tree, r->key, r->ksz, new_pos | bucket, hash, it->ver);
            if (write_record(new_df, r) != 0) {
                fprintf(stderr, "write error: %s\n", tmp);
                ht_destroy(cur_tree);
                close_mfile(f);
                fclose(new_df);
                return NULL;
            }
        }else{
            deleted ++;
        }
        if (it) free(it);
        p += record_length(r); 
        free_record(r);
    }
    uint32_t deleted_bytes = f->size - ftell(new_df);
    if (recovered != NULL) *recovered = deleted_bytes;
    close_mfile(f);
    fclose(new_df);
    
    unlink(hintpath);
    unlink(path);
    rename(tmp, path);
    fprintf(stderr, "optimize %s complete, %d records deleted, %u bytes came back\n", 
            path, deleted, deleted_bytes);
    return cur_tree;
}
