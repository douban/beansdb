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
#include <pthread.h>
#include <time.h>

#include "hint.h"
#include "quicklz.h"
#include "diskmgr.h"
#include "fnv1a.h"

const  int MAX_MMAP_SIZE = 1<<12; // 4G
static int curr_mmap_size = 0;
static pthread_mutex_t mmap_lock = PTHREAD_MUTEX_INITIALIZER;


// for build hint
struct param
{
    int size;
    int curr;
    char* buf;
};

void collect_items(Item* it, void* param)
{
    int ksize = strlen(it->key);
    int length = sizeof(HintRecord) + ksize + 1 - NAME_IN_RECORD;
    struct param *p = (struct param *)param;
    if (p->size - p->curr < length)
    {
        p->size *= 2;
        p->buf = (char*)realloc(p->buf, p->size);
    }

    HintRecord *r = (HintRecord*)(p->buf + p->curr);
    r->ksize = ksize;
    r->pos = it->pos >> 8;
    r->version = it->ver;
    r->hash = it->hash;
    memcpy(r->key, it->key, r->ksize + 1);

    p->curr += length;
}

void write_hint_file(char *buf, int size, const char* path)
{
    // compress
    char *dst = buf;
    if (strcmp(path + strlen(path) - 4, ".qlz") == 0)
    {
        char* wbuf = (char*)malloc(QLZ_SCRATCH_COMPRESS);
        dst = (char*)malloc(size + 400);
        size = qlz_compress(buf, dst, size, wbuf);
        free(wbuf);
    }

    char tmp[PATH_MAX];
    sprintf(tmp, "%s.tmp", path);
    FILE *hf = fopen(tmp, "wb");
    if (NULL==hf)
    {
        fprintf(stderr, "open %s failed\n", tmp);
        return;
    }
    int n = fwrite(dst, 1, size, hf);
    fclose(hf);
    if (dst != buf) free(dst);

    if (n == size)
    {
        mgr_unlink(path);
        mgr_rename(tmp, path);
    }
    else
    {
        fprintf(stderr, "write to %s failed \n", tmp);
    }
}

void build_hint(HTree* tree, const char* hintpath)
{
    struct param p;
    p.size = 1024 * 1024;
    p.curr = 0;
    p.buf = (char*)malloc(p.size);

    ht_visit(tree, collect_items, &p);
    ht_destroy(tree);

    write_hint_file(p.buf, p.curr, hintpath);
    free(p.buf);
}

MFile* open_mfile(const char* path)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        fprintf(stderr, "open mfile %s failed\n", path);
        return NULL;
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1)
    {
        close(fd);
        return  NULL;
    }
#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
    posix_fadvise(fd, 0, sb.st_size, POSIX_FADV_SEQUENTIAL);
#endif

    pthread_mutex_lock(&mmap_lock);
    int mb = sb.st_size >> 20;
    while (curr_mmap_size + mb > MAX_MMAP_SIZE && mb > 100)
    {
        pthread_mutex_unlock(&mmap_lock);
        sleep(5);
        pthread_mutex_lock(&mmap_lock);
    }
    curr_mmap_size += mb;
    pthread_mutex_unlock(&mmap_lock);

    MFile *f = (MFile*) malloc(sizeof(MFile));
    f->fd = fd;
    f->size = sb.st_size;

    if (f->size > 0)
    {
        f->addr = (char*) mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (f->addr == MAP_FAILED)
        {
            fprintf(stderr, "mmap failed %s\n", path);
            close(fd);
            pthread_mutex_lock(&mmap_lock);
            curr_mmap_size -= mb;
            pthread_mutex_unlock(&mmap_lock);
            free(f);
            return NULL;
        }

        if (madvise(f->addr, sb.st_size, MADV_SEQUENTIAL) < 0)
        {
            fprintf(stderr, "Unable to madvise() region %p\n", f->addr);
        }
    }
    else
    {
        f->addr = NULL;
    }

    return f;
}

void close_mfile(MFile *f)
{
    if (f->addr)
    {
        madvise(f->addr, f->size, MADV_DONTNEED);
        munmap(f->addr, f->size);
    }
#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
    posix_fadvise(f->fd, 0, f->size, POSIX_FADV_DONTNEED);
#endif
    close(f->fd);
    pthread_mutex_lock(&mmap_lock);
    curr_mmap_size -= f->size >> 20;
    pthread_mutex_unlock(&mmap_lock);
    free(f);
}

HintFile *open_hint(const char* path, const char* new_path)
{
    MFile *f = open_mfile(path);
    if (f == NULL)
    {
        return NULL;
    }

    HintFile *hint = (HintFile*) malloc(sizeof(HintFile));
    hint->f = f;
    hint->buf = f->addr;
    hint->size = f->size;

    if (strcmp(path + strlen(path) - 4, ".qlz") == 0 && hint->size > 0)
    {
        char wbuf[QLZ_SCRATCH_DECOMPRESS];
        int size = qlz_size_decompressed(hint->buf);
        char* buf = (char*)malloc(size);
        int vsize = qlz_decompress(hint->buf, buf, wbuf);
        if (vsize != size)
        {
            fprintf(stderr, "decompress %s failed: %d < %d, remove it\n", path, vsize, size);
            mgr_unlink(path);
            exit(1);
        }
        hint->size = size;
        hint->buf = buf;
    }

    if (new_path != NULL)
    {
        write_hint_file(hint->buf, hint->size, new_path);
    }

    return hint;
}

void close_hint(HintFile *hint)
{
    if (hint->buf != hint->f->addr && hint->buf != NULL)
    {
        free(hint->buf);
    }
    close_mfile(hint->f);
    free(hint);
}

void scanHintFile(HTree* tree, int bucket, const char* path, const char* new_path)
{
    HintFile* hint = open_hint(path, new_path);
    if (hint == NULL) return;

    char *p = hint->buf, *end = hint->buf + hint->size;
    while (p < end)
    {
        HintRecord *r = (HintRecord*) p;
        p += sizeof(HintRecord) - NAME_IN_RECORD + r->ksize + 1;
        if (p > end)
        {
            fprintf(stderr, "scan %s: unexpected end, need %ld byte\n", path, p - end);
            break;
        }
        uint32_t pos = (r->pos << 8) | (bucket & 0xff);
        if (r->version > 0)
            ht_add2(tree, r->key, r->ksize, pos, r->hash, r->version);
        else
            ht_remove2(tree, r->key, r->ksize);
    }

    close_hint(hint);
}

int count_deleted_record(HTree* tree, int bucket, const char* path, int *total)
{
    *total = 0;
    HintFile *hint = open_hint(path, NULL);
    if (hint == NULL)
    {
        return 0;
    }

    char *p = hint->buf, *end = hint->buf + hint->size;
    int deleted = 0;
    while (p < end)
    {
        HintRecord *r = (HintRecord*) p;
        p += sizeof(HintRecord) - NAME_IN_RECORD + r->ksize + 1;
        if (p > end)
        {
            fprintf(stderr, "scan %s: unexpected end, need %ld byte\n", path, p - end);
            break;
        }
        (*total) ++;
        Item *it = ht_get2(tree, r->key, r->ksize);
        if (it == NULL || it->pos != ((r->pos << 8) | bucket) || it->ver <= 0)
        {
            deleted ++;
        }
        if (it) free(it);
    }

    close_hint(hint);
    return deleted;
}
