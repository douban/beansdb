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
 *      Hurricane Lee <hurricane1026@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <libgen.h>

#include "diskmgr.h"

#include <unistd.h>
#include "const.h"
#include "log.h"
struct disk_mgr
{
    char **disks;
    int ndisks;
};

static inline char* simple_basename(const char *path)
{
    char *p = (char*)path + strlen(path);
    while (*p != '/' && p >= path)
        --p;
    return ++p;
}

ssize_t mgr_readlink(const char *path, char *buf, size_t bufsiz)
{
    int n = readlink(path, buf, bufsiz);
    if (n < 0)
    {
        log_fatal("readlink fail %s", path);
        return -1;
    }
    buf[n] = 0;
    if (strncmp(simple_basename(path), simple_basename(buf), bufsiz) != 0 )
    {
        log_fatal("basename not match %s->%s", path, buf);
        return -2;
    }
    return n;
}

Mgr* mgr_create(const char **disks, int ndisks)
{
    char *cwd = getcwd(NULL, 0);
    Mgr *mgr = (Mgr*) safe_malloc(sizeof(Mgr));
    mgr->ndisks = ndisks;
    mgr->disks = (char**)safe_malloc(sizeof(char*) * ndisks);
    int i=0;
    for (i=0; i<ndisks; i++)
    {
        if (0 != access(disks[i], F_OK) && 0 != mkdir(disks[i], 0755))
        {
            log_error("access %s failed", disks[i]);
            free(mgr->disks);
            free(mgr);
            return NULL;
        }
        mgr->disks[i] = strdup(disks[i]);

        // auto symlink
        //if (1) {
        DIR* dp = opendir(disks[i]);
        if (dp == NULL)
        {
            log_error("opendir failed: %s", disks[i]);
            continue;
        }
        struct dirent *de;
        char target[MAX_PATH_LEN], sym[MAX_PATH_LEN], real[MAX_PATH_LEN];
        struct stat sb;
        while ((de = readdir(dp)) != NULL)
        {
            int len = strlen(de->d_name);
            if (de->d_name[0] == '.') continue;
            if (len != 8 && len != 9 && len != 12) continue; // .data .htree .hint.qlz
            safe_snprintf(target, MAX_PATH_LEN, "%s/%s", disks[i], de->d_name);
            if (stat(target, &sb) != 0)
            {
                mgr_readlink(target, real, MAX_PATH_LEN);
                log_warn("find empty link in startup %s -> %s, unlink!", target, real);
                unlink(target);
                continue;
            }
            if (sb.st_size == 0)
            {
                log_warn("rm empty file/link in startup %s, unlink!", target);
                unlink(target);
                continue;
            }
            if (i == 0) 
            {
                if (lstat(target, &sb) == 0 
                        && (sb.st_mode & S_IFMT) == S_IFLNK 
                    && mgr_readlink(target, real, MAX_PATH_LEN) <= 0)
                {
                    log_warn("rm bad link in startup %s, unlink!", target);
                    unlink(target);
                }
                continue;
            }
            if (lstat(target, &sb) != 0 || (sb.st_mode & S_IFMT) != S_IFREG)
            {
                log_warn("find non-regular file on non-0 disk  %s, unlink", target);
                unlink(target);
                continue;
            }
            safe_snprintf(sym, MAX_PATH_LEN, "%s/%s", disks[0], de->d_name);
            if (0 == lstat(sym, &sb)) 
            {
                if ((sb.st_mode & S_IFMT) == S_IFLNK
                        && mgr_readlink(sym, real, MAX_PATH_LEN) > 0
                        && strncmp(target, real, MAX_PATH_LEN) == 0
                        && strncmp(simple_basename(target), simple_basename(real), MAX_PATH_LEN) == 0
                        )
                {
                    continue;
                }
                else 
                {
                    log_fatal("bad link:%s for file %s, exit! ", sym, target);
                    exit(-1);
                }
            }
            int r = 0;
            if (target[0] != '/')//TODO: better change all disks at the begining
            {
                safe_snprintf(real, MAX_PATH_LEN, "%s/%s", cwd, target);
                r = symlink(real, sym);
            }
            else
            {
                r = symlink(target, sym);
            }
            if (0 != r)
            {
                log_fatal("symlink failed %s -> %s, exit!", sym, target);
                exit(-1);
            }
            log_warn("auto link for %s", target);
        }
        (void) closedir(dp);
        //}
    }
    free(cwd);
    return mgr;
}


void mgr_destroy(Mgr *mgr)
{
    int i=0;
    for (i=0; i< mgr->ndisks; i++)
    {
        free(mgr->disks[i]);
    }
    free(mgr->disks);
    free(mgr);
}

const char* mgr_base(Mgr *mgr)
{
    return mgr->disks[0];
}

static uint64_t
get_disk_avail(const char *path, uint64_t *total)
{
    struct statvfs stat;
    int r = statvfs(path, &stat);
    if (r != 0)
    {
        return 0ULL;
    }
    if (total != NULL)
    {
        *total = stat.f_blocks * stat.f_frsize;
    }
    return stat.f_bavail * stat.f_frsize;
}

const char* mgr_alloc(Mgr *mgr, const char *name)
{
    if (mgr->ndisks == 1)
    {
        return mgr->disks[0];
    }
    uint64_t maxa= 0;
    int maxi = 0, i;
    char path[MAX_PATH_LEN];
    struct stat sb;
    for (i=0; i< mgr->ndisks; i++)
    {
        safe_snprintf(path, MAX_PATH_LEN, "%s/%s", mgr->disks[i], name);
        if (lstat(path, &sb) == 0 && (sb.st_mode & S_IFMT) == S_IFREG)
        {
            return mgr->disks[i];
        }
        uint64_t avail = get_disk_avail(mgr->disks[i], NULL);
        if (avail > maxa || (avail == maxa && (rand() & 1) == 1) )
        {
            maxa = avail;
            maxi = i;
        }
    }
    if (maxi != 0)
    {
        // create symlink
        char target[MAX_PATH_LEN];
        safe_snprintf(target, MAX_PATH_LEN, "%s/%s", mgr->disks[maxi], name);
        safe_snprintf(path, MAX_PATH_LEN, "%s/%s", mgr->disks[0], name);
        if (lstat(path, &sb) == 0)
        {
            unlink(path);
        }
        if (symlink(target, path) != 0)
        {
            log_fatal("create symlink failed: %s -> %s", path, target);
            exit(1);
        }
    }
    return mgr->disks[maxi];
}

void mgr_unlink(const char *path)
{
    struct stat sb;
    if ( 0 != lstat(path, &sb))
        return;
    log_notice("mgr_unlink %s", path);
    if ((sb.st_mode & S_IFMT) == S_IFLNK)
    {
        char buf[MAX_PATH_LEN];
        int n = mgr_readlink(path, buf, MAX_PATH_LEN);
        if (n > 0)
        {
            unlink(buf);
        }
    }
    unlink(path);
}

void mgr_rename(const char *oldpath, const char *newpath)
{
    log_notice("mgr_rename %s -> %s", oldpath, newpath);
    struct stat sb;
    char ropath[MAX_PATH_LEN];
    char rnpath[MAX_PATH_LEN];
    if (lstat(oldpath, &sb) == 0 && (sb.st_mode & S_IFMT) == S_IFLNK)
    {
        int n = mgr_readlink(oldpath, ropath, MAX_PATH_LEN);
        if (n > 0)
        {
            char *ropath_dup = strdup(ropath);
            sprintf(rnpath, "%s/%s", dirname(ropath_dup), simple_basename(newpath));
            free(ropath_dup);

            if (symlink(rnpath, newpath) != 0)
                log_error("symlink failed: %s -> %s", rnpath, newpath);
            log_notice("mgr_rename real %s -> %s", ropath, rnpath);
            rename(ropath, rnpath);
            unlink(oldpath);
        }
    }
    else
    {
        rename(oldpath, newpath);
    }
}

void mgr_stat(Mgr *mgr, uint64_t *total, uint64_t *avail)
{
    int i=0;
    *total = 0;
    *avail = 0;
    for (i=0; i< mgr->ndisks; i++)
    {
        uint64_t t;
        *avail += get_disk_avail(mgr->disks[i], &t);
        *total += t;
    }
}
