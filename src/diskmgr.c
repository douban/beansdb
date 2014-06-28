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
                unlink(target);
            }
            if (i == 0) continue;
            if (lstat(target, &sb) != 0 || (sb.st_mode & S_IFMT) != S_IFREG)
            {
                unlink(target);
                continue;
            }
            safe_snprintf(sym, MAX_PATH_LEN, "%s/%s", disks[0], de->d_name);
            if (0 == stat(sym, &sb)) continue;
            int r = 0;
            if (target[0] != '/')
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
                log_error("symlink failed %s -> %s", sym, target);
            }
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
        if (avail > maxa)
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
    if (lstat(path, &sb) == 0 && (sb.st_mode & S_IFMT) == S_IFLNK)
    {
        char buf[MAX_PATH_LEN];
        int n = readlink(path, buf, MAX_PATH_LEN);
        if (n > 0)
        {
            buf[n] = 0;
            unlink(buf);
        }
        else
        {
            log_error("readlink failed: %s", path);
        }
    }
    unlink(path);
}

void mgr_rename(const char *oldpath, const char *newpath)
{
    struct stat sb;
    char ropath[MAX_PATH_LEN];
    char rnpath[MAX_PATH_LEN];
    if (lstat(oldpath, &sb) == 0 && (sb.st_mode & S_IFMT) == S_IFLNK)
    {
        int n = readlink(oldpath, ropath, MAX_PATH_LEN);
        if (n > 0)
        {
            ropath[n] = 0;
            char *ropath_dup = strdup(ropath);
            char *newpath_dup = strdup(newpath);
            sprintf(rnpath, "%s/%s", dirname(ropath_dup), basename(newpath_dup));
            free(ropath_dup);
            free(newpath_dup); 

            rename(ropath, rnpath);
            unlink(oldpath);
            if (symlink(rnpath, newpath) != 0)
                log_error("symlink failed: %s -> %s", rnpath, newpath);
        }
        else
        {
            log_error("readlink failed: %s", oldpath);
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
