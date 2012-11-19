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

#ifndef __DISKMGR_H__
#define __DISKMGR_H__

#include <stdint.h>

typedef struct disk_mgr Mgr;

Mgr* mgr_create(const char **disks, int ndisks);
void mgr_destroy(Mgr *mgr);

const char* mgr_base(Mgr *mgr);
const char* mgr_alloc(Mgr *mgr, const char *path);

void mgr_unlink(const char *path);

void mgr_stat(Mgr *mgr, uint64_t *total, uint64_t *avail);

#endif
