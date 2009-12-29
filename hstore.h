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

#ifndef __HSTORE_H__
#define __HSTORE_H__

typedef struct t_hstore HStore;

HStore* hs_open(char *path, int height, int start, int end);
void    hs_close(HStore *store);
void    hs_check(HStore *store, int scan_limit);
void    hs_stop_check(HStore *store);
void    hs_flush(HStore *store, int limit);
void    hs_clear(HStore *store);
bool    hs_set(HStore *store, char *key, char* value, 
                int vlen, int version, uint32_t flag);
char*   hs_get(HStore *store, char *key, int *vlen, uint32_t *flag);
bool    hs_delete(HStore *store, char *key);

#endif
