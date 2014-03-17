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

#include "fnv1a.h"

inline uint32_t fnv1a(const char *key, int key_len)
{
    uint32_t h = FNV_32_INIT;
    int i;

    for (i=0; i<key_len; i++)
    {
        h ^= (uint32_t)key[i];
        h *= FNV_32_PRIME;
    }

    return h;
}
