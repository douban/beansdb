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
#ifndef __HTREE_H__
#define __HTREE_H__

#include <stdbool.h>
#include <stdint.h>

typedef struct t_item Item;
struct t_item {
    uint32_t pos;
    int32_t  ver;
    uint16_t hash;
    uint8_t  length;
    char     key[1];
};

#define ITEM_PADDING 1

typedef struct t_hash_tree HTree;
typedef void (*fun_visitor) (Item *it, void *param);

uint32_t fnv1a(const char *key, int key_len);

HTree*   ht_new(int depth, int pos);
void     ht_destroy(HTree *tree);
void     ht_add(HTree *tree, const char* key, uint32_t pos, uint16_t hash, int32_t ver);
void     ht_remove(HTree *tree, const char *key);
Item*    ht_get(HTree *tree, const char *key);
Item*    ht_get2(HTree *tree, const char *key, int ksz);
uint32_t ht_get_hash(HTree *tree, const char *key, int *count);
char*    ht_list(HTree *tree, const char *dir, const char *prefix);
void     ht_visit(HTree *tree, fun_visitor visitor, void *param);

// not thread safe
void     ht_add2(HTree *tree, const char* key, int ksz, uint32_t pos, uint16_t hash, int32_t ver);
void     ht_remove2(HTree *tree, const char *key, int ksz);

#endif /* __HTREE_H__ */
