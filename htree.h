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

typedef struct t_hash_tree HTree;

HTree*   ht_open(char *path, int depth);
void     ht_close(HTree *tree);
void     ht_clear(HTree *tree);
void     ht_add(HTree *tree, char *name, int ver, uint32_t hash, bool update);
void     ht_remove(HTree *tree, char *name, bool update);
void     ht_flush(HTree *tree);
uint32_t ht_get_hash(HTree *tree, char *key, int *count);
char*    ht_list(HTree *tree, char *dir);

#endif /* __HTREE_H__ */
