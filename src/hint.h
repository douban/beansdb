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

#ifndef __HINT_H__
#define __HINT_H__

#include "htree.h"

typedef struct {
    int fd;
    size_t size;
    char *addr;
} MFile;

MFile* open_mfile(const char* path);
void close_mfile(MFile *f);
void write_file(char *buf, int size, const char* path);

void scanHintFile(HTree* tree, int bucket, const char* path, const char* new_path);
void build_hint(HTree* tree, const char* path);
int count_deleted_record(HTree* tree, int bucket, const char* path, int *total);

#endif
