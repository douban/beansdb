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

#ifndef __RECORD_H__
#define __RECORD_H__

#include <stdio.h>
#include <time.h>
#include "htree.h"

typedef struct data_record {
	char *value;
    union {
        bool free_value;    // free value or not
        uint32_t crc;
    };
    int32_t tstamp;
    int32_t flag;
    int32_t version;
    uint32_t ksz;
    uint32_t vsz;
	char key[0];
} DataRecord;

typedef bool (*RecordVisitor)(DataRecord *r, void *arg1, void *arg2);

uint32_t gen_hash(char* buf, int size);

char* record_value(DataRecord *r);
void free_record(DataRecord *r);
DataRecord* decode_record(char* buf, uint32_t size, bool decomp);
char* encode_record(DataRecord* r, int* size);	
DataRecord* read_record(FILE *f, bool decomp);
DataRecord* fast_read_record(int fd, off_t offset, bool decomp);

void scanDataFile(HTree* tree, int bucket, const char* path, const char* hintpath);
void scanDataFileBefore(HTree* tree, int bucket, const char* path, time_t before);
HTree* optimizeDataFile(HTree* tree, int bucket, const char* path, const char* hintpath, int limit, uint32_t *recovered); 
void visit_record(const char* path, RecordVisitor visitor, void *arg1, void *arg2, bool decomp);

#endif
