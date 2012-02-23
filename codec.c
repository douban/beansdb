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

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>

#include "codec.h"

typedef struct {
    int nargs;
    char fmt[0];
} Fmt;

const size_t DICT_SIZE = 64 * 256;
const size_t RDICT_SIZE = 64 * 256 * 128 - 1;

static Fmt** dict = NULL;
static int*  rdict = NULL;
static int dict_used = 1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void dc_init()
{
    pthread_mutex_lock(&lock);

    if (dict == NULL) {
        dict = (Fmt**)malloc(sizeof(char*) * DICT_SIZE);
        memset(dict, 0, sizeof(Fmt*) * DICT_SIZE);
        dict_used = 1;
        
        rdict = (int*)malloc(sizeof(int) * RDICT_SIZE);
        memset(rdict, 0, sizeof(int) * RDICT_SIZE);
    }
    
    pthread_mutex_unlock(&lock);
}

int32_t b64_encode(const char* src, int len) {
    int32_t n = 0;
    int i;
    for (i=0; i<len; i++) {
         n <<= 6;
         char c = src[i];
         if ('0'<=c && c <= '9') {
            n += c-'0';
         }else if ('a'<=c && c<='z'){
            n += c-'a' + 10;
         }else if ('A'<=c && c<='Z'){
            n += c-'A' + 36;
         }
    }
    return n;
}

int b64_decode(char* dst, int32_t n) {
    int i;
    for (i=0;i<5;i++) {
         char c;
         int32_t m = n & 0x3f;
         if (m >= 36) {
            c = 'A' + (m-36);
         }else if (m >= 10){
            c = 'a' + (m-10);
         }else {
            c = '0' + m;
         }
         dst[4-i] = c;
         n >>= 6;
    }
    return 5;
}

int dc_encode(char* buf, const char* src, int len)
{
    if (src == NULL || buf == NULL){
        return 0;
    }
    if (len > 20 && memcmp(src, "/photo/", 7) == 0 && strstr(src, "_") != NULL) {
        // skip /photo/thumb/SG94-EpQ_p866859435
        goto RET;
    } else if (len > 6 && len < 100 && src[0] > 0){
        int m=0;
        char fmt[255];
        bool hex[20];
        char num[20][10];
        int32_t args[10];
        const char *p=src, *q=src + len;
        char *dst=fmt;
        if ((len >= 18 && memcmp(src, "/status/", 8) == 0 ||    
            len == 29 && memcmp(src, "/anduin/urlgrabcontent/", 23) == 0) 
            && src[len-7] == '/') {
            // hack for /status/raw/2IP3Kv 
            memcpy(dst, src, len-5);
            dst += len-5;
            *dst ++ = '%';
            *dst ++ = 'v';
            args[0] = b64_encode(src+len-5, 5);
            m = 1;
        }else{
        while(p<q){
            if (*p == '%' || *p == '@' || *p == ':'){  // not supported format
                goto RET;
            }
            if (*p >= '1' && *p <= '9' || *p >= 'a' && *p <= 'f'){
                char *nd = num[m];
                hex[m] = false;
                while(p < q && (*p >= '0' && *p <= '9' || *p >= 'a' && *p <= 'f')) {
                    if (*p >= 'a' && *p <= 'f') hex[m] = true;
                    *nd ++ = *p ++;
                    if (hex[m] && nd-num[m] >= 8 || !hex[m] && nd-num[m] >=9) {
                        break;
                    }
                }
                // 8digit+1hex, pop it
                if (hex[m] && nd-num[m]==9) {
                    nd--;
                    p--;
                    hex[m] = false;
                }
                *nd = 0;
                if (hex[m] && nd - num[m] >= 4){
                    *dst ++ = '%';
                    *dst ++ = 'x';
                    args[m] = strtol(num[m], NULL, 16);
                    m ++;                    
                } else if (!hex[m] && nd - num[m] >= 3) {
                    *dst ++ = '%';
                    *dst ++ = 'd';
                    args[m] = atoi(num[m]);
                    m ++;                    
                }else{
                    memcpy(dst, num[m], nd - num[m]);
                    dst += nd - num[m];
                }
            }else{
                *dst ++ = *p++;
            }
        }
        }
        *dst = 0; // ending 0
        int flen = dst - fmt, prefix;
        if (m > 0 && m <= 2){
            uint32_t h = fnv1a(fmt, flen) % RDICT_SIZE;
            if (rdict[h] == 0){
                pthread_mutex_lock(&lock);
                if (rdict[h] == 0) {
                    if (dict_used < DICT_SIZE) {
                        dict[dict_used] = (Fmt*) malloc(sizeof(Fmt) + flen + 1);
                        dict[dict_used]->nargs = m;
                        memcpy(dict[dict_used]->fmt, fmt, flen + 1);
                        fprintf(stderr, "new fmt %d: %s <= %s\n", dict_used, fmt, src);
                        rdict[h] = dict_used ++;
                    } else {
                        fprintf(stderr, "not captched fmt: %s <= %s\n", fmt, src);
                        rdict[h] = -1; // not again
                    }
                }
                pthread_mutex_unlock(&lock);
            }
            register int rh = rdict[h];
            if (rh > 0 && dict[rh] != NULL && strcmp(fmt, dict[rh]->fmt) == 0) {
                if (rh < 64) {
                    prefix = 1;
                    *buf = - rh;
                }else{
                    prefix = 2;
                    *buf = - (rh & 0x3f) - 64;
                    *(unsigned char*)(buf+1) = rh >> 6; 
                }
                memcpy(buf+prefix, args, sizeof(int32_t)*m);
                return prefix + m * sizeof(int32_t);
            }
            if (rh > 0) {
                fprintf(stderr, "collision fmt: %s <= %s\n", fmt, src);
            }
        }
    }
RET:
    memcpy(buf, src, len);
    return len;
}

int dc_decode(char* buf, const char* src, int len)
{
    if (buf == NULL || src == NULL || len == 0){
        return 0;
    }

    if (src[0] < 0){
        int idx = -*src;
        int32_t* args = (int32_t*)(src + 1);
        if (idx >= 64) {
            idx -= 64;
            idx += (*(unsigned char*)(src+1)) << 6;
            args = (int32_t*)(src + 2);
        }
        Fmt *f = dict[idx];
        int rlen = 0;
        int flen = strlen(f->fmt);
        if (f->fmt[flen-1] == 'v' && f->fmt[flen-2] == '%') {
            //hack for /status/xxx/1xxxx
            memcpy(buf, f->fmt, flen-2);
            b64_decode(buf+flen-2, args[0]);
            rlen = flen+3;
            buf[rlen] = 0;
        }else{
        switch(f->nargs){
            case 1: rlen = sprintf(buf, f->fmt, args[0]); break;
            case 2: rlen = sprintf(buf, f->fmt, args[0], args[1]); break;
            case 3: rlen = sprintf(buf, f->fmt, args[0], args[1], args[2]); break;
            default: ; 
        }}
        return rlen;
    }
    memcpy(buf, src, len);
    buf[len] = 0;
    return len;
}

