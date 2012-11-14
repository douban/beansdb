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
#include <string.h>

#include "codec.h"

typedef struct {
    unsigned char nargs;
    char fmt[7];
} Fmt;

inline int fmt_size(Fmt *fmt) {
    return sizeof(Fmt) + strlen(fmt->fmt) - 7 + 1;
}

const size_t DICT_SIZE = 4096;
const size_t RDICT_SIZE = 4096 * 19 - 1;

struct t_codec {
    Fmt **dict;
    short *rdict;
    int dict_used;
};

Codec* dc_new() 
{
    Codec *dc = (Codec*) malloc(sizeof(struct t_codec));

    dc->dict = (Fmt**)malloc(sizeof(char*) * DICT_SIZE);
    memset(dc->dict, 0, sizeof(Fmt*) * DICT_SIZE);
    
    dc->rdict = (int*)malloc(sizeof(int) * RDICT_SIZE);
    memset(dc->rdict, 0, sizeof(int) * RDICT_SIZE);

    dc->dict_used = 1;

    return dc;
}

int dc_size(Codec *dc) {
    int i, s = sizeof(int) * 3;
    for (i=1; i<dc->dict_used; i++) {
        s += 1 + fmt_size(dc->dict[i]);
    }
    s += sizeof(short) * RDICT_SIZE;
    return s;
}

int dc_dump(Codec *dc, char *buf, int size)
{
    char *orig = buf;
    int i=0, *pi = (int*)buf;
    if (size < sizeof(int) * 3) return -1;
    pi[0] = DICT_SIZE;
    pi[1] = RDICT_SIZE;
    pi[2] = dc->dict_used;
    buf += sizeof(int) * 3;

    for (i=1; i<dc->dict_used; i++) {
        unsigned char s = fmt_size(dc->dict[i]);
        if (buf + s + 1 - orig > size) return -1;
        *(unsigned char*)buf ++ = s;
        memcpy(buf, &dc->dict[i], s);
        buf += s;
    }

    if (buf + sizeof(short) * RDICT_SIZE - orig > size) return -1;
    memcpy(buf, dc->rdict, sizeof(short) * RDICT_SIZE);
    buf += sizeof(short) * RDICT_SIZE;

    return buf - orig;
}

int dc_load(Codec *dc, const char *buf, int size)
{
    const char *orig = buf;
    int i, *pi = (int*) buf;
    if (dc == NULL) return -1;
    if (pi[0] != DICT_SIZE || pi[1] != RDICT_SIZE) return -1;
    dc->dict_used = pi[2];
    buf += sizeof(int) * 3;

    for (i=1; i<dc->dict_used; i++) {
        size_t s = *(unsigned char*) buf++;
        dc->dict[i] = (Fmt*)malloc(s);
        if (dc->dict[i] == NULL) {
            dc->dict_used = 1;
            return -1;
        }
        memcpy(dc->dict[i], buf, s);
        buf += s;
    }

    memcpy(dc->rdict, buf, sizeof(short) * RDICT_SIZE);
    buf += sizeof(short) * RDICT_SIZE;

    if (orig + size != buf) return -1;

    return 0;
}

void dc_destroy(Codec *dc)
{
    if (dc == NULL) return;

    free(dc->rdict);
    free(dc->dict);
    free(dc);
}

static inline 
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

static inline
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

int dc_encode(Codec* dc, char* buf, const char* src, int len)
{
    if (src == NULL || buf == NULL){
        return 0;
    }
    if (dc != NULL && len > 6 && len < 100 && src[0] > 0){
        int m=0;
        char fmt[255];
        bool hex[20];
        char num[20][10];
        int32_t args[10];
        const char *p=src, *q=src + len;
        char *dst=fmt;
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
        *dst = 0; // ending 0
        int flen = dst - fmt, prefix;
        if (m > 0 && m <= 2){
            Fmt **dict = dc->dict;
            uint32_t h = fnv1a(fmt, flen) % RDICT_SIZE;
            if (dc->rdict[h] == 0){
                if (dc->dict_used < DICT_SIZE) {
                    dict[dc->dict_used] = (Fmt*) malloc(sizeof(Fmt) + flen - 7 + 1);
                    dict[dc->dict_used]->nargs = m;
                    memcpy(dict[dc->dict_used]->fmt, fmt, flen + 1);
                    fprintf(stderr, "new fmt %d: %s <= %s\n", dc->dict_used, fmt, src);
                    dc->rdict[h] = dc->dict_used ++;
                } else {
                    fprintf(stderr, "not captched fmt: %s <= %s\n", fmt, src);
                    dc->rdict[h] = -1; // not again
                }
            }
            int rh = dc->rdict[h];
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

int dc_decode(Codec* dc, char* buf, const char* src, int len)
{
    if (buf == NULL || src == NULL || len == 0){
        return 0;
    }

    if (dc != NULL && src[0] < 0){
        int idx = -*src;
        int32_t* args = (int32_t*)(src + 1);
        if (idx >= 64) {
            idx -= 64;
            idx += (*(unsigned char*)(src+1)) << 6;
            args = (int32_t*)(src + 2);
        }
        Fmt *f = dc->dict[idx];
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
