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

#define max(a,b) ((a)>(b)?(a):(b))

typedef struct {
    unsigned char nargs;
    char fmt[7];
} Fmt;

inline int fmt_size(Fmt *fmt) {
    return sizeof(Fmt) + strlen(fmt->fmt) - 7 + 1;
}

const size_t DEFAULT_DICT_SIZE = 1024;
const size_t MAX_DICT_SIZE = 16384;

#define RDICT_SIZE(DICT_SIZE) ((DICT_SIZE) * 7 + 1)

struct t_codec {
    size_t dict_size;
    Fmt **dict;
    size_t rdict_size;
    short *rdict;
    int dict_used;
};

Codec* dc_new() 
{
    Codec *dc = (Codec*) malloc(sizeof(struct t_codec));
    
    dc->dict_size = DEFAULT_DICT_SIZE;
    dc->dict = (Fmt**)malloc(sizeof(Fmt*) * dc->dict_size);
    memset(dc->dict, 0, sizeof(Fmt*) * dc->dict_size);
   
    dc->rdict_size = RDICT_SIZE(dc->dict_size);
    dc->rdict = (short*)malloc(sizeof(short) * dc->rdict_size);
    memset(dc->rdict, 0, sizeof(short) * dc->rdict_size);

    dc->dict_used = 1;

    return dc;
}

int dc_size(Codec *dc) {
    int i, s = sizeof(int);
    for (i=1; i<dc->dict_used; i++) {
        s += 1 + fmt_size(dc->dict[i]);
    }
    return s;
}

int dc_dump(Codec *dc, char *buf, int size)
{
    char *orig = buf;
    int i=0;
    if (size < sizeof(int)) return -1;
    *(int*)buf = dc->dict_used;
    buf += sizeof(int);

    for (i=1; i<dc->dict_used; i++) {
        unsigned char s = fmt_size(dc->dict[i]);
        if (buf + s + 1 - orig > size) return -1;
        *(unsigned char*)buf ++ = s;
        memcpy(buf, dc->dict[i], s);
        buf += s;
    }

    return buf - orig;
}

void dc_rebuild(Codec *dc) 
{
    int i;
    dc->rdict_size = RDICT_SIZE(dc->dict_size);
    free(dc->rdict);
    dc->rdict = (short*) malloc(sizeof(short) * dc->rdict_size);
    memset(dc->rdict, 0, sizeof(short) * dc->rdict_size);

    for (i=1; i<dc->dict_used; i++) {
        uint32_t h = fnv1a(dc->dict[i]->fmt, strlen(dc->dict[i]->fmt)) % dc->rdict_size;
        while (dc->rdict[h] > 0) {
            h ++;
            if (h == dc->rdict_size) h = 0;
        }
        dc->rdict[h] = i;
    }
}

void dc_enlarge(Codec *dc)
{
    dc->dict_size = max(dc->dict_size * 2, MAX_DICT_SIZE);
    dc->dict = (Fmt**) realloc(dc->dict, sizeof(Fmt*) * dc->dict_size);

    dc_rebuild(dc);
}    

int dc_load(Codec *dc, const char *buf, int size)
{
    const char *orig = buf;
    int i;
    if (dc == NULL) return -1;
    int used = *(int*)buf;
    if (used >= MAX_DICT_SIZE) return -1;
    dc->dict_used = used;
    buf += sizeof(int);
    if (dc->dict_size < dc->dict_used * 2) {
        dc->dict_size = max(dc->dict_used * 2, MAX_DICT_SIZE);
        dc->dict = (Fmt**) realloc(dc->dict, sizeof(Fmt*) * dc->dict_size);
        if (dc->dict == NULL) {
            dc->dict_used = 1;
            return -1;
        }
    }

    for (i=1; i<dc->dict_used; i++) {
        int s = *(unsigned char*) buf++;
        dc->dict[i] = (Fmt*)malloc(s);
        if (dc->dict[i] == NULL) {
            dc->dict_used = 1;
            return -1;
        }
        memcpy(dc->dict[i], buf, s);
        buf += s;
    }

    dc_rebuild(dc);

    return 0;
}

void dc_destroy(Codec *dc)
{
    int i;
    if (dc == NULL) return;
    
    if (dc->rdict) free(dc->rdict);
    for (i=1; i<dc->dict_used; i++)
        free(dc->dict[i]);
    if (dc->dict) free(dc->dict);
    free(dc);
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
            uint32_t h = fnv1a(fmt, flen) % dc->rdict_size;
            // test hash collision
            while (dc->rdict[h] > 0 && strcmp(fmt, dict[dc->rdict[h]]->fmt) != 0) {
                h ++;
                if (h == dc->rdict_size) h = 0;
            }
            int rh = dc->rdict[h];
            if (rh == 0){
                if (dc->dict_used < dc->dict_size) {
                    dict[dc->dict_used] = (Fmt*) malloc(sizeof(Fmt) + flen - 7 + 1);
                    dict[dc->dict_used]->nargs = m;
                    memcpy(dict[dc->dict_used]->fmt, fmt, flen + 1);
                    // fprintf(stderr, "new fmt %d: %s <= %s\n", dc->dict_used, fmt, src);
                    dc->rdict[h] = rh = dc->dict_used ++;
                    if (dc->dict_used == dc->dict_size && dc->dict_size < MAX_DICT_SIZE) {
                        dc_enlarge(dc);
                    }
                } else {
                    fprintf(stderr, "not captched fmt: %s <= %s\n", fmt, src);
                    dc->rdict[h] = rh = -1; // not again
                }
            }
            if (rh > 0) {
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
        switch(f->nargs){
            case 1: rlen = sprintf(buf, f->fmt, args[0]); break;
            case 2: rlen = sprintf(buf, f->fmt, args[0], args[1]); break;
            case 3: rlen = sprintf(buf, f->fmt, args[0], args[1], args[2]); break;
            default: ; 
        }
        return rlen;
    }
    memcpy(buf, src, len);
    buf[len] = 0;
    return len;
}
