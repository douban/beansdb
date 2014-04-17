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
 *      Hurricane Lee <hurricane1026@gmail.com>
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>

#ifdef HAVE_MALLOC_H
/* OpenBSD has a malloc.h, but warns to use stdlib.h instead */
#ifndef __OpenBSD__
#include <malloc.h>
#endif
#endif

#ifdef __GNUC__
#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif


//#include "const.h"

inline static void*
_safe_malloc(size_t s, const char *file, int line, const char *func)
{
    void *p = malloc(s);
    if (unlikely(p == NULL))
    {
        fprintf(stderr, "Out of memory: %d, %zu bytes in %s (%s:%i)\n", errno, s, func, file, line);
        /*
        * memset will make debug easier
        */
        //memset(p, 0, s);
        exit(1);
    }
    return p;
}

#define safe_malloc(X) _safe_malloc(X, __FILE__, __LINE__, __FUNCTION__)

inline static void*
_try_malloc(size_t s, const char *file, int line, const char *func)
{
    void *p = malloc(s);
    if (unlikely(p == NULL))
    {
        fprintf(stderr, "Out of memory: %d, %zu bytes in %s (%s:%i) but continue working.\n", errno, s, func, file, line);
    }
    return p;
}

#define try_malloc(X) _try_malloc(X, __FILE__, __LINE__, __FUNCTION__)

inline static void*
_safe_realloc(void* ptr, size_t s, const char *file, int line, const char *func)
{
    void *p = realloc(ptr, s);
    if (unlikely(p == NULL))
    {
        fprintf(stderr, "Realloc failed: %d, %zu bytes in %s (%s:%i)\n", errno, s, func, file, line);
        exit(1);
    }
    return p;
}

#define safe_realloc(X, Y) _safe_realloc(X, Y, __FILE__, __LINE__, __FUNCTION__)

inline static void*
_try_realloc(void* ptr, size_t s, const char *file, int line, const char *func)
{
    void *p = realloc(ptr, s);
    if (unlikely(p == NULL))
    {
        fprintf(stderr, "Realloc failed: %d, %zu bytes in %s (%s:%i), but continue working\n", errno, s, func, file, line);
    }
    return p;
}

#define try_realloc(X, Y) _try_realloc(X, Y, __FILE__, __LINE__, __FUNCTION__)


inline static size_t
_check_snprintf(const char *file, int line, const char *func, char* s, size_t n, const char* format, ...)
{
    va_list args;
    size_t result_len;
    va_start (args, format);
    result_len = vsnprintf(s, n, format, args);
    if (unlikely(result_len >= n))
    {
        fprintf(stderr, "Truncation: content truncated while calling snprintf \
                in %s (%s:%i), %zu content print to %zu length buffer.", file, func, line, result_len, n);
        exit(1);
    }
    va_end(args);
    return result_len;
}

#define safe_snprintf(BUFFER, N, FORMAT, ...) _check_snprintf(__FILE__, __LINE__, __FUNCTION__, BUFFER, N, FORMAT, __VA_ARGS__)

/*
inline static char*
gen_path(char *dst, const char *base, const char *fmt, int i, const size_t max_path_len)
{
    static char path[MAX_PATH_LEN];
    //char name[16];
    if (likely(dst == NULL && max_path_len <= MAX_PATH_LEN))
        dst = path;
    else
    {
        fprintf(stderr, "Try to do a snprintf over a insufficient buffer");
        exit(1);
    }
    //snprintf(name, 16, fmt, i);
    //snprintf(dst, max_path_len, fmt, base, i);
    safe_snprintf(dst, max_path_len, fmt, base, i);
    return dst;
}
*/

#define min(a,b) ((a)<(b)?(a):(b))

#endif
