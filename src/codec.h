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

#ifndef __CODEC_H__
#define __CODEC_H__

typedef struct t_codec Codec;

Codec* dc_new();
void dc_destroy(Codec *dc);

int dc_encode(Codec* dc, char* buf, const char *src, int len);
int dc_decode(Codec* dc, char* buf, const char *src, int len);

#endif

