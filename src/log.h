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

#ifndef __LOG_H__
#define __LOG_H__

#include <stdarg.h>

#include "zlog.h"

zlog_category_t *cat;

int log_init(const char* conf_path);
void log_finish();
#define log_fatal(FORMAT, ...) zlog_fatal(cat, FORMAT, ##__VA_ARGS__)
#define log_error(FORMAT, ...) zlog_error(cat, FORMAT, ##__VA_ARGS__)
#define log_warn(FORMAT, ...) zlog_warn(cat, FORMAT, ##__VA_ARGS__)
#define log_notice(FORMAT, ...) zlog_notice(cat, FORMAT, ##__VA_ARGS__)
#define log_info(FORMAT, ...) zlog_info(cat, FORMAT, ##__VA_ARGS__)
#define log_debug(FORMAT, ...) zlog_debug(cat, FORMAT, ##__VA_ARGS__)
#endif
