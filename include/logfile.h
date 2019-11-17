/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _LOGFILE_H
#define _LOGFILE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

// logfile_append() checks for logfile_disable internally to make it easier from here

#define logfile_top_msg(msg)                               logfile_append (hashcat_ctx, "%s\t%s",                  logfile_ctx->topid,                     (msg))
#define logfile_sub_msg(msg)                               logfile_append (hashcat_ctx, "%s\t%s\t%s",              logfile_ctx->topid, logfile_ctx->subid, (msg))
#define logfile_top_var_uint64(var,val)                    logfile_append (hashcat_ctx, "%s\t%s\t%" PRIu64 "",     logfile_ctx->topid,                     (var), (u64)   (val))
#define logfile_sub_var_uint64(var,val)                    logfile_append (hashcat_ctx, "%s\t%s\t%s\t%" PRIu64 "", logfile_ctx->topid, logfile_ctx->subid, (var), (u64)   (val))
#define logfile_top_var_uint(var,val)                      logfile_append (hashcat_ctx, "%s\t%s\t%u",              logfile_ctx->topid,                     (var), (u32)   (val))
#define logfile_sub_var_uint(var,val)                      logfile_append (hashcat_ctx, "%s\t%s\t%s\t%u",          logfile_ctx->topid, logfile_ctx->subid, (var), (u32)   (val))
#define logfile_top_var_char(var,val)                      logfile_append (hashcat_ctx, "%s\t%s\t%c",              logfile_ctx->topid,                     (var), (char)  (val))
#define logfile_sub_var_char(var,val)                      logfile_append (hashcat_ctx, "%s\t%s\t%s\t%c",          logfile_ctx->topid, logfile_ctx->subid, (var), (char)  (val))
#define logfile_top_var_string(var,val) if ((val) != NULL) logfile_append (hashcat_ctx, "%s\t%s\t%s",              logfile_ctx->topid,                     (var), (val))
#define logfile_sub_var_string(var,val) if ((val) != NULL) logfile_append (hashcat_ctx, "%s\t%s\t%s\t%s",          logfile_ctx->topid, logfile_ctx->subid, (var), (val))

#define logfile_top_uint(var)   logfile_top_var_uint   (#var, (var))
#define logfile_sub_uint(var)   logfile_sub_var_uint   (#var, (var))
#define logfile_top_uint64(var) logfile_top_var_uint64 (#var, (var))
#define logfile_sub_uint64(var) logfile_sub_var_uint64 (#var, (var))
#define logfile_top_char(var)   logfile_top_var_char   (#var, (var))
#define logfile_sub_char(var)   logfile_sub_var_char   (#var, (var))
#define logfile_top_string(var) logfile_top_var_string (#var, (var))
#define logfile_sub_string(var) logfile_sub_var_string (#var, (var))

void logfile_generate_topid (hashcat_ctx_t *hashcat_ctx);
void logfile_generate_subid (hashcat_ctx_t *hashcat_ctx);
void logfile_append         (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
int  logfile_init           (hashcat_ctx_t *hashcat_ctx);
void logfile_destroy        (hashcat_ctx_t *hashcat_ctx);

#endif // _LOGFILE_H
