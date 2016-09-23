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

// logfile_append() checks for logfile_disable internally to make it easier from here

#define logfile_top_msg(msg)                               logfile_append (logfile_ctx, "%s\t%s",                  logfile_ctx->topid,                     (msg));
#define logfile_sub_msg(msg)                               logfile_append (logfile_ctx, "%s\t%s\t%s",              logfile_ctx->topid, logfile_ctx->subid, (msg));
#define logfile_top_var_uint64(var,val)                    logfile_append (logfile_ctx, "%s\t%s\t%" PRIu64 "",     logfile_ctx->topid,                     (var), (val));
#define logfile_sub_var_uint64(var,val)                    logfile_append (logfile_ctx, "%s\t%s\t%s\t%" PRIu64 "", logfile_ctx->topid, logfile_ctx->subid, (var), (val));
#define logfile_top_var_uint(var,val)                      logfile_append (logfile_ctx, "%s\t%s\t%u",              logfile_ctx->topid,                     (var), (val));
#define logfile_sub_var_uint(var,val)                      logfile_append (logfile_ctx, "%s\t%s\t%s\t%u",          logfile_ctx->topid, logfile_ctx->subid, (var), (val));
#define logfile_top_var_char(var,val)                      logfile_append (logfile_ctx, "%s\t%s\t%c",              logfile_ctx->topid,                     (var), (val));
#define logfile_sub_var_char(var,val)                      logfile_append (logfile_ctx, "%s\t%s\t%s\t%c",          logfile_ctx->topid, logfile_ctx->subid, (var), (val));
#define logfile_top_var_string(var,val) if ((val) != NULL) logfile_append (logfile_ctx, "%s\t%s\t%s",              logfile_ctx->topid,                     (var), (val));
#define logfile_sub_var_string(var,val) if ((val) != NULL) logfile_append (logfile_ctx, "%s\t%s\t%s\t%s",          logfile_ctx->topid, logfile_ctx->subid, (var), (val));

#define logfile_top_uint(var)   logfile_top_var_uint   (#var, (var));
#define logfile_sub_uint(var)   logfile_sub_var_uint   (#var, (var));
#define logfile_top_uint64(var) logfile_top_var_uint64 (#var, (var));
#define logfile_sub_uint64(var) logfile_sub_var_uint64 (#var, (var));
#define logfile_top_char(var)   logfile_top_var_char   (#var, (var));
#define logfile_sub_char(var)   logfile_sub_var_char   (#var, (var));
#define logfile_top_string(var) logfile_top_var_string (#var, (var));
#define logfile_sub_string(var) logfile_sub_var_string (#var, (var));

void logfile_generate_topid (logfile_ctx_t *logfile_ctx);
void logfile_generate_subid (logfile_ctx_t *logfile_ctx);

void logfile_append (const logfile_ctx_t *logfile_ctx, const char *fmt, ...);

void logfile_init (logfile_ctx_t *logfile_ctx, const user_options_t *user_options, const folder_config_t *folder_config);
void logfile_destroy (logfile_ctx_t *logfile_ctx);

#endif // _LOGFILE_H
