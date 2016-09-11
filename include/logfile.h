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

#define LOGFILE_DISABLE 0

// logfile_append() checks for logfile_disable internally to make it easier from here

#define logfile_top_msg(msg)                               logfile_append ("%s\t%s",                  data.topid,             (msg));
#define logfile_sub_msg(msg)                               logfile_append ("%s\t%s\t%s",              data.topid, data.subid, (msg));
#define logfile_top_var_uint64(var,val)                    logfile_append ("%s\t%s\t%" PRIu64 "",     data.topid,             (var), (val));
#define logfile_sub_var_uint64(var,val)                    logfile_append ("%s\t%s\t%s\t%" PRIu64 "", data.topid, data.subid, (var), (val));
#define logfile_top_var_uint(var,val)                      logfile_append ("%s\t%s\t%u",              data.topid,             (var), (val));
#define logfile_sub_var_uint(var,val)                      logfile_append ("%s\t%s\t%s\t%u",          data.topid, data.subid, (var), (val));
#define logfile_top_var_char(var,val)                      logfile_append ("%s\t%s\t%c",              data.topid,             (var), (val));
#define logfile_sub_var_char(var,val)                      logfile_append ("%s\t%s\t%s\t%c",          data.topid, data.subid, (var), (val));
#define logfile_top_var_string(var,val) if ((val) != NULL) logfile_append ("%s\t%s\t%s",              data.topid,             (var), (val));
#define logfile_sub_var_string(var,val) if ((val) != NULL) logfile_append ("%s\t%s\t%s\t%s",          data.topid, data.subid, (var), (val));

#define logfile_top_uint64(var) logfile_top_var_uint64 (#var, (var));
#define logfile_sub_uint64(var) logfile_sub_var_uint64 (#var, (var));
#define logfile_top_uint(var)   logfile_top_var_uint   (#var, (var));
#define logfile_sub_uint(var)   logfile_sub_var_uint   (#var, (var));
#define logfile_top_char(var)   logfile_top_var_char   (#var, (var));
#define logfile_sub_char(var)   logfile_sub_var_char   (#var, (var));
#define logfile_top_string(var) logfile_top_var_string (#var, (var));
#define logfile_sub_string(var) logfile_sub_var_string (#var, (var));

char *logfile_generate_topid (void);
char *logfile_generate_subid (void);

void logfile_append (const char *fmt, ...);

#endif // _LOGFILE_H
