/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _LOGGING_H
#define _LOGGING_H

#include <stdio.h>
#include <stdarg.h>

int log_out_nn (FILE *fp, const char *fmt, ...);
int log_info_nn (const char *fmt, ...);
int log_error_nn (const char *fmt, ...);

int log_out (FILE *fp, const char *fmt, ...);
int log_info (const char *fmt, ...);
int log_error (const char *fmt, ...);

#endif // _LOGGING_H
