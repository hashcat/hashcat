/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#pragma once

#include <stdio.h>
#include <stdarg.h>

int log_out_nn (FILE *fp, const char *fmt, ...);
int log_info_nn (const char *fmt, ...);
int log_error_nn (const char *fmt, ...);

int log_out (FILE *fp, const char *fmt, ...);
int log_info (const char *fmt, ...);
int log_error (const char *fmt, ...);
