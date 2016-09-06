/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _LOGFILE_H
#define _LOGFILE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

char *logfile_generate_topid (void);
char *logfile_generate_subid (void);

void logfile_append (const char *fmt, ...);

#endif // _LOGFILE_H
