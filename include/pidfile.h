/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _PIDFILE_H
#define _PIDFILE_H

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#if defined (__unix__)
#include <sys/types.h>
#include <sys/stat.h>
#endif // __unix__

#if defined (__WIN32__)
#include <windows.h>
#include <psapi.h>
#endif // __WIN32__

void unlink_pidfile (hashcat_ctx_t *hashcat_ctx);

int pidfile_ctx_init (hashcat_ctx_t *hashcat_ctx);

void pidfile_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // _PIDFILE_H
