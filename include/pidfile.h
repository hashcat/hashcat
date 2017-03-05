/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _PIDFILE_H
#define _PIDFILE_H

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#if defined (_WIN)
#include <windows.h>
#include <psapi.h>
#endif // _WIN

int pidfile_ctx_init (hashcat_ctx_t *hashcat_ctx);

void pidfile_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // _PIDFILE_H
