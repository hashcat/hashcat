/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _STDOUT_H
#define _STDOUT_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <search.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>

#if defined (_POSIX)
#include <pthread.h>
#include <pwd.h>
#endif // _POSIX

void process_stdout (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const user_options_t *user_options, const rules_ctx_t *rules_ctx, const mask_ctx_t *mask_ctx, const uint pws_cnt);

#endif // _STDOUT_H
