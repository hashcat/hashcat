/**
 * Author......: Jens Steube <jens.steube@gmail.com>
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

#define STDOUT_FLAG 0

typedef struct
{
  FILE *fp;

  char  buf[BUFSIZ];
  int   len;

} out_t;

void process_stdout (hc_device_param_t *device_param, const uint pws_cnt);

#endif // _STDOUT_H
