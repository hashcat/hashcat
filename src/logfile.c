/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "timer.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "types.h"
#include "memory.h"
#include "hwmon.h"
#include "rp_cpu.h"
#include "interface.h"
#include "mpsp.h"
#include "opencl.h"
#include "restore.h"
#include "outfile.h"
#include "potfile.h"
#include "loopback.h"
#include "data.h"
#include "logfile.h"

extern hc_global_data_t data;

static FILE *logfile_open (char *logfile)
{
  FILE *fp = fopen (logfile, "ab");

  if (fp == NULL)
  {
    fp = stdout;
  }

  return fp;
}

static void logfile_close (FILE *fp)
{
  if (fp == stdout) return;

  fclose (fp);
}

void logfile_append (const char *fmt, ...)
{
  if (data.logfile_disable == 1) return;

  FILE *fp = logfile_open (data.logfile);

  va_list ap;

  va_start (ap, fmt);

  vfprintf (fp, fmt, ap);

  va_end (ap);

  fputc ('\n', fp);

  fflush (fp);

  logfile_close (fp);
}

static int logfile_generate_id ()
{
  const int n = rand ();

  time_t t;

  time (&t);

  return t + n;
}

char *logfile_generate_topid ()
{
  const int id = logfile_generate_id ();

  char *topid = (char *) mymalloc (1 + 16 + 1);

  snprintf (topid, 1 + 16, "TOP%08x", id);

  return topid;
}

char *logfile_generate_subid ()
{
  const int id = logfile_generate_id ();

  char *subid = (char *) mymalloc (1 + 16 + 1);

  snprintf (subid, 1 + 16, "SUB%08x", id);

  return subid;
}
