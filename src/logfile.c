#include <common.h>
#include <logfile.h>
#include <hc_global_data_t.h>
#include <hc_global.h>

FILE *logfile_open(char *logfile)
{
  FILE *fp = fopen(logfile, "ab");

  if (fp == NULL)
  {
    fp = stdout;
  }

  return fp;
}

void logfile_close(FILE *fp)
{
  if (fp == stdout) return;

  fclose(fp);
}

void logfile_append(const char *fmt, ...)
{
  if (data.logfile_disable == 1) return;

  FILE *fp = logfile_open(data.logfile);

  va_list ap;

  va_start(ap, fmt);

  vfprintf(fp, fmt, ap);

  va_end(ap);

  fputc('\n', fp);

  fflush(fp);

  logfile_close(fp);
}

int logfile_generate_id()
{
  const int n = rand();

  time_t t;

  time(&t);

  return t + n;
}

char *logfile_generate_topid()
{
  const int id = logfile_generate_id();

  char *topid = (char *)mymalloc(1 + 16 + 1);

  snprintf(topid, 1 + 16, "TOP%08x", id);

  return topid;
}

char *logfile_generate_subid()
{
  const int id = logfile_generate_id();

  char *subid = (char *)mymalloc(1 + 16 + 1);

  snprintf(subid, 1 + 16, "SUB%08x", id);

  return subid;
}
