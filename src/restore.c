/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "timer.h"
#include "memory.h"
#include "logging.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "thread.h"
#include "rp_cpu.h"
#include "hwmon.h"
#include "interface.h"
#include "mpsp.h"
#include "opencl.h"
#include "restore.h"
#include "outfile.h"
#include "potfile.h"
#include "data.h"

extern hc_global_data_t data;

#if defined (_WIN)
static void fsync (int fd)
{
  HANDLE h = (HANDLE) _get_osfhandle (fd);

  FlushFileBuffers (h);
}
#endif

u64 get_lowest_words_done ()
{
  u64 words_cur = -1llu;

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    const u64 words_done = device_param->words_done;

    if (words_done < words_cur) words_cur = words_done;
  }

  // It's possible that a device's workload isn't finished right after a restore-case.
  // In that case, this function would return 0 and overwrite the real restore point
  // There's also data.words_cur which is set to rd->words_cur but it changes while
  // the attack is running therefore we should stick to rd->words_cur.
  // Note that -s influences rd->words_cur we should keep a close look on that.

  if (words_cur < data.rd->words_cur) words_cur = data.rd->words_cur;

  return words_cur;
}

restore_data_t *init_restore (int argc, char **argv)
{
  restore_data_t *rd = (restore_data_t *) mymalloc (sizeof (restore_data_t));

  if (data.restore_disable == 0)
  {
    FILE *fp = fopen (data.eff_restore_file, "rb");

    if (fp)
    {
      size_t nread = fread (rd, sizeof (restore_data_t), 1, fp);

      if (nread != 1)
      {
        log_error ("ERROR: Cannot read %s", data.eff_restore_file);

        exit (-1);
      }

      fclose (fp);

      if (rd->pid)
      {
        char *pidbin = (char *) mymalloc (HCBUFSIZ_LARGE);

        int pidbin_len = -1;

        #if defined (_POSIX)
        snprintf (pidbin, HCBUFSIZ_LARGE - 1, "/proc/%d/cmdline", rd->pid);

        FILE *fd = fopen (pidbin, "rb");

        if (fd)
        {
          pidbin_len = fread (pidbin, 1, HCBUFSIZ_LARGE, fd);

          pidbin[pidbin_len] = 0;

          fclose (fd);

          char *argv0_r = strrchr (argv[0], '/');

          char *pidbin_r = strrchr (pidbin, '/');

          if (argv0_r == NULL) argv0_r = argv[0];

          if (pidbin_r == NULL) pidbin_r = pidbin;

          if (strcmp (argv0_r, pidbin_r) == 0)
          {
            log_error ("ERROR: Already an instance %s running on pid %d", pidbin, rd->pid);

            exit (-1);
          }
        }

        #elif defined (_WIN)
        HANDLE hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, rd->pid);

        char *pidbin2 = (char *) mymalloc (HCBUFSIZ_LARGE);

        int pidbin2_len = -1;

        pidbin_len = GetModuleFileName (NULL, pidbin, HCBUFSIZ_LARGE);
        pidbin2_len = GetModuleFileNameEx (hProcess, NULL, pidbin2, HCBUFSIZ_LARGE);

        pidbin[pidbin_len] = 0;
        pidbin2[pidbin2_len] = 0;

        if (pidbin2_len)
        {
          if (strcmp (pidbin, pidbin2) == 0)
          {
            log_error ("ERROR: Already an instance %s running on pid %d", pidbin2, rd->pid);

            exit (-1);
          }
        }

        myfree (pidbin2);

        #endif

        myfree (pidbin);
      }

      if (rd->version < RESTORE_VERSION_MIN)
      {
        log_error ("ERROR: Cannot use outdated %s. Please remove it.", data.eff_restore_file);

        exit (-1);
      }
    }
  }

  memset (rd, 0, sizeof (restore_data_t));

  rd->version = RESTORE_VERSION_CUR;

  #if defined (_POSIX)
  rd->pid = getpid ();
  #elif defined (_WIN)
  rd->pid = GetCurrentProcessId ();
  #endif

  if (getcwd (rd->cwd, 255) == NULL)
  {
    myfree (rd);

    return (NULL);
  }

  rd->argc = argc;
  rd->argv = argv;

  return (rd);
}

void read_restore (const char *eff_restore_file, restore_data_t *rd)
{
  FILE *fp = fopen (eff_restore_file, "rb");

  if (fp == NULL)
  {
    log_error ("ERROR: Restore file '%s': %s", eff_restore_file, strerror (errno));

    exit (-1);
  }

  if (fread (rd, sizeof (restore_data_t), 1, fp) != 1)
  {
    log_error ("ERROR: Can't read %s", eff_restore_file);

    exit (-1);
  }

  rd->argv = (char **) mycalloc (rd->argc, sizeof (char *));

  char *buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  for (uint i = 0; i < rd->argc; i++)
  {
    if (fgets (buf, HCBUFSIZ_LARGE - 1, fp) == NULL)
    {
      log_error ("ERROR: Can't read %s", eff_restore_file);

      exit (-1);
    }

    size_t len = strlen (buf);

    if (len) buf[len - 1] = 0;

    rd->argv[i] = mystrdup (buf);
  }

  myfree (buf);

  fclose (fp);

  log_info ("INFO: Changing current working directory to the path found within the .restore file: '%s'", rd->cwd);

  if (chdir (rd->cwd))
  {
    log_error ("ERROR: The directory '%s' does not exist. It is needed to restore (--restore) the session.\n"
               "       You could either create this directory (or link it) or update the .restore file using e.g. the analyze_hc_restore.pl tool:\n"
               "       https://github.com/philsmd/analyze_hc_restore\n"
               "       The directory must be relative to (or contain) all files/folders mentioned within the command line.", rd->cwd);

    exit (-1);
  }
}

void write_restore (const char *new_restore_file, restore_data_t *rd)
{
  u64 words_cur = get_lowest_words_done ();

  rd->words_cur = words_cur;

  FILE *fp = fopen (new_restore_file, "wb");

  if (fp == NULL)
  {
    log_error ("ERROR: %s: %s", new_restore_file, strerror (errno));

    exit (-1);
  }

  if (setvbuf (fp, NULL, _IONBF, 0))
  {
    log_error ("ERROR: setvbuf file '%s': %s", new_restore_file, strerror (errno));

    exit (-1);
  }

  fwrite (rd, sizeof (restore_data_t), 1, fp);

  for (uint i = 0; i < rd->argc; i++)
  {
    fprintf (fp, "%s", rd->argv[i]);
    fputc ('\n', fp);
  }

  fflush (fp);

  fsync (fileno (fp));

  fclose (fp);
}

void cycle_restore ()
{
  const char *eff_restore_file = data.eff_restore_file;
  const char *new_restore_file = data.new_restore_file;

  restore_data_t *rd = data.rd;

  write_restore (new_restore_file, rd);

  struct stat st;

  memset (&st, 0, sizeof(st));

  if (stat (eff_restore_file, &st) == 0)
  {
    if (unlink (eff_restore_file))
    {
      log_info ("WARN: Unlink file '%s': %s", eff_restore_file, strerror (errno));
    }
  }

  if (rename (new_restore_file, eff_restore_file))
  {
    log_info ("WARN: Rename file '%s' to '%s': %s", new_restore_file, eff_restore_file, strerror (errno));
  }
}
