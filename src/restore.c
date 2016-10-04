/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "user_options.h"
#include "restore.h"

#if defined (_WIN)
static void fsync (int fd)
{
  HANDLE h = (HANDLE) _get_osfhandle (fd);

  FlushFileBuffers (h);
}
#endif

u64 get_lowest_words_done (const restore_ctx_t *restore_ctx, const opencl_ctx_t *opencl_ctx)
{
  if (restore_ctx->enabled == false) return 0;

  restore_data_t *rd = restore_ctx->rd;

  u64 words_cur = -1llu;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    const u64 words_done = device_param->words_done;

    if (words_done < words_cur) words_cur = words_done;
  }

  // It's possible that a device's workload isn't finished right after a restore-case.
  // In that case, this function would return 0 and overwrite the real restore point
  // There's also status_ctx->words_cur which is set to rd->words_cur but it changes while
  // the attack is running therefore we should stick to rd->words_cur.
  // Note that -s influences rd->words_cur we should keep a close look on that.

  if (words_cur < rd->words_cur) words_cur = rd->words_cur;

  return words_cur;
}

static void check_running_process (restore_ctx_t *restore_ctx)
{
  char *eff_restore_file = restore_ctx->eff_restore_file;

  FILE *fp = fopen (eff_restore_file, "rb");

  if (fp == NULL) return;

  restore_data_t *rd = (restore_data_t *) mymalloc (sizeof (restore_data_t));

  const size_t nread = fread (rd, sizeof (restore_data_t), 1, fp);

  if (nread != 1)
  {
    log_error ("ERROR: Cannot read %s", eff_restore_file);

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

      char *argv0_r = strrchr (restore_ctx->argv[0], '/');

      char *pidbin_r = strrchr (pidbin, '/');

      if (argv0_r == NULL) argv0_r = restore_ctx->argv[0];

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
    log_error ("ERROR: Cannot use outdated %s. Please remove it.", eff_restore_file);

    exit (-1);
  }

  myfree (rd);
}

void init_restore (restore_ctx_t *restore_ctx)
{
  restore_data_t *rd = (restore_data_t *) mymalloc (sizeof (restore_data_t));

  restore_ctx->rd = rd;

  check_running_process (restore_ctx);

  rd->version = RESTORE_VERSION_CUR;

  rd->argc = restore_ctx->argc;
  rd->argv = restore_ctx->argv;

  #if defined (_POSIX)
  rd->pid = getpid ();
  #elif defined (_WIN)
  rd->pid = GetCurrentProcessId ();
  #endif

  if (getcwd (rd->cwd, 255) == NULL)
  {
    log_error ("ERROR: getcwd(): %s", strerror (errno));

    exit (-1);
  }
}

void read_restore (restore_ctx_t *restore_ctx)
{
  if (restore_ctx->enabled == false) return;

  char *eff_restore_file = restore_ctx->eff_restore_file;

  FILE *fp = fopen (eff_restore_file, "rb");

  if (fp == NULL)
  {
    log_error ("ERROR: Restore file '%s': %s", eff_restore_file, strerror (errno));

    exit (-1);
  }

  restore_data_t *rd = restore_ctx->rd;

  if (fread (rd, sizeof (restore_data_t), 1, fp) != 1)
  {
    log_error ("ERROR: Can't read %s", eff_restore_file);

    exit (-1);
  }

  rd->argv = (char **) mycalloc (rd->argc, sizeof (char *));

  char *buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  for (u32 i = 0; i < rd->argc; i++)
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

void write_restore (restore_ctx_t *restore_ctx, opencl_ctx_t *opencl_ctx)
{
  if (restore_ctx->enabled == false) return;

  const u64 words_cur = get_lowest_words_done (restore_ctx, opencl_ctx);

  restore_data_t *rd = restore_ctx->rd;

  rd->words_cur = words_cur;

  char *new_restore_file = restore_ctx->new_restore_file;

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

  for (u32 i = 0; i < rd->argc; i++)
  {
    fprintf (fp, "%s", rd->argv[i]);

    fputc ('\n', fp);
  }

  fflush (fp);

  fsync (fileno (fp));

  fclose (fp);
}

void cycle_restore (restore_ctx_t *restore_ctx, opencl_ctx_t *opencl_ctx)
{
  if (restore_ctx->enabled == false) return;

  const char *eff_restore_file = restore_ctx->eff_restore_file;
  const char *new_restore_file = restore_ctx->new_restore_file;

  write_restore (restore_ctx, opencl_ctx);

  struct stat st;

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

void unlink_restore (restore_ctx_t *restore_ctx, status_ctx_t *status_ctx)
{
  if ((status_ctx->devices_status == STATUS_EXHAUSTED) && (status_ctx->run_thread_level1 == true)) // this is to check for [c]heckpoint
  {
    unlink (restore_ctx->eff_restore_file);
    unlink (restore_ctx->new_restore_file);
  }

  if (status_ctx->devices_status == STATUS_CRACKED)
  {
    unlink (restore_ctx->eff_restore_file);
    unlink (restore_ctx->new_restore_file);
  }
}

void stop_at_checkpoint (restore_ctx_t *restore_ctx, status_ctx_t *status_ctx)
{
  // this feature only makes sense if --restore-disable was not specified

  if (restore_ctx->enabled == false)
  {
    log_info ("WARNING: This feature is disabled when --restore-disable is specified");

    return;
  }

  if (status_ctx->devices_status != STATUS_RUNNING) return;

  if ((status_ctx->run_thread_level1 == true) && (status_ctx->run_thread_level2 == true))
  {
    status_ctx->run_main_level1   = false;
    status_ctx->run_main_level2   = false;
    status_ctx->run_main_level3   = false;
    status_ctx->run_thread_level1 = false;
    status_ctx->run_thread_level2 = true;

    log_info ("Checkpoint enabled: Will quit at next Restore Point update");
  }
  else
  {
    status_ctx->run_main_level1   = true;
    status_ctx->run_main_level2   = true;
    status_ctx->run_main_level3   = true;
    status_ctx->run_thread_level1 = true;
    status_ctx->run_thread_level2 = true;

    log_info ("Checkpoint disabled: Restore Point updates will no longer be monitored");
  }
}

int restore_ctx_init (restore_ctx_t *restore_ctx, user_options_t *user_options, const folder_config_t *folder_config, int argc, char **argv)
{
  restore_ctx->enabled = false;

  char *eff_restore_file = (char *) mymalloc (HCBUFSIZ_TINY);
  char *new_restore_file = (char *) mymalloc (HCBUFSIZ_TINY);

  snprintf (eff_restore_file, HCBUFSIZ_TINY - 1, "%s/%s.restore",     folder_config->session_dir, user_options->session);
  snprintf (new_restore_file, HCBUFSIZ_TINY - 1, "%s/%s.restore.new", folder_config->session_dir, user_options->session);

  restore_ctx->argc = argc;
  restore_ctx->argv = argv;

  restore_ctx->eff_restore_file = eff_restore_file;
  restore_ctx->new_restore_file = new_restore_file;

  init_restore (restore_ctx);

  if (argc ==    0) return 0;
  if (argv == NULL) return 0;

  if (user_options->benchmark       == true) return 0;
  if (user_options->keyspace        == true) return 0;
  if (user_options->left            == true) return 0;
  if (user_options->opencl_info     == true) return 0;
  if (user_options->show            == true) return 0;
  if (user_options->stdout_flag     == true) return 0;
  if (user_options->usage           == true) return 0;
  if (user_options->version         == true) return 0;
  if (user_options->restore_disable == true) return 0;

  restore_ctx->enabled = true;

  if (user_options->restore == true)
  {
    read_restore (restore_ctx);

    restore_data_t *rd = restore_ctx->rd;

    if (rd->version < RESTORE_VERSION_MIN)
    {
      log_error ("ERROR: Incompatible restore-file version");

      return -1;
    }

    #if defined (_POSIX)
    rd->pid = getpid ();
    #elif defined (_WIN)
    rd->pid = GetCurrentProcessId ();
    #endif

    user_options_init (user_options);

    const int rc_options_getopt = user_options_getopt (user_options, rd->argc, rd->argv);

    if (rc_options_getopt == -1) return -1;
  }

  return 0;
}

void restore_ctx_destroy (restore_ctx_t *restore_ctx)
{
  myfree (restore_ctx->eff_restore_file);
  myfree (restore_ctx->new_restore_file);

  myfree (restore_ctx->rd);

  if (restore_ctx->enabled == false) return;

  memset (restore_ctx, 0, sizeof (restore_ctx_t));
}
