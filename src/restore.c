/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "user_options.h"
#include "restore.h"

#if defined (_WIN)
static void fsync (int fd)
{
  HANDLE h = (HANDLE) _get_osfhandle (fd);

  FlushFileBuffers (h);
}
#endif

u64 get_lowest_words_done (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;
  opencl_ctx_t  *opencl_ctx  = hashcat_ctx->opencl_ctx;

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

static int check_running_process (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  char *eff_restore_file = restore_ctx->eff_restore_file;

  FILE *fp = fopen (eff_restore_file, "rb");

  if (fp == NULL) return 0;

  restore_data_t *rd = (restore_data_t *) hcmalloc (hashcat_ctx, sizeof (restore_data_t)); VERIFY_PTR (rd);

  const size_t nread = fread (rd, sizeof (restore_data_t), 1, fp);

  if (nread != 1)
  {
    event_log_error (hashcat_ctx, "Cannot read %s", eff_restore_file);

    return -1;
  }

  fclose (fp);

  if (rd->pid)
  {
    char *pidbin = (char *) hcmalloc (hashcat_ctx, HCBUFSIZ_LARGE); VERIFY_PTR (pidbin);

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
        event_log_error (hashcat_ctx, "Already an instance %s running on pid %d", pidbin, rd->pid);

        return -1;
      }
    }

    #elif defined (_WIN)
    HANDLE hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, rd->pid);

    char *pidbin2 = (char *) hcmalloc (hashcat_ctx, HCBUFSIZ_LARGE); VERIFY_PTR (pidbin2);

    int pidbin2_len = -1;

    pidbin_len = GetModuleFileName (NULL, pidbin, HCBUFSIZ_LARGE);
    pidbin2_len = GetModuleFileNameEx (hProcess, NULL, pidbin2, HCBUFSIZ_LARGE);

    pidbin[pidbin_len] = 0;
    pidbin2[pidbin2_len] = 0;

    if (pidbin2_len)
    {
      if (strcmp (pidbin, pidbin2) == 0)
      {
        event_log_error (hashcat_ctx, "Already an instance %s running on pid %d", pidbin2, rd->pid);

        return -1;
      }
    }

    hcfree (pidbin2);

    #endif

    hcfree (pidbin);
  }

  if (rd->version < RESTORE_VERSION_MIN)
  {
    event_log_error (hashcat_ctx, "Cannot use outdated %s. Please remove it.", eff_restore_file);

    return -1;
  }

  hcfree (rd);

  return 0;
}

static int init_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  restore_data_t *rd = (restore_data_t *) hcmalloc (hashcat_ctx, sizeof (restore_data_t)); VERIFY_PTR (rd);

  restore_ctx->rd = rd;

  const int rc = check_running_process (hashcat_ctx);

  if (rc == -1) return -1;

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
    event_log_error (hashcat_ctx, "getcwd(): %s", strerror (errno));

    return -1;
  }

  return 0;
}

static int read_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  if (restore_ctx->enabled == false) return 0;

  char *eff_restore_file = restore_ctx->eff_restore_file;

  FILE *fp = fopen (eff_restore_file, "rb");

  if (fp == NULL)
  {
    event_log_error (hashcat_ctx, "Restore file '%s': %s", eff_restore_file, strerror (errno));

    return -1;
  }

  restore_data_t *rd = restore_ctx->rd;

  if (fread (rd, sizeof (restore_data_t), 1, fp) != 1)
  {
    event_log_error (hashcat_ctx, "Can't read %s", eff_restore_file);

    return -1;
  }

  rd->argv = (char **) hccalloc (hashcat_ctx, rd->argc, sizeof (char *)); VERIFY_PTR (rd->argv);

  char *buf = (char *) hcmalloc (hashcat_ctx, HCBUFSIZ_LARGE); VERIFY_PTR (buf);

  for (u32 i = 0; i < rd->argc; i++)
  {
    if (fgets (buf, HCBUFSIZ_LARGE - 1, fp) == NULL)
    {
      event_log_error (hashcat_ctx, "Can't read %s", eff_restore_file);

      return -1;
    }

    size_t len = strlen (buf);

    if (len) buf[len - 1] = 0;

    rd->argv[i] = hcstrdup (hashcat_ctx, buf);
  }

  hcfree (buf);

  fclose (fp);

  event_log_info (hashcat_ctx, "INFO: Changing current working directory to '%s'", rd->cwd);
  event_log_info (hashcat_ctx, "");

  if (chdir (rd->cwd))
  {
    event_log_error (hashcat_ctx,
      "The directory '%s' does not exist. It is needed to restore (--restore) the session." EOL
      "You could either create this directory or update the .restore file using e.g. the analyze_hc_restore.pl tool:" EOL
      "https://github.com/philsmd/analyze_hc_restore" EOL
      "The directory must contain all files and folders mentioned within the command line.", rd->cwd);

    return -1;
  }

  return 0;
}

static int write_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  if (restore_ctx->enabled == false) return 0;

  const u64 words_cur = get_lowest_words_done (hashcat_ctx);

  restore_data_t *rd = restore_ctx->rd;

  rd->words_cur = words_cur;

  char *new_restore_file = restore_ctx->new_restore_file;

  FILE *fp = fopen (new_restore_file, "wb");

  if (fp == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", new_restore_file, strerror (errno));

    return -1;
  }

  if (setvbuf (fp, NULL, _IONBF, 0))
  {
    event_log_error (hashcat_ctx, "setvbuf file '%s': %s", new_restore_file, strerror (errno));

    return -1;
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

  return 0;
}

int cycle_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  if (restore_ctx->enabled == false) return 0;

  const char *eff_restore_file = restore_ctx->eff_restore_file;
  const char *new_restore_file = restore_ctx->new_restore_file;

  const int rc_write_restore = write_restore (hashcat_ctx);

  if (rc_write_restore == -1) return -1;

  struct stat st;

  if (stat (eff_restore_file, &st) == 0)
  {
    if (unlink (eff_restore_file))
    {
      event_log_warning (hashcat_ctx, "Unlink file '%s': %s", eff_restore_file, strerror (errno));
    }
  }

  if (rename (new_restore_file, eff_restore_file))
  {
    event_log_warning (hashcat_ctx, "Rename file '%s' to '%s': %s", new_restore_file, eff_restore_file, strerror (errno));
  }

  return 0;
}

void unlink_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;
  status_ctx_t  *status_ctx  = hashcat_ctx->status_ctx;

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

void stop_at_checkpoint (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;
  status_ctx_t  *status_ctx  = hashcat_ctx->status_ctx;

  // this feature only makes sense if --restore-disable was not specified

  if (restore_ctx->enabled == false)
  {
    event_log_warning (hashcat_ctx, "This feature is disabled when --restore-disable is specified");

    return;
  }

  if (status_ctx->devices_status != STATUS_RUNNING) return;

  if ((status_ctx->run_thread_level1 == true) && (status_ctx->run_thread_level2 == true))
  {
    status_ctx->run_main_level2   = false;
    status_ctx->run_main_level3   = false;
    status_ctx->run_thread_level1 = false;
    status_ctx->run_thread_level2 = true;

    event_log_info (hashcat_ctx, "Checkpoint enabled: Will quit at next Restore Point update");
  }
  else
  {
    status_ctx->run_main_level2   = true;
    status_ctx->run_main_level3   = true;
    status_ctx->run_thread_level1 = true;
    status_ctx->run_thread_level2 = true;

    event_log_info (hashcat_ctx, "Checkpoint disabled: Restore Point updates will no longer be monitored");
  }
}

int restore_ctx_init (hashcat_ctx_t *hashcat_ctx, int argc, char **argv)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  restore_ctx_t   *restore_ctx   = hashcat_ctx->restore_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  restore_ctx->enabled = false;

  char *eff_restore_file = (char *) hcmalloc (hashcat_ctx, HCBUFSIZ_TINY); VERIFY_PTR (eff_restore_file);
  char *new_restore_file = (char *) hcmalloc (hashcat_ctx, HCBUFSIZ_TINY); VERIFY_PTR (new_restore_file);

  snprintf (eff_restore_file, HCBUFSIZ_TINY - 1, "%s/%s.restore",     folder_config->session_dir, user_options->session);
  snprintf (new_restore_file, HCBUFSIZ_TINY - 1, "%s/%s.restore.new", folder_config->session_dir, user_options->session);

  restore_ctx->argc = argc;
  restore_ctx->argv = argv;

  restore_ctx->eff_restore_file = eff_restore_file;
  restore_ctx->new_restore_file = new_restore_file;

  const int rc_init_restore = init_restore (hashcat_ctx);

  if (rc_init_restore == -1) return -1;

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
    const int rc_read_restore = read_restore (hashcat_ctx);

    if (rc_read_restore == -1) return -1;

    restore_data_t *rd = restore_ctx->rd;

    if (rd->version < RESTORE_VERSION_MIN)
    {
      event_log_error (hashcat_ctx, "Incompatible restore-file version");

      return -1;
    }

    #if defined (_POSIX)
    rd->pid = getpid ();
    #elif defined (_WIN)
    rd->pid = GetCurrentProcessId ();
    #endif

    user_options_init (hashcat_ctx);

    const int rc_options_getopt = user_options_getopt (hashcat_ctx, rd->argc, rd->argv);

    if (rc_options_getopt == -1) return -1;
  }

  return 0;
}

void restore_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  hcfree (restore_ctx->eff_restore_file);
  hcfree (restore_ctx->new_restore_file);

  hcfree (restore_ctx->rd);

  if (restore_ctx->enabled == false) return;

  memset (restore_ctx, 0, sizeof (restore_ctx_t));
}
