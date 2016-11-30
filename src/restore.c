/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "user_options.h"
#include "shared.h"
#include "restore.h"

#if defined (_WIN)
static void fsync (int fd)
{
  HANDLE h = (HANDLE) _get_osfhandle (fd);

  FlushFileBuffers (h);
}
#endif

static int check_running_process (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  char *eff_restore_file = restore_ctx->eff_restore_file;

  FILE *fp = fopen (eff_restore_file, "rb");

  if (fp == NULL) return 0;

  restore_data_t *rd = (restore_data_t *) hcmalloc (sizeof (restore_data_t));

  const size_t nread = fread (rd, sizeof (restore_data_t), 1, fp);

  fclose (fp);

  if (nread != 1)
  {
    event_log_error (hashcat_ctx, "Cannot read %s", eff_restore_file);

    return -1;
  }

  if (rd->pid)
  {
    #if defined (_POSIX)

    char *pidbin = (char *) hcmalloc (HCBUFSIZ_LARGE);

    snprintf (pidbin, HCBUFSIZ_LARGE - 1, "/proc/%u/cmdline", rd->pid);

    FILE *fd = fopen (pidbin, "rb");

    if (fd)
    {
      size_t pidbin_len = fread (pidbin, 1, HCBUFSIZ_LARGE, fd);

      pidbin[pidbin_len] = 0;

      fclose (fd);

      char *argv0_r = strrchr (restore_ctx->argv[0], '/');

      char *pidbin_r = strrchr (pidbin, '/');

      if (argv0_r == NULL) argv0_r = restore_ctx->argv[0];

      if (pidbin_r == NULL) pidbin_r = pidbin;

      if (strcmp (argv0_r, pidbin_r) == 0)
      {
        event_log_error (hashcat_ctx, "Already an instance %s running on pid %u", pidbin, rd->pid);

        return -1;
      }
    }

    hcfree (pidbin);

    #elif defined (_WIN)

    HANDLE hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, rd->pid);

    char *pidbin  = (char *) hcmalloc (HCBUFSIZ_LARGE);
    char *pidbin2 = (char *) hcmalloc (HCBUFSIZ_LARGE);

    int pidbin_len  = GetModuleFileName (NULL, pidbin, HCBUFSIZ_LARGE);
    int pidbin2_len = GetModuleFileNameEx (hProcess, NULL, pidbin2, HCBUFSIZ_LARGE);

    pidbin[pidbin_len]   = 0;
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
    hcfree (pidbin);

    #endif
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

  restore_data_t *rd = (restore_data_t *) hcmalloc (sizeof (restore_data_t));

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

    fclose (fp);

    return -1;
  }

  rd->argv = (char **) hccalloc (rd->argc, sizeof (char *));

  char *buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  for (u32 i = 0; i < rd->argc; i++)
  {
    if (fgets (buf, HCBUFSIZ_LARGE - 1, fp) == NULL)
    {
      event_log_error (hashcat_ctx, "Can't read %s", eff_restore_file);

      fclose (fp);

      return -1;
    }

    size_t len = strlen (buf);

    if (len) buf[len - 1] = 0;

    rd->argv[i] = hcstrdup (buf);
  }

  hcfree (buf);

  fclose (fp);

  event_log_warning (hashcat_ctx, "Changing current working directory to '%s'", rd->cwd);
  event_log_warning (hashcat_ctx, "");

  if (chdir (rd->cwd))
  {
    event_log_error (hashcat_ctx, "The directory '%s' does not exist. It is needed to restore (--restore) the session.", rd->cwd);
    event_log_error (hashcat_ctx, "You could either create this directory or update the .restore file using e.g. the analyze_hc_restore.pl tool:");
    event_log_error (hashcat_ctx, "https://github.com/philsmd/analyze_hc_restore");
    event_log_error (hashcat_ctx, "The directory must contain all files and folders mentioned within the command line.");

    return -1;
  }

  return 0;
}

static int write_restore (hashcat_ctx_t *hashcat_ctx)
{
  const mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  const restore_ctx_t  *restore_ctx  = hashcat_ctx->restore_ctx;
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

  if (restore_ctx->enabled == false) return 0;

  restore_data_t *rd = restore_ctx->rd;

  rd->masks_pos = mask_ctx->masks_pos;
  rd->dicts_pos = straight_ctx->dicts_pos;
  rd->words_cur = status_ctx->words_cur;

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

    fclose (fp);

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

  rd->masks_pos = 0;
  rd->dicts_pos = 0;
  rd->words_cur = 0;

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

  hc_stat_t st;

  if (hc_stat (eff_restore_file, &st) == 0)
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

  if (restore_ctx->enabled == false) return;

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

int restore_ctx_init (hashcat_ctx_t *hashcat_ctx, int argc, char **argv)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  restore_ctx_t   *restore_ctx   = hashcat_ctx->restore_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  restore_ctx->enabled = false;

  if (user_options->benchmark       == true) return 0;
  if (user_options->keyspace        == true) return 0;
  if (user_options->left            == true) return 0;
  if (user_options->opencl_info     == true) return 0;
  if (user_options->show            == true) return 0;
  if (user_options->stdout_flag     == true) return 0;
  if (user_options->speed_only      == true) return 0;
  if (user_options->usage           == true) return 0;
  if (user_options->version         == true) return 0;
  if (user_options->restore_disable == true) return 0;

  if (argc ==    0) return 0;
  if (argv == NULL) return 0;

  if (user_options->restore_file_path == NULL)
  {
    restore_ctx->eff_restore_file = (char *) hcmalloc (HCBUFSIZ_TINY);
    restore_ctx->new_restore_file = (char *) hcmalloc (HCBUFSIZ_TINY);

    snprintf (restore_ctx->eff_restore_file, HCBUFSIZ_TINY - 1, "%s/%s.restore",     folder_config->session_dir, user_options->session);
    snprintf (restore_ctx->new_restore_file, HCBUFSIZ_TINY - 1, "%s/%s.restore.new", folder_config->session_dir, user_options->session);
  }
  else
  {
    restore_ctx->eff_restore_file = hcstrdup (user_options->restore_file_path);
    restore_ctx->new_restore_file = (char *) hcmalloc (HCBUFSIZ_TINY);

    snprintf (restore_ctx->new_restore_file, HCBUFSIZ_TINY - 1, "%s.new", user_options->restore_file_path);
  }

  restore_ctx->argc = argc;
  restore_ctx->argv = argv;

  const int rc_init_restore = init_restore (hashcat_ctx);

  if (rc_init_restore == -1) return -1;

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

  if (restore_ctx->enabled == false) return;

  hcfree (restore_ctx->eff_restore_file);
  hcfree (restore_ctx->new_restore_file);

  hcfree (restore_ctx->rd);

  memset (restore_ctx, 0, sizeof (restore_ctx_t));
}
