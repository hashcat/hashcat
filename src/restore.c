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
#include "filehandling.h"
#include "path.h"
#include "pidfile.h"
#include "folder.h"
#include "restore.h"

static int init_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  restore_data_t *rd = (restore_data_t *) hcmalloc (sizeof (restore_data_t));

  restore_ctx->rd = rd;

  rd->version = RESTORE_VERSION_CUR;

  rd->argc = restore_ctx->argc;
  rd->argv = restore_ctx->argv;

  if (getcwd (rd->cwd, 255) == NULL)
  {
    event_log_error (hashcat_ctx, "getcwd(): %s", strerror (errno));

    return -1;
  }

  return 0;
}

// Everything that comes out of the restore file is shown to the user before it is acted on, and the
// file can hold any byte at all. A terminal escape sequence in there would let the file decide what
// the screen says about it, so anything outside printable ASCII is written as \xNN instead.

static char *restore_str_escape (const char *src)
{
  const size_t src_len = strlen (src);

  char *dst = (char *) hcmalloc ((src_len * 4) + 1);

  size_t dst_len = 0;

  for (size_t i = 0; i < src_len; i++)
  {
    const u8 c = (u8) src[i];

    if ((c >= 0x20) && (c <= 0x7e))
    {
      dst[dst_len] = (char) c;

      dst_len++;

      continue;
    }

    snprintf (&dst[dst_len], 5, "\\x%02x", c);

    dst_len += 4;
  }

  dst[dst_len] = 0;

  return dst;
}

// The command line printed for --restore is meant to be pasted into a shell, which is somewhere the
// arguments in the file have never been. Quoting them is not cosmetic. An argument holding
// '; rm -rf ~; ' would otherwise turn something the file controls into something the shell runs, and
// that would be a worse hole than the one being closed.
//
// A word built only out of the characters below means the same thing quoted or not, and nearly all of
// a hashcat command line is built out of exactly those. Anything else is wrapped, in single quotes on
// a POSIX shell where every byte inside is literal, and in double quotes on Windows because cmd.exe
// does not take single ones.

static bool restore_char_is_bare (const char c)
{
  if ((c >= 'A') && (c <= 'Z')) return true;
  if ((c >= 'a') && (c <= 'z')) return true;
  if ((c >= '0') && (c <= '9')) return true;

  if (strchr ("_./=:,@+-", c) != NULL) return true;

  return false;
}

static char *restore_shell_quote (const char *src)
{
  const size_t src_len = strlen (src);

  bool bare = (src_len > 0);

  for (size_t i = 0; i < src_len; i++)
  {
    if (restore_char_is_bare (src[i]) == true) continue;

    bare = false;

    break;
  }

  if (bare == true) return hcstrdup (src);

  // A single quote inside single quotes cannot be escaped, so the quoting is closed, the quote is
  // passed through on its own, and the quoting is opened again. That is four characters for one, and
  // it is the worst any byte can cost.

  char *dst = (char *) hcmalloc ((src_len * 4) + 3);

  size_t dst_len = 0;

  #if defined (_WIN)

  // cmd.exe gives a backslash no meaning of its own, and the characters that could end the quoted
  // region early are rejected as not pasteable before this runs, so the bytes can go through as they
  // are. The program being started parses its own argv though, and that parser folds a run of
  // backslashes touching a double quote into half as many. A trailing run would swallow the closing
  // quote, so it is doubled. Backslashes anywhere else are literal, which keeps a printed path
  // looking like the path.

  dst[dst_len] = '"';

  dst_len++;

  for (size_t i = 0; i < src_len; i++)
  {
    dst[dst_len] = src[i];

    dst_len++;
  }

  size_t tail = 0;

  while ((tail < src_len) && (src[src_len - 1 - tail] == '\\')) tail++;

  for (size_t i = 0; i < tail; i++)
  {
    dst[dst_len] = '\\';

    dst_len++;
  }

  dst[dst_len] = '"';

  dst_len++;

  #else

  dst[dst_len] = '\'';

  dst_len++;

  for (size_t i = 0; i < src_len; i++)
  {
    const char c = src[i];

    if (c == '\'')
    {
      dst[dst_len + 0] = '\'';
      dst[dst_len + 1] = '\\';
      dst[dst_len + 2] = '\'';
      dst[dst_len + 3] = '\'';

      dst_len += 4;

      continue;
    }

    dst[dst_len] = c;

    dst_len++;
  }

  dst[dst_len] = '\'';

  dst_len++;

  #endif

  dst[dst_len] = 0;

  return dst;
}

// No quoting makes a byte the terminal reads as a command safe to hand back to the user as something
// to paste, so a file holding one gets no pasteable line at all. On Windows three printable
// characters join that list. cmd.exe expands %VAR% inside double quotes and there is no quoting that
// stops it. With delayed expansion enabled the same happens to !VAR!. And cmd.exe does not let a
// backslash escape a double quote, so a double quote inside an argument would end the quoted region
// and hand the rest of the argument to the shell. A restore file hashcat wrote holds none of them.

static bool restore_str_is_pasteable (const char *src)
{
  const size_t src_len = strlen (src);

  for (size_t i = 0; i < src_len; i++)
  {
    const u8 c = (u8) src[i];

    if (c <  0x20) return false;
    if (c >  0x7e) return false;

    #if defined (_WIN)
    if (c == '%') return false;
    if (c == '!') return false;
    if (c == '"') return false;
    #endif
  }

  return true;
}

// The options below are hashcat's own bookkeeping and are appended fresh to every printed command
// line, so a copy left over from a previous resume is dropped rather than printed twice.

// A restore file named by a relative path was resolved against the directory hashcat was started in,
// and the printed command line may begin by changing to a different one. Printing the path as it was
// given would then point at a file that is not there, so it is made absolute first.

static bool restore_path_is_absolute (const char *path)
{
  if (path[0] == '/') return true;

  #if defined (_WIN)
  if (path[0] == '\\') return true;
  if ((path[0] != 0) && (path[1] == ':')) return true;
  #endif

  return false;
}

// The printed command line is sized before it is built, so this never has to cut anything. It is
// bounded anyway, because a buffer that is one byte short should print a short command line rather
// than corrupt the heap.

static size_t restore_cmd_append (char *dst, const size_t dst_sz, size_t dst_len, const char *src)
{
  const size_t src_len = strlen (src);

  for (size_t i = 0; i < src_len; i++)
  {
    if (dst_len == (dst_sz - 1)) break;

    dst[dst_len] = src[i];

    dst_len++;
  }

  dst[dst_len] = 0;

  return dst_len;
}

static bool restore_arg_is_ours (const char *arg)
{
  if (strcmp (arg, "--restore")           == 0) return true;
  if (strcmp (arg, "--restore-auto")      == 0) return true;
  if (strcmp (arg, "--restore-position")  == 0) return true;
  if (strcmp (arg, "--restore-file-path") == 0) return true;

  if (strncmp (arg, "--restore-file-path=", sizeof ("--restore-file-path=") - 1) == 0) return true;

  return false;
}

static int check_restore_cwd (hashcat_ctx_t *hashcat_ctx, const bool with_chdir);

static int read_restore (hashcat_ctx_t *hashcat_ctx, const bool with_argv, const bool with_chdir)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  if (restore_ctx->enabled == false) return 0;

  char *eff_restore_file = restore_ctx->eff_restore_file;

  HCFILE fp;

  if (hc_fopen (&fp, eff_restore_file, "rb") == false)
  {
    event_log_error (hashcat_ctx, "Restore file '%s': %s", eff_restore_file, hc_fopen_strerror ());

    return -1;
  }

  restore_data_t *rd = restore_ctx->rd;

  if (hc_fread (rd, sizeof (restore_data_t), 1, &fp) != 1)
  {
    event_log_error (hashcat_ctx, "Cannot read %s", eff_restore_file);

    hc_fclose (&fp);

    return -1;
  }

  // cwd is read straight out of the file and everything below reads it as a string. Nothing in the
  // file guarantees a zero appears anywhere in those 256 bytes, and a path filling all of them would
  // run chdir and the error messages off the end of the struct.

  rd->cwd[sizeof (rd->cwd) - 1] = 0;

  // Under --restore-position only the position is wanted, so the argv in the file is never read and
  // never parsed. The read above overwrote argc and the argv pointer with what the file said, so
  // both are put back to this session's own command line, which is what gets written out again.

  if (with_argv == false)
  {
    rd->argc = restore_ctx->argc;
    rd->argv = restore_ctx->argv;

    hc_fclose (&fp);

    return check_restore_cwd (hashcat_ctx, with_chdir);
  }

  // we only use these 2 checks to avoid "tainted string" warnings

  if (rd->argc < 1)
  {
    event_log_error (hashcat_ctx, "Unusually low number of arguments (argc) within restore file %s", eff_restore_file);

    hc_fclose (&fp);

    return -1;
  }

  if (rd->argc > 250) // some upper bound check is always good (with some dirs/dicts it could be a large string)
  {
    event_log_error (hashcat_ctx, "Unusually high number of arguments (argc) within restore file %s", eff_restore_file);

    hc_fclose (&fp);

    return -1;
  }

  // One more than argc, left as the NULL the C runtime puts at argv[argc] for main. Code that walks
  // this array reads that element when there are no positional arguments left, and a restore file
  // can say there are none.

  rd->argv = (char **) hccalloc (rd->argc + 1, sizeof (char *));

  char *buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  if (buf == NULL)
  {
    event_log_error(hashcat_ctx, "hcmalloc: %s", strerror(errno));
    hc_fclose(&fp);
    hcfree(rd->argv);
    return -1;
  }

  for (u32 i = 0; i < rd->argc; i++)
  {
    if (hc_fgets (buf, HCBUFSIZ_LARGE - 1, &fp) == NULL)
    {
      event_log_error (hashcat_ctx, "Cannot read %s", eff_restore_file);

      hc_fclose (&fp);

      hcfree (buf);

      return -1;
    }

    size_t len = strlen (buf);

    if (len) buf[len - 1] = 0;

    rd->argv[i] = hcstrdup (buf);
  }

  hcfree (buf);

  hc_fclose (&fp);

  return check_restore_cwd (hashcat_ctx, with_chdir);
}

static int check_restore_cwd (hashcat_ctx_t *hashcat_ctx, const bool with_chdir)
{
  restore_ctx_t   *restore_ctx   = hashcat_ctx->restore_ctx;
  folder_config_t *folder_config = hashcat_ctx->folder_config;

  restore_data_t *rd = restore_ctx->rd;

  // Under --restore nothing is run and the directory is only printed, so a session whose directory
  // has since been moved or deleted still gets its command line shown rather than an error.

  if (with_chdir == false) return 0;

  if (hc_path_exist (rd->cwd) == false)
  {
    char *cwd = restore_str_escape (rd->cwd);

    event_log_error (hashcat_ctx, "%s: %s", cwd, strerror (errno));

    hcfree (cwd);

    return -1;
  }

  if (hc_path_is_directory (rd->cwd) == false)
  {
    char *cwd = restore_str_escape (rd->cwd);

    event_log_error (hashcat_ctx, "%s: %s", cwd, strerror (errno));

    hcfree (cwd);

    return -1;
  }

  if (strncmp (rd->cwd, folder_config->cwd, sizeof (rd->cwd)) != 0) // check if we need to change the current working directory
  {
    char *cwd = restore_str_escape (rd->cwd);

    event_log_warning (hashcat_ctx, "Changing current working directory to '%s'", cwd);
    event_log_warning (hashcat_ctx, NULL);

    hcfree (cwd);

    if (chdir (rd->cwd))
    {
      char *cwd_err = restore_str_escape (rd->cwd);

      event_log_error (hashcat_ctx, "Directory '%s' needed to restore the session was not found.", cwd_err);

      hcfree (cwd_err);

      event_log_warning (hashcat_ctx, "Either create the directory, or update the directory within the .restore file.");
      event_log_warning (hashcat_ctx, "Restore files can be analyzed and modified with analyze_hc_restore.pl:");
      event_log_warning (hashcat_ctx, "    https://github.com/philsmd/analyze_hc_restore");
      event_log_warning (hashcat_ctx, "Directory must contain all files and folders from the original command line.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    // if we are here, we also need to update the folder_config and .pid file:

    /**
     * updated folders
     */

    // copy the paths of INSTALL_FOLDER and SHARED_FOLDER from the folder config:

    char *install_folder = hcstrdup (folder_config->install_dir);
    char *shared_folder  = hcstrdup (folder_config->shared_dir);

    folder_config_destroy (hashcat_ctx);

    const int rc_folder_config_init = folder_config_init (hashcat_ctx, install_folder, shared_folder);

    hcfree (install_folder);
    hcfree (shared_folder);

    if (rc_folder_config_init == -1) return -1;

    /**
     * updated pidfile
     */

    pidfile_ctx_destroy (hashcat_ctx);

    if (pidfile_ctx_init (hashcat_ctx) == -1) return -1;
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

  HCFILE fp;

  if (hc_fopen (&fp, new_restore_file, "wb") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", new_restore_file, hc_fopen_strerror ());

    return -1;
  }

  if (setvbuf (fp.pfp, NULL, _IONBF, 0))
  {
    event_log_error (hashcat_ctx, "setvbuf file '%s': %s", new_restore_file, strerror (errno));

    hc_fclose (&fp);

    return -1;
  }

  hc_fwrite (rd, sizeof (restore_data_t), 1, &fp);

  for (u32 i = 0; i < rd->argc; i++)
  {
    hc_fprintf (&fp, "%s", rd->argv[i]);

    hc_fputc ('\n', &fp);
  }

  hc_fflush (&fp);

  hc_fsync (&fp);

  hc_fclose (&fp);

  rd->masks_pos = 0;
  rd->dicts_pos = 0;
  rd->words_cur = 0;

  return 0;
}

int cycle_restore (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  if (restore_ctx->enabled == false) return 0;

  const mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

  // no updates, no need to write
  if ((restore_ctx->masks_pos_prev == mask_ctx->masks_pos)
   && (restore_ctx->dicts_pos_prev == straight_ctx->dicts_pos)
   && (restore_ctx->words_cur_prev == status_ctx->words_cur)) return 0;

  restore_ctx->masks_pos_prev = mask_ctx->masks_pos;
  restore_ctx->dicts_pos_prev = straight_ctx->dicts_pos;
  restore_ctx->words_cur_prev = status_ctx->words_cur;

  const char *eff_restore_file = restore_ctx->eff_restore_file;
  const char *new_restore_file = restore_ctx->new_restore_file;

  if (write_restore (hashcat_ctx) == -1) return -1;

  if (hc_path_exist (eff_restore_file) == true)
  {
    if (unlink (eff_restore_file) == -1)
    {
      event_log_warning (hashcat_ctx, "Unlink file '%s': %s", eff_restore_file, strerror (errno));
    }
  }

  if (rename (new_restore_file, eff_restore_file) == -1)
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

// A restore file is a command line. It used to be read out of the file, parsed by user_options_getopt
// as if it had been typed, and run, with whatever the user actually typed thrown away first. Every
// option was reachable that way, including the ones that name the files hashcat writes and the one
// that names a Python source file the bridges compile and execute.
//
// That cannot be filtered. An --outfile in the file is there because one was given when the session
// started, so refusing it would break the feature the file exists for. So the file stops being a
// command line instead: --restore prints what it holds and stops, and the printed line carries
// --restore-position, under which hashcat takes the position out of the file and nothing else. After
// that no argv is ever parsed out of a file unless --restore-auto asks for the old behaviour.

static void print_restore_command (hashcat_ctx_t *hashcat_ctx, const u32 argc, char **argv)
{
  const restore_ctx_t   *restore_ctx   = hashcat_ctx->restore_ctx;
  const folder_config_t *folder_config = hashcat_ctx->folder_config;
  const user_options_t  *user_options  = hashcat_ctx->user_options;

  const restore_data_t *rd = restore_ctx->rd;

  event_log_warning (hashcat_ctx, "A restore file holds the whole command line of the session it belongs to, and hashcat does");
  event_log_warning (hashcat_ctx, "not run it for you. What this one holds is below.");
  event_log_warning (hashcat_ctx, NULL);

  bool pasteable = restore_str_is_pasteable (rd->cwd);

  for (u32 i = 1; i < argc; i++)
  {
    if (restore_str_is_pasteable (argv[i]) == true) continue;

    pasteable = false;

    break;
  }

  if (pasteable == false)
  {
    event_log_warning (hashcat_ctx, "Part of it is not printable text, so it is not printed as a command line to run. A restore");
    event_log_warning (hashcat_ctx, "file written by hashcat does not hold anything like that. Look at this one before you use it:");
    event_log_warning (hashcat_ctx, NULL);
    event_log_warning (hashcat_ctx, "    https://github.com/philsmd/analyze_hc_restore");
    event_log_warning (hashcat_ctx, NULL);

    char *cwd = restore_str_escape (rd->cwd);

    event_log_warning (hashcat_ctx, "  directory    %s", cwd);

    hcfree (cwd);

    for (u32 i = 1; i < argc; i++)
    {
      char *arg = restore_str_escape (argv[i]);

      event_log_warning (hashcat_ctx, "  argument %3u %s", i, arg);

      hcfree (arg);
    }

    event_log_warning (hashcat_ctx, NULL);

    return;
  }

  event_log_warning (hashcat_ctx, "Read it, then run it yourself if it is what you expect:");
  event_log_warning (hashcat_ctx, NULL);

  // argv[0] is in the file as well and the file is not trusted, so the name of the program to run is
  // never taken from it. It is the binary the user has just started.

  const char *hc_bin = (user_options->hc_bin == NULL) ? PROGNAME : user_options->hc_bin;

  char *restore_path = NULL;

  if (restore_path_is_absolute (restore_ctx->eff_restore_file) == true)
  {
    restore_path = hcstrdup (restore_ctx->eff_restore_file);
  }
  else
  {
    hc_asprintf (&restore_path, "%s/%s", folder_config->cwd, restore_ctx->eff_restore_file);
  }

  char *bin_quoted  = restore_shell_quote (hc_bin);
  char *path_quoted = restore_shell_quote (restore_path);

  hcfree (restore_path);

  char **quoted = (char **) hccalloc (argc, sizeof (char *));

  size_t cmd_sz = strlen (bin_quoted) + strlen (path_quoted) + 64;

  for (u32 i = 1; i < argc; i++)
  {
    if (restore_arg_is_ours (argv[i]) == true)
    {
      // --restore-file-path carries its value in the argument after it, so both of them go.

      if (strcmp (argv[i], "--restore-file-path") == 0) i++;

      continue;
    }

    quoted[i] = restore_shell_quote (argv[i]);

    cmd_sz += strlen (quoted[i]) + 1;
  }

  char *cmd = (char *) hcmalloc (cmd_sz);

  size_t cmd_len = 0;

  cmd_len = restore_cmd_append (cmd, cmd_sz, cmd_len, bin_quoted);

  // The two options hashcat adds go in front of the arguments the user typed, not after them. A
  // command line may contain "--", and everything after that is an operand rather than an option:
  // appended at the end they would arrive as two more work arguments and the printed line would
  // fail with "--restore-position: No such file or directory". In front they are read as options
  // whatever the rest of the line looks like, and the order makes no difference anywhere else
  // because the options may appear in any position.

  cmd_len = restore_cmd_append (cmd, cmd_sz, cmd_len, " --restore-position --restore-file-path=");
  cmd_len = restore_cmd_append (cmd, cmd_sz, cmd_len, path_quoted);

  for (u32 i = 1; i < argc; i++)
  {
    if (quoted[i] == NULL) continue;

    cmd_len = restore_cmd_append (cmd, cmd_sz, cmd_len, " ");
    cmd_len = restore_cmd_append (cmd, cmd_sz, cmd_len, quoted[i]);
  }

  // The two lines below go out with printf rather than through the event log, which wraps a message
  // in colour on a terminal and cuts it at HCBUFSIZ_SMALL. Neither is wanted for a line whose whole
  // purpose is to be copied somewhere else intact.

  if (strncmp (rd->cwd, folder_config->cwd, sizeof (rd->cwd)) != 0)
  {
    char *cwd_quoted = restore_shell_quote (rd->cwd);

    printf ("  cd %s\n", cwd_quoted);

    hcfree (cwd_quoted);
  }

  printf ("  %s\n", cmd);

  fflush (stdout);

  for (u32 i = 1; i < argc; i++)
  {
    hcfree (quoted[i]);
  }

  hcfree (quoted);
  hcfree (cmd);
  hcfree (path_quoted);
  hcfree (bin_quoted);

  event_log_warning (hashcat_ctx, NULL);
  event_log_warning (hashcat_ctx, "Everything on that line except the two restore options came out of the restore file.");
  event_log_warning (hashcat_ctx, NULL);
}

// --restore-auto keeps the old one step resume for anything that drives hashcat without a person
// watching. The command line still comes out of the file there, so it is at least shown before it is
// used. Warnings are not silenced by --quiet, and whoever hands out a restore file also hands out the
// command used to run it.

#define RESTORE_ARG_DISPLAY_MAX 1024

static void show_restore_argv (hashcat_ctx_t *hashcat_ctx, const u32 argc, char **argv)
{
  event_log_warning (hashcat_ctx, "Restoring this command line out of the restore file:");
  event_log_warning (hashcat_ctx, NULL);

  for (u32 i = 1; i < argc; i++)
  {
    char *arg = restore_str_escape (argv[i]);

    const size_t arg_len = strlen (arg);

    if (arg_len > RESTORE_ARG_DISPLAY_MAX)
    {
      arg[RESTORE_ARG_DISPLAY_MAX] = 0;

      event_log_warning (hashcat_ctx, "  %s [%" PRIu64 " more characters not shown]", arg, (u64) (arg_len - RESTORE_ARG_DISPLAY_MAX));
    }
    else
    {
      event_log_warning (hashcat_ctx, "  %s", arg);
    }

    hcfree (arg);
  }

  event_log_warning (hashcat_ctx, NULL);
}

int restore_ctx_init (hashcat_ctx_t *hashcat_ctx, int argc, char **argv)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  restore_ctx_t   *restore_ctx   = hashcat_ctx->restore_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  restore_ctx->enabled = false;

  if (user_options->usage            > 0)     return 0;
  if (user_options->backend_info     > 0)     return 0;
  if (user_options->hash_info        > 0)     return 0;

  if (user_options->benchmark       == true)  return 0;
  if (user_options->keyspace        == true)  return 0;
  if (user_options->lookup          != NULL)  return 0;
  if (user_options->left            == true)  return 0;
  if (user_options->show            == true)  return 0;
  if (user_options->stdout_flag     == true)  return 0;
  if (user_options->speed_only      == true)  return 0;
  if (user_options->progress_only   == true)  return 0;
  if (user_options->version         == true)  return 0;
  if (user_options->identify        == true)  return 0;
  if (user_options->restore_enable  == false) return 0;

  if (argc ==    0) return 0;
  if (argv == NULL) return 0;

  if (user_options->restore_file_path == NULL)
  {
    hc_asprintf (&restore_ctx->eff_restore_file, "%s/%s.restore",     folder_config->session_dir, user_options->session);
    hc_asprintf (&restore_ctx->new_restore_file, "%s/%s.restore.new", folder_config->session_dir, user_options->session);
  }
  else
  {
    restore_ctx->eff_restore_file = hcstrdup (user_options->restore_file_path);
    hc_asprintf (&restore_ctx->new_restore_file, "%s.new", user_options->restore_file_path);
  }

  restore_ctx->argc = argc;
  restore_ctx->argv = argv;

  if (init_restore (hashcat_ctx) == -1) return -1;

  restore_ctx->enabled = true;

  restore_ctx->restore_execute = false;

  if ((user_options->restore == true) || (user_options->restore_position == true))
  {
    // Under --restore-position the argv in the file is never read. Under --restore nothing is run,
    // so the recorded directory is printed rather than entered.

    const bool with_argv  = (user_options->restore == true);
    const bool with_chdir = (user_options->restore == false) || (user_options->restore_auto == true);

    if (read_restore (hashcat_ctx, with_argv, with_chdir) == -1) return -1;

    restore_data_t *rd = restore_ctx->rd;

    if (rd->version < RESTORE_VERSION_MIN)
    {
      event_log_error (hashcat_ctx, "Incompatible restore-file version.");

      return -1;
    }

    if (user_options->restore == false)
    {
      restore_ctx->restore_execute = true;
    }
    else if (user_options->restore_auto == true)
    {
      show_restore_argv (hashcat_ctx, rd->argc, rd->argv);

      user_options_init (hashcat_ctx);

      if (user_options_getopt (hashcat_ctx, rd->argc, rd->argv) == -1) return -1;

      restore_ctx->restore_execute = true;
    }
    else
    {
      print_restore_command (hashcat_ctx, rd->argc, rd->argv);

      restore_ctx->print_only = true;

      return 0;
    }
  }

  restore_ctx->masks_pos_prev = -1;
  restore_ctx->dicts_pos_prev = -1;
  restore_ctx->words_cur_prev = -1;

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
