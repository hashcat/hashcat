/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"
#include "folder.h"
#include <libgen.h>

#if defined (__APPLE__)
#include "event.h"
#elif defined (__FreeBSD__) || defined (__NetBSD__)
#include <sys/param.h>
#include <sys/sysctl.h>
#endif

static int get_exec_path (char *exec_path, const size_t exec_path_sz)
{
  #if defined (__linux__) || defined (__CYGWIN__)

  char *tmp = NULL;

  hc_asprintf (&tmp, "/proc/%d/exe", getpid ());

  const ssize_t len = readlink (tmp, exec_path, exec_path_sz - 1);

  hcfree (tmp);

  if (len == -1) return -1;

  #elif defined (_WIN)

  memset (exec_path, 0, exec_path_sz);

  const int len = 0;

  #elif defined (__APPLE__)

  u32 size = (u32) exec_path_sz;

  if (_NSGetExecutablePath (exec_path, &size) != 0) return -1;

  const size_t len = strlen (exec_path);

  #elif defined (__FreeBSD__)

  int mib[4];

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PATHNAME;
  mib[3] = -1;

  size_t size = exec_path_sz;

  sysctl (mib, 4, exec_path, &size, NULL, 0);

  const size_t len = strlen (exec_path);

  #elif defined (__NetBSD__)

  int mib[4];

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC_ARGS;
  mib[2] = getpid ();
  mib[3] = KERN_PROC_PATHNAME;

  size_t size = exec_path_sz;

  sysctl (mib, 4, exec_path, &size, NULL, 0);

  const size_t len = strlen (exec_path);

  #else
  #error Your Operating System is not supported or detected
  #endif

  exec_path[len] = 0;

  return 0;
}

static void get_install_dir (char *install_dir, const char *exec_path)
{
  strncpy (install_dir, exec_path, HCBUFSIZ_TINY - 1);

  char *last_slash = NULL;

  if ((last_slash = strrchr (install_dir, '/')) != NULL)
  {
    *last_slash = 0;
  }
  else if ((last_slash = strrchr (install_dir, '\\')) != NULL)
  {
    *last_slash = 0;
  }
  else
  {
    install_dir[0] = '.';
    install_dir[1] = 0;
  }
}

#if defined (_POSIX)
static void get_profile_dir (char *profile_dir, const char *home_dir)
{
  snprintf (profile_dir, HCBUFSIZ_TINY, "%s/%s", home_dir, DOT_HASHCAT);

  if (hc_path_is_directory (profile_dir)) return;

  char *xdg_data_home = getenv ("XDG_DATA_HOME");

  if (xdg_data_home)
  {
    snprintf (profile_dir, HCBUFSIZ_TINY, "%s/hashcat", xdg_data_home);
  }
  else
  {
    snprintf (profile_dir, HCBUFSIZ_TINY, "%s/.local/share/hashcat", home_dir);
  }
}

static void get_cache_dir (char *cache_dir, const char *home_dir)
{
  snprintf (cache_dir, HCBUFSIZ_TINY, "%s/%s", home_dir, DOT_HASHCAT);

  if (hc_path_is_directory (cache_dir)) return;

  char *xdg_cache_home = getenv ("XDG_CACHE_HOME");

  if (xdg_cache_home)
  {
    snprintf (cache_dir, HCBUFSIZ_TINY, "%s/hashcat", xdg_cache_home);
  }
  else
  {
    snprintf (cache_dir, HCBUFSIZ_TINY, "%s/.cache/hashcat", home_dir);
  }
}

static void get_session_dir (char *session_dir, const char *profile_dir)
{
  snprintf (session_dir, HCBUFSIZ_TINY, "%s/%s", profile_dir, SESSIONS_FOLDER);
}
#endif // _POSIX

int count_dictionaries (char **dictionary_files)
{
  if (dictionary_files == NULL) return 0;

  int cnt = 0;

  for (int d = 0; dictionary_files[d] != NULL; d++)
  {
    cnt++;
  }

  return cnt;
}

char *first_file_in_directory (const char *path)
{
  DIR *d = NULL;

  if ((d = opendir (path)) != NULL)
  {
    char *first_file = NULL;

    #if 0

    struct dirent e;

    for (;;)
    {
      memset (&e, 0, sizeof (e));

      struct dirent *de = NULL;

      if (readdir_r (d, &e, &de) != 0) break;

      if (de == NULL) break;

    #else

    struct dirent *de = NULL;

    while ((de = readdir (d)) != NULL)
    {

    #endif

      if (de->d_name[0] == '.') continue;

      first_file = strdup (de->d_name);

      break;
    }

    closedir (d);

    return first_file;
  }

  return NULL;
}

char **scan_directory (const char *path)
{
  char *tmp_path = hcstrdup (path);

  size_t tmp_path_len = strlen (tmp_path);

  while (tmp_path[tmp_path_len - 1] == '/' || tmp_path[tmp_path_len - 1] == '\\')
  {
    tmp_path[tmp_path_len - 1] = 0;

    tmp_path_len = strlen (tmp_path);
  }

  char **files = NULL;

  size_t num_files = 0;

  DIR *d = NULL;

  if ((d = opendir (tmp_path)) != NULL)
  {
    #if 0

    struct dirent e;

    for (;;)
    {
      memset (&e, 0, sizeof (e));

      struct dirent *de = NULL;

      if (readdir_r (d, &e, &de) != 0) break;

      if (de == NULL) break;

    #else

    struct dirent *de = NULL;

    while ((de = readdir (d)) != NULL)
    {

    #endif

      if (de->d_name[0] == '.') continue;

      char *path_file = NULL;

      hc_asprintf (&path_file, "%s/%s", tmp_path, de->d_name);

      DIR *d_test = NULL;

      if ((d_test = opendir (path_file)) != NULL)
      {
        closedir (d_test);

        hcfree (path_file);
      }
      else
      {
        files = (char **) hcrealloc (files, (num_files + 1) * sizeof (char *), sizeof (char *));

        files[num_files] = path_file;

        num_files++;
      }
    }

    closedir (d);
  }
  else if (errno == ENOTDIR)
  {
    files = (char **) hcrealloc (files, (num_files + 1) * sizeof (char *), sizeof (char *));

    files[num_files] = hcstrdup (path);

    num_files++;
  }

  files = (char **) hcrealloc (files, (num_files + 1) * sizeof (char *), sizeof (char *));

  files[num_files] = NULL;

  hcfree (tmp_path);

  return files;
}

int folder_config_init (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const char *install_folder, MAYBE_UNUSED const char *shared_folder)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;

  /**
   * There's some buggy OpenCL runtime that do not support -I.
   * A workaround is to chdir() to the OpenCL folder,
   * then compile the kernels,
   * then chdir() back to where we came from so we need to save it first
   * - temporary disabled due to https://github.com/hashcat/hashcat/issues/2379
   */

  char *cwd = (char *) hcmalloc (HCBUFSIZ_TINY);

  if (getcwd (cwd, HCBUFSIZ_TINY - 1) == NULL)
  {
    event_log_error (hashcat_ctx, "getcwd(): %s", strerror (errno));

    hcfree (cwd);

    return -1;
  }

  /**
   * folders, as discussed on https://github.com/hashcat/hashcat/issues/20
   */

  const size_t exec_path_sz = 1024;

  char *exec_path = (char *) hcmalloc (exec_path_sz);

  const int rc = get_exec_path (exec_path, exec_path_sz);

  if (rc == -1)
  {
    event_log_error (hashcat_ctx, "get_exec_path() failed.");

    hcfree (cwd);

    hcfree (exec_path);

    return -1;
  }

  #if defined (_POSIX)

  static const char SLASH[] = "/";

  if (install_folder == NULL) install_folder = SLASH; // makes library use easier

  char *resolved_install_folder = realpath (install_folder, NULL);
  char *resolved_exec_path      = realpath (exec_path, NULL);

  if (resolved_install_folder == NULL) resolved_install_folder = hcstrdup (SLASH);

  /*
  This causes invalid error out if install_folder (/usr/local/bin) does not exist
  if (resolved_install_folder == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", resolved_install_folder, strerror (errno));

    hcfree (cwd);

    hcfree (exec_path);

    hcfree (resolved_install_folder);

    return -1;
  }
  */

  if (resolved_exec_path == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", exec_path, strerror (errno));

    hcfree (cwd);

    hcfree (exec_path);

    hcfree (resolved_install_folder);

    return -1;
  }

  char *install_dir = (char *) hcmalloc (HCBUFSIZ_TINY);

  get_install_dir (install_dir, resolved_exec_path);

  char *profile_dir = NULL;
  char *cache_dir   = NULL;
  char *session_dir = NULL;
  char *shared_dir  = NULL;

  if (strcmp (install_dir, resolved_install_folder) == 0)
  {
    struct passwd pw;
    struct passwd *pwp = NULL;

    char buf[HCBUFSIZ_TINY];

    memset (buf, 0, sizeof (buf));
    memset (&pw, 0, sizeof (pw));

    getpwuid_r (getuid (), &pw, buf, HCBUFSIZ_TINY, &pwp);

    const char *home_dir = pwp->pw_dir;

    profile_dir = (char *) hcmalloc (HCBUFSIZ_TINY);
    cache_dir   = (char *) hcmalloc (HCBUFSIZ_TINY);
    session_dir = (char *) hcmalloc (HCBUFSIZ_TINY);

    get_profile_dir (profile_dir, home_dir);
    get_cache_dir   (cache_dir,   home_dir);
    get_session_dir (session_dir, profile_dir);

    shared_dir = hcstrdup (shared_folder);

    hc_mkdir_rec (profile_dir, 0700);
    hc_mkdir_rec (cache_dir,   0700);
    hc_mkdir     (session_dir, 0700);
  }
  else
  {
    profile_dir = install_dir;
    cache_dir   = install_dir;
    session_dir = install_dir;
    shared_dir  = install_dir;
  }

  hcfree (resolved_install_folder);
  hcfree (resolved_exec_path);

  #else

  char *install_dir = hcmalloc (HCBUFSIZ_TINY);

  get_install_dir (install_dir, exec_path);

  char *profile_dir = install_dir;
  char *cache_dir   = install_dir;
  char *session_dir = install_dir;
  char *shared_dir  = install_dir;

  #endif

  hcfree (exec_path);

  /**
   * There are a lot of problems related to bad support of -I parameters when building the kernel.
   * Each OpenCL runtime handles it slightly differently.
   * The most problematic is with new AMD drivers on Windows, which cannot handle quote characters!
   * The best workaround found so far is to modify the TMP variable (only inside hashcat process) before the runtime is loaded.
   */

  char *cpath = NULL;

  #if defined (_WIN)

  hc_asprintf (&cpath, "%s\\OpenCL\\", shared_dir);

  char *cpath_real = NULL;

  hc_asprintf (&cpath_real, "%s\\OpenCL\\", shared_dir);

  #else

  hc_asprintf (&cpath, "%s/OpenCL/", shared_dir);

  char *cpath_real = (char *) hcmalloc (PATH_MAX);

  if (realpath (cpath, cpath_real) == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", cpath, strerror (errno));

    hcfree (cwd);

    hcfree (shared_dir);

    // Attention: since hcfree () doesn't set the pointer to NULL, we need to do it externally such that
    // we prevent double-freeing the same memory address (this happens if e.g. profile_dir == session_dir)

    if (profile_dir == shared_dir) profile_dir = NULL;
    if (cache_dir   == shared_dir) cache_dir   = NULL;
    if (session_dir == shared_dir) session_dir = NULL;

    shared_dir = NULL;

    hcfree (profile_dir);

    if (session_dir == profile_dir) session_dir = NULL;
    if (cache_dir   == profile_dir) cache_dir   = NULL;

    profile_dir = NULL;

    hcfree (cache_dir);

    if (session_dir == cache_dir) session_dir = NULL;

    cache_dir = NULL;

    hcfree (session_dir);

    session_dir = NULL;

    hcfree (cpath_real);

    cpath_real = NULL;

    return -1;
  }

  #endif

  hcfree (cpath);

  //if (getenv ("TMP") == NULL)
  /* temporary disabled due to https://github.com/hashcat/hashcat/issues/2379
  if (true)
  {
    char *tmp;

    hc_asprintf (&tmp, "TMP=%s", cpath_real);

    putenv (tmp);
  }
  */

  // not escaping here, using quotes later
  // naive_escape (cpath_real, PATH_MAX,  ' ', '\\');

  #if defined (_WIN)

  naive_replace (cpath_real, '\\', '/');

  #endif

  /**
   * kernel cache, we need to make sure folder exist
   */

  char *kernels_folder = NULL;

  hc_asprintf (&kernels_folder, "%s/kernels", cache_dir);

  hc_mkdir (kernels_folder, 0700);

  hcfree (kernels_folder);

  /**
   * store for later use
   */

  folder_config->cwd          = cwd;
  folder_config->install_dir  = install_dir;
  folder_config->profile_dir  = profile_dir;
  folder_config->cache_dir    = cache_dir;
  folder_config->session_dir  = session_dir;
  folder_config->shared_dir   = shared_dir;
  folder_config->cpath_real   = cpath_real;

  return 0;
}

void folder_config_destroy (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;

  hcfree (folder_config->cpath_real);
  hcfree (folder_config->cwd);
  hcfree (folder_config->install_dir);

  memset (folder_config, 0, sizeof (folder_config_t));
}

int hc_mkdir (const char *name, MAYBE_UNUSED const int mode)
{
  #if defined (_WIN)
  return _mkdir (name);
  #else
  return mkdir (name, mode);
  #endif
}

int hc_mkdir_rec (const char *path, MAYBE_UNUSED const int mode)
{
  char *fullpath = hcstrdup (path);

  char *subpath = dirname (fullpath);

  if (strlen (subpath) > 1)
  {
    if (hc_mkdir_rec (subpath, mode) == -1) return -1;
  }

  if (hc_mkdir (path, mode) == -1)
  {
    if (errno != EEXIST) return -1;
  }

  hcfree (fullpath);

  return 0;
}
