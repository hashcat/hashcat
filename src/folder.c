/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "shared.h"
#include "folder.h"

#if defined (__APPLE__)
#include "logging.h"
#endif

int sort_by_stringptr (const void *p1, const void *p2)
{
  const char **s1 = (const char **) p1;
  const char **s2 = (const char **) p2;

  return strcmp (*s1, *s2);
}

char *get_exec_path ()
{
  size_t exec_path_len = 1024;

  char *exec_path = (char *) mymalloc (exec_path_len);

  #if defined (__linux__)

  char tmp[32] = { 0 };

  snprintf (tmp, sizeof (tmp) - 1, "/proc/%d/exe", getpid ());

  const int len = readlink (tmp, exec_path, exec_path_len - 1);

  #elif defined (_WIN)

  const int len = GetModuleFileName (NULL, exec_path, exec_path_len - 1);

  #elif defined (__APPLE__)

  u32 size = (u32) exec_path_len;

  if (_NSGetExecutablePath (exec_path, &size) != 0)
  {
    log_error("! executable path buffer too small\n");

    exit (-1);
  }

  const size_t len = strlen (exec_path);

  #elif defined (__FreeBSD__)

  int mib[4];

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PATHNAME;
  mib[3] = -1;

  char tmp[32] = { 0 };

  size_t size = exec_path_len;

  sysctl (mib, 4, exec_path, &size, NULL, 0);

  const int len = readlink (tmp, exec_path, exec_path_len - 1);

  #else
  #error Your Operating System is not supported or detected
  #endif

  exec_path[len] = 0;

  return exec_path;
}

char *get_install_dir (const char *progname)
{
  char *install_dir = mystrdup (progname);
  char *last_slash  = NULL;

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

  return (install_dir);
}

char *get_profile_dir (const char *homedir)
{
  char *profile_dir = (char *) mymalloc (HCBUFSIZ_TINY + 1);

  snprintf (profile_dir, HCBUFSIZ_TINY - 1, "%s/%s", homedir, DOT_HASHCAT);

  return profile_dir;
}

char *get_session_dir (const char *profile_dir)
{
  char *session_dir = (char *) mymalloc (HCBUFSIZ_TINY);

  snprintf (session_dir, HCBUFSIZ_TINY - 1, "%s/%s", profile_dir, SESSIONS_FOLDER);

  return session_dir;
}

int count_dictionaries (char **dictionary_files)
{
  if (dictionary_files == NULL) return 0;

  int cnt = 0;

  for (int d = 0; dictionary_files[d] != NULL; d++)
  {
    cnt++;
  }

  return (cnt);
}

char **scan_directory (const char *path)
{
  char *tmp_path = mystrdup (path);

  size_t tmp_path_len = strlen (tmp_path);

  while (tmp_path[tmp_path_len - 1] == '/' || tmp_path[tmp_path_len - 1] == '\\')
  {
    tmp_path[tmp_path_len - 1] = 0;

    tmp_path_len = strlen (tmp_path);
  }

  char **files = NULL;

  int num_files = 0;

  DIR *d = NULL;

  if ((d = opendir (tmp_path)) != NULL)
  {
    #if defined (__APPLE__)

    struct dirent e;

    for (;;)
    {
      memset (&e, 0, sizeof (e));

      struct dirent *de = NULL;

      if (readdir_r (d, &e, &de) != 0)
      {
        log_error ("ERROR: readdir_r() failed");

        break;
      }

      if (de == NULL) break;

    #else

    struct dirent *de;

    while ((de = readdir (d)) != NULL)
    {

    #endif

      if ((strcmp (de->d_name, ".") == 0) || (strcmp (de->d_name, "..") == 0)) continue;

      size_t path_size = strlen (tmp_path) + 1 + strlen (de->d_name);

      char *path_file = (char *) mymalloc (path_size + 1);

      snprintf (path_file, path_size + 1, "%s/%s", tmp_path, de->d_name);

      path_file[path_size] = 0;

      DIR *d_test;

      if ((d_test = opendir (path_file)) != NULL)
      {
        closedir (d_test);

        myfree (path_file);
      }
      else
      {
        files = (char **) myrealloc (files, (size_t) num_files * sizeof (char *), sizeof (char *));

        num_files++;

        files[num_files - 1] = path_file;
      }
    }

    closedir (d);
  }
  else if (errno == ENOTDIR)
  {
    files = (char **) myrealloc (files, (size_t) num_files * sizeof (char *), sizeof (char *));

    num_files++;

    files[num_files - 1] = mystrdup (path);
  }

  files = (char **) myrealloc (files, (size_t) num_files * sizeof (char *), sizeof (char *));

  num_files++;

  files[num_files - 1] = NULL;

  myfree (tmp_path);

  return (files);
}

int folder_config_init (folder_config_t *folder_config, const char *install_folder, const char *shared_folder)
{
  /**
   * There's some buggy OpenCL runtime that do not support -I.
   * A workaround is to chdir() to the OpenCL folder,
   * then compile the kernels,
   * then chdir() back to where we came from so we need to save it first
   */

  char *cwd = (char *) mymalloc (HCBUFSIZ_TINY);

  if (getcwd (cwd, HCBUFSIZ_TINY - 1) == NULL)
  {
    log_error ("ERROR: getcwd(): %s", strerror (errno));

    return -1;
  }

  /**
   * folders, as discussed on https://github.com/hashcat/hashcat/issues/20
   */

  char *exec_path = get_exec_path ();

  #if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)

  if (install_folder == NULL) install_folder = "/"; // makes library use easier

  char *resolved_install_folder = realpath (install_folder, NULL);
  char *resolved_exec_path      = realpath (exec_path, NULL);

  if (resolved_install_folder == NULL)
  {
    log_error ("ERROR: %s: %s", resolved_install_folder, strerror (errno));

    return -1;
  }

  if (resolved_exec_path == NULL)
  {
    log_error ("ERROR: %s: %s", resolved_exec_path, strerror (errno));

    return -1;
  }

  char *install_dir = get_install_dir (resolved_exec_path);
  char *profile_dir = NULL;
  char *session_dir = NULL;
  char *shared_dir  = NULL;

  if (strcmp (install_dir, resolved_install_folder) == 0)
  {
    struct passwd *pw = getpwuid (getuid ());

    const char *homedir = pw->pw_dir;

    profile_dir = get_profile_dir (homedir);
    session_dir = get_session_dir (profile_dir);
    shared_dir  = mystrdup (shared_folder);

    hc_mkdir (profile_dir, 0700);
    hc_mkdir (session_dir, 0700);
  }
  else
  {
    profile_dir = install_dir;
    session_dir = install_dir;
    shared_dir  = install_dir;
  }

  myfree (resolved_install_folder);
  myfree (resolved_exec_path);

  #else

  if (install_folder == NULL) install_folder = NULL; // make compiler happy
  if (shared_folder  == NULL) shared_folder  = NULL; // make compiler happy

  char *install_dir = get_install_dir (exec_path);
  char *profile_dir = install_dir;
  char *session_dir = install_dir;
  char *shared_dir  = install_dir;

  #endif

  myfree (exec_path);

  /**
   * There's alot of problem related to bad support -I parameters when building the kernel.
   * Each OpenCL runtime handles it slightly different.
   * The most problematic is with new AMD drivers on Windows, which can not handle quote characters!
   * The best workaround found so far is to modify the TMP variable (only inside hashcat process) before the runtime is load
   */

  char *cpath = (char *) mymalloc (HCBUFSIZ_TINY);

  #if defined (_WIN)

  snprintf (cpath, HCBUFSIZ_TINY - 1, "%s\\OpenCL\\", shared_dir);

  char *cpath_real = (char *) mymalloc (HCBUFSIZ_TINY);

  if (GetFullPathName (cpath, HCBUFSIZ_TINY - 1, cpath_real, NULL) == 0)
  {
    log_error ("ERROR: %s: %s", cpath, "GetFullPathName()");

    return -1;
  }

  #else

  snprintf (cpath, HCBUFSIZ_TINY - 1, "%s/OpenCL/", shared_dir);

  char *cpath_real = (char *) mymalloc (PATH_MAX);

  if (realpath (cpath, cpath_real) == NULL)
  {
    log_error ("ERROR: %s: %s", cpath, strerror (errno));

    return -1;
  }

  #endif

  myfree (cpath);

  //if (getenv ("TMP") == NULL)
  if (1)
  {
    char tmp[1000];

    snprintf (tmp, sizeof (tmp) - 1, "TMP=%s", cpath_real);

    putenv (tmp);
  }

  #if defined (_WIN)

  naive_replace (cpath_real, '\\', '/');

  // not escaping here, windows using quotes later
  // naive_escape (cpath_real, PATH_MAX,  ' ', '\\');

  #else

  naive_escape (cpath_real, PATH_MAX,  ' ', '\\');

  #endif

  /**
   * kernel cache, we need to make sure folder exist
   */

  char *kernels_folder = (char *) mymalloc (HCBUFSIZ_TINY);

  snprintf (kernels_folder, HCBUFSIZ_TINY - 1, "%s/kernels", profile_dir);

  hc_mkdir (kernels_folder, 0700);

  myfree (kernels_folder);

  /**
   * store for later use
   */

  folder_config->cwd          = cwd;
  folder_config->install_dir  = install_dir;
  folder_config->profile_dir  = profile_dir;
  folder_config->session_dir  = session_dir;
  folder_config->shared_dir   = shared_dir;
  folder_config->cpath_real   = cpath_real;

  return 0;
}

void folder_config_destroy (folder_config_t *folder_config)
{
  myfree (folder_config->cpath_real);
  myfree (folder_config->cwd);
  myfree (folder_config->install_dir);

  memset (folder_config, 0, sizeof (folder_config_t));
}

int hc_mkdir (const char *name, int mode)
{
  #if defined (_WIN)
  if (mode == 0) mode = 0; // makes compiler happy
  return _mkdir (name);
  #else
  return mkdir (name, mode);
  #endif
}
