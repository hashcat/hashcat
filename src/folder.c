/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#ifdef __APPLE__
#include <stdio.h>
#endif

#include "common.h"
#include "memory.h"
#include "folder.h"

#ifdef __APPLE__
#include "types_int.h"
#include "logging.h"
#endif

char *get_exec_path ()
{
  int exec_path_len = 1024;

  char *exec_path = (char *) mymalloc (exec_path_len);

  #ifdef __linux__

  char tmp[32] = { 0 };

  snprintf (tmp, sizeof (tmp) - 1, "/proc/%d/exe", getpid ());

  const int len = readlink (tmp, exec_path, exec_path_len - 1);

  #elif WIN

  const int len = GetModuleFileName (NULL, exec_path, exec_path_len - 1);

  #elif __APPLE__

  uint size = exec_path_len;

  if (_NSGetExecutablePath (exec_path, &size) != 0)
  {
    log_error("! executable path buffer too small\n");

    exit (-1);
  }

  const int len = strlen (exec_path);

  #elif __FreeBSD__

  int mib[4];
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PATHNAME;
  mib[3] = -1;

  char tmp[32] = { 0 };

  size_t size = exec_path_len;
  sysctl(mib, 4, exec_path, &size, NULL, 0);

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
  size_t len = strlen (homedir) + 1 + strlen (DOT_HASHCAT) + 1;

  char *profile_dir = (char *) mymalloc (len + 1);

  snprintf (profile_dir, len, "%s/%s", homedir, DOT_HASHCAT);

  return profile_dir;
}

char *get_session_dir (const char *profile_dir)
{
  size_t len = strlen (profile_dir) + 1 + strlen (SESSIONS_FOLDER) + 1;

  char *session_dir = (char *) mymalloc (len + 1);

  snprintf (session_dir, len, "%s/%s", profile_dir, SESSIONS_FOLDER);

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
    #ifdef __APPLE__

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

      int path_size = strlen (tmp_path) + 1 + strlen (de->d_name);

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
        files = (char **) myrealloc (files, num_files * sizeof (char *), sizeof (char *));

        num_files++;

        files[num_files - 1] = path_file;
      }
    }

    closedir (d);
  }
  else if (errno == ENOTDIR)
  {
    files = (char **) myrealloc (files, num_files * sizeof (char *), sizeof (char *));

    num_files++;

    files[num_files - 1] = mystrdup (path);
  }

  files = (char **) myrealloc (files, num_files * sizeof (char *), sizeof (char *));

  num_files++;

  files[num_files - 1] = NULL;

  myfree (tmp_path);

  return (files);
}
