/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// What can be told about a path, either from the text of the path itself or from what the
// filesystem says about the name, without ever reading the file behind it.
//
// This is the other half of the pair that filehandling.c completes. Opening a file through HCFILE
// means the contents may be compressed, so it costs the decompressors. Asking whether a path exists,
// whether it is readable, or what its last component is costs a stat and nothing else, and the two
// have no business being one object. Modules ask the second question and never the first.

#include "common.h"
#include "types.h"
#include "path.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

char *filename_from_filepath (char *filepath)
{
  char *ptr = NULL;

  if ((ptr = strrchr (filepath, '/')) != NULL)
  {
    ptr++;
  }
  else if ((ptr = strrchr (filepath, '\\')) != NULL)
  {
    ptr++;
  }
  else
  {
    ptr = filepath;
  }

  return ptr;
}
bool hc_path_is_file (const char *path)
{
  struct stat s;

  memset (&s, 0, sizeof (s));

  if (stat (path, &s) == -1) return false;

  if (S_ISREG (s.st_mode)) return true;

  return false;
}

bool hc_path_is_directory (const char *path)
{
  struct stat s;

  memset (&s, 0, sizeof (s));

  if (stat (path, &s) == -1) return false;

  if (S_ISDIR (s.st_mode)) return true;

  return false;
}

bool hc_path_is_fifo (const char *path)
{
  struct stat s;

  memset (&s, 0, sizeof (s));

  if (stat (path, &s) == -1) return false;

  if (S_ISFIFO (s.st_mode) == true) return true;

  return false;
}

bool hc_path_is_empty (const char *path)
{
  struct stat s;

  memset (&s, 0, sizeof (s));

  if (stat (path, &s) == -1) return false;

  if (s.st_size == 0) return true;

  return false;
}

bool hc_path_exist (const char *path)
{
  if (access (path, F_OK) == -1) return false;

  return true;
}

bool hc_path_read (const char *path)
{
  if (access (path, R_OK) == -1) return false;

  return true;
}

bool hc_path_write (const char *path)
{
  if (access (path, W_OK) == -1) return false;

  return true;
}

bool hc_path_create (const char *path)
{
  if (hc_path_exist (path) == true) return false;

#ifdef O_CLOEXEC
  const int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR);
#else
  const int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
#endif

  if (fd == -1) return false;

  close (fd);

  unlink (path);

  return true;
}
bool check_file_suffix (const char *file, const char *suffix)
{
  if (file == NULL)   return false;
  if (suffix == NULL) return false;

  const size_t len_file = strlen (file);
  const size_t len_suffix = strlen (suffix);

  if (len_suffix > len_file) return false;

  return strcmp (file + len_file - len_suffix, suffix) == 0;
}

bool remove_file_suffix (char *file, const char *suffix)
{
  if (file == NULL)   return false;
  if (suffix == NULL) return false;

  if (check_file_suffix (file, suffix) == false) return false;

  const size_t len_file = strlen (file);
  const size_t len_suffix = strlen (suffix);

  file[len_file - len_suffix] = 0;

  return true;
}