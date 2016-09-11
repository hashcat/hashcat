/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>

#if defined (_POSIX)
#include <sys/types.h>
#if defined (__APPLE__)
#include <mach-o/dyld.h>
#endif // __APPLE__
#endif // _POSIX

#if defined (_WIN)
#include <windows.h>
#endif

#define DOT_HASHCAT     ".hashcat"
#define SESSIONS_FOLDER "sessions"

#if defined (_WIN)
#define mkdir(name,mode) mkdir (name)
#endif

int sort_by_stringptr (const void *p1, const void *p2);

char *get_exec_path   (void);
char *get_install_dir (const char *progname);
char *get_profile_dir (const char *homedir);
char *get_session_dir (const char *profile_dir);

int count_dictionaries (char **dictionary_files);

char **scan_directory (const char *path);
