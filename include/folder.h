/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>

#if defined (_POSIX)
#include <sys/types.h>
#include <pwd.h>
#endif

#if defined (__APPLE__)
#include <mach-o/dyld.h>
#endif // __APPLE__

#if defined (_WIN)
#include <windows.h>
#include <direct.h>
#endif

#define DOT_HASHCAT     ".hashcat"
#define SESSIONS_FOLDER "sessions"

int sort_by_stringptr (const void *p1, const void *p2);

char *get_exec_path   (void);
char *get_install_dir (const char *progname);
char *get_profile_dir (const char *homedir);
char *get_session_dir (const char *profile_dir);

int count_dictionaries (char **dictionary_files);

char **scan_directory (const char *path);

int  folder_config_init    (folder_config_t *folder_config, const char *install_folder, const char *shared_folder);
void folder_config_destroy (folder_config_t *folder_config);

int hc_mkdir (const char *name, int mode);
