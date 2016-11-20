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

int count_dictionaries (char **dictionary_files);

char *first_file_in_directory (const char *path);

char **scan_directory (const char *path);

int  folder_config_init    (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const char *install_folder, MAYBE_UNUSED const char *shared_folder);
void folder_config_destroy (hashcat_ctx_t *hashcat_ctx);

int hc_mkdir (const char *name, MAYBE_UNUSED const int mode);
