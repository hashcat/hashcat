/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _FOLDER_H
#define _FOLDER_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>

#if defined (_WIN)
#include <windows.h>
#include <direct.h>
#else
#include <sys/types.h>
#include <pwd.h>
#if defined (__APPLE__)
#include <mach-o/dyld.h>
#endif // __APPLE__
#endif // _WIN

#define DOT_HASHCAT     ".hashcat"
#define SESSIONS_FOLDER "sessions"

int count_dictionaries (char **dictionary_files);

char *first_file_in_directory (const char *path);

char **scan_directory (const char *path);

int  folder_config_init    (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const char *install_folder, MAYBE_UNUSED const char *shared_folder);
void folder_config_destroy (hashcat_ctx_t *hashcat_ctx);

int hc_mkdir (const char *name, MAYBE_UNUSED const int mode);
int hc_mkdir_rec (const char *path, MAYBE_UNUSED const int mode);

#endif // _FOLDER_H
