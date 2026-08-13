/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_FOLDER_H
#define HC_FOLDER_H

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

// Legacy only. This directory predates XDG support and is no longer used for anything; it is named
// here so a user who still has one can be told where their files moved to. Do not resolve paths
// through it and do not mention it in a document.

#define DOT_HASHCAT     ".hashcat"
#define SESSIONS_FOLDER "sessions"

HC_PLUGIN_API int count_dictionaries (char **dictionary_files);

HC_PLUGIN_API char *first_file_in_directory (const char *path);

HC_PLUGIN_API char **scan_directory (const char *path);

int  folder_config_init    (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const char *install_folder, MAYBE_UNUSED const char *shared_folder);
void folder_config_destroy (hashcat_ctx_t *hashcat_ctx);

HC_PLUGIN_API int hc_mkdir (const char *name, MAYBE_UNUSED const int mode);
HC_PLUGIN_API int hc_mkdir_rec (const char *path, MAYBE_UNUSED const int mode);

#endif // HC_FOLDER_H
