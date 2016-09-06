/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#pragma once

#include <stdio.h>
#include <unistd.h>

#ifdef _POSIX
#include <sys/types.h>
#endif

#ifdef _WIN
#include <windows.h>
#endif

#define DOT_HASHCAT     ".hashcat"
#define SESSIONS_FOLDER "sessions"

char *get_exec_path   (void);
char *get_install_dir (const char *progname);
char *get_profile_dir (const char *homedir);
char *get_session_dir (const char *profile_dir);
