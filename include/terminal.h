/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _TERMINAL_H
#define _TERMINAL_H

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#if defined (_WIN)
#include <windows.h>
#else
#include <termios.h>
#if defined (__APPLE__)
#include <sys/ioctl.h>
#endif // __APPLE__
#endif // _WIN

#if !defined (_WIN) && !defined (__CYGWIN__) && !defined (__MSYS__)
#include <sys/utsname.h>
#if !defined (__linux__)
#include <sys/sysctl.h>
#endif // ! __linux__
#endif // ! _WIN && | __CYGWIN__ && ! __MSYS__

void welcome_screen (hashcat_ctx_t *hashcat_ctx, const char *version_tag);
void goodbye_screen (hashcat_ctx_t *hashcat_ctx, const time_t proc_start, const time_t proc_stop);

int setup_console (void);

void send_prompt  (hashcat_ctx_t *hashcat_ctx);
void clear_prompt (hashcat_ctx_t *hashcat_ctx);

HC_API_CALL void *thread_keypress (void *p);

#if defined (_WIN)
void SetConsoleWindowSize (const int x);
#endif

int tty_break (void);
int tty_getchar (void);
int tty_fix (void);

bool is_stdout_terminal (void);

void compress_terminal_line_length (char *out_buf, const size_t keep_from_beginning, const size_t keep_from_end);

void hash_info                          (hashcat_ctx_t *hashcat_ctx);

void backend_info                       (hashcat_ctx_t *hashcat_ctx);
void backend_info_compact               (hashcat_ctx_t *hashcat_ctx);

void status_progress_machine_readable   (hashcat_ctx_t *hashcat_ctx);
void status_progress                    (hashcat_ctx_t *hashcat_ctx);
void status_speed_machine_readable      (hashcat_ctx_t *hashcat_ctx);
void status_speed                       (hashcat_ctx_t *hashcat_ctx);
void status_display_machine_readable    (hashcat_ctx_t *hashcat_ctx);
void status_display                     (hashcat_ctx_t *hashcat_ctx);
void status_benchmark_machine_readable  (hashcat_ctx_t *hashcat_ctx);
void status_benchmark                   (hashcat_ctx_t *hashcat_ctx);

#endif // _TERMINAL_H
