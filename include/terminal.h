/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_TERMINAL_H
#define HC_TERMINAL_H

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#if defined (_WIN)
#include <windows.h>
#else
#include <termios.h>
#if defined (__APPLE__)   || defined (__OpenBSD__)   || defined (__NetBSD__) || \
    defined (__FreeBSD__) || defined (__DragonFly__)
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#endif
#endif // _WIN

#if defined (_POSIX)
#include <sys/utsname.h>
#if !defined (__APPLE__)   && !defined (__OpenBSD__)   && !defined (__NetBSD__) && \
    !defined (__FreeBSD__) && !defined (__DragonFly__)
#include <sys/sysinfo.h>
#endif
#endif // _POSIX

HC_API void welcome_screen (hashcat_ctx_t *hashcat_ctx, const char *version_tag);
HC_API void goodbye_screen (hashcat_ctx_t *hashcat_ctx, const time_t proc_start, const time_t proc_stop);

HC_API int setup_console (void);

HC_API void send_prompt  (hashcat_ctx_t *hashcat_ctx);
HC_API void clear_prompt (hashcat_ctx_t *hashcat_ctx);

#if defined (_WIN32) || defined (__WIN32__)
HC_API HC_API_CALL DWORD thread_keypress (void *p);
#else
HC_API HC_API_CALL void *thread_keypress (void *p);
#endif

#if defined (_WIN)
void SetConsoleWindowSize (const int x);
#endif

// An arrow key is not a character. A POSIX terminal sends it as a three byte escape sequence and the
// Windows console reports it as a virtual key code with a zero AsciiChar, which is also what a
// timeout looks like. tty_getchar () turns both into one of these, chosen above the range any real
// key can produce so the keypress switch can carry them like any other key.

#define TTY_KEY_LEFT  0x100
#define TTY_KEY_RIGHT 0x101
#define TTY_KEY_UP    0x102
#define TTY_KEY_DOWN  0x103

int tty_break (void);
int tty_getchar (void);
int tty_fix (void);

HC_API bool is_stdout_terminal (void);

void compress_terminal_line_length (char *out_buf, const size_t keep_from_beginning, const size_t keep_from_end);

HC_API void hash_info                          (hashcat_ctx_t *hashcat_ctx);

HC_API void backend_info                       (hashcat_ctx_t *hashcat_ctx);
HC_API void backend_info_compact               (hashcat_ctx_t *hashcat_ctx);

void status_progress_machine_readable   (hashcat_ctx_t *hashcat_ctx);
HC_API void status_progress                    (hashcat_ctx_t *hashcat_ctx);
void status_speed_machine_readable      (hashcat_ctx_t *hashcat_ctx);
HC_API void status_speed                       (hashcat_ctx_t *hashcat_ctx);
void status_display_machine_readable    (hashcat_ctx_t *hashcat_ctx);
HC_API void status_display                     (hashcat_ctx_t *hashcat_ctx);
void status_benchmark_machine_readable  (hashcat_ctx_t *hashcat_ctx);
HC_API void status_benchmark                   (hashcat_ctx_t *hashcat_ctx);

#endif // HC_TERMINAL_H
