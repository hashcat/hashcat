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

#if defined (_POSIX)
#include <termios.h>
#if defined (__APPLE__)
#include <sys/ioctl.h>
#endif // __APPLE__
#endif // _POSIX

#if defined (_WIN)
#include <windows.h>
#endif // _WIN

void welcome_screen (const user_options_t *user_options, const time_t proc_start, const char *version_tag);
void goodbye_screen (const user_options_t *user_options, const time_t proc_start, const time_t proc_stop);

int setup_console ();

void send_prompt ();
void clear_prompt ();

void *thread_keypress (void *p);

#if defined (_WIN)
void SetConsoleWindowSize (const int x);
#endif

int tty_break();
int tty_getchar();
int tty_fix();

#endif // _TERMINAL_H
