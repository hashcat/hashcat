/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _TERMINAL_H
#define _TERMINAL_H

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef _POSIX
#include <termios.h>
#endif // _POSIX

#ifdef _WIN
#include <windows.h>
#endif // _WIN

int tty_break();
int tty_getchar();
int tty_fix();

#endif // _TERMINAL_H
