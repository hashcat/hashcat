/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#ifndef _SHARED_H
#define _SHARED_H

#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <inttypes.h>

/**
 * OS specific includes
 */

#if defined (_POSIX)
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#endif // _POSIX

#if defined (_WIN)
#include <windows.h>
#endif // _WIN

/**
 * functions ok for shared
 */

u32 get_random_num (const u32 min, const u32 max);

u32 mydivc32 (const u32 dividend, const u32 divisor);
u64 mydivc64 (const u64 dividend, const u64 divisor);

void naive_replace (char *s, const u8 key_char, const u8 replace_char);
void naive_escape (char *s, size_t s_max, const u8 key_char, const u8 escape_char);

void hc_sleep (const int sec);

#endif // _SHARED_H
