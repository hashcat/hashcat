/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#ifndef COMMON_H
#define COMMON_H

#define _POSIX_SOURCE
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define _CRT_SECURE_NO_WARNINGS

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <ctype.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <search.h>
#include <fcntl.h>

/**
 *  Added to support API
 */
#include <float.h>
#include <inttypes.h>

#ifdef _POSIX
#include <sys/time.h>
#include <pthread.h>
#include <semaphore.h>
#include <dlfcn.h>
#include <pwd.h>

#ifdef LINUX
#include <termio.h>
#endif

#ifdef OSX
#include <termios.h>
#include <sys/ioctl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#endif

typedef void *OCL_LIB;

#ifdef HAVE_HWMON
typedef void *NV_LIB;
typedef void *AMD_LIB;
#ifdef OSX
#define __stdcall
#endif
#endif

#endif // _POSIX

#ifdef _WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#include <conio.h>
#include <tchar.h>
#include <psapi.h>
#include <io.h>

typedef UINT8  uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef INT8   int8_t;
typedef INT16  int16_t;
typedef INT32  int32_t;
typedef INT64  int64_t;

typedef UINT32 uint;
typedef UINT64 uint64_t;

typedef HINSTANCE OCL_LIB;

#ifdef HAVE_HWMON
typedef HINSTANCE NV_LIB;
typedef HINSTANCE AMD_LIB;
#endif

#define mkdir(name,mode) mkdir (name)

#endif // _WIN

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef uint32_t uint; // we need to get rid of this sooner or later, for consistency

#define EXEC_CACHE   128

#define SPEED_CACHE  128
#define SPEED_MAXAGE 4096

#undef  BUFSIZ
#define BUFSIZ 8192

/**
 * functions
 */

void log_out_nn (FILE *fp, const char *fmt, ...);
void log_info_nn (const char *fmt, ...);
void log_error_nn (const char *fmt, ...);

void log_out (FILE *fp, const char *fmt, ...);
void log_info (const char *fmt, ...);
void log_error (const char *fmt, ...);

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))


/**
 * All the variables below have been moved from oclHashcat.c to share with API
 *
 */


#define INCR_RULES              10000
#define INCR_SALTS              100000
#define INCR_MASKS              1000
#define INCR_POT                1000

#define USAGE                   0
#define VERSION                 0
#define QUIET                   0
#define MARKOV_THRESHOLD        0
#define MARKOV_DISABLE          0
#define MARKOV_CLASSIC          0
#define BENCHMARK               0
#define BENCHMARK_REPEATS       2
#define RESTORE                 0
#define RESTORE_TIMER           60
#define RESTORE_DISABLE         0
#define STATUS                  0
#define STATUS_TIMER            10
#define STATUS_AUTOMAT          0
#define LOOPBACK                0
#define WEAK_HASH_THRESHOLD     100
#define SHOW                    0
#define LEFT                    0
#define USERNAME                0
#define REMOVE                  0
#define REMOVE_TIMER            60
#define SKIP                    0
#define LIMIT                   0
#define KEYSPACE                0
#define POTFILE_DISABLE         0
#define DEBUG_MODE              0
#define RP_GEN                  0
#define RP_GEN_FUNC_MIN         1
#define RP_GEN_FUNC_MAX         4
#define RP_GEN_SEED             0
#define RULE_BUF_L              ":"
#define RULE_BUF_R              ":"
#define FORCE                   0
#define RUNTIME                 0
#define HEX_CHARSET             0
#define HEX_SALT                0
#define HEX_WORDLIST            0
#define OUTFILE_FORMAT          3
#define OUTFILE_AUTOHEX         1
#define OUTFILE_CHECK_TIMER     5
#define ATTACK_MODE             0
#define HASH_MODE               0
#define SEGMENT_SIZE            32
#define INCREMENT               0
#define INCREMENT_MIN           1
#define INCREMENT_MAX           PW_MAX
#define SEPARATOR               ':'
#define BITMAP_MIN              16
#define BITMAP_MAX              24
#define GPU_TEMP_DISABLE        0
#define GPU_TEMP_ABORT          90
#define GPU_TEMP_RETAIN         80
#define WORKLOAD_PROFILE        2
#define KERNEL_ACCEL            0
#define KERNEL_LOOPS            0
#define KERNEL_RULES            1024
#define KERNEL_COMBS            1024
#define KERNEL_BFS              1024
#define KERNEL_THREADS          64
#define POWERTUNE_ENABLE        0
#define LOGFILE_DISABLE         0
#define SCRYPT_TMTO             0
#define OPENCL_VECTOR_WIDTH     0

#define WL_MODE_STDIN           1
#define WL_MODE_FILE            2
#define WL_MODE_MASK            3

#define HL_MODE_FILE            4
#define HL_MODE_ARG             5

#define HLFMTS_CNT              11
#define HLFMT_HASHCAT           0
#define HLFMT_PWDUMP            1
#define HLFMT_PASSWD            2
#define HLFMT_SHADOW            3
#define HLFMT_DCC               4
#define HLFMT_DCC2              5
#define HLFMT_NETNTLM1          7
#define HLFMT_NETNTLM2          8
#define HLFMT_NSLDAP            9
#define HLFMT_NSLDAPS           10

#define HLFMT_TEXT_HASHCAT      "native hashcat"
#define HLFMT_TEXT_PWDUMP       "pwdump"
#define HLFMT_TEXT_PASSWD       "passwd"
#define HLFMT_TEXT_SHADOW       "shadow"
#define HLFMT_TEXT_DCC          "DCC"
#define HLFMT_TEXT_DCC2         "DCC 2"
#define HLFMT_TEXT_NETNTLM1     "NetNTLMv1"
#define HLFMT_TEXT_NETNTLM2     "NetNTLMv2"
#define HLFMT_TEXT_NSLDAP       "nsldap"
#define HLFMT_TEXT_NSLDAPS      "nsldaps"

#define ATTACK_MODE_STRAIGHT    0
#define ATTACK_MODE_COMBI       1
#define ATTACK_MODE_TOGGLE      2
#define ATTACK_MODE_BF          3
#define ATTACK_MODE_PERM        4
#define ATTACK_MODE_TABLE       5
#define ATTACK_MODE_HYBRID1     6
#define ATTACK_MODE_HYBRID2     7
#define ATTACK_MODE_NONE        100

#define ATTACK_KERN_STRAIGHT    0
#define ATTACK_KERN_COMBI       1
#define ATTACK_KERN_BF          3
#define ATTACK_KERN_NONE        100

#define ATTACK_EXEC_OUTSIDE_KERNEL  10
#define ATTACK_EXEC_INSIDE_KERNEL   11

#define COMBINATOR_MODE_BASE_LEFT   10001
#define COMBINATOR_MODE_BASE_RIGHT  10002

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))

#define MAX_CUT_TRIES           4

#define MAX_DICTSTAT            10000

#define NUM_DEFAULT_BENCHMARK_ALGORITHMS 133


#endif // COMMON_H
