/*
 * xxhsum - Command line interface for xxhash algorithms
 * Copyright (C) 2013-2020 Yann Collet
 *
 * GPL v2 License
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * You can contact the author at:
 *   - xxHash homepage: https://www.xxhash.com
 *   - xxHash source repository: https://github.com/Cyan4973/xxHash
 */

/*
 * xxhsum:
 * Provides hash value of a file content, or a list of files, or stdin
 * Display convention is Big Endian, for both 32 and 64 bits algorithms
 */


/* ************************************
 *  Compiler Options
 **************************************/
/* MS Visual */
#if defined(_MSC_VER) || defined(_WIN32)
#  ifndef _CRT_SECURE_NO_WARNINGS
#    define _CRT_SECURE_NO_WARNINGS   /* removes visual warnings */
#  endif
#endif

/* Under Linux at least, pull in the *64 commands */
#ifndef _LARGEFILE64_SOURCE
#  define _LARGEFILE64_SOURCE
#endif

/* ************************************
 *  Includes
 **************************************/
#include <limits.h>
#include <stdlib.h>     /* malloc, calloc, free, exit */
#include <string.h>     /* strcmp, memcpy */
#include <stdio.h>      /* fprintf, fopen, ftello64, fread, stdin, stdout, _fileno (when present) */
#include <sys/types.h>  /* stat, stat64, _stat64 */
#include <sys/stat.h>   /* stat, stat64, _stat64 */
#include <time.h>       /* clock_t, clock, CLOCKS_PER_SEC */
#include <assert.h>     /* assert */
#include <errno.h>      /* errno */

#define XXH_STATIC_LINKING_ONLY   /* *_state_t */
#include "xxhash.h"

#ifdef XXHSUM_DISPATCH
#  include "xxh_x86dispatch.h"
#endif


/* ************************************
 *  OS-Specific Includes
 **************************************/
#if !defined(_WIN32) && (defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__)) /* UNIX-like OS */ \
   || defined(__midipix__) || defined(__VMS))
#  if (defined(__APPLE__) && defined(__MACH__)) || defined(__SVR4) || defined(_AIX) || defined(__hpux) /* POSIX.1-2001 (SUSv3) conformant */ \
     || defined(__DragonFly__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)  /* BSD distros */
#    define PLATFORM_POSIX_VERSION 200112L
#  else
#    if defined(__linux__) || defined(__linux)
#      ifndef _POSIX_C_SOURCE
#        define _POSIX_C_SOURCE 200112L  /* use feature test macro */
#      endif
#    endif
#    include <unistd.h>  /* declares _POSIX_VERSION */
#    if defined(_POSIX_VERSION)  /* POSIX compliant */
#      define PLATFORM_POSIX_VERSION _POSIX_VERSION
#    else
#      define PLATFORM_POSIX_VERSION 0
#    endif
#  endif
#endif
#if !defined(PLATFORM_POSIX_VERSION)
#  define PLATFORM_POSIX_VERSION -1
#endif

#if (defined(__linux__) && (PLATFORM_POSIX_VERSION >= 1)) \
 || (PLATFORM_POSIX_VERSION >= 200112L) \
 || defined(__DJGPP__) \
 || defined(__MSYS__)
#  include <unistd.h>   /* isatty */
#  define IS_CONSOLE(stdStream) isatty(fileno(stdStream))
#elif defined(MSDOS) || defined(OS2)
#  include <io.h>       /* _isatty */
#  define IS_CONSOLE(stdStream) _isatty(_fileno(stdStream))
#elif defined(WIN32) || defined(_WIN32)
#  include <io.h>      /* _isatty */
#  include <windows.h> /* DeviceIoControl, HANDLE, FSCTL_SET_SPARSE */
#  include <stdio.h>   /* FILE */
static __inline int IS_CONSOLE(FILE* stdStream) {
    DWORD dummy;
    return _isatty(_fileno(stdStream)) && GetConsoleMode((HANDLE)_get_osfhandle(_fileno(stdStream)), &dummy);
}
#else
#  define IS_CONSOLE(stdStream) 0
#endif

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(_WIN32)
#  include <fcntl.h>   /* _O_BINARY */
#  include <io.h>      /* _setmode, _fileno, _get_osfhandle */
#  if !defined(__DJGPP__)
#    include <windows.h> /* DeviceIoControl, HANDLE, FSCTL_SET_SPARSE */
#    include <winioctl.h> /* FSCTL_SET_SPARSE */
#    define SET_BINARY_MODE(file) { int const unused=_setmode(_fileno(file), _O_BINARY); (void)unused; }
#  else
#    define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#  endif
#else
#  define SET_BINARY_MODE(file)
#endif

#if !defined(S_ISREG)
#  define S_ISREG(x) (((x) & S_IFMT) == S_IFREG)
#endif

/* Unicode helpers for Windows to make UTF-8 act as it should. */
#ifdef _WIN32
/*
 * Converts a UTF-8 string to UTF-16. Acts like strdup. The string must be freed afterwards.
 * This version allows keeping the output length.
 */
static wchar_t* utf8_to_utf16_len(const char* str, int* lenOut)
{
    int const len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (lenOut != NULL) *lenOut = len;
    if (len == 0) return NULL;
    {   wchar_t* buf = (wchar_t*)malloc((size_t)len * sizeof(wchar_t));
        if (buf != NULL) {
            if (MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, len) == 0) {
                free(buf);
                return NULL;
       }    }
       return buf;
    }
}

/* Converts a UTF-8 string to UTF-16. Acts like strdup. The string must be freed afterwards. */
static wchar_t* utf8_to_utf16(const char *str)
{
    return utf8_to_utf16_len(str, NULL);
}

/*
 * Converts a UTF-16 string to UTF-8. Acts like strdup. The string must be freed afterwards.
 * This version allows keeping the output length.
 */
static char* utf16_to_utf8_len(const wchar_t *str, int *lenOut)
{
    int len = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
    if (lenOut != NULL) *lenOut = len;
    if (len == 0) return NULL;
    {   char* const buf = (char*)malloc((size_t)len * sizeof(char));
        if (buf != NULL) {
            if (WideCharToMultiByte(CP_UTF8, 0, str, -1, buf, len, NULL, NULL) == 0) {
                free(buf);
                return NULL;
        }    }
        return buf;
    }
}

/* Converts a UTF-16 string to UTF-8. Acts like strdup. The string must be freed afterwards. */
static char *utf16_to_utf8(const wchar_t *str)
{
    return utf16_to_utf8_len(str, NULL);
}

/*
 * fopen wrapper that supports UTF-8
 *
 * fopen will only accept ANSI filenames, which means that we can't open Unicode filenames.
 *
 * In order to open a Unicode filename, we need to convert filenames to UTF-16 and use _wfopen.
 */
static FILE* XXH_fopen_wrapped(const char *filename, const wchar_t *mode)
{
    wchar_t* const wide_filename = utf8_to_utf16(filename);
    if (wide_filename == NULL) return NULL;
    {   FILE* const f = _wfopen(wide_filename, mode);
        free(wide_filename);
        return f;
    }
}

/*
 * In case it isn't available, this is what MSVC 2019 defines in stdarg.h.
 */
#if defined(_MSC_VER) && !defined(__clang__) && !defined(va_copy)
#  define va_copy(destination, source) ((destination) = (source))
#endif

/*
 * fprintf wrapper that supports UTF-8.
 *
 * fprintf doesn't properly handle Unicode on Windows.
 *
 * Additionally, it is codepage sensitive on console and may crash the program.
 *
 * Instead, we use vsnprintf, and either print with fwrite or convert to UTF-16
 * for console output and use the codepage-independent WriteConsoleW.
 *
 * Credit to t-mat: https://github.com/t-mat/xxHash/commit/5691423
 */
static int fprintf_utf8(FILE *stream, const char *format, ...)
{
    int result;
    va_list args;
    va_list copy;

    va_start(args, format);

    /*
     * To be safe, make a va_copy.
     *
     * Note that Microsoft doesn't use va_copy in its sample code:
     *   https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/vsprintf-vsprintf-l-vswprintf-vswprintf-l-vswprintf-l?view=vs-2019
     */
    va_copy(copy, args);
    /* Counts the number of characters needed for vsnprintf. */
    result = _vscprintf(format, copy);
    va_end(copy);

    if (result > 0) {
        /* Create a buffer for vsnprintf */
        const size_t nchar = (size_t)result + 1;
        char* u8_str = (char*)malloc(nchar * sizeof(u8_str[0]));

        if (u8_str == NULL) {
            result = -1;
        } else {
            /* Generate the UTF-8 string with vsnprintf. */
            result = _vsnprintf(u8_str, nchar - 1, format, args);
            u8_str[nchar - 1] = '\0';
            if (result > 0) {
                /*
                 * Check if we are outputting to a console. Don't use IS_CONSOLE
                 * directly -- we don't need to call _get_osfhandle twice.
                 */
                int fileNb = _fileno(stream);
                intptr_t handle_raw = _get_osfhandle(fileNb);
                HANDLE handle = (HANDLE)handle_raw;
                DWORD dwTemp;

                if (handle_raw < 0) {
                     result = -1;
                } else if (_isatty(fileNb) && GetConsoleMode(handle, &dwTemp)) {
                    /*
                     * Convert to UTF-16 and output with WriteConsoleW.
                     *
                     * This is codepage independent and works on Windows XP's
                     * default msvcrt.dll.
                     */
                    int len;
                    wchar_t *const u16_buf = utf8_to_utf16_len(u8_str, &len);
                    if (u16_buf == NULL) {
                        result = -1;
                    } else {
                        if (WriteConsoleW(handle, u16_buf, (DWORD)len - 1, &dwTemp, NULL)) {
                            result = (int)dwTemp;
                        } else {
                            result = -1;
                        }
                        free(u16_buf);
                    }
                } else {
                    /* fwrite the UTF-8 string if we are printing to a file */
                    result = (int)fwrite(u8_str, 1, nchar - 1, stream);
                    if (result == 0) {
                        result = -1;
                    }
                }
            }
            free(u8_str);
        }
    }
    va_end(args);
    return result;
}
/*
 * Since we always use literals in the "mode" argument, it is just easier to append "L" to
 * the string to make it UTF-16 and avoid the hassle of a second manual conversion.
 */
#  define XXH_fopen(filename, mode) XXH_fopen_wrapped(filename, L##mode)
#else
#  define XXH_fopen(filename, mode) fopen(filename, mode)
#endif

/* ************************************
*  Basic Types
**************************************/
#if defined(__cplusplus) /* C++ */ \
 || (defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L)  /* C99 */
#  include <stdint.h>
    typedef uint8_t  U8;
    typedef uint32_t U32;
    typedef uint64_t U64;
# else
#   include <limits.h>
    typedef unsigned char      U8;
#   if UINT_MAX == 0xFFFFFFFFUL
      typedef unsigned int     U32;
#   else
      typedef unsigned long    U32;
#   endif
    typedef unsigned long long U64;
#endif /* not C++/C99 */

static unsigned BMK_isLittleEndian(void)
{
    const union { U32 u; U8 c[4]; } one = { 1 };   /* don't use static: performance detrimental  */
    return one.c[0];
}


/* *************************************
 *  Constants
 ***************************************/
#define LIB_VERSION XXH_VERSION_MAJOR.XXH_VERSION_MINOR.XXH_VERSION_RELEASE
#define QUOTE(str) #str
#define EXPAND_AND_QUOTE(str) QUOTE(str)
#define PROGRAM_VERSION EXPAND_AND_QUOTE(LIB_VERSION)

/* Show compiler versions in WELCOME_MESSAGE. CC_VERSION_FMT will return the printf specifiers,
 * and VERSION will contain the comma separated list of arguments to the CC_VERSION_FMT string. */
#if defined(__clang_version__)
/* Clang does its own thing. */
#  ifdef __apple_build_version__
#    define CC_VERSION_FMT "Apple Clang %s"
#  else
#    define CC_VERSION_FMT "Clang %s"
#  endif
#  define CC_VERSION  __clang_version__
#elif defined(__VERSION__)
/* GCC and ICC */
#  define CC_VERSION_FMT "%s"
#  ifdef __INTEL_COMPILER /* icc adds its prefix */
#    define CC_VERSION __VERSION__
#  else /* assume GCC */
#    define CC_VERSION "GCC " __VERSION__
#  endif
#elif defined(_MSC_FULL_VER) && defined(_MSC_BUILD)
/*
 * MSVC
 *  "For example, if the version number of the Visual C++ compiler is
 *   15.00.20706.01, the _MSC_FULL_VER macro evaluates to 150020706."
 *
 *   https://docs.microsoft.com/en-us/cpp/preprocessor/predefined-macros?view=vs-2017
 */
#  define CC_VERSION_FMT "MSVC %02i.%02i.%05i.%02i"
#  define CC_VERSION  _MSC_FULL_VER / 10000000 % 100, _MSC_FULL_VER / 100000 % 100, _MSC_FULL_VER % 100000, _MSC_BUILD
#elif defined(__TINYC__)
/* tcc stores its version in the __TINYC__ macro. */
#  define CC_VERSION_FMT "tcc %i.%i.%i"
#  define CC_VERSION __TINYC__ / 10000 % 100, __TINYC__ / 100 % 100, __TINYC__ % 100
#else
#  define CC_VERSION_FMT "%s"
#  define CC_VERSION "unknown compiler"
#endif

/* makes the next part easier */
#if defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#   define ARCH_X64 1
#   define ARCH_X86 "x86_64"
#elif defined(__i386__) || defined(_M_IX86) || defined(_M_IX86_FP)
#   define ARCH_X86 "i386"
#endif

/* Try to detect the architecture. */
#if defined(ARCH_X86)
#  if defined(XXHSUM_DISPATCH)
#    define ARCH ARCH_X86 " autoVec"
#  elif defined(__AVX512F__)
#    define ARCH ARCH_X86 " + AVX512"
#  elif defined(__AVX2__)
#    define ARCH ARCH_X86 " + AVX2"
#  elif defined(__AVX__)
#    define ARCH ARCH_X86 " + AVX"
#  elif defined(_M_X64) || defined(_M_AMD64) || defined(__x86_64__) \
      || defined(__SSE2__) || (defined(_M_IX86_FP) && _M_IX86_FP == 2)
#     define ARCH ARCH_X86 " + SSE2"
#  else
#     define ARCH ARCH_X86
#  endif
#elif defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
#  define ARCH "aarch64 + NEON"
#elif defined(__arm__) || defined(__thumb__) || defined(__thumb2__) || defined(_M_ARM)
/* ARM has a lot of different features that can change xxHash significantly. */
#  if defined(__thumb2__) || (defined(__thumb__) && (__thumb__ == 2 || __ARM_ARCH >= 7))
#    define ARCH_THUMB " Thumb-2"
#  elif defined(__thumb__)
#    define ARCH_THUMB " Thumb-1"
#  else
#    define ARCH_THUMB ""
#  endif
/* ARMv7 has unaligned by default */
#  if defined(__ARM_FEATURE_UNALIGNED) || __ARM_ARCH >= 7 || defined(_M_ARMV7VE)
#    define ARCH_UNALIGNED " + unaligned"
#  else
#    define ARCH_UNALIGNED ""
#  endif
#  if defined(__ARM_NEON) || defined(__ARM_NEON__)
#    define ARCH_NEON " + NEON"
#  else
#    define ARCH_NEON ""
#  endif
#  define ARCH "ARMv" EXPAND_AND_QUOTE(__ARM_ARCH) ARCH_THUMB ARCH_NEON ARCH_UNALIGNED
#elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__)
#  if defined(__GNUC__) && defined(__POWER9_VECTOR__)
#    define ARCH "ppc64 + POWER9 vector"
#  elif defined(__GNUC__) && defined(__POWER8_VECTOR__)
#    define ARCH "ppc64 + POWER8 vector"
#  else
#    define ARCH "ppc64"
#  endif
#elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)
#  define ARCH "ppc"
#elif defined(__AVR)
#  define ARCH "AVR"
#elif defined(__mips64)
#  define ARCH "mips64"
#elif defined(__mips)
#  define ARCH "mips"
#elif defined(__s390x__)
#  define ARCH "s390x"
#elif defined(__s390__)
#  define ARCH "s390"
#else
#  define ARCH "unknown"
#endif

static const int g_nbBits = (int)(sizeof(void*)*8);
static const char g_lename[] = "little endian";
static const char g_bename[] = "big endian";
#define ENDIAN_NAME (BMK_isLittleEndian() ? g_lename : g_bename)
static const char author[] = "Yann Collet";
#define WELCOME_MESSAGE(exename) "%s %s by %s \n", exename, PROGRAM_VERSION, author
#define FULL_WELCOME_MESSAGE(exename) "%s %s by %s \n" \
                    "compiled as %i-bit %s %s with " CC_VERSION_FMT " \n", \
                    exename, PROGRAM_VERSION, author, \
                    g_nbBits, ARCH, ENDIAN_NAME, CC_VERSION

#define KB *( 1<<10)
#define MB *( 1<<20)
#define GB *(1U<<30)

static size_t XXH_DEFAULT_SAMPLE_SIZE = 100 KB;
#define NBLOOPS    3                              /* Default number of benchmark iterations */
#define TIMELOOP_S 1
#define TIMELOOP  (TIMELOOP_S * CLOCKS_PER_SEC)   /* target timing per iteration */
#define TIMELOOP_MIN (TIMELOOP / 2)               /* minimum timing to validate a result */
#define XXHSUM32_DEFAULT_SEED 0                   /* Default seed for algo_xxh32 */
#define XXHSUM64_DEFAULT_SEED 0                   /* Default seed for algo_xxh64 */

#define MAX_MEM    (2 GB - 64 MB)

static const char stdinName[] = "-";
typedef enum { algo_xxh32=0, algo_xxh64=1, algo_xxh128=2 } AlgoSelected;
static AlgoSelected g_defaultAlgo = algo_xxh64;    /* required within main() & usage() */

/* <16 hex char> <SPC> <SPC> <filename> <'\0'>
 * '4096' is typical Linux PATH_MAX configuration. */
#define DEFAULT_LINE_LENGTH (sizeof(XXH64_hash_t) * 2 + 2 + 4096 + 1)

/* Maximum acceptable line length. */
#define MAX_LINE_LENGTH (32 KB)


/* ************************************
 *  Display macros
 **************************************/
#ifdef _WIN32
#define DISPLAY(...)         fprintf_utf8(stderr, __VA_ARGS__)
#define DISPLAYRESULT(...)   fprintf_utf8(stdout, __VA_ARGS__)
#else
#define DISPLAY(...)         fprintf(stderr, __VA_ARGS__)
#define DISPLAYRESULT(...)   fprintf(stdout, __VA_ARGS__)
#endif

#define DISPLAYLEVEL(l, ...) do { if (g_displayLevel>=l) DISPLAY(__VA_ARGS__); } while (0)
static int g_displayLevel = 2;


/* ************************************
 *  Local variables
 **************************************/
static U32 g_nbIterations = NBLOOPS;


/* ************************************
 *  Benchmark Functions
 **************************************/
static clock_t BMK_clockSpan( clock_t start )
{
    return clock() - start;   /* works even if overflow; Typical max span ~ 30 mn */
}


static size_t BMK_findMaxMem(U64 requiredMem)
{
    size_t const step = 64 MB;
    void* testmem = NULL;

    requiredMem = (((requiredMem >> 26) + 1) << 26);
    requiredMem += 2*step;
    if (requiredMem > MAX_MEM) requiredMem = MAX_MEM;

    while (!testmem) {
        if (requiredMem > step) requiredMem -= step;
        else requiredMem >>= 1;
        testmem = malloc ((size_t)requiredMem);
    }
    free (testmem);

    /* keep some space available */
    if (requiredMem > step) requiredMem -= step;
    else requiredMem >>= 1;

    return (size_t)requiredMem;
}


static U64 BMK_GetFileSize(const char* infilename)
{
    int r;
#if defined(_MSC_VER)
    struct _stat64 statbuf;
    r = _stat64(infilename, &statbuf);
#else
    struct stat statbuf;
    r = stat(infilename, &statbuf);
#endif
    if (r || !S_ISREG(statbuf.st_mode)) return 0;   /* No good... */
    return (U64)statbuf.st_size;
}

/*
 * Allocates a string containing s1 and s2 concatenated. Acts like strdup.
 * The result must be freed.
 */
static char* XXH_strcatDup(const char* s1, const char* s2)
{
    assert(s1 != NULL);
    assert(s2 != NULL);
    {   size_t len1 = strlen(s1);
        size_t len2 = strlen(s2);
        char* buf = (char*)malloc(len1 + len2 + 1);
        if (buf != NULL) {
            /* strcpy(buf, s1) */
            memcpy(buf, s1, len1);
            /* strcat(buf, s2) */
            memcpy(buf + len1, s2, len2 + 1);
        }
        return buf;
    }
}


/* use #define to make them constant, required for initialization */
#define PRIME32 2654435761U
#define PRIME64 11400714785074694797ULL

/*
 * Fills a test buffer with pseudorandom data.
 *
 * This is used in the sanity check - its values must not be changed.
 */
static void BMK_fillTestBuffer(U8* buffer, size_t len)
{
    U64 byteGen = PRIME32;
    size_t i;

    assert(buffer != NULL);

    for (i=0; i<len; i++) {
        buffer[i] = (U8)(byteGen>>56);
        byteGen *= PRIME64;
    }
}

/*
 * A secret buffer used for benchmarking XXH3's withSecret variants.
 *
 * In order for the bench to be realistic, the secret buffer would need to be
 * pre-generated.
 *
 * Adding a pointer to the parameter list would be messy.
 */
static U8 g_benchSecretBuf[XXH3_SECRET_SIZE_MIN];

/*
 * Wrappers for the benchmark.
 *
 * If you would like to add other hashes to the bench, create a wrapper and add
 * it to the g_hashesToBench table. It will automatically be added.
 */
typedef U32 (*hashFunction)(const void* buffer, size_t bufferSize, U32 seed);

static U32 localXXH32(const void* buffer, size_t bufferSize, U32 seed)
{
    return XXH32(buffer, bufferSize, seed);
}
static U32 localXXH64(const void* buffer, size_t bufferSize, U32 seed)
{
    return (U32)XXH64(buffer, bufferSize, seed);
}
static U32 localXXH3_64b(const void* buffer, size_t bufferSize, U32 seed)
{
    (void)seed;
    return (U32)XXH3_64bits(buffer, bufferSize);
}
static U32 localXXH3_64b_seeded(const void* buffer, size_t bufferSize, U32 seed)
{
    return (U32)XXH3_64bits_withSeed(buffer, bufferSize, seed);
}
static U32 localXXH3_64b_secret(const void* buffer, size_t bufferSize, U32 seed)
{
    (void)seed;
    return (U32)XXH3_64bits_withSecret(buffer, bufferSize, g_benchSecretBuf, sizeof(g_benchSecretBuf));
}
static U32 localXXH3_128b(const void* buffer, size_t bufferSize, U32 seed)
{
    (void)seed;
    return (U32)(XXH3_128bits(buffer, bufferSize).low64);
}
static U32 localXXH3_128b_seeded(const void* buffer, size_t bufferSize, U32 seed)
{
    return (U32)(XXH3_128bits_withSeed(buffer, bufferSize, seed).low64);
}
static U32 localXXH3_128b_secret(const void* buffer, size_t bufferSize, U32 seed)
{
    (void)seed;
    return (U32)(XXH3_128bits_withSecret(buffer, bufferSize, g_benchSecretBuf, sizeof(g_benchSecretBuf)).low64);
}
static U32 localXXH3_stream(const void* buffer, size_t bufferSize, U32 seed)
{
    XXH3_state_t state;
    (void)seed;
    XXH3_64bits_reset(&state);
    XXH3_64bits_update(&state, buffer, bufferSize);
    return (U32)XXH3_64bits_digest(&state);
}
static U32 localXXH3_stream_seeded(const void* buffer, size_t bufferSize, U32 seed)
{
    XXH3_state_t state;
    XXH3_INITSTATE(&state);
    XXH3_64bits_reset_withSeed(&state, (XXH64_hash_t)seed);
    XXH3_64bits_update(&state, buffer, bufferSize);
    return (U32)XXH3_64bits_digest(&state);
}
static U32 localXXH128_stream(const void* buffer, size_t bufferSize, U32 seed)
{
    XXH3_state_t state;
    (void)seed;
    XXH3_128bits_reset(&state);
    XXH3_128bits_update(&state, buffer, bufferSize);
    return (U32)(XXH3_128bits_digest(&state).low64);
}
static U32 localXXH128_stream_seeded(const void* buffer, size_t bufferSize, U32 seed)
{
    XXH3_state_t state;
    XXH3_INITSTATE(&state);
    XXH3_128bits_reset_withSeed(&state, (XXH64_hash_t)seed);
    XXH3_128bits_update(&state, buffer, bufferSize);
    return (U32)(XXH3_128bits_digest(&state).low64);
}


typedef struct {
    const char*  name;
    hashFunction func;
} hashInfo;

#define NB_HASHFUNC 12
static const hashInfo g_hashesToBench[NB_HASHFUNC] = {
    { "XXH32",             &localXXH32 },
    { "XXH64",             &localXXH64 },
    { "XXH3_64b",          &localXXH3_64b },
    { "XXH3_64b w/seed",   &localXXH3_64b_seeded },
    { "XXH3_64b w/secret", &localXXH3_64b_secret },
    { "XXH128",            &localXXH3_128b },
    { "XXH128 w/seed",     &localXXH3_128b_seeded },
    { "XXH128 w/secret",   &localXXH3_128b_secret },
    { "XXH3_stream",       &localXXH3_stream },
    { "XXH3_stream w/seed",&localXXH3_stream_seeded },
    { "XXH128_stream",     &localXXH128_stream },
    { "XXH128_stream w/seed",&localXXH128_stream_seeded },
};

#define NB_TESTFUNC (1 + 2 * NB_HASHFUNC)
static char g_testIDs[NB_TESTFUNC] = { 0 };
static const char k_testIDs_default[NB_TESTFUNC] = { 0,
        1 /*XXH32*/, 0,
        1 /*XXH64*/, 0,
        1 /*XXH3*/, 0, 0, 0, 0, 0,
        1 /*XXH128*/ };

#define HASHNAME_MAX 29
static void BMK_benchHash(hashFunction h, const char* hName, int testID,
                          const void* buffer, size_t bufferSize)
{
    U32 nbh_perIteration = (U32)((300 MB) / (bufferSize+1)) + 1;  /* first iteration conservatively aims for 300 MB/s */
    unsigned iterationNb, nbIterations = g_nbIterations + !g_nbIterations /* min 1 */;
    double fastestH = 100000000.;
    assert(HASHNAME_MAX > 2);
    DISPLAYLEVEL(2, "\r%80s\r", "");       /* Clean display line */

    for (iterationNb = 1; iterationNb <= nbIterations; iterationNb++) {
        U32 r=0;
        clock_t cStart;

        DISPLAYLEVEL(2, "%2u-%-*.*s : %10u ->\r",
                        iterationNb,
                        HASHNAME_MAX, HASHNAME_MAX, hName,
                        (unsigned)bufferSize);
        cStart = clock();
        while (clock() == cStart);   /* starts clock() at its exact beginning */
        cStart = clock();

        {   U32 u;
            for (u=0; u<nbh_perIteration; u++)
                r += h(buffer, bufferSize, u);
        }
        if (r==0) DISPLAYLEVEL(3,".\r");  /* do something with r to defeat compiler "optimizing" hash away */

        {   clock_t const nbTicks = BMK_clockSpan(cStart);
            double const ticksPerHash = ((double)nbTicks / TIMELOOP) / nbh_perIteration;
            /*
             * clock() is the only decent portable timer, but it isn't very
             * precise.
             *
             * Sometimes, this lack of precision is enough that the benchmark
             * finishes before there are enough ticks to get a meaningful result.
             *
             * For example, on a Core 2 Duo (without any sort of Turbo Boost),
             * the imprecise timer caused peculiar results like so:
             *
             *    XXH3_64b                   4800.0 MB/s // conveniently even
             *    XXH3_64b unaligned         4800.0 MB/s
             *    XXH3_64b seeded            9600.0 MB/s // magical 2x speedup?!
             *    XXH3_64b seeded unaligned  4800.0 MB/s
             *
             * If we sense a suspiciously low number of ticks, we increase the
             * iterations until we can get something meaningful.
             */
            if (nbTicks < TIMELOOP_MIN) {
                /* Not enough time spent in benchmarking, risk of rounding bias */
                if (nbTicks == 0) { /* faster than resolution timer */
                    nbh_perIteration *= 100;
                } else {
                    /*
                     * update nbh_perIteration so that the next round lasts
                     * approximately 1 second.
                     */
                    double nbh_perSecond = (1 / ticksPerHash) + 1;
                    if (nbh_perSecond > (double)(4000U<<20)) nbh_perSecond = (double)(4000U<<20);   /* avoid overflow */
                    nbh_perIteration = (U32)nbh_perSecond;
                }
                /* g_nbIterations==0 => quick evaluation, no claim of accuracy */
                if (g_nbIterations>0) {
                    iterationNb--;   /* new round for a more accurate speed evaluation */
                    continue;
                }
            }
            if (ticksPerHash < fastestH) fastestH = ticksPerHash;
            if (fastestH>0.) { /* avoid div by zero */
                DISPLAYLEVEL(2, "%2u-%-*.*s : %10u -> %8.0f it/s (%7.1f MB/s) \r",
                            iterationNb,
                            HASHNAME_MAX, HASHNAME_MAX, hName,
                            (unsigned)bufferSize,
                            (double)1 / fastestH,
                            ((double)bufferSize / (1 MB)) / fastestH);
        }   }
        {   double nbh_perSecond = (1 / fastestH) + 1;
            if (nbh_perSecond > (double)(4000U<<20)) nbh_perSecond = (double)(4000U<<20);   /* avoid overflow */
            nbh_perIteration = (U32)nbh_perSecond;
        }
    }
    DISPLAYLEVEL(1, "%2i#%-*.*s : %10u -> %8.0f it/s (%7.1f MB/s) \n",
                    testID,
                    HASHNAME_MAX, HASHNAME_MAX, hName,
                    (unsigned)bufferSize,
                    (double)1 / fastestH,
                    ((double)bufferSize / (1 MB)) / fastestH);
    if (g_displayLevel<1)
        DISPLAYLEVEL(0, "%u, ", (unsigned)((double)1 / fastestH));
}


/*!
 * BMK_benchMem():
 * buffer: Must be 16-byte aligned.
 * The real allocated size of buffer is supposed to be >= (bufferSize+3).
 * returns: 0 on success, 1 if error (invalid mode selected)
 */
static void BMK_benchMem(const void* buffer, size_t bufferSize)
{
    assert((((size_t)buffer) & 15) == 0);  /* ensure alignment */
    BMK_fillTestBuffer(g_benchSecretBuf, sizeof(g_benchSecretBuf));
    {   int i;
        for (i = 1; i < NB_TESTFUNC; i++) {
            int const hashFuncID = (i-1) / 2;
            assert(g_hashesToBench[hashFuncID].name != NULL);
            if (g_testIDs[i] == 0) continue;
            /* aligned */
            if ((i % 2) == 1) {
                BMK_benchHash(g_hashesToBench[hashFuncID].func, g_hashesToBench[hashFuncID].name, i, buffer, bufferSize);
            }
            /* unaligned */
            if ((i % 2) == 0) {
                /* Append "unaligned". */
                char* const hashNameBuf = XXH_strcatDup(g_hashesToBench[hashFuncID].name, " unaligned");
                assert(hashNameBuf != NULL);
                BMK_benchHash(g_hashesToBench[hashFuncID].func, hashNameBuf, i, ((const char*)buffer)+3, bufferSize);
                free(hashNameBuf);
            }
    }   }
}

static size_t BMK_selectBenchedSize(const char* fileName)
{
    U64 const inFileSize = BMK_GetFileSize(fileName);
    size_t benchedSize = (size_t) BMK_findMaxMem(inFileSize);
    if ((U64)benchedSize > inFileSize) benchedSize = (size_t)inFileSize;
    if (benchedSize < inFileSize) {
        DISPLAY("Not enough memory for '%s' full size; testing %i MB only...\n", fileName, (int)(benchedSize>>20));
    }
    return benchedSize;
}


static int BMK_benchFiles(const char*const* fileNamesTable, int nbFiles)
{
    int fileIdx;
    for (fileIdx=0; fileIdx<nbFiles; fileIdx++) {
        const char* const inFileName = fileNamesTable[fileIdx];
        assert(inFileName != NULL);

        {   FILE* const inFile = XXH_fopen( inFileName, "rb" );
            size_t const benchedSize = BMK_selectBenchedSize(inFileName);
            char* const buffer = (char*)calloc(benchedSize+16+3, 1);
            void* const alignedBuffer = (buffer+15) - (((size_t)(buffer+15)) & 0xF);  /* align on next 16 bytes */

            /* Checks */
            if (inFile==NULL){
                DISPLAY("Error: Could not open '%s': %s.\n", inFileName, strerror(errno));
                free(buffer);
                exit(11);
            }
            if(!buffer) {
                DISPLAY("\nError: Out of memory.\n");
                fclose(inFile);
                exit(12);
            }

            /* Fill input buffer */
            {   size_t const readSize = fread(alignedBuffer, 1, benchedSize, inFile);
                fclose(inFile);
                if(readSize != benchedSize) {
                    DISPLAY("\nError: Could not read '%s': %s.\n", inFileName, strerror(errno));
                    free(buffer);
                    exit(13);
            }   }

            /* bench */
            BMK_benchMem(alignedBuffer, benchedSize);

            free(buffer);
    }   }
    return 0;
}


static int BMK_benchInternal(size_t keySize)
{
    void* const buffer = calloc(keySize+16+3, 1);
    if (buffer == NULL) {
        DISPLAY("\nError: Out of memory.\n");
        exit(12);
    }

    {   const void* const alignedBuffer = ((char*)buffer+15) - (((size_t)((char*)buffer+15)) & 0xF);  /* align on next 16 bytes */

        /* bench */
        DISPLAYLEVEL(1, "Sample of ");
        if (keySize > 10 KB) {
            DISPLAYLEVEL(1, "%u KB", (unsigned)(keySize >> 10));
        } else {
            DISPLAYLEVEL(1, "%u bytes", (unsigned)keySize);
        }
        DISPLAYLEVEL(1, "...        \n");

        BMK_benchMem(alignedBuffer, keySize);
        free(buffer);
    }
    return 0;
}


/* ************************************************
 * Self-test:
 * ensure results consistency accross platforms
 *********************************************** */

static void BMK_checkResult32(XXH32_hash_t r1, XXH32_hash_t r2)
{
    static int nbTests = 1;
    if (r1!=r2) {
        DISPLAY("\rError: 32-bit hash test %i: Internal sanity check failed!\n", nbTests);
        DISPLAY("\rGot 0x%08X, expected 0x%08X.\n", (unsigned)r1, (unsigned)r2);
        DISPLAY("\rNote: If you modified the hash functions, make sure to either update the values\n"
                  "or temporarily comment out the tests in BMK_sanityCheck.\n");
        exit(1);
    }
    nbTests++;
}

static void BMK_checkResult64(XXH64_hash_t r1, XXH64_hash_t r2)
{
    static int nbTests = 1;
    if (r1!=r2) {
        DISPLAY("\rError: 64-bit hash test %i: Internal sanity check failed!\n", nbTests);
        DISPLAY("\rGot 0x%08X%08XULL, expected 0x%08X%08XULL.\n",
                (unsigned)(r1>>32), (unsigned)r1, (unsigned)(r2>>32), (unsigned)r2);
        DISPLAY("\rNote: If you modified the hash functions, make sure to either update the values\n"
                  "or temporarily comment out the tests in BMK_sanityCheck.\n");
        exit(1);
    }
    nbTests++;
}

static void BMK_checkResult128(XXH128_hash_t r1, XXH128_hash_t r2)
{
    static int nbTests = 1;
    if ((r1.low64 != r2.low64) || (r1.high64 != r2.high64)) {
        DISPLAY("\rError: 128-bit hash test %i: Internal sanity check failed.\n", nbTests);
        DISPLAY("\rGot { 0x%08X%08XULL, 0x%08X%08XULL }, expected { 0x%08X%08XULL, 0x%08X%08XULL } \n",
                (unsigned)(r1.low64>>32), (unsigned)r1.low64, (unsigned)(r1.high64>>32), (unsigned)r1.high64,
                (unsigned)(r2.low64>>32), (unsigned)r2.low64, (unsigned)(r2.high64>>32), (unsigned)r2.high64 );
        DISPLAY("\rNote: If you modified the hash functions, make sure to either update the values\n"
                  "or temporarily comment out the tests in BMK_sanityCheck.\n");
        exit(1);
    }
    nbTests++;
}


static void BMK_testXXH32(const void* data, size_t len, U32 seed, U32 Nresult)
{
    XXH32_state_t *state = XXH32_createState();
    size_t pos;

    assert(state != NULL);
    if (len>0) assert(data != NULL);

    BMK_checkResult32(XXH32(data, len, seed), Nresult);

    (void)XXH32_reset(state, seed);
    (void)XXH32_update(state, data, len);
    BMK_checkResult32(XXH32_digest(state), Nresult);

    (void)XXH32_reset(state, seed);
    for (pos=0; pos<len; pos++)
        (void)XXH32_update(state, ((const char*)data)+pos, 1);
    BMK_checkResult32(XXH32_digest(state), Nresult);
    XXH32_freeState(state);
}

static void BMK_testXXH64(const void* data, size_t len, U64 seed, U64 Nresult)
{
    XXH64_state_t *state = XXH64_createState();
    size_t pos;

    assert(state != NULL);
    if (len>0) assert(data != NULL);

    BMK_checkResult64(XXH64(data, len, seed), Nresult);

    (void)XXH64_reset(state, seed);
    (void)XXH64_update(state, data, len);
    BMK_checkResult64(XXH64_digest(state), Nresult);

    (void)XXH64_reset(state, seed);
    for (pos=0; pos<len; pos++)
        (void)XXH64_update(state, ((const char*)data)+pos, 1);
    BMK_checkResult64(XXH64_digest(state), Nresult);
    XXH64_freeState(state);
}

static U32 BMK_rand(void)
{
    static U64 seed = PRIME32;
    seed *= PRIME64;
    return (U32)(seed >> 40);
}


void BMK_testXXH3(const void* data, size_t len, U64 seed, U64 Nresult)
{
    if (len>0) assert(data != NULL);

    {   U64 const Dresult = XXH3_64bits_withSeed(data, len, seed);
        BMK_checkResult64(Dresult, Nresult);
    }

    /* check that the no-seed variant produces same result as seed==0 */
    if (seed == 0) {
        U64 const Dresult = XXH3_64bits(data, len);
        BMK_checkResult64(Dresult, Nresult);
    }

    /* streaming API test */
    {   XXH3_state_t* const state = XXH3_createState();
        assert(state != NULL);
        /* single ingestion */
        (void)XXH3_64bits_reset_withSeed(state, seed);
        (void)XXH3_64bits_update(state, data, len);
        BMK_checkResult64(XXH3_64bits_digest(state), Nresult);

        /* random ingestion */
        {   size_t p = 0;
            (void)XXH3_64bits_reset_withSeed(state, seed);
            while (p < len) {
                size_t const modulo = len > 2 ? len : 2;
                size_t l = (size_t)(BMK_rand()) % modulo;
                if (p + l > len) l = len - p;
                (void)XXH3_64bits_update(state, (const char*)data+p, l);
                p += l;
            }
            BMK_checkResult64(XXH3_64bits_digest(state), Nresult);
        }

        /* byte by byte ingestion */
        {   size_t pos;
            (void)XXH3_64bits_reset_withSeed(state, seed);
            for (pos=0; pos<len; pos++)
                (void)XXH3_64bits_update(state, ((const char*)data)+pos, 1);
            BMK_checkResult64(XXH3_64bits_digest(state), Nresult);
        }
        XXH3_freeState(state);
    }
}

void BMK_testXXH3_withSecret(const void* data, size_t len, const void* secret, size_t secretSize, U64 Nresult)
{
    if (len>0) assert(data != NULL);

    {   U64 const Dresult = XXH3_64bits_withSecret(data, len, secret, secretSize);
        BMK_checkResult64(Dresult, Nresult);
    }

    /* streaming API test */
    {   XXH3_state_t *state = XXH3_createState();
        assert(state != NULL);
        (void)XXH3_64bits_reset_withSecret(state, secret, secretSize);
        (void)XXH3_64bits_update(state, data, len);
        BMK_checkResult64(XXH3_64bits_digest(state), Nresult);

        /* random ingestion */
        {   size_t p = 0;
            (void)XXH3_64bits_reset_withSecret(state, secret, secretSize);
            while (p < len) {
                size_t const modulo = len > 2 ? len : 2;
                size_t l = (size_t)(BMK_rand()) % modulo;
                if (p + l > len) l = len - p;
                (void)XXH3_64bits_update(state, (const char*)data+p, l);
                p += l;
            }
            BMK_checkResult64(XXH3_64bits_digest(state), Nresult);
        }

        /* byte by byte ingestion */
        {   size_t pos;
            (void)XXH3_64bits_reset_withSecret(state, secret, secretSize);
            for (pos=0; pos<len; pos++)
                (void)XXH3_64bits_update(state, ((const char*)data)+pos, 1);
            BMK_checkResult64(XXH3_64bits_digest(state), Nresult);
        }
        XXH3_freeState(state);
    }
}

void BMK_testXXH128(const void* data, size_t len, U64 seed, XXH128_hash_t Nresult)
{
    {   XXH128_hash_t const Dresult = XXH3_128bits_withSeed(data, len, seed);
        BMK_checkResult128(Dresult, Nresult);
    }

    /* check that XXH128() is identical to XXH3_128bits_withSeed() */
    {   XXH128_hash_t const Dresult2 = XXH128(data, len, seed);
        BMK_checkResult128(Dresult2, Nresult);
    }

    /* check that the no-seed variant produces same result as seed==0 */
    if (seed == 0) {
        XXH128_hash_t const Dresult = XXH3_128bits(data, len);
        BMK_checkResult128(Dresult, Nresult);
    }

    /* streaming API test */
    {   XXH3_state_t *state = XXH3_createState();
        assert(state != NULL);

        /* single ingestion */
        (void)XXH3_128bits_reset_withSeed(state, seed);
        (void)XXH3_128bits_update(state, data, len);
        BMK_checkResult128(XXH3_128bits_digest(state), Nresult);

        /* random ingestion */
        {   size_t p = 0;
            (void)XXH3_128bits_reset_withSeed(state, seed);
            while (p < len) {
                size_t const modulo = len > 2 ? len : 2;
                size_t l = (size_t)(BMK_rand()) % modulo;
                if (p + l > len) l = len - p;
                (void)XXH3_128bits_update(state, (const char*)data+p, l);
                p += l;
            }
            BMK_checkResult128(XXH3_128bits_digest(state), Nresult);
        }

        /* byte by byte ingestion */
        {   size_t pos;
            (void)XXH3_128bits_reset_withSeed(state, seed);
            for (pos=0; pos<len; pos++)
                (void)XXH3_128bits_update(state, ((const char*)data)+pos, 1);
            BMK_checkResult128(XXH3_128bits_digest(state), Nresult);
        }
        XXH3_freeState(state);
    }
}

void BMK_testXXH128_withSecret(const void* data, size_t len, const void* secret, size_t secretSize, XXH128_hash_t Nresult)
{
    if (len>0) assert(data != NULL);

    {   XXH128_hash_t const Dresult = XXH3_128bits_withSecret(data, len, secret, secretSize);
        BMK_checkResult128(Dresult, Nresult);
    }

    /* streaming API test */
    {   XXH3_state_t* const state = XXH3_createState();
        assert(state != NULL);
        (void)XXH3_128bits_reset_withSecret(state, secret, secretSize);
        (void)XXH3_128bits_update(state, data, len);
        BMK_checkResult128(XXH3_128bits_digest(state), Nresult);

        /* random ingestion */
        {   size_t p = 0;
            (void)XXH3_128bits_reset_withSecret(state, secret, secretSize);
            while (p < len) {
                size_t const modulo = len > 2 ? len : 2;
                size_t l = (size_t)(BMK_rand()) % modulo;
                if (p + l > len) l = len - p;
                (void)XXH3_128bits_update(state, (const char*)data+p, l);
                p += l;
            }
            BMK_checkResult128(XXH3_128bits_digest(state), Nresult);
        }

        /* byte by byte ingestion */
        {   size_t pos;
            (void)XXH3_128bits_reset_withSecret(state, secret, secretSize);
            for (pos=0; pos<len; pos++)
                (void)XXH3_128bits_update(state, ((const char*)data)+pos, 1);
            BMK_checkResult128(XXH3_128bits_digest(state), Nresult);
        }
        XXH3_freeState(state);
    }
}

#define SECRET_SAMPLE_NBBYTES 4
typedef struct { U8 byte[SECRET_SAMPLE_NBBYTES]; } verifSample_t;

void BMK_testSecretGenerator(const void* customSeed, size_t len, verifSample_t result)
{
    static int nbTests = 1;
    const int sampleIndex[SECRET_SAMPLE_NBBYTES] = { 0, 62, 131, 191};
    U8 secretBuffer[XXH3_SECRET_DEFAULT_SIZE] = {0};
    verifSample_t samples;
    int i;

    XXH3_generateSecret(secretBuffer, customSeed, len);
    for (i=0; i<SECRET_SAMPLE_NBBYTES; i++) {
        samples.byte[i] = secretBuffer[sampleIndex[i]];
    }
    if (memcmp(&samples, &result, sizeof(result))) {
        DISPLAY("\rError: Secret generation test %i: Internal sanity check failed. \n", nbTests);
        DISPLAY("\rGot { 0x%02X, 0x%02X, 0x%02X, 0x%02X }, expected { 0x%02X, 0x%02X, 0x%02X, 0x%02X } \n",
                samples.byte[0], samples.byte[1], samples.byte[2], samples.byte[3],
                result.byte[0], result.byte[1], result.byte[2], result.byte[3] );
        exit(1);
    }
    nbTests++;
}


/*!
 * BMK_sanityCheck():
 * Runs a sanity check before the benchmark.
 *
 * Exits on an incorrect output.
 */
static void BMK_sanityCheck(void)
{
#define SANITY_BUFFER_SIZE 2367
    U8 sanityBuffer[SANITY_BUFFER_SIZE];
    BMK_fillTestBuffer(sanityBuffer, sizeof(sanityBuffer));

    BMK_testXXH32(NULL,          0, 0,       0x02CC5D05);
    BMK_testXXH32(NULL,          0, PRIME32, 0x36B78AE7);
    BMK_testXXH32(sanityBuffer,  1, 0,       0xCF65B03E);
    BMK_testXXH32(sanityBuffer,  1, PRIME32, 0xB4545AA4);
    BMK_testXXH32(sanityBuffer, 14, 0,       0x1208E7E2);
    BMK_testXXH32(sanityBuffer, 14, PRIME32, 0x6AF1D1FE);
    BMK_testXXH32(sanityBuffer,222, 0,       0x5BD11DBD);
    BMK_testXXH32(sanityBuffer,222, PRIME32, 0x58803C5F);

    BMK_testXXH64(NULL        ,  0, 0,       0xEF46DB3751D8E999ULL);
    BMK_testXXH64(NULL        ,  0, PRIME32, 0xAC75FDA2929B17EFULL);
    BMK_testXXH64(sanityBuffer,  1, 0,       0xE934A84ADB052768ULL);
    BMK_testXXH64(sanityBuffer,  1, PRIME32, 0x5014607643A9B4C3ULL);
    BMK_testXXH64(sanityBuffer,  4, 0,       0x9136A0DCA57457EEULL);
    BMK_testXXH64(sanityBuffer, 14, 0,       0x8282DCC4994E35C8ULL);
    BMK_testXXH64(sanityBuffer, 14, PRIME32, 0xC3BD6BF63DEB6DF0ULL);
    BMK_testXXH64(sanityBuffer,222, 0,       0xB641AE8CB691C174ULL);
    BMK_testXXH64(sanityBuffer,222, PRIME32, 0x20CB8AB7AE10C14AULL);

    BMK_testXXH3(NULL,           0, 0,       0x2D06800538D394C2ULL);  /* empty string */
    BMK_testXXH3(NULL,           0, PRIME64, 0xA8A6B918B2F0364AULL);
    BMK_testXXH3(sanityBuffer,   1, 0,       0xC44BDFF4074EECDBULL);  /*  1 -  3 */
    BMK_testXXH3(sanityBuffer,   1, PRIME64, 0x032BE332DD766EF8ULL);  /*  1 -  3 */
    BMK_testXXH3(sanityBuffer,   6, 0,       0x27B56A84CD2D7325ULL);  /*  4 -  8 */
    BMK_testXXH3(sanityBuffer,   6, PRIME64, 0x84589C116AB59AB9ULL);  /*  4 -  8 */
    BMK_testXXH3(sanityBuffer,  12, 0,       0xA713DAF0DFBB77E7ULL);  /*  9 - 16 */
    BMK_testXXH3(sanityBuffer,  12, PRIME64, 0xE7303E1B2336DE0EULL);  /*  9 - 16 */
    BMK_testXXH3(sanityBuffer,  24, 0,       0xA3FE70BF9D3510EBULL);  /* 17 - 32 */
    BMK_testXXH3(sanityBuffer,  24, PRIME64, 0x850E80FC35BDD690ULL);  /* 17 - 32 */
    BMK_testXXH3(sanityBuffer,  48, 0,       0x397DA259ECBA1F11ULL);  /* 33 - 64 */
    BMK_testXXH3(sanityBuffer,  48, PRIME64, 0xADC2CBAA44ACC616ULL);  /* 33 - 64 */
    BMK_testXXH3(sanityBuffer,  80, 0,       0xBCDEFBBB2C47C90AULL);  /* 65 - 96 */
    BMK_testXXH3(sanityBuffer,  80, PRIME64, 0xC6DD0CB699532E73ULL);  /* 65 - 96 */
    BMK_testXXH3(sanityBuffer, 195, 0,       0xCD94217EE362EC3AULL);  /* 129-240 */
    BMK_testXXH3(sanityBuffer, 195, PRIME64, 0xBA68003D370CB3D9ULL);  /* 129-240 */

    BMK_testXXH3(sanityBuffer, 403, 0,       0xCDEB804D65C6DEA4ULL);  /* one block, last stripe is overlapping */
    BMK_testXXH3(sanityBuffer, 403, PRIME64, 0x6259F6ECFD6443FDULL);  /* one block, last stripe is overlapping */
    BMK_testXXH3(sanityBuffer, 512, 0,       0x617E49599013CB6BULL);  /* one block, finishing at stripe boundary */
    BMK_testXXH3(sanityBuffer, 512, PRIME64, 0x3CE457DE14C27708ULL);  /* one block, finishing at stripe boundary */
    BMK_testXXH3(sanityBuffer,2048, 0,       0xDD59E2C3A5F038E0ULL);  /* 2 blocks, finishing at block boundary */
    BMK_testXXH3(sanityBuffer,2048, PRIME64, 0x66F81670669ABABCULL);  /* 2 blocks, finishing at block boundary */
    BMK_testXXH3(sanityBuffer,2240, 0,       0x6E73A90539CF2948ULL);  /* 3 blocks, finishing at stripe boundary */
    BMK_testXXH3(sanityBuffer,2240, PRIME64, 0x757BA8487D1B5247ULL);  /* 3 blocks, finishing at stripe boundary */
    BMK_testXXH3(sanityBuffer,2367, 0,       0xCB37AEB9E5D361EDULL);  /* 3 blocks, last stripe is overlapping */
    BMK_testXXH3(sanityBuffer,2367, PRIME64, 0xD2DB3415B942B42AULL);  /* 3 blocks, last stripe is overlapping */

    /* XXH3 with Custom Secret */
    {   const void* const secret = sanityBuffer + 7;
        const size_t secretSize = XXH3_SECRET_SIZE_MIN + 11;
        assert(sizeof(sanityBuffer) >= 7 + secretSize);
        BMK_testXXH3_withSecret(NULL,           0, secret, secretSize, 0x3559D64878C5C66CULL);  /* empty string */
        BMK_testXXH3_withSecret(sanityBuffer,   1, secret, secretSize, 0x8A52451418B2DA4DULL);  /*  1 -  3 */
        BMK_testXXH3_withSecret(sanityBuffer,   6, secret, secretSize, 0x82C90AB0519369ADULL);  /*  4 -  8 */
        BMK_testXXH3_withSecret(sanityBuffer,  12, secret, secretSize, 0x14631E773B78EC57ULL);  /*  9 - 16 */
        BMK_testXXH3_withSecret(sanityBuffer,  24, secret, secretSize, 0xCDD5542E4A9D9FE8ULL);  /* 17 - 32 */
        BMK_testXXH3_withSecret(sanityBuffer,  48, secret, secretSize, 0x33ABD54D094B2534ULL);  /* 33 - 64 */
        BMK_testXXH3_withSecret(sanityBuffer,  80, secret, secretSize, 0xE687BA1684965297ULL);  /* 65 - 96 */
        BMK_testXXH3_withSecret(sanityBuffer, 195, secret, secretSize, 0xA057273F5EECFB20ULL);  /* 129-240 */

        BMK_testXXH3_withSecret(sanityBuffer, 403, secret, secretSize, 0x14546019124D43B8ULL);  /* one block, last stripe is overlapping */
        BMK_testXXH3_withSecret(sanityBuffer, 512, secret, secretSize, 0x7564693DD526E28DULL);  /* one block, finishing at stripe boundary */
        BMK_testXXH3_withSecret(sanityBuffer,2048, secret, secretSize, 0xD32E975821D6519FULL);  /* >= 2 blocks, at least one scrambling */
        BMK_testXXH3_withSecret(sanityBuffer,2367, secret, secretSize, 0x293FA8E5173BB5E7ULL);  /* >= 2 blocks, at least one scrambling, last stripe unaligned */

        BMK_testXXH3_withSecret(sanityBuffer,64*10*3, secret, secretSize, 0x751D2EC54BC6038BULL);  /* exactly 3 full blocks, not a multiple of 256 */
    }

    /* XXH128 */
    {   XXH128_hash_t const expected = { 0x6001C324468D497FULL, 0x99AA06D3014798D8ULL };
        BMK_testXXH128(NULL,           0, 0,     expected);         /* empty string */
    }
    {   XXH128_hash_t const expected = { 0x5444F7869C671AB0ULL, 0x92220AE55E14AB50ULL };
        BMK_testXXH128(NULL,           0, PRIME32, expected);
    }
    {   XXH128_hash_t const expected = { 0xC44BDFF4074EECDBULL, 0xA6CD5E9392000F6AULL };
        BMK_testXXH128(sanityBuffer,   1, 0,       expected);       /* 1-3 */
    }
    {   XXH128_hash_t const expected = { 0xB53D5557E7F76F8DULL, 0x89B99554BA22467CULL };
        BMK_testXXH128(sanityBuffer,   1, PRIME32, expected);       /* 1-3 */
    }
    {   XXH128_hash_t const expected = { 0x3E7039BDDA43CFC6ULL, 0x082AFE0B8162D12AULL };
        BMK_testXXH128(sanityBuffer,   6, 0,       expected);       /* 4-8 */
    }
    {   XXH128_hash_t const expected = { 0x269D8F70BE98856EULL, 0x5A865B5389ABD2B1ULL };
        BMK_testXXH128(sanityBuffer,   6, PRIME32, expected);       /* 4-8 */
    }
    {   XXH128_hash_t const expected = { 0x061A192713F69AD9ULL, 0x6E3EFD8FC7802B18ULL };
        BMK_testXXH128(sanityBuffer,  12, 0,       expected);       /* 9-16 */
    }
    {   XXH128_hash_t const expected = { 0x9BE9F9A67F3C7DFBULL, 0xD7E09D518A3405D3ULL };
        BMK_testXXH128(sanityBuffer,  12, PRIME32, expected);       /* 9-16 */
    }
    {   XXH128_hash_t const expected = { 0x1E7044D28B1B901DULL, 0x0CE966E4678D3761ULL };
        BMK_testXXH128(sanityBuffer,  24, 0,       expected);       /* 17-32 */
    }
    {   XXH128_hash_t const expected = { 0xD7304C54EBAD40A9ULL, 0x3162026714A6A243ULL };
        BMK_testXXH128(sanityBuffer,  24, PRIME32, expected);       /* 17-32 */
    }
    {   XXH128_hash_t const expected = { 0xF942219AED80F67BULL, 0xA002AC4E5478227EULL };
        BMK_testXXH128(sanityBuffer,  48, 0,       expected);       /* 33-64 */
    }
    {   XXH128_hash_t const expected = { 0x7BA3C3E453A1934EULL, 0x163ADDE36C072295ULL };
        BMK_testXXH128(sanityBuffer,  48, PRIME32, expected);       /* 33-64 */
    }
    {   XXH128_hash_t const expected = { 0x5E8BAFB9F95FB803ULL, 0x4952F58181AB0042ULL };
        BMK_testXXH128(sanityBuffer,  81, 0,       expected);       /* 65-96 */
    }
    {   XXH128_hash_t const expected = { 0x703FBB3D7A5F755CULL, 0x2724EC7ADC750FB6ULL };
        BMK_testXXH128(sanityBuffer,  81, PRIME32, expected);       /* 65-96 */
    }
    {   XXH128_hash_t const expected = { 0xF1AEBD597CEC6B3AULL, 0x337E09641B948717ULL };
        BMK_testXXH128(sanityBuffer, 222, 0,       expected);       /* 129-240 */
    }
    {   XXH128_hash_t const expected = { 0xAE995BB8AF917A8DULL, 0x91820016621E97F1ULL };
        BMK_testXXH128(sanityBuffer, 222, PRIME32, expected);       /* 129-240 */
    }
    {   XXH128_hash_t const expected = { 0xCDEB804D65C6DEA4ULL, 0x1B6DE21E332DD73DULL };
        BMK_testXXH128(sanityBuffer, 403, 0,       expected);       /* one block, last stripe is overlapping */
    }
    {   XXH128_hash_t const expected = { 0x6259F6ECFD6443FDULL, 0xBED311971E0BE8F2ULL };
        BMK_testXXH128(sanityBuffer, 403, PRIME64, expected);       /* one block, last stripe is overlapping */
    }
    {   XXH128_hash_t const expected = { 0x617E49599013CB6BULL, 0x18D2D110DCC9BCA1ULL };
        BMK_testXXH128(sanityBuffer, 512, 0,       expected);       /* one block, finishing at stripe boundary */
    }
    {   XXH128_hash_t const expected = { 0x3CE457DE14C27708ULL, 0x925D06B8EC5B8040ULL };
        BMK_testXXH128(sanityBuffer, 512, PRIME64, expected);       /* one block, finishing at stripe boundary */
    }
    {   XXH128_hash_t const expected = { 0xDD59E2C3A5F038E0ULL, 0xF736557FD47073A5ULL };
        BMK_testXXH128(sanityBuffer,2048, 0,       expected);       /* two blocks, finishing at block boundary */
    }
    {   XXH128_hash_t const expected = { 0x230D43F30206260BULL, 0x7FB03F7E7186C3EAULL };
        BMK_testXXH128(sanityBuffer,2048, PRIME32, expected);       /* two blocks, finishing at block boundary */
    }
    {   XXH128_hash_t const expected = { 0x6E73A90539CF2948ULL, 0xCCB134FBFA7CE49DULL };
        BMK_testXXH128(sanityBuffer,2240, 0,       expected);      /* two blocks, ends at stripe boundary */
    }
    {   XXH128_hash_t const expected = { 0xED385111126FBA6FULL, 0x50A1FE17B338995FULL };
        BMK_testXXH128(sanityBuffer,2240, PRIME32, expected);       /* two blocks, ends at stripe boundary */
    }
    {   XXH128_hash_t const expected = { 0xCB37AEB9E5D361EDULL, 0xE89C0F6FF369B427ULL };
        BMK_testXXH128(sanityBuffer,2367, 0,       expected);       /* two blocks, last stripe is overlapping */
    }
    {   XXH128_hash_t const expected = { 0x6F5360AE69C2F406ULL, 0xD23AAE4B76C31ECBULL };
        BMK_testXXH128(sanityBuffer,2367, PRIME32, expected);       /* two blocks, last stripe is overlapping */
    }

    /* XXH128 with custom Secret */
    {   const void* const secret = sanityBuffer + 7;
        const size_t secretSize = XXH3_SECRET_SIZE_MIN + 11;
        assert(sizeof(sanityBuffer) >= 7 + secretSize);

        {   XXH128_hash_t const expected = { 0x005923CCEECBE8AEULL, 0x5F70F4EA232F1D38ULL };
            BMK_testXXH128_withSecret(NULL,           0, secret, secretSize,     expected);         /* empty string */
        }
        {   XXH128_hash_t const expected = { 0x8A52451418B2DA4DULL, 0x3A66AF5A9819198EULL };
            BMK_testXXH128_withSecret(sanityBuffer,   1, secret, secretSize,       expected);       /* 1-3 */
        }
        {   XXH128_hash_t const expected = { 0x0B61C8ACA7D4778FULL, 0x376BD91B6432F36DULL };
            BMK_testXXH128_withSecret(sanityBuffer,   6, secret, secretSize,       expected);       /* 4-8 */
        }
        {   XXH128_hash_t const expected = { 0xAF82F6EBA263D7D8ULL, 0x90A3C2D839F57D0FULL };
            BMK_testXXH128_withSecret(sanityBuffer,  12, secret, secretSize,       expected);       /* 9-16 */
        }
    }

    /* secret generator */
    {   verifSample_t const expected = { { 0xB8, 0x26, 0x83, 0x7E } };
        BMK_testSecretGenerator(NULL, 0, expected);
    }

    {   verifSample_t const expected = { { 0xA6, 0x16, 0x06, 0x7B } };
        BMK_testSecretGenerator(sanityBuffer, 1, expected);
    }

    {   verifSample_t const expected = { { 0xDA, 0x2A, 0x12, 0x11 } };
        BMK_testSecretGenerator(sanityBuffer, XXH3_SECRET_SIZE_MIN - 1, expected);
    }

    {   verifSample_t const expected = { { 0x7E, 0x48, 0x0C, 0xA7 } };
        BMK_testSecretGenerator(sanityBuffer, XXH3_SECRET_DEFAULT_SIZE + 500, expected);
    }

    DISPLAYLEVEL(3, "\r%70s\r", "");       /* Clean display line */
    DISPLAYLEVEL(3, "Sanity check -- all tests ok\n");
}


/* ********************************************************
*  File Hashing
**********************************************************/
#if defined(_MSC_VER)
    typedef struct __stat64 stat_t;
    typedef int mode_t;
#else
    typedef struct stat stat_t;
#endif

#include <sys/types.h>  /* struct stat / __start64 */
#include <sys/stat.h>   /* stat() / _stat64() */

int XSUM_isDirectory(const char* infilename)
{
    stat_t statbuf;
#if defined(_MSC_VER)
    int const r = _stat64(infilename, &statbuf);
    if (!r && (statbuf.st_mode & _S_IFDIR)) return 1;
#else
    int const r = stat(infilename, &statbuf);
    if (!r && S_ISDIR(statbuf.st_mode)) return 1;
#endif
    return 0;
}

/* for support of --little-endian display mode */
static void BMK_display_LittleEndian(const void* ptr, size_t length)
{
    const U8* const p = (const U8*)ptr;
    size_t idx;
    for (idx=length-1; idx<length; idx--)    /* intentional underflow to negative to detect end */
        DISPLAYRESULT("%02x", p[idx]);
}

static void BMK_display_BigEndian(const void* ptr, size_t length)
{
    const U8* const p = (const U8*)ptr;
    size_t idx;
    for (idx=0; idx<length; idx++)
        DISPLAYRESULT("%02x", p[idx]);
}

typedef union {
    XXH32_hash_t   xxh32;
    XXH64_hash_t   xxh64;
    XXH128_hash_t xxh128;
} Multihash;

/*
 * XSUM_hashStream:
 * Reads data from `inFile`, generating an incremental hash of type hashType,
 * using `buffer` of size `blockSize` for temporary storage.
 */
static Multihash
XSUM_hashStream(FILE* inFile,
                AlgoSelected hashType,
                void* buffer, size_t blockSize)
{
    XXH32_state_t state32;
    XXH64_state_t state64;
    XXH3_state_t state128;

    /* Init */
    (void)XXH32_reset(&state32, XXHSUM32_DEFAULT_SEED);
    (void)XXH64_reset(&state64, XXHSUM64_DEFAULT_SEED);
    (void)XXH3_128bits_reset(&state128);

    /* Load file & update hash */
    {   size_t readSize;
        while ((readSize = fread(buffer, 1, blockSize, inFile)) > 0) {
            switch(hashType)
            {
            case algo_xxh32:
                (void)XXH32_update(&state32, buffer, readSize);
                break;
            case algo_xxh64:
                (void)XXH64_update(&state64, buffer, readSize);
                break;
            case algo_xxh128:
                (void)XXH3_128bits_update(&state128, buffer, readSize);
                break;
            default:
                assert(0);
            }
        }
        if (ferror(inFile)) {
            DISPLAY("Error: a failure occurred reading the input file.\n");
            exit(1);
    }   }

    {   Multihash finalHash = {0};
        switch(hashType)
        {
        case algo_xxh32:
            finalHash.xxh32 = XXH32_digest(&state32);
            break;
        case algo_xxh64:
            finalHash.xxh64 = XXH64_digest(&state64);
            break;
        case algo_xxh128:
            finalHash.xxh128 = XXH3_128bits_digest(&state128);
            break;
        default:
            assert(0);
        }
        return finalHash;
    }
}

                                       /* algo_xxh32, algo_xxh64, algo_xxh128 */
static const char* XSUM_algoName[] =    { "XXH32",    "XXH64",    "XXH128" };
static const char* XSUM_algoLE_name[] = { "XXH32_LE", "XXH64_LE", "XXH128_LE" };
static const size_t XSUM_algoLength[] = { 4,          8,          16 };

#define XSUM_TABLE_ELT_SIZE(table)   (sizeof(table) / sizeof(*table))

typedef void (*XSUM_displayHash_f)(const void*, size_t);  /* display function signature */

static void XSUM_printLine_BSD_internal(const char* filename,
                                        const void* canonicalHash, const AlgoSelected hashType,
                                        const char* algoString[],
                                        XSUM_displayHash_f f_displayHash)
{
    assert(0 <= hashType && hashType <= XSUM_TABLE_ELT_SIZE(XSUM_algoName));
    {   const char* const typeString = algoString[hashType];
        const size_t hashLength = XSUM_algoLength[hashType];
        DISPLAYRESULT("%s (%s) = ", typeString, filename);
        f_displayHash(canonicalHash, hashLength);
        DISPLAYRESULT("\n");
}   }

static void XSUM_printLine_BSD_LE(const char* filename, const void* canonicalHash, const AlgoSelected hashType)
{
    XSUM_printLine_BSD_internal(filename, canonicalHash, hashType, XSUM_algoLE_name, BMK_display_LittleEndian);
}

static void XSUM_printLine_BSD(const char* filename, const void* canonicalHash, const AlgoSelected hashType)
{
    XSUM_printLine_BSD_internal(filename, canonicalHash, hashType, XSUM_algoName, BMK_display_BigEndian);
}

static void XSUM_printLine_GNU_internal(const char* filename,
                               const void* canonicalHash, const AlgoSelected hashType,
                               XSUM_displayHash_f f_displayHash)
{
    assert(0 <= hashType && hashType <= XSUM_TABLE_ELT_SIZE(XSUM_algoName));
    {   const size_t hashLength = XSUM_algoLength[hashType];
        f_displayHash(canonicalHash, hashLength);
        DISPLAYRESULT("  %s\n", filename);
}   }

static void XSUM_printLine_GNU(const char* filename,
                               const void* canonicalHash, const AlgoSelected hashType)
{
    XSUM_printLine_GNU_internal(filename, canonicalHash, hashType, BMK_display_BigEndian);
}

static void XSUM_printLine_GNU_LE(const char* filename,
                                  const void* canonicalHash, const AlgoSelected hashType)
{
    XSUM_printLine_GNU_internal(filename, canonicalHash, hashType, BMK_display_LittleEndian);
}

typedef enum { big_endian, little_endian} Display_endianess;

typedef enum { display_gnu, display_bsd } Display_convention;

typedef void (*XSUM_displayLine_f)(const char*, const void*, AlgoSelected);  /* line display signature */

static XSUM_displayLine_f XSUM_kDisplayLine_fTable[2][2] = {
    { XSUM_printLine_GNU, XSUM_printLine_GNU_LE },
    { XSUM_printLine_BSD, XSUM_printLine_BSD_LE }
};

static int XSUM_hashFile(const char* fileName,
                         const AlgoSelected hashType,
                         const Display_endianess displayEndianess,
                         const Display_convention convention)
{
    size_t const blockSize = 64 KB;
    XSUM_displayLine_f const f_displayLine = XSUM_kDisplayLine_fTable[convention][displayEndianess];
    FILE* inFile;
    Multihash hashValue;
    assert(displayEndianess==big_endian || displayEndianess==little_endian);
    assert(convention==display_gnu || convention==display_bsd);

    /* Check file existence */
    if (fileName == stdinName) {
        inFile = stdin;
        fileName = "stdin";
        SET_BINARY_MODE(stdin);
    } else {
        if (XSUM_isDirectory(fileName)) {
            DISPLAY("xxhsum: %s: Is a directory \n", fileName);
            return 1;
        }
        inFile = XXH_fopen( fileName, "rb" );
        if (inFile==NULL) {
            DISPLAY("Error: Could not open '%s': %s. \n", fileName, strerror(errno));
            return 1;
    }   }

    /* Memory allocation & streaming */
    {   void* const buffer = malloc(blockSize);
        if (buffer == NULL) {
            DISPLAY("\nError: Out of memory.\n");
            fclose(inFile);
            return 1;
        }

        /* Stream file & update hash */
        hashValue = XSUM_hashStream(inFile, hashType, buffer, blockSize);

        fclose(inFile);
        free(buffer);
    }

    /* display Hash value in selected format */
    switch(hashType)
    {
    case algo_xxh32:
        {   XXH32_canonical_t hcbe32;
            (void)XXH32_canonicalFromHash(&hcbe32, hashValue.xxh32);
            f_displayLine(fileName, &hcbe32, hashType);
            break;
        }
    case algo_xxh64:
        {   XXH64_canonical_t hcbe64;
            (void)XXH64_canonicalFromHash(&hcbe64, hashValue.xxh64);
            f_displayLine(fileName, &hcbe64, hashType);
            break;
        }
    case algo_xxh128:
        {   XXH128_canonical_t hcbe128;
            (void)XXH128_canonicalFromHash(&hcbe128, hashValue.xxh128);
            f_displayLine(fileName, &hcbe128, hashType);
            break;
        }
    default:
        assert(0);  /* not possible */
    }

    return 0;
}


/*
 * XSUM_hashFiles:
 * If fnTotal==0, read from stdin instead.
 */
static int XSUM_hashFiles(const char*const * fnList, int fnTotal,
                          AlgoSelected hashType,
                          Display_endianess displayEndianess,
                          Display_convention convention)
{
    int fnNb;
    int result = 0;

    if (fnTotal==0)
        return XSUM_hashFile(stdinName, hashType, displayEndianess, convention);

    for (fnNb=0; fnNb<fnTotal; fnNb++)
        result |= XSUM_hashFile(fnList[fnNb], hashType, displayEndianess, convention);
    DISPLAYLEVEL(2, "\r%70s\r", "");
    return result;
}


typedef enum {
    GetLine_ok,
    GetLine_eof,
    GetLine_exceedMaxLineLength,
    GetLine_outOfMemory
} GetLineResult;

typedef enum {
    CanonicalFromString_ok,
    CanonicalFromString_invalidFormat
} CanonicalFromStringResult;

typedef enum {
    ParseLine_ok,
    ParseLine_invalidFormat
} ParseLineResult;

typedef enum {
    LineStatus_hashOk,
    LineStatus_hashFailed,
    LineStatus_failedToOpen
} LineStatus;

typedef union {
    XXH32_canonical_t xxh32;
    XXH64_canonical_t xxh64;
    XXH128_canonical_t xxh128;
} Canonical;

typedef struct {
    Canonical   canonical;
    const char* filename;
    int         xxhBits;    /* canonical type: 32:xxh32, 64:xxh64, 128:xxh128 */
} ParsedLine;

typedef struct {
    unsigned long   nProperlyFormattedLines;
    unsigned long   nImproperlyFormattedLines;
    unsigned long   nMismatchedChecksums;
    unsigned long   nOpenOrReadFailures;
    unsigned long   nMixedFormatLines;
    int             quit;
} ParseFileReport;

typedef struct {
    const char*     inFileName;
    FILE*           inFile;
    int             lineMax;
    char*           lineBuf;
    size_t          blockSize;
    char*           blockBuf;
    U32             strictMode;
    U32             statusOnly;
    U32             warn;
    U32             quiet;
    ParseFileReport report;
} ParseFileArg;


/*
 * Reads a line from stream `inFile`.
 * Returns GetLine_ok, if it reads line successfully.
 * Returns GetLine_eof, if stream reaches EOF.
 * Returns GetLine_exceedMaxLineLength, if line length is longer than MAX_LINE_LENGTH.
 * Returns GetLine_outOfMemory, if line buffer memory allocation failed.
 */
static GetLineResult getLine(char** lineBuf, int* lineMax, FILE* inFile)
{
    GetLineResult result = GetLine_ok;
    size_t len = 0;

    if ((*lineBuf == NULL) || (*lineMax<1)) {
        free(*lineBuf);  /* in case it's != NULL */
        *lineMax = 0;
        *lineBuf = (char*)malloc(DEFAULT_LINE_LENGTH);
        if(*lineBuf == NULL) return GetLine_outOfMemory;
        *lineMax = DEFAULT_LINE_LENGTH;
    }

    for (;;) {
        const int c = fgetc(inFile);
        if (c == EOF) {
            /*
             * If we meet EOF before first character, returns GetLine_eof,
             * otherwise GetLine_ok.
             */
            if (len == 0) result = GetLine_eof;
            break;
        }

        /* Make enough space for len+1 (for final NUL) bytes. */
        if (len+1 >= (size_t)*lineMax) {
            char* newLineBuf = NULL;
            size_t newBufSize = (size_t)*lineMax;

            newBufSize += (newBufSize/2) + 1; /* x 1.5 */
            if (newBufSize > MAX_LINE_LENGTH) newBufSize = MAX_LINE_LENGTH;
            if (len+1 >= newBufSize) return GetLine_exceedMaxLineLength;

            newLineBuf = (char*) realloc(*lineBuf, newBufSize);
            if (newLineBuf == NULL) return GetLine_outOfMemory;

            *lineBuf = newLineBuf;
            *lineMax = (int)newBufSize;
        }

        if (c == '\n') break;
        (*lineBuf)[len++] = (char) c;
    }

    (*lineBuf)[len] = '\0';
    return result;
}


/*
 * Converts one hexadecimal character to integer.
 * Returns -1 if the given character is not hexadecimal.
 */
static int charToHex(char c)
{
    int result = -1;
    if (c >= '0' && c <= '9') {
        result = (int) (c - '0');
    } else if (c >= 'A' && c <= 'F') {
        result = (int) (c - 'A') + 0x0a;
    } else if (c >= 'a' && c <= 'f') {
        result = (int) (c - 'a') + 0x0a;
    }
    return result;
}


/*
 * Converts canonical ASCII hexadecimal string `hashStr`
 * to the big endian binary representation in unsigned char array `dst`.
 *
 * Returns CanonicalFromString_invalidFormat if hashStr is not well formatted.
 * Returns CanonicalFromString_ok if hashStr is parsed successfully.
 */
static CanonicalFromStringResult canonicalFromString(unsigned char* dst,
                                                     size_t dstSize,
                                                     const char* hashStr,
                                                     int reverseBytes)
{
    size_t i;
    for (i = 0; i < dstSize; ++i) {
        int h0, h1;
        size_t j = reverseBytes ? dstSize - i - 1 : i;

        h0 = charToHex(hashStr[j*2 + 0]);
        if (h0 < 0) return CanonicalFromString_invalidFormat;

        h1 = charToHex(hashStr[j*2 + 1]);
        if (h1 < 0) return CanonicalFromString_invalidFormat;

        dst[i] = (unsigned char) ((h0 << 4) | h1);
    }
    return CanonicalFromString_ok;
}


/*
 * Parse single line of xxHash checksum file.
 * Returns ParseLine_invalidFormat if the line is not well formatted.
 * Returns ParseLine_ok if the line is parsed successfully.
 * And members of parseLine will be filled by parsed values.
 *
 *  - line must be terminated with '\0' without a trailing newline.
 *  - Since parsedLine.filename will point within given argument `line`,
 *    users must keep `line`s content when they are using parsedLine.
 *  - The line may be modified to carve up the information it contains.
 *
 * xxHash checksum lines should have the following format:
 *
 *      <8, 16, or 32 hexadecimal char> <space> <space> <filename...> <'\0'>
 *
 * or:
 *
 *      <algorithm> <' ('> <filename> <') = '> <hexstring> <'\0'>
 */
static ParseLineResult parseLine(ParsedLine* parsedLine, char* line, int rev)
{
    char* const firstSpace = strchr(line, ' ');
    const char* hash_ptr;
    size_t hash_len;

    parsedLine->filename = NULL;
    parsedLine->xxhBits = 0;

    if (firstSpace == NULL || !firstSpace[1]) return ParseLine_invalidFormat;

    if (firstSpace[1] == '(') {
        char* lastSpace = strrchr(line, ' ');
        if (lastSpace - firstSpace < 5) return ParseLine_invalidFormat;
        if (lastSpace[-1] != '=' || lastSpace[-2] != ' ' || lastSpace[-3] != ')') return ParseLine_invalidFormat;
        lastSpace[-3] = '\0'; /* Terminate the filename */
        *firstSpace = '\0';
        rev = strstr(line, "_LE") != NULL; /* was output little-endian */
        hash_ptr = lastSpace + 1;
        hash_len = strlen(hash_ptr);
        /* NOTE: This currently ignores the hash description at the start of the string.
         * In the future we should parse it and verify that it matches the hash length.
         * It could also be used to allow both XXH64 & XXH3_64bits to be differentiated. */
    } else {
        hash_ptr = line;
        hash_len = (size_t)(firstSpace - line);
    }

    switch (hash_len)
    {
    case 8:
        {   XXH32_canonical_t* xxh32c = &parsedLine->canonical.xxh32;
            if (canonicalFromString(xxh32c->digest, sizeof(xxh32c->digest), hash_ptr, rev)
                != CanonicalFromString_ok) {
                return ParseLine_invalidFormat;
            }
            parsedLine->xxhBits = 32;
            break;
        }

    case 16:
        {   XXH64_canonical_t* xxh64c = &parsedLine->canonical.xxh64;
            if (canonicalFromString(xxh64c->digest, sizeof(xxh64c->digest), hash_ptr, rev)
                != CanonicalFromString_ok) {
                return ParseLine_invalidFormat;
            }
            parsedLine->xxhBits = 64;
            break;
        }

    case 32:
        {   XXH128_canonical_t* xxh128c = &parsedLine->canonical.xxh128;
            if (canonicalFromString(xxh128c->digest, sizeof(xxh128c->digest), hash_ptr, rev)
                != CanonicalFromString_ok) {
                return ParseLine_invalidFormat;
            }
            parsedLine->xxhBits = 128;
            break;
        }

    default:
            return ParseLine_invalidFormat;
            break;
    }

    /* note : skipping second separation character, which can be anything,
     * allowing insertion of custom markers such as '*' */
    parsedLine->filename = firstSpace + 2;
    return ParseLine_ok;
}


/*!
 * Parse xxHash checksum file.
 */
static void parseFile1(ParseFileArg* parseFileArg, int rev)
{
    const char* const inFileName = parseFileArg->inFileName;
    ParseFileReport* const report = &parseFileArg->report;

    unsigned long lineNumber = 0;
    memset(report, 0, sizeof(*report));

    while (!report->quit) {
        LineStatus lineStatus = LineStatus_hashFailed;
        ParsedLine parsedLine;
        memset(&parsedLine, 0, sizeof(parsedLine));

        lineNumber++;
        if (lineNumber == 0) {
            /* This is unlikely happen, but md5sum.c has this error check. */
            DISPLAY("%s: Error: Too many checksum lines\n", inFileName);
            report->quit = 1;
            break;
        }

        {   GetLineResult const getLineResult = getLine(&parseFileArg->lineBuf,
                                                        &parseFileArg->lineMax,
                                                         parseFileArg->inFile);
            if (getLineResult != GetLine_ok) {
                if (getLineResult == GetLine_eof) break;

                switch (getLineResult)
                {
                case GetLine_ok:
                case GetLine_eof:
                    /* These cases never happen.  See above getLineResult related "if"s.
                       They exist just for make gcc's -Wswitch-enum happy. */
                    assert(0);
                    break;

                default:
                    DISPLAY("%s:%lu: Error: Unknown error.\n", inFileName, lineNumber);
                    break;

                case GetLine_exceedMaxLineLength:
                    DISPLAY("%s:%lu: Error: Line too long.\n", inFileName, lineNumber);
                    break;

                case GetLine_outOfMemory:
                    DISPLAY("%s:%lu: Error: Out of memory.\n", inFileName, lineNumber);
                    break;
                }
                report->quit = 1;
                break;
        }   }

        if (parseLine(&parsedLine, parseFileArg->lineBuf, rev) != ParseLine_ok) {
            report->nImproperlyFormattedLines++;
            if (parseFileArg->warn) {
                DISPLAY("%s:%lu: Error: Improperly formatted checksum line.\n",
                        inFileName, lineNumber);
            }
            continue;
        }

        report->nProperlyFormattedLines++;

        do {
            FILE* const fp = XXH_fopen(parsedLine.filename, "rb");
            if (fp == NULL) {
                lineStatus = LineStatus_failedToOpen;
                break;
            }
            lineStatus = LineStatus_hashFailed;
            switch (parsedLine.xxhBits)
            {
            case 32:
                {   Multihash const xxh = XSUM_hashStream(fp, algo_xxh32, parseFileArg->blockBuf, parseFileArg->blockSize);
                    if (xxh.xxh32 == XXH32_hashFromCanonical(&parsedLine.canonical.xxh32)) {
                        lineStatus = LineStatus_hashOk;
                }   }
                break;

            case 64:
                {   Multihash const xxh = XSUM_hashStream(fp, algo_xxh64, parseFileArg->blockBuf, parseFileArg->blockSize);
                    if (xxh.xxh64 == XXH64_hashFromCanonical(&parsedLine.canonical.xxh64)) {
                        lineStatus = LineStatus_hashOk;
                }   }
                break;

            case 128:
                {   Multihash const xxh = XSUM_hashStream(fp, algo_xxh128, parseFileArg->blockBuf, parseFileArg->blockSize);
                    if (XXH128_isEqual(xxh.xxh128, XXH128_hashFromCanonical(&parsedLine.canonical.xxh128))) {
                        lineStatus = LineStatus_hashOk;
                }   }
                break;

            default:
                break;
            }
            fclose(fp);
        } while (0);

        switch (lineStatus)
        {
        default:
            DISPLAY("%s: Error: Unknown error.\n", inFileName);
            report->quit = 1;
            break;

        case LineStatus_failedToOpen:
            report->nOpenOrReadFailures++;
            if (!parseFileArg->statusOnly) {
                DISPLAYRESULT("%s:%lu: Could not open or read '%s': %s.\n",
                    inFileName, lineNumber, parsedLine.filename, strerror(errno));
            }
            break;

        case LineStatus_hashOk:
        case LineStatus_hashFailed:
            {   int b = 1;
                if (lineStatus == LineStatus_hashOk) {
                    /* If --quiet is specified, don't display "OK" */
                    if (parseFileArg->quiet) b = 0;
                } else {
                    report->nMismatchedChecksums++;
                }

                if (b && !parseFileArg->statusOnly) {
                    DISPLAYRESULT("%s: %s\n", parsedLine.filename
                        , lineStatus == LineStatus_hashOk ? "OK" : "FAILED");
            }   }
            break;
        }
    }   /* while (!report->quit) */
}


/*  Parse xxHash checksum file.
 *  Returns 1, if all procedures were succeeded.
 *  Returns 0, if any procedures was failed.
 *
 *  If strictMode != 0, return error code if any line is invalid.
 *  If statusOnly != 0, don't generate any output.
 *  If warn != 0, print a warning message to stderr.
 *  If quiet != 0, suppress "OK" line.
 *
 *  "All procedures are succeeded" means:
 *    - Checksum file contains at least one line and less than SIZE_T_MAX lines.
 *    - All files are properly opened and read.
 *    - All hash values match with its content.
 *    - (strict mode) All lines in checksum file are consistent and well formatted.
 */
static int checkFile(const char* inFileName,
                     const Display_endianess displayEndianess,
                     U32 strictMode,
                     U32 statusOnly,
                     U32 warn,
                     U32 quiet)
{
    int result = 0;
    FILE* inFile = NULL;
    ParseFileArg parseFileArgBody;
    ParseFileArg* const parseFileArg = &parseFileArgBody;
    ParseFileReport* const report = &parseFileArg->report;

    /* note: stdinName is special constant pointer.  It is not a string. */
    if (inFileName == stdinName) {
        /*
         * Note: Since we expect text input for xxhash -c mode,
         * we don't set binary mode for stdin.
         */
        inFileName = "stdin";
        inFile = stdin;
    } else {
        inFile = XXH_fopen( inFileName, "rt" );
    }

    if (inFile == NULL) {
        DISPLAY("Error: Could not open '%s': %s\n", inFileName, strerror(errno));
        return 0;
    }

    parseFileArg->inFileName  = inFileName;
    parseFileArg->inFile      = inFile;
    parseFileArg->lineMax     = DEFAULT_LINE_LENGTH;
    parseFileArg->lineBuf     = (char*) malloc((size_t)parseFileArg->lineMax);
    parseFileArg->blockSize   = 64 * 1024;
    parseFileArg->blockBuf    = (char*) malloc(parseFileArg->blockSize);
    parseFileArg->strictMode  = strictMode;
    parseFileArg->statusOnly  = statusOnly;
    parseFileArg->warn        = warn;
    parseFileArg->quiet       = quiet;

    if ( (parseFileArg->lineBuf == NULL)
      || (parseFileArg->blockBuf == NULL) ) {
        DISPLAY("Error: : memory allocation failed \n");
        exit(1);
    }
    parseFile1(parseFileArg, displayEndianess != big_endian);

    free(parseFileArg->blockBuf);
    free(parseFileArg->lineBuf);

    if (inFile != stdin) fclose(inFile);

    /* Show error/warning messages.  All messages are copied from md5sum.c
     */
    if (report->nProperlyFormattedLines == 0) {
        DISPLAY("%s: no properly formatted xxHash checksum lines found\n", inFileName);
    } else if (!statusOnly) {
        if (report->nImproperlyFormattedLines) {
            DISPLAYRESULT("%lu %s improperly formatted\n"
                , report->nImproperlyFormattedLines
                , report->nImproperlyFormattedLines == 1 ? "line is" : "lines are");
        }
        if (report->nOpenOrReadFailures) {
            DISPLAYRESULT("%lu listed %s could not be read\n"
                , report->nOpenOrReadFailures
                , report->nOpenOrReadFailures == 1 ? "file" : "files");
        }
        if (report->nMismatchedChecksums) {
            DISPLAYRESULT("%lu computed %s did NOT match\n"
                , report->nMismatchedChecksums
                , report->nMismatchedChecksums == 1 ? "checksum" : "checksums");
    }   }

    /* Result (exit) code logic is copied from
     * gnu coreutils/src/md5sum.c digest_check() */
    result =   report->nProperlyFormattedLines != 0
            && report->nMismatchedChecksums == 0
            && report->nOpenOrReadFailures == 0
            && (!strictMode || report->nImproperlyFormattedLines == 0)
            && report->quit == 0;
    return result;
}


static int checkFiles(const char*const* fnList, int fnTotal,
                      const Display_endianess displayEndianess,
                      U32 strictMode,
                      U32 statusOnly,
                      U32 warn,
                      U32 quiet)
{
    int ok = 1;

    /* Special case for stdinName "-",
     * note: stdinName is not a string.  It's special pointer. */
    if (fnTotal==0) {
        ok &= checkFile(stdinName, displayEndianess, strictMode, statusOnly, warn, quiet);
    } else {
        int fnNb;
        for (fnNb=0; fnNb<fnTotal; fnNb++)
            ok &= checkFile(fnList[fnNb], displayEndianess, strictMode, statusOnly, warn, quiet);
    }
    return ok ? 0 : 1;
}


/* ********************************************************
*  Main
**********************************************************/

static int usage(const char* exename)
{
    DISPLAY( WELCOME_MESSAGE(exename) );
    DISPLAY( "Print or verify checksums using fast non-cryptographic algorithm xxHash \n\n" );
    DISPLAY( "Usage: %s [options] [files] \n\n", exename);
    DISPLAY( "When no filename provided or when '-' is provided, uses stdin as input. \n");
    DISPLAY( "Options: \n");
    DISPLAY( "  -H#         algorithm selection: 0,1,2 or 32,64,128 (default: %i) \n", (int)g_defaultAlgo);
    DISPLAY( "  -c, --check read xxHash checksum from [files] and check them \n");
    DISPLAY( "  -h, --help  display a long help page about advanced options \n");
    return 0;
}


static int usage_advanced(const char* exename)
{
    usage(exename);
    DISPLAY( "Advanced :\n");
    DISPLAY( "  -V, --version        Display version information \n");
    DISPLAY( "      --tag            Produce BSD-style checksum lines \n");
    DISPLAY( "      --little-endian  Checksum values use little endian convention (default: big endian) \n");
    DISPLAY( "  -b                   Run benchmark \n");
    DISPLAY( "  -b#                  Bench only algorithm variant # \n");
    DISPLAY( "  -i#                  Number of times to run the benchmark (default: %u) \n", (unsigned)g_nbIterations);
    DISPLAY( "  -q, --quiet          Don't display version header in benchmark mode \n");
    DISPLAY( "\n");
    DISPLAY( "The following four options are useful only when verifying checksums (-c): \n");
    DISPLAY( "  -q, --quiet          Don't print OK for each successfully verified file \n");
    DISPLAY( "      --status         Don't output anything, status code shows success \n");
    DISPLAY( "      --strict         Exit non-zero for improperly formatted checksum lines \n");
    DISPLAY( "      --warn           Warn about improperly formatted checksum lines \n");
    return 0;
}

static int badusage(const char* exename)
{
    DISPLAY("Wrong parameters\n\n");
    usage(exename);
    return 1;
}

static void errorOut(const char* msg)
{
    DISPLAY("%s \n", msg); exit(1);
}

static const char* lastNameFromPath(const char* path)
{
    const char* name = path;
    if (strrchr(name, '/')) name = strrchr(name, '/') + 1;
    if (strrchr(name, '\\')) name = strrchr(name, '\\') + 1; /* windows */
    return name;
}

/*!
 * readU32FromCharChecked():
 * @return 0 if success, and store the result in *value.
 * Allows and interprets K, KB, KiB, M, MB and MiB suffix.
 * Will also modify `*stringPtr`, advancing it to position where it stopped reading.
 * @return 1 if an overflow error occurs
 */
static int readU32FromCharChecked(const char** stringPtr, U32* value)
{
    static const U32 max = (((U32)(-1)) / 10) - 1;
    U32 result = 0;
    while ((**stringPtr >='0') && (**stringPtr <='9')) {
        if (result > max) return 1; /* overflow error */
        result *= 10;
        result += (U32)(**stringPtr - '0');
        (*stringPtr)++ ;
    }
    if ((**stringPtr=='K') || (**stringPtr=='M')) {
        U32 const maxK = ((U32)(-1)) >> 10;
        if (result > maxK) return 1; /* overflow error */
        result <<= 10;
        if (**stringPtr=='M') {
            if (result > maxK) return 1; /* overflow error */
            result <<= 10;
        }
        (*stringPtr)++;  /* skip `K` or `M` */
        if (**stringPtr=='i') (*stringPtr)++;
        if (**stringPtr=='B') (*stringPtr)++;
    }
    *value = result;
    return 0;
}

/*!
 * readU32FromChar():
 * @return: unsigned integer value read from input in `char` format.
 *  allows and interprets K, KB, KiB, M, MB and MiB suffix.
 *  Will also modify `*stringPtr`, advancing it to position where it stopped reading.
 *  Note: function will exit() program if digit sequence overflows
 */
static U32 readU32FromChar(const char** stringPtr) {
    U32 result;
    if (readU32FromCharChecked(stringPtr, &result)) {
        static const char errorMsg[] = "Error: numeric value too large";
        errorOut(errorMsg);
    }
    return result;
}

static int XXH_main(int argc, const char* const* argv)
{
    int i, filenamesStart = 0;
    const char* const exename = lastNameFromPath(argv[0]);
    U32 benchmarkMode = 0;
    U32 fileCheckMode = 0;
    U32 strictMode    = 0;
    U32 statusOnly    = 0;
    U32 warn          = 0;
    int explicitStdin = 0;
    U32 selectBenchIDs= 0;  /* 0 == use default k_testIDs_default, kBenchAll == bench all */
    static const U32 kBenchAll = 99;
    size_t keySize    = XXH_DEFAULT_SAMPLE_SIZE;
    AlgoSelected algo     = g_defaultAlgo;
    Display_endianess displayEndianess = big_endian;
    Display_convention convention = display_gnu;

    /* special case: xxhNNsum default to NN bits checksum */
    if (strstr(exename,  "xxh32sum") != NULL) algo = g_defaultAlgo = algo_xxh32;
    if (strstr(exename,  "xxh64sum") != NULL) algo = g_defaultAlgo = algo_xxh64;
    if (strstr(exename, "xxh128sum") != NULL) algo = g_defaultAlgo = algo_xxh128;

    for (i=1; i<argc; i++) {
        const char* argument = argv[i];
        assert(argument != NULL);

        if (!strcmp(argument, "--check")) { fileCheckMode = 1; continue; }
        if (!strcmp(argument, "--benchmark-all")) { benchmarkMode = 1; selectBenchIDs = kBenchAll; continue; }
        if (!strcmp(argument, "--bench-all")) { benchmarkMode = 1; selectBenchIDs = kBenchAll; continue; }
        if (!strcmp(argument, "--quiet")) { g_displayLevel--; continue; }
        if (!strcmp(argument, "--little-endian")) { displayEndianess = little_endian; continue; }
        if (!strcmp(argument, "--strict")) { strictMode = 1; continue; }
        if (!strcmp(argument, "--status")) { statusOnly = 1; continue; }
        if (!strcmp(argument, "--warn")) { warn = 1; continue; }
        if (!strcmp(argument, "--help")) { return usage_advanced(exename); }
        if (!strcmp(argument, "--version")) { DISPLAY(FULL_WELCOME_MESSAGE(exename)); BMK_sanityCheck(); return 0; }
        if (!strcmp(argument, "--tag")) { convention = display_bsd; continue; }

        if (!strcmp(argument, "--")) {
            if (filenamesStart==0 && i!=argc-1) filenamesStart=i+1; /* only supports a continuous list of filenames */
            break;  /* treat rest of arguments as strictly file names */
        }
        if (*argument != '-') {
            if (filenamesStart==0) filenamesStart=i;   /* only supports a continuous list of filenames */
            break;  /* treat rest of arguments as strictly file names */
        }

        /* command selection */
        argument++;   /* note: *argument=='-' */
        if (*argument == 0) explicitStdin = 1;

        while (*argument != 0) {
            switch(*argument)
            {
            /* Display version */
            case 'V':
                DISPLAY(FULL_WELCOME_MESSAGE(exename)); return 0;

            /* Display help on usage */
            case 'h':
                return usage_advanced(exename);

            /* select hash algorithm */
            case 'H': argument++;
                switch(readU32FromChar(&argument)) {
                    case 0 :
                    case 32: algo = algo_xxh32; break;
                    case 1 :
                    case 64: algo = algo_xxh64; break;
                    case 2 :
                    case 128: algo = algo_xxh128; break;
                    default:
                        return badusage(exename);
                }
                break;

            /* File check mode */
            case 'c':
                fileCheckMode=1;
                argument++;
                break;

            /* Warning mode (file check mode only, alias of "--warning") */
            case 'w':
                warn=1;
                argument++;
                break;

            /* Trigger benchmark mode */
            case 'b':
                argument++;
                benchmarkMode = 1;
                do {
                    if (*argument == ',') argument++;
                    selectBenchIDs = readU32FromChar(&argument); /* select one specific test */
                    if (selectBenchIDs < NB_TESTFUNC) {
                        g_testIDs[selectBenchIDs] = 1;
                    } else
                        selectBenchIDs = kBenchAll;
                } while (*argument == ',');
                break;

            /* Modify Nb Iterations (benchmark only) */
            case 'i':
                argument++;
                g_nbIterations = readU32FromChar(&argument);
                break;

            /* Modify Block size (benchmark only) */
            case 'B':
                argument++;
                keySize = readU32FromChar(&argument);
                break;

            /* Modify verbosity of benchmark output (hidden option) */
            case 'q':
                argument++;
                g_displayLevel--;
                break;

            default:
                return badusage(exename);
            }
        }
    }   /* for(i=1; i<argc; i++) */

    /* Check benchmark mode */
    if (benchmarkMode) {
        DISPLAYLEVEL(2, FULL_WELCOME_MESSAGE(exename) );
        BMK_sanityCheck();
        if (selectBenchIDs == 0) memcpy(g_testIDs, k_testIDs_default, sizeof(g_testIDs));
        if (selectBenchIDs == kBenchAll) memset(g_testIDs, 1, sizeof(g_testIDs));
        if (filenamesStart==0) return BMK_benchInternal(keySize);
        return BMK_benchFiles(argv+filenamesStart, argc-filenamesStart);
    }

    /* Check if input is defined as console; trigger an error in this case */
    if ( (filenamesStart==0) && IS_CONSOLE(stdin) && !explicitStdin)
        return badusage(exename);

    if (filenamesStart==0) filenamesStart = argc;
    if (fileCheckMode) {
        return checkFiles(argv+filenamesStart, argc-filenamesStart,
                          displayEndianess, strictMode, statusOnly, warn, (g_displayLevel < 2) /*quiet*/);
    } else {
        return XSUM_hashFiles(argv+filenamesStart, argc-filenamesStart, algo, displayEndianess, convention);
    }
}

/* Windows main wrapper which properly handles UTF-8 command line arguments. */
#ifdef _WIN32
/* Converts a UTF-16 argv to UTF-8. */
static char** convert_argv(int argc, const wchar_t* const utf16_argv[])
{
    char** const utf8_argv = (char**)malloc((size_t)(argc + 1) * sizeof(char*));
    if (utf8_argv != NULL) {
        int i;
        for (i = 0; i < argc; i++) {
            utf8_argv[i] = utf16_to_utf8(utf16_argv[i]);
        }
        utf8_argv[argc] = NULL;
    }
    return utf8_argv;
}
/* Frees arguments returned by convert_argv */
static void free_argv(int argc, char** argv)
{
    int i;
    if (argv == NULL) {
        return;
    }
    for (i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
}


/*
 * On Windows, main's argv parameter is useless. Instead of UTF-8, you get ANSI
 * encoding, and any unknown characters will show up as mojibake.
 *
 * While this doesn't affect most programs, what does happen is that we can't
 * open any files with Unicode filenames.
 *
 * We instead convert wmain's arguments to UTF-8, preserving Unicode arguments.
 *
 * This function is wrapped by `__wgetmainargs()` and `main()` below on MinGW
 * with Unicode disabled, but if possible, we try to use `wmain()`.
 */
static int XXH_wmain(int argc, const wchar_t* const utf16_argv[])
{
    /* Convert the UTF-16 arguments to UTF-8. */
    char** utf8_argv = convert_argv(argc, utf16_argv);

    if (utf8_argv == NULL) {
        /* An unfortunate but incredibly unlikely error, */
        fprintf(stderr, "Error converting command line arguments!\n");
        return 1;
    } else {
        int ret;

        /*
         * MinGW's terminal uses full block buffering for stderr.
         *
         * This is nonstandard behavior and causes text to not display until
         * the buffer fills.
         *
         * `setvbuf()` can easily correct this to make text display instantly.
         */
        setvbuf(stderr, NULL, _IONBF, 0);

        /* Call our real main function */
        ret = XXH_main(argc, (const char* const *) utf8_argv);

        /* Cleanup */
        free_argv(argc, utf8_argv);
        return ret;
    }
}

#if defined(_MSC_VER)                     /* MSVC always accepts wmain */ \
 || defined(_UNICODE) || defined(UNICODE) /* defined with -municode on MinGW-w64 */

/* Preferred: Use the real `wmain()`. */
#if defined(__cplusplus)
extern "C"
#endif
int wmain(int argc, const wchar_t* utf16_argv[])
{
    return XXH_wmain(argc, utf16_argv);
}

#else /* Non-Unicode MinGW */

/*
 * Wrap `XXH_wmain()` using `main()` and `__wgetmainargs()` on MinGW without
 * Unicode support.
 *
 * `__wgetmainargs()` is used in the CRT startup to retrieve the arguments for
 * `wmain()`, so we use it on MinGW to emulate `wmain()`.
 *
 * It is an internal function and not declared in any public headers, so we
 * have to declare it manually.
 *
 * An alternative that doesn't mess with internal APIs is `GetCommandLineW()`
 * with `CommandLineToArgvW()`, but the former doesn't expand wildcards and the
 * latter requires linking to Shell32.dll and its numerous dependencies.
 *
 * This method keeps our dependencies to kernel32.dll and the CRT.
 *
 * https://docs.microsoft.com/en-us/cpp/c-runtime-library/getmainargs-wgetmainargs?view=vs-2019
 */
typedef struct {
    int newmode;
} _startupinfo;

#ifdef __cplusplus
extern "C"
#endif
int __cdecl __wgetmainargs(
    int*          Argc,
    wchar_t***    Argv,
    wchar_t***    Env,
    int           DoWildCard,
    _startupinfo* StartInfo
);

int main(int ansi_argc, const char* ansi_argv[])
{
    int       utf16_argc;
    wchar_t** utf16_argv;
    wchar_t** utf16_envp;         /* Unused but required */
    _startupinfo startinfo = {0}; /* 0 == don't change new mode */

    /* Get wmain's UTF-16 arguments. Make sure we expand wildcards. */
    if (__wgetmainargs(&utf16_argc, &utf16_argv, &utf16_envp, 1, &startinfo) < 0)
        /* In the very unlikely case of an error, use the ANSI arguments. */
        return XXH_main(ansi_argc, ansi_argv);

    /* Call XXH_wmain with our UTF-16 arguments */
    return XXH_wmain(utf16_argc, (const wchar_t* const *)utf16_argv);
}

#endif /* Non-Unicode MinGW */

#else /* Not Windows */

/* Wrap main normally on non-Windows platforms. */
int main(int argc, const char* argv[])
{
    return XXH_main(argc, argv);
}
#endif /* !Windows */
