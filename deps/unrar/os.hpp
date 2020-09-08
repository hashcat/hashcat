#ifndef _RAR_OS_
#define _RAR_OS_

#define FALSE 0
#define TRUE  1

#ifdef __EMX__
  #define INCL_BASE
#endif

#if defined(RARDLL) && !defined(SILENT)
#define SILENT
#endif

#include <new>


#if defined(_WIN_ALL) || defined(_EMX)

#define LITTLE_ENDIAN
#define NM  2048

#ifdef _WIN_ALL


// We got a report that just "#define STRICT" is incompatible with
// "#define STRICT 1" in Windows 10 SDK minwindef.h and depending on the order
// in which these statements are reached this may cause a compiler warning
// and build break for other projects incorporating this source.
// So we changed it to "#define STRICT 1".
#ifndef STRICT
#define STRICT 1
#endif

// 'ifndef' check here is needed for unrar.dll header to avoid macro
// re-definition warnings in third party projects.
#ifndef UNICODE
#define UNICODE
#endif

#undef WINVER
#undef _WIN32_WINNT
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501

#if !defined(ZIPSFX)
#define RAR_SMP
#endif

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <prsht.h>
#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#include <powrprof.h>
#pragma comment(lib, "PowrProf.lib")
#include <shellapi.h>
#include <shlobj.h>
#include <winioctl.h>
#include <wincrypt.h>
#include <wchar.h>
#include <wctype.h>


#endif // _WIN_ALL

#include <sys/types.h>
#include <sys/stat.h>
#include <dos.h>

#if !defined(_EMX) && !defined(_MSC_VER)
  #include <dir.h>
#endif
#ifdef _MSC_VER
  #if _MSC_VER<1500
    #define for if (0) ; else for
  #endif
  #include <direct.h>
  #include <intrin.h>

  #define USE_SSE
  #define SSE_ALIGNMENT 16
#else
  #include <dirent.h>
#endif // _MSC_VER

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <dos.h>
#include <io.h>
#include <time.h>
#include <signal.h>


#define SAVE_LINKS

#define ENABLE_ACCESS

#define DefConfigName  L"rar.ini"
#define DefLogName     L"rar.log"


#define SPATHDIVIDER L"\\"
#define CPATHDIVIDER '\\'
#define MASKALL      L"*"

#define READBINARY   "rb"
#define READTEXT     "rt"
#define UPDATEBINARY "r+b"
#define CREATEBINARY "w+b"
#define WRITEBINARY  "wb"
#define APPENDTEXT   "at"

#if defined(_WIN_ALL)
  #ifdef _MSC_VER
    #define _stdfunction __cdecl
    #define _forceinline __forceinline
  #else
    #define _stdfunction _USERENTRY
    #define _forceinline inline
  #endif
#else
  #define _stdfunction
  #define _forceinline inline
#endif

#endif // defined(_WIN_ALL) || defined(_EMX)

#ifdef _UNIX

#define NM  2048

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#if defined(__QNXNTO__)
  #include <sys/param.h>
#endif
#if defined(RAR_SMP) && defined(__APPLE__)
  #include <sys/sysctl.h>
#endif
#ifndef SFX_MODULE
    #include <sys/statvfs.h>
#endif
#include <pwd.h>
#include <grp.h>
#include <wchar.h>
#include <wctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <utime.h>
#include <locale.h>


#ifdef  S_IFLNK
#define SAVE_LINKS
#endif

#if defined(__linux) || defined(__FreeBSD__)
#include <sys/time.h>
#define USE_LUTIMES
#endif

#define ENABLE_ACCESS

#define DefConfigName  L".rarrc"
#define DefLogName     L".rarlog"


#define SPATHDIVIDER L"/"
#define CPATHDIVIDER '/'
#define MASKALL      L"*"

#define READBINARY   "r"
#define READTEXT     "r"
#define UPDATEBINARY "r+"
#define CREATEBINARY "w+"
#define WRITEBINARY  "w"
#define APPENDTEXT   "a"

#define _stdfunction 
#define _forceinline inline

#ifdef _APPLE
  #if defined(__BIG_ENDIAN__) && !defined(BIG_ENDIAN)
    #define BIG_ENDIAN
    #undef LITTLE_ENDIAN
  #endif
  #if defined(__i386__) && !defined(LITTLE_ENDIAN)
    #define LITTLE_ENDIAN
    #undef BIG_ENDIAN
  #endif
#endif

#if defined(__sparc) || defined(sparc) || defined(__hpux)
  #ifndef BIG_ENDIAN
     #define BIG_ENDIAN
  #endif
#endif

#if _POSIX_C_SOURCE >= 200809L
  #define UNIX_TIME_NS // Nanosecond time precision in Unix.
#endif

#endif // _UNIX

#if 0
  #define MSGID_INT
  typedef int MSGID;
#else
  typedef const wchar* MSGID;
#endif

#ifndef SSE_ALIGNMENT // No SSE use and no special data alignment is required.
  #define SSE_ALIGNMENT 1
#endif

#define safebuf static

// Solaris defines _LITTLE_ENDIAN or _BIG_ENDIAN.
#if defined(_LITTLE_ENDIAN) && !defined(LITTLE_ENDIAN)
  #define LITTLE_ENDIAN
#endif
#if defined(_BIG_ENDIAN) && !defined(BIG_ENDIAN)
  #define BIG_ENDIAN
#endif

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
  #if defined(__i386) || defined(i386) || defined(__i386__) || defined(__x86_64)
    #define LITTLE_ENDIAN
  #elif defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN || defined(__LITTLE_ENDIAN__)
    #define LITTLE_ENDIAN
  #elif defined(BYTE_ORDER) && BYTE_ORDER == BIG_ENDIAN || defined(__BIG_ENDIAN__)
    #define BIG_ENDIAN
  #else
    #error "Neither LITTLE_ENDIAN nor BIG_ENDIAN are defined. Define one of them."
  #endif
#endif

#if defined(LITTLE_ENDIAN) && defined(BIG_ENDIAN)
  #if defined(BYTE_ORDER) && BYTE_ORDER == BIG_ENDIAN
    #undef LITTLE_ENDIAN
  #elif defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN
    #undef BIG_ENDIAN
  #else
    #error "Both LITTLE_ENDIAN and BIG_ENDIAN are defined. Undef one of them."
  #endif
#endif

#if !defined(BIG_ENDIAN) && defined(_WIN_ALL) || defined(__i386__) || defined(__x86_64__)
// Allow not aligned integer access, increases speed in some operations.
#define ALLOW_MISALIGNED
#endif

#endif // _RAR_OS_
