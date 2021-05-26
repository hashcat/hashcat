/* 7zMain.c - Test application for 7z Decoder
2021-04-29 : Igor Pavlov : Public domain */

#include "Precomp.h"

#include <stdio.h>
#include <string.h>

#include "../../CpuArch.h"

#include "../../7z.h"
#include "../../7zAlloc.h"
#include "../../7zBuf.h"
#include "../../7zCrc.h"
#include "../../7zFile.h"
#include "../../7zVersion.h"

#ifndef USE_WINDOWS_FILE
/* for mkdir */
#ifdef _WIN32
#include <direct.h>
#else
#include <stdlib.h>
#include <time.h>
#ifdef __GNUC__
#include <sys/time.h>
#endif
#include <fcntl.h>
// #include <utime.h>
#include <sys/stat.h>
#include <errno.h>
#endif
#endif


#define kInputBufSize ((size_t)1 << 18)

static const ISzAlloc g_Alloc = { SzAlloc, SzFree };


static void Print(const char *s)
{
  fputs(s, stdout);
}


static int Buf_EnsureSize(CBuf *dest, size_t size)
{
  if (dest->size >= size)
    return 1;
  Buf_Free(dest, &g_Alloc);
  return Buf_Create(dest, size, &g_Alloc);
}

#ifndef _WIN32
#define _USE_UTF8
#endif

/* #define _USE_UTF8 */

#ifdef _USE_UTF8

#define _UTF8_START(n) (0x100 - (1 << (7 - (n))))

#define _UTF8_RANGE(n) (((UInt32)1) << ((n) * 5 + 6))

#define _UTF8_HEAD(n, val) ((Byte)(_UTF8_START(n) + (val >> (6 * (n)))))
#define _UTF8_CHAR(n, val) ((Byte)(0x80 + (((val) >> (6 * (n))) & 0x3F)))

static size_t Utf16_To_Utf8_Calc(const UInt16 *src, const UInt16 *srcLim)
{
  size_t size = 0;
  for (;;)
  {
    UInt32 val;
    if (src == srcLim)
      return size;
    
    size++;
    val = *src++;
   
    if (val < 0x80)
      continue;

    if (val < _UTF8_RANGE(1))
    {
      size++;
      continue;
    }

    if (val >= 0xD800 && val < 0xDC00 && src != srcLim)
    {
      UInt32 c2 = *src;
      if (c2 >= 0xDC00 && c2 < 0xE000)
      {
        src++;
        size += 3;
        continue;
      }
    }

    size += 2;
  }
}

static Byte *Utf16_To_Utf8(Byte *dest, const UInt16 *src, const UInt16 *srcLim)
{
  for (;;)
  {
    UInt32 val;
    if (src == srcLim)
      return dest;
    
    val = *src++;
    
    if (val < 0x80)
    {
      *dest++ = (Byte)val;
      continue;
    }

    if (val < _UTF8_RANGE(1))
    {
      dest[0] = _UTF8_HEAD(1, val);
      dest[1] = _UTF8_CHAR(0, val);
      dest += 2;
      continue;
    }

    if (val >= 0xD800 && val < 0xDC00 && src != srcLim)
    {
      UInt32 c2 = *src;
      if (c2 >= 0xDC00 && c2 < 0xE000)
      {
        src++;
        val = (((val - 0xD800) << 10) | (c2 - 0xDC00)) + 0x10000;
        dest[0] = _UTF8_HEAD(3, val);
        dest[1] = _UTF8_CHAR(2, val);
        dest[2] = _UTF8_CHAR(1, val);
        dest[3] = _UTF8_CHAR(0, val);
        dest += 4;
        continue;
      }
    }
    
    dest[0] = _UTF8_HEAD(2, val);
    dest[1] = _UTF8_CHAR(1, val);
    dest[2] = _UTF8_CHAR(0, val);
    dest += 3;
  }
}

static SRes Utf16_To_Utf8Buf(CBuf *dest, const UInt16 *src, size_t srcLen)
{
  size_t destLen = Utf16_To_Utf8_Calc(src, src + srcLen);
  destLen += 1;
  if (!Buf_EnsureSize(dest, destLen))
    return SZ_ERROR_MEM;
  *Utf16_To_Utf8(dest->data, src, src + srcLen) = 0;
  return SZ_OK;
}

#endif

static SRes Utf16_To_Char(CBuf *buf, const UInt16 *s
    #ifndef _USE_UTF8
    , UINT codePage
    #endif
    )
{
  unsigned len = 0;
  for (len = 0; s[len] != 0; len++) {}

  #ifndef _USE_UTF8
  {
    const unsigned size = len * 3 + 100;
    if (!Buf_EnsureSize(buf, size))
      return SZ_ERROR_MEM;
    {
      buf->data[0] = 0;
      if (len != 0)
      {
        const char defaultChar = '_';
        BOOL defUsed;
        const unsigned numChars = (unsigned)WideCharToMultiByte(
            codePage, 0, (LPCWSTR)s, (int)len, (char *)buf->data, (int)size, &defaultChar, &defUsed);
        if (numChars == 0 || numChars >= size)
          return SZ_ERROR_FAIL;
        buf->data[numChars] = 0;
      }
      return SZ_OK;
    }
  }
  #else
  return Utf16_To_Utf8Buf(buf, s, len);
  #endif
}

#ifdef _WIN32
  #ifndef USE_WINDOWS_FILE
    static UINT g_FileCodePage = CP_ACP;
    #define MY_FILE_CODE_PAGE_PARAM ,g_FileCodePage
  #endif
#else
  #define MY_FILE_CODE_PAGE_PARAM
#endif

static WRes MyCreateDir(const UInt16 *name)
{
  #ifdef USE_WINDOWS_FILE
  
  return CreateDirectoryW((LPCWSTR)name, NULL) ? 0 : GetLastError();
  
  #else

  CBuf buf;
  WRes res;
  Buf_Init(&buf);
  RINOK(Utf16_To_Char(&buf, name MY_FILE_CODE_PAGE_PARAM));

  res =
  #ifdef _WIN32
  _mkdir((const char *)buf.data)
  #else
  mkdir((const char *)buf.data, 0777)
  #endif
  == 0 ? 0 : errno;
  Buf_Free(&buf, &g_Alloc);
  return res;
  
  #endif
}

static WRes OutFile_OpenUtf16(CSzFile *p, const UInt16 *name)
{
  #ifdef USE_WINDOWS_FILE
  return OutFile_OpenW(p, (LPCWSTR)name);
  #else
  CBuf buf;
  WRes res;
  Buf_Init(&buf);
  RINOK(Utf16_To_Char(&buf, name MY_FILE_CODE_PAGE_PARAM));
  res = OutFile_Open(p, (const char *)buf.data);
  Buf_Free(&buf, &g_Alloc);
  return res;
  #endif
}


static SRes PrintString(const UInt16 *s)
{
  CBuf buf;
  SRes res;
  Buf_Init(&buf);
  res = Utf16_To_Char(&buf, s
      #ifndef _USE_UTF8
      , CP_OEMCP
      #endif
      );
  if (res == SZ_OK)
    Print((const char *)buf.data);
  Buf_Free(&buf, &g_Alloc);
  return res;
}

static void UInt64ToStr(UInt64 value, char *s, int numDigits)
{
  char temp[32];
  int pos = 0;
  do
  {
    temp[pos++] = (char)('0' + (unsigned)(value % 10));
    value /= 10;
  }
  while (value != 0);

  for (numDigits -= pos; numDigits > 0; numDigits--)
    *s++ = ' ';

  do
    *s++ = temp[--pos];
  while (pos);
  *s = '\0';
}

static char *UIntToStr(char *s, unsigned value, int numDigits)
{
  char temp[16];
  int pos = 0;
  do
    temp[pos++] = (char)('0' + (value % 10));
  while (value /= 10);

  for (numDigits -= pos; numDigits > 0; numDigits--)
    *s++ = '0';

  do
    *s++ = temp[--pos];
  while (pos);
  *s = '\0';
  return s;
}

static void UIntToStr_2(char *s, unsigned value)
{
  s[0] = (char)('0' + (value / 10));
  s[1] = (char)('0' + (value % 10));
}


#define PERIOD_4 (4 * 365 + 1)
#define PERIOD_100 (PERIOD_4 * 25 - 1)
#define PERIOD_400 (PERIOD_100 * 4 + 1)



#ifndef _WIN32

// MS uses long for BOOL, but long is 32-bit in MS. So we use int.
// typedef long BOOL;
typedef int BOOL;

typedef struct _FILETIME
{
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME;

static LONG TIME_GetBias()
{
  time_t utc = time(NULL);
  struct tm *ptm = localtime(&utc);
  int localdaylight = ptm->tm_isdst; /* daylight for local timezone */
  ptm = gmtime(&utc);
  ptm->tm_isdst = localdaylight; /* use local daylight, not that of Greenwich */
  LONG bias = (int)(mktime(ptm)-utc);
  return bias;
}

#define TICKS_PER_SEC 10000000

#define GET_TIME_64(pft) ((pft)->dwLowDateTime | ((UInt64)(pft)->dwHighDateTime << 32))

#define SET_FILETIME(ft, v64) \
   (ft)->dwLowDateTime = (DWORD)v64; \
   (ft)->dwHighDateTime = (DWORD)(v64 >> 32);

#define WINAPI
#define TRUE 1

static BOOL WINAPI FileTimeToLocalFileTime(const FILETIME *fileTime, FILETIME *localFileTime)
{
  UInt64 v = GET_TIME_64(fileTime);
  v = (UInt64)((Int64)v - (Int64)TIME_GetBias() * TICKS_PER_SEC);
  SET_FILETIME(localFileTime, v);
  return TRUE;
}

static const UInt32 kNumTimeQuantumsInSecond = 10000000;
static const UInt32 kFileTimeStartYear = 1601;
static const UInt32 kUnixTimeStartYear = 1970;
static const UInt64 kUnixTimeOffset =
    (UInt64)60 * 60 * 24 * (89 + 365 * (kUnixTimeStartYear - kFileTimeStartYear));

static Int64 Time_FileTimeToUnixTime64(const FILETIME *ft)
{
  UInt64 winTime = GET_TIME_64(ft);
  return (Int64)(winTime / kNumTimeQuantumsInSecond) - (Int64)kUnixTimeOffset;
}

#if defined(_AIX)
  #define MY_ST_TIMESPEC st_timespec
#else
  #define MY_ST_TIMESPEC timespec
#endif

static void FILETIME_To_timespec(const FILETIME *ft, struct MY_ST_TIMESPEC *ts)
{
  if (ft)
  {
    const Int64 sec = Time_FileTimeToUnixTime64(ft);
    // time_t is long
    const time_t sec2 = (time_t)sec;
    if (sec2 == sec)
    {
      ts->tv_sec = sec2;
      UInt64 winTime = GET_TIME_64(ft);
      ts->tv_nsec = (long)((winTime % 10000000) * 100);;
      return;
    }
  }
  // else
  {
    ts->tv_sec = 0;
    // ts.tv_nsec = UTIME_NOW; // set to the current time
    ts->tv_nsec = UTIME_OMIT; // keep old timesptamp
  }
}

static WRes Set_File_FILETIME(const UInt16 *name, const FILETIME *mTime)
{
  struct timespec times[2];
  
  const int flags = 0; // follow link
    // = AT_SYMLINK_NOFOLLOW; // don't follow link

  CBuf buf;
  int res;
  Buf_Init(&buf);
  RINOK(Utf16_To_Char(&buf, name MY_FILE_CODE_PAGE_PARAM));
  FILETIME_To_timespec(NULL, &times[0]);
  FILETIME_To_timespec(mTime, &times[1]);
  res = utimensat(AT_FDCWD, (const char *)buf.data, times, flags);
  Buf_Free(&buf, &g_Alloc);
  if (res == 0)
    return 0;
  return errno;
}

#endif

static void NtfsFileTime_to_FILETIME(const CNtfsFileTime *t, FILETIME *ft)
{
  ft->dwLowDateTime = (DWORD)(t->Low);
  ft->dwHighDateTime = (DWORD)(t->High);
}

static void ConvertFileTimeToString(const CNtfsFileTime *nTime, char *s)
{
  unsigned year, mon, hour, min, sec;
  Byte ms[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  unsigned t;
  UInt32 v;
  // UInt64 v64 = nt->Low | ((UInt64)nt->High << 32);
  UInt64 v64;
  {
    FILETIME fileTime, locTime;
    NtfsFileTime_to_FILETIME(nTime, &fileTime);
    if (!FileTimeToLocalFileTime(&fileTime, &locTime))
    {
      locTime.dwHighDateTime =
      locTime.dwLowDateTime = 0;
    }
    v64 = locTime.dwLowDateTime | ((UInt64)locTime.dwHighDateTime << 32);
  }
  v64 /= 10000000;
  sec = (unsigned)(v64 % 60); v64 /= 60;
  min = (unsigned)(v64 % 60); v64 /= 60;
  hour = (unsigned)(v64 % 24); v64 /= 24;

  v = (UInt32)v64;

  year = (unsigned)(1601 + v / PERIOD_400 * 400);
  v %= PERIOD_400;

  t = v / PERIOD_100; if (t ==  4) t =  3; year += t * 100; v -= t * PERIOD_100;
  t = v / PERIOD_4;   if (t == 25) t = 24; year += t * 4;   v -= t * PERIOD_4;
  t = v / 365;        if (t ==  4) t =  3; year += t;       v -= t * 365;

  if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
    ms[1] = 29;
  for (mon = 0;; mon++)
  {
    unsigned d = ms[mon];
    if (v < d)
      break;
    v -= d;
  }
  s = UIntToStr(s, year, 4); *s++ = '-';
  UIntToStr_2(s, mon + 1); s[2] = '-'; s += 3;
  UIntToStr_2(s, (unsigned)v + 1); s[2] = ' '; s += 3;
  UIntToStr_2(s, hour); s[2] = ':'; s += 3;
  UIntToStr_2(s, min); s[2] = ':'; s += 3;
  UIntToStr_2(s, sec); s[2] = 0;
}

static void PrintLF()
{
  Print("\n");
}

static void PrintError(char *s)
{
  Print("\nERROR: ");
  Print(s);
  PrintLF();
}

static void PrintError_WRes(const char *message, WRes wres)
{
  Print("\nERROR: ");
  Print(message);
  PrintLF();
  {
    char s[32];
    UIntToStr(s, (unsigned)wres, 1);
    Print("System error code: ");
    Print(s);
  }
  // sprintf(buffer + strlen(buffer), "\nSystem error code: %d", (unsigned)wres);
  #ifdef _WIN32
  {
    char *s = NULL;
    if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, wres, 0, (LPSTR) &s, 0, NULL) != 0 && s)
    {
      Print(" : ");
      Print(s);
      LocalFree(s);
    }
  }
  #else
  {
    const char *s = strerror(wres);
    if (s)
    {
      Print(" : ");
      Print(s);
    }
  }
  #endif
  PrintLF();
}

static void GetAttribString(UInt32 wa, BoolInt isDir, char *s)
{
  #ifdef USE_WINDOWS_FILE
  s[0] = (char)(((wa & FILE_ATTRIBUTE_DIRECTORY) != 0 || isDir) ? 'D' : '.');
  s[1] = (char)(((wa & FILE_ATTRIBUTE_READONLY ) != 0) ? 'R': '.');
  s[2] = (char)(((wa & FILE_ATTRIBUTE_HIDDEN   ) != 0) ? 'H': '.');
  s[3] = (char)(((wa & FILE_ATTRIBUTE_SYSTEM   ) != 0) ? 'S': '.');
  s[4] = (char)(((wa & FILE_ATTRIBUTE_ARCHIVE  ) != 0) ? 'A': '.');
  s[5] = 0;
  #else
  s[0] = (char)(((wa & (1 << 4)) != 0 || isDir) ? 'D' : '.');
  s[1] = 0;
  #endif
}


// #define NUM_PARENTS_MAX 128

int MY_CDECL main(int numargs, char *args[])
{
  ISzAlloc allocImp;
  ISzAlloc allocTempImp;

  CFileInStream archiveStream;
  CLookToRead2 lookStream;
  CSzArEx db;
  SRes res;
  UInt16 *temp = NULL;
  size_t tempSize = 0;
  // UInt32 parents[NUM_PARENTS_MAX];

  Print("\n7z Decoder " MY_VERSION_CPU " : " MY_COPYRIGHT_DATE "\n\n");

  if (numargs == 1)
  {
    Print(
      "Usage: 7zDec <command> <archive_name>\n\n"
      "<Commands>\n"
      "  e: Extract files from archive (without using directory names)\n"
      "  l: List contents of archive\n"
      "  t: Test integrity of archive\n"
      "  x: eXtract files with full paths\n");
    return 0;
  }

  if (numargs < 3)
  {
    PrintError("incorrect command");
    return 1;
  }

  #if defined(_WIN32) && !defined(USE_WINDOWS_FILE) && !defined(UNDER_CE)
  g_FileCodePage = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
  #endif


  allocImp = g_Alloc;
  allocTempImp = g_Alloc;

  {
    WRes wres =
    #ifdef UNDER_CE
      InFile_OpenW(&archiveStream.file, L"\test.7z"); // change it
    #else
      InFile_Open(&archiveStream.file, args[2]);
    #endif
    if (wres != 0)
    {
      PrintError_WRes("cannot open input file", wres);
      return 1;
    }
  }

  FileInStream_CreateVTable(&archiveStream);
  archiveStream.wres = 0;
  LookToRead2_CreateVTable(&lookStream, False);
  lookStream.buf = NULL;

  res = SZ_OK;

  {
    lookStream.buf = (Byte *)ISzAlloc_Alloc(&allocImp, kInputBufSize);
    if (!lookStream.buf)
      res = SZ_ERROR_MEM;
    else
    {
      lookStream.bufSize = kInputBufSize;
      lookStream.realStream = &archiveStream.vt;
      LookToRead2_Init(&lookStream);
    }
  }
    
  CrcGenerateTable();
    
  SzArEx_Init(&db);
    
  if (res == SZ_OK)
  {
    res = SzArEx_Open(&db, &lookStream.vt, &allocImp, &allocTempImp);
  }
  
  if (res == SZ_OK)
  {
    char *command = args[1];
    int listCommand = 0, testCommand = 0, fullPaths = 0;
    
    if (strcmp(command, "l") == 0) listCommand = 1;
    else if (strcmp(command, "t") == 0) testCommand = 1;
    else if (strcmp(command, "e") == 0) { }
    else if (strcmp(command, "x") == 0) { fullPaths = 1; }
    else
    {
      PrintError("incorrect command");
      res = SZ_ERROR_FAIL;
    }

    if (res == SZ_OK)
    {
      UInt32 i;

      /*
      if you need cache, use these 3 variables.
      if you use external function, you can make these variable as static.
      */
      UInt32 blockIndex = 0xFFFFFFFF; /* it can have any value before first call (if outBuffer = 0) */
      Byte *outBuffer = 0; /* it must be 0 before first call for each new archive. */
      size_t outBufferSize = 0;  /* it can have any value before first call (if outBuffer = 0) */

      for (i = 0; i < db.NumFiles; i++)
      {
        size_t offset = 0;
        size_t outSizeProcessed = 0;
        // const CSzFileItem *f = db.Files + i;
        size_t len;
        const BoolInt isDir = SzArEx_IsDir(&db, i);
        if (listCommand == 0 && isDir && !fullPaths)
          continue;
        len = SzArEx_GetFileNameUtf16(&db, i, NULL);
        // len = SzArEx_GetFullNameLen(&db, i);

        if (len > tempSize)
        {
          SzFree(NULL, temp);
          tempSize = len;
          temp = (UInt16 *)SzAlloc(NULL, tempSize * sizeof(temp[0]));
          if (!temp)
          {
            res = SZ_ERROR_MEM;
            break;
          }
        }

        SzArEx_GetFileNameUtf16(&db, i, temp);
        /*
        if (SzArEx_GetFullNameUtf16_Back(&db, i, temp + len) != temp)
        {
          res = SZ_ERROR_FAIL;
          break;
        }
        */

        if (listCommand)
        {
          char attr[8], s[32], t[32];
          UInt64 fileSize;

          GetAttribString(SzBitWithVals_Check(&db.Attribs, i) ? db.Attribs.Vals[i] : 0, isDir, attr);

          fileSize = SzArEx_GetFileSize(&db, i);
          UInt64ToStr(fileSize, s, 10);
          
          if (SzBitWithVals_Check(&db.MTime, i))
            ConvertFileTimeToString(&db.MTime.Vals[i], t);
          else
          {
            size_t j;
            for (j = 0; j < 19; j++)
              t[j] = ' ';
            t[j] = '\0';
          }
          
          Print(t);
          Print(" ");
          Print(attr);
          Print(" ");
          Print(s);
          Print("  ");
          res = PrintString(temp);
          if (res != SZ_OK)
            break;
          if (isDir)
            Print("/");
          PrintLF();
          continue;
        }

        Print(testCommand ?
            "T ":
            "- ");
        res = PrintString(temp);
        if (res != SZ_OK)
          break;
        
        if (isDir)
          Print("/");
        else
        {
          res = SzArEx_Extract(&db, &lookStream.vt, i,
              &blockIndex, &outBuffer, &outBufferSize,
              &offset, &outSizeProcessed,
              &allocImp, &allocTempImp);
          if (res != SZ_OK)
            break;
        }
        
        if (!testCommand)
        {
          CSzFile outFile;
          size_t processedSize;
          size_t j;
          UInt16 *name = (UInt16 *)temp;
          const UInt16 *destPath = (const UInt16 *)name;
 
          for (j = 0; name[j] != 0; j++)
            if (name[j] == '/')
            {
              if (fullPaths)
              {
                name[j] = 0;
                MyCreateDir(name);
                name[j] = CHAR_PATH_SEPARATOR;
              }
              else
                destPath = name + j + 1;
            }
    
          if (isDir)
          {
            MyCreateDir(destPath);
            PrintLF();
            continue;
          }
          else
          {
            WRes wres = OutFile_OpenUtf16(&outFile, destPath);
            if (wres != 0)
            {
              PrintError_WRes("cannot open output file", wres);
              res = SZ_ERROR_FAIL;
              break;
            }
          }

          processedSize = outSizeProcessed;
          
          {
            WRes wres = File_Write(&outFile, outBuffer + offset, &processedSize);
            if (wres != 0 || processedSize != outSizeProcessed)
            {
              PrintError_WRes("cannot write output file", wres);
              res = SZ_ERROR_FAIL;
              break;
            }
          }

          {
            FILETIME mtime;
            FILETIME *mtimePtr = NULL;
            
            #ifdef USE_WINDOWS_FILE
            FILETIME ctime;
            FILETIME *ctimePtr = NULL;
            #endif

            if (SzBitWithVals_Check(&db.MTime, i))
            {
              const CNtfsFileTime *t = &db.MTime.Vals[i];
              mtime.dwLowDateTime = (DWORD)(t->Low);
              mtime.dwHighDateTime = (DWORD)(t->High);
              mtimePtr = &mtime;
            }

            #ifdef USE_WINDOWS_FILE
            if (SzBitWithVals_Check(&db.CTime, i))
            {
              const CNtfsFileTime *t = &db.CTime.Vals[i];
              ctime.dwLowDateTime = (DWORD)(t->Low);
              ctime.dwHighDateTime = (DWORD)(t->High);
              ctimePtr = &ctime;
            }

            if (mtimePtr || ctimePtr)
              SetFileTime(outFile.handle, ctimePtr, NULL, mtimePtr);
            #endif
          
            {
              WRes wres = File_Close(&outFile);
              if (wres != 0)
              {
                PrintError_WRes("cannot close output file", wres);
                res = SZ_ERROR_FAIL;
                break;
              }
            }

            #ifndef USE_WINDOWS_FILE
            #ifdef _WIN32
            mtimePtr = mtimePtr;
            #else
            if (mtimePtr)
              Set_File_FILETIME(destPath, mtimePtr);
            #endif
            #endif
          }
          
          #ifdef USE_WINDOWS_FILE
          if (SzBitWithVals_Check(&db.Attribs, i))
          {
            UInt32 attrib = db.Attribs.Vals[i];
            /* p7zip stores posix attributes in high 16 bits and adds 0x8000 as marker.
               We remove posix bits, if we detect posix mode field */
            if ((attrib & 0xF0000000) != 0)
              attrib &= 0x7FFF;
            SetFileAttributesW((LPCWSTR)destPath, attrib);
          }
          #endif
        }
        PrintLF();
      }
      ISzAlloc_Free(&allocImp, outBuffer);
    }
  }

  SzFree(NULL, temp);
  SzArEx_Free(&db, &allocImp);
  ISzAlloc_Free(&allocImp, lookStream.buf);

  File_Close(&archiveStream.file);
  
  if (res == SZ_OK)
  {
    Print("\nEverything is Ok\n");
    return 0;
  }
  
  if (res == SZ_ERROR_UNSUPPORTED)
    PrintError("decoder doesn't support this archive");
  else if (res == SZ_ERROR_MEM)
    PrintError("cannot allocate memory");
  else if (res == SZ_ERROR_CRC)
    PrintError("CRC error");
  else if (res == SZ_ERROR_READ /* || archiveStream.Res != 0 */)
    PrintError_WRes("Read Error", archiveStream.wres);
  else
  {
    char s[32];
    UInt64ToStr((unsigned)res, s, 0);
    PrintError(s);
  }
  
  return 1;
}
