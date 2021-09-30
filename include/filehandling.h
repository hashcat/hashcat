/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _FILEHANDLING_H
#define _FILEHANDLING_H

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

/* internally used for buffered I/O */
#ifndef HCFILE_BUFFER_SIZE
#define HCFILE_BUFFER_SIZE 256 * 1024
#endif

/* any read/write operations bigger than this maybe divided */
#ifndef HCFILE_CHUNK_SIZE
#define HCFILE_CHUNK_SIZE 4 * 1024 * 1024
#endif

#if defined (__CYGWIN__)
int    _wopen       (const char *path, int oflag, ...);
#endif

bool   hc_fopen        (HCFILE * restrict fp, const char * restrict path, const char * restrict mode);
bool   hc_fopen_raw    (HCFILE * restrict fp, const char * restrict path, const char * restrict mode);
bool   hc_fopen_stdout (HCFILE *fp);
int    hc_fscanf       (HCFILE * restrict fp, const char * restrict format, ...);
int    hc_fprintf      (HCFILE * restrict fp, const char * restrict format, ...);
int    hc_vfprintf     (HCFILE * restrict fp, const char * restrict format, va_list ap);
int    hc_fseek        (HCFILE *fp, off_t offset, int whence);
void   hc_rewind       (HCFILE *fp);
int    hc_fstat        (HCFILE * restrict fp, struct stat * restrict buf);
off_t  hc_ftell        (HCFILE *fp);
int    hc_fgetc        (HCFILE *fp);
int    hc_feof         (HCFILE *fp);
void   hc_fflush       (HCFILE *fp);
void   hc_fsync        (HCFILE *fp);
void   hc_fclose       (HCFILE *fp);
int    hc_fputc        (int c, HCFILE *fp);
char  *hc_fgets        (char * restrict buf, int len, HCFILE * restrict fp);
size_t hc_fwrite       (const void * restrict ptr, size_t size, size_t nmemb, HCFILE * restrict fp);
size_t hc_fread        (void * restrict ptr, size_t size, size_t nmemb, HCFILE * restrict fp);

int    hc_lockfile     (HCFILE *fp);
int    hc_unlockfile   (HCFILE *fp);

int    fgetl           (HCFILE * restrict fp, char * restrict buf, int len);
u64    count_lines     (HCFILE *fp);

#endif // _FILEHANDLING_H
