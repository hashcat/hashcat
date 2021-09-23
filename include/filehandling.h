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

bool   hc_fopen        (HCFILE *fp, const char *path, const char *mode);
bool   hc_fopen_raw    (HCFILE *fp, const char *path, const char *mode);
bool   hc_fopen_stdout (HCFILE *fp);
int    hc_fscanf       (HCFILE *fp, const char *format, ...);
int    hc_fprintf      (HCFILE *fp, const char *format, ...);
int    hc_vfprintf     (HCFILE *fp, const char *format, va_list ap);
int    hc_fseek        (HCFILE *fp, off_t offset, int whence);
void   hc_rewind       (HCFILE *fp);
int    hc_fstat        (HCFILE *fp, struct stat *buf);
off_t  hc_ftell        (HCFILE *fp);
int    hc_fgetc        (HCFILE *fp);
int    hc_feof         (HCFILE *fp);
void   hc_fflush       (HCFILE *fp);
void   hc_fsync        (HCFILE *fp);
void   hc_fclose       (HCFILE *fp);
int    hc_fputc        (int c, HCFILE *fp);
char  *hc_fgets        (char *buf, int len, HCFILE *fp);
size_t hc_fwrite       (const void *ptr, size_t size, size_t nmemb, HCFILE *fp);
size_t hc_fread        (void *ptr, size_t size, size_t nmemb, HCFILE *fp);

int    hc_lockfile     (HCFILE *fp);
int    hc_unlockfile   (HCFILE *fp);

int    fgetl           (HCFILE *fp, char *line_buf, int line_sz);
u64    count_lines     (HCFILE *fp);

#endif // _FILEHANDLING_H
