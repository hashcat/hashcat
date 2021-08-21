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

#if defined (__CYGWIN__)
int    _wopen       (const char *path, int oflag, ...);
#endif

bool   hc_fopen     (HCFILE *fp, const char *path, const char *mode);
bool   hc_fopen_raw (HCFILE *fp, const char *path, const char *mode);
int    hc_fscanf    (HCFILE *fp, const char *format, void *ptr);
int    hc_fprintf   (HCFILE *fp, const char *format, ...);
int    hc_vfprintf  (HCFILE *fp, const char *format, va_list ap);
int    hc_fseek     (HCFILE *fp, off_t offset, int whence);
void   hc_rewind    (HCFILE *fp);
int    hc_fstat     (HCFILE *fp, struct stat *buf);
off_t  hc_ftell     (HCFILE *fp);
int    hc_fgetc     (HCFILE *fp);
int    hc_feof      (HCFILE *fp);
void   hc_fflush    (HCFILE *fp);
void   hc_fsync     (HCFILE *fp);
void   hc_fclose    (HCFILE *fp);
int    hc_fputc     (int c, HCFILE *fp);
char  *hc_fgets     (char *buf, int len, HCFILE *fp);
size_t hc_fwrite    (const void *ptr, size_t size, size_t nmemb, HCFILE *fp);
size_t hc_fread     (void *ptr, size_t size, size_t nmemb, HCFILE *fp);

size_t fgetl        (HCFILE *fp, char *line_buf, const size_t line_sz);
u64    count_lines  (HCFILE *fp);
size_t in_superchop (char *buf);
size_t superchop_with_length (char *buf, const size_t len);


#endif // _FILEHANDLING_H
