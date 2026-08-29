/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_FILEHANDLING_H
#define HC_FILEHANDLING_H

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>

#if defined (__CYGWIN__)
int _wopen (const char *path, int oflag, ...);
#endif

HC_PLUGIN_API bool   hc_fopen     (HCFILE *fp, const char *path, const char *mode);
HC_PLUGIN_API bool   hc_fopen_raw (HCFILE *fp, const char *path, const char *mode);
HC_PLUGIN_API bool   hc_fopen_mem (HCFILE *fp, const u8 *buf, const size_t len);

// Why the last open in this thread failed. A compression library that is not installed is a
// reason errno cannot express: the file is fine and nothing about it is a system error, so
// reporting strerror () there names the wrong problem. Everywhere else this is strerror (errno),
// so a caller can use it in place of one without changing what it prints.

HC_PLUGIN_API const char *hc_fopen_strerror (void);
HC_PLUGIN_API int    hc_fscanf    (HCFILE *fp, const char *format, void *ptr);
HC_PLUGIN_API int    hc_fprintf   (HCFILE *fp, const char *format, ...);
HC_PLUGIN_API int    hc_vfprintf  (HCFILE *fp, const char *format, va_list ap);
HC_PLUGIN_API int    hc_fseek     (HCFILE *fp, off_t offset, int whence);
HC_PLUGIN_API void   hc_rewind    (HCFILE *fp);
HC_PLUGIN_API int    hc_fstat     (HCFILE *fp, struct stat *buf);
HC_PLUGIN_API off_t  hc_ftell     (HCFILE *fp);
HC_PLUGIN_API int    hc_fgetc     (HCFILE *fp);
HC_PLUGIN_API int    hc_feof      (HCFILE *fp);
HC_PLUGIN_API void   hc_fflush    (HCFILE *fp);
HC_PLUGIN_API void   hc_fsync     (HCFILE *fp);
HC_PLUGIN_API void   hc_fclose    (HCFILE *fp);
HC_PLUGIN_API int    hc_fputc     (int c, HCFILE *fp);
HC_PLUGIN_API char  *hc_fgets     (char *buf, int len, HCFILE *fp);
HC_PLUGIN_API size_t hc_fwrite    (const void *ptr, size_t size, size_t nmemb, HCFILE *fp);
HC_PLUGIN_API size_t hc_fread     (void *ptr, size_t size, size_t nmemb, HCFILE *fp);

HC_PLUGIN_API size_t fgetl        (HCFILE *fp, char *line_buf, const size_t line_sz);
HC_PLUGIN_API u64    count_lines  (HCFILE *fp);
HC_PLUGIN_API size_t in_superchop (char *buf);
HC_PLUGIN_API size_t superchop_with_length (char *buf, const size_t len);

HC_PLUGIN_API bool  hc_path_has_bom (const char *path);
HC_PLUGIN_API bool  hc_same_files   (char *file1, char *file2);
HC_PLUGIN_API char *file_to_buffer  (const char *filename);

#endif // HC_FILEHANDLING_H
