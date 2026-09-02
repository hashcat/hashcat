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

// Whether a path holds one of the compressed formats hc_fopen () decodes, decided by the same magic
// bytes hc_fopen () decides it by. A caller that has to know one step earlier, because a compressed
// file is read a different way from a plain one, asks here instead of keeping its own copy of the
// magic table.

HC_PLUGIN_API bool hc_path_is_compressed (const char *path);

// Reading a compressed file from somewhere other than its start.
//
// Only .zst works this way today. A .zst is a run of independent frames and each of them decodes
// without the ones before it, while a .gz or an .xz has to be walked from the beginning. Both calls
// do nothing on a container that has no frames, so a caller does not have to know which it has.
//
// hc_frame_notify () asks to be told about every frame boundary the reader crosses from here on, and
// a NULL callback stops that again. The boundaries arrive in the order they are read, so a caller
// that reads the whole file once learns where all of them are.
//
// hc_frame_restart () goes back to one of them. comp_off and uncomp_off are what the callback
// reported for that boundary, and the file reads on from there as if it had been opened at that
// frame. Answers false when the container has no frames or the descriptor could not be moved.

HC_PLUGIN_API void hc_frame_notify  (HCFILE *fp, hc_frame_cb_t cb, void *userdata);
HC_PLUGIN_API bool hc_frame_restart (HCFILE *fp, const u64 comp_off, const u64 uncomp_off);

HC_PLUGIN_API bool  hc_path_has_bom (const char *path);
HC_PLUGIN_API bool  hc_same_files   (char *file1, char *file2);
HC_PLUGIN_API char *file_to_buffer  (const char *filename);

#endif // HC_FILEHANDLING_H
