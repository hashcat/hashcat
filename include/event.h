/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EVENT_H
#define HC_EVENT_H

#include <stdio.h>
#include <stdarg.h>

void event_call (const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len);

#define EVENT(id)              event_call ((id), hashcat_ctx, NULL,  0)
#define EVENT_DATA(id,buf,len) event_call ((id), hashcat_ctx, (buf), (len))

#ifndef __MINGW_PRINTF_FORMAT
#define __MINGW_PRINTF_FORMAT printf
#endif

__attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3))) size_t event_log_advice_nn  (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3))) size_t event_log_info_nn    (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3))) size_t event_log_warning_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3))) size_t event_log_error_nn   (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);

__attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3))) size_t event_log_advice     (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3))) size_t event_log_info       (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3))) size_t event_log_warning    (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3))) size_t event_log_error      (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);

int  event_ctx_init         (hashcat_ctx_t *hashcat_ctx);
void event_ctx_destroy      (hashcat_ctx_t *hashcat_ctx);

#endif // HC_EVENT_H
