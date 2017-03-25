/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EVENT_H
#define _EVENT_H

#include <stdio.h>
#include <stdarg.h>

void event_call (const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len);

#define EVENT(id)              event_call ((id), hashcat_ctx, NULL,  0)
#define EVENT_DATA(id,buf,len) event_call ((id), hashcat_ctx, (buf), (len))

__attribute__ ((format (printf, 2, 3))) size_t event_log_advice_nn  (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_info_nn    (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_warning_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_error_nn   (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);

__attribute__ ((format (printf, 2, 3))) size_t event_log_advice     (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_info       (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_warning    (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_error      (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);

int  event_ctx_init         (hashcat_ctx_t *hashcat_ctx);
void event_ctx_destroy      (hashcat_ctx_t *hashcat_ctx);

#endif // _EVENT_H
