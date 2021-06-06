/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EVENT_H
#define _EVENT_H

#include <stdio.h>
#include <stdarg.h>

void event_call (const u32 id, void *hashcat_ctx, const void *buf, const size_t len);

#define EVENT(id)              event_call ((id), hashcat_ctx, NULL,  0)
#define EVENT_DATA(id,buf,len) event_call ((id), hashcat_ctx, (buf), (len))

__attribute__ ((format (printf, 2, 3))) size_t event_log_advice_nn  (void *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_info_nn    (void *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_warning_nn (void *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_error_nn   (void *hashcat_ctx, const char *fmt, ...);

__attribute__ ((format (printf, 2, 3))) size_t event_log_advice     (void *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_info       (void *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_warning    (void *hashcat_ctx, const char *fmt, ...);
__attribute__ ((format (printf, 2, 3))) size_t event_log_error      (void *hashcat_ctx, const char *fmt, ...);

int  event_ctx_init         (void *hashcat_ctx);
void event_ctx_destroy      (void *hashcat_ctx);

#endif // _EVENT_H
