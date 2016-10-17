/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _MONITOR_H
#define _MONITOR_H

int get_runtime_left (const hashcat_ctx_t *hashcat_ctx);

void *thread_monitor (void *p);

#endif // _MONITOR_H
