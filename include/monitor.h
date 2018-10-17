/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _MONITOR_H
#define _MONITOR_H

#define STDIN_TIMEOUT_MIN  20 // warn  after no input from stdin for x seconds
#define STDIN_TIMEOUT_MAX 120 // abort after no input from stdin for x seconds

int get_runtime_left (const hashcat_ctx_t *hashcat_ctx);

HC_API_CALL void *thread_monitor (void *p);

#endif // _MONITOR_H
