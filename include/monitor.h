/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef MONITOR_H
#define MONITOR_H

#define STDIN_TIMEOUT_WARN 20 // warn if no input from stdin for x seconds

int get_runtime_left (const hashcat_ctx_t *hashcat_ctx);

HC_API_CALL void *thread_monitor (void *p);

#endif // MONITOR_H
