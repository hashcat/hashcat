/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _SESSION_H
#define _SESSION_H

void session_ctx_init (session_ctx_t *session_ctx, const u32 kernel_rules_cnt, kernel_rule_t *kernel_rules_buf);

void session_ctx_destroy (session_ctx_t *session_ctx);

#endif // _SESSION_H
