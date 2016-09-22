/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "session.h"

void session_ctx_init (session_ctx_t *session_ctx, const u32 kernel_rules_cnt, kernel_rule_t *kernel_rules_buf)
{
  session_ctx->kernel_rules_cnt = kernel_rules_cnt;
  session_ctx->kernel_rules_buf = kernel_rules_buf;
}

void session_ctx_destroy (session_ctx_t *session_ctx)
{
  session_ctx->kernel_rules_buf = NULL;
  session_ctx->kernel_rules_cnt = 0;
}
