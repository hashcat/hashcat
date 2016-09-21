/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "session.h"

void session_ctx_init (session_ctx_t *session_ctx, const u32 kernel_rules_cnt, kernel_rule_t *kernel_rules_buf, const u32 bitmap_size, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, u32 *bitmap_s1_a, u32 *bitmap_s1_b, u32 *bitmap_s1_c, u32 *bitmap_s1_d, u32 *bitmap_s2_a, u32 *bitmap_s2_b, u32  *bitmap_s2_c, u32 *bitmap_s2_d)
{
  session_ctx->kernel_rules_cnt = kernel_rules_cnt;
  session_ctx->kernel_rules_buf = kernel_rules_buf;

  session_ctx->bitmap_size      = bitmap_size;
  session_ctx->bitmap_mask      = bitmap_mask;
  session_ctx->bitmap_shift1    = bitmap_shift1;
  session_ctx->bitmap_shift2    = bitmap_shift2;

  session_ctx->bitmap_s1_a      = bitmap_s1_a;
  session_ctx->bitmap_s1_b      = bitmap_s1_b;
  session_ctx->bitmap_s1_c      = bitmap_s1_c;
  session_ctx->bitmap_s1_d      = bitmap_s1_d;
  session_ctx->bitmap_s2_a      = bitmap_s2_a;
  session_ctx->bitmap_s2_b      = bitmap_s2_b;
  session_ctx->bitmap_s2_c      = bitmap_s2_c;
  session_ctx->bitmap_s2_d      = bitmap_s2_d;
}

void session_ctx_destroy (session_ctx_t *session_ctx)
{
  session_ctx->kernel_rules_buf = NULL;
  session_ctx->kernel_rules_cnt = 0;

  session_ctx->bitmap_size      = 0;
  session_ctx->bitmap_mask      = 0;
  session_ctx->bitmap_shift1    = 0;
  session_ctx->bitmap_shift2    = 0;

  session_ctx->bitmap_s1_a      = NULL;
  session_ctx->bitmap_s1_b      = NULL;
  session_ctx->bitmap_s1_c      = NULL;
  session_ctx->bitmap_s1_d      = NULL;
  session_ctx->bitmap_s2_a      = NULL;
  session_ctx->bitmap_s2_b      = NULL;
  session_ctx->bitmap_s2_c      = NULL;
  session_ctx->bitmap_s2_d      = NULL;
}
