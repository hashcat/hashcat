/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "session.h"

void session_ctx_init (session_ctx_t *session_ctx, const bool quiet, const bool force, const bool benchmark, const u32 scrypt_tmto, char *cwd, char *install_dir, char *profile_dir, char *session_dir, char *shared_dir, char *cpath_real, const u32 wordlist_mode, char *rule_buf_l, char *rule_buf_r, const int rule_len_l, const int rule_len_r, const u32 kernel_rules_cnt, kernel_rule_t *kernel_rules_buf, const u32 attack_mode, const u32 attack_kern, const u32 bitmap_size, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, u32 *bitmap_s1_a, u32 *bitmap_s1_b, u32 *bitmap_s1_c, u32 *bitmap_s1_d, u32 *bitmap_s2_a, u32 *bitmap_s2_b, u32  *bitmap_s2_c, u32 *bitmap_s2_d)
{
  session_ctx->quiet            = quiet;
  session_ctx->force            = force;
  session_ctx->benchmark        = benchmark;

  session_ctx->scrypt_tmto      = scrypt_tmto;

  session_ctx->cwd              = cwd;
  session_ctx->install_dir      = install_dir;
  session_ctx->profile_dir      = profile_dir;
  session_ctx->session_dir      = session_dir;
  session_ctx->shared_dir       = shared_dir;
  session_ctx->cpath_real       = cpath_real;

  session_ctx->wordlist_mode    = wordlist_mode;

  session_ctx->rule_buf_l       = rule_buf_l;
  session_ctx->rule_buf_r       = rule_buf_r;
  session_ctx->rule_len_l       = rule_len_l;
  session_ctx->rule_len_r       = rule_len_r;

  session_ctx->kernel_rules_cnt = kernel_rules_cnt;
  session_ctx->kernel_rules_buf = kernel_rules_buf;

  session_ctx->attack_mode      = attack_mode;
  session_ctx->attack_kern      = attack_kern;

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
  session_ctx->quiet            = false;
  session_ctx->force            = false;
  session_ctx->benchmark        = false;

  session_ctx->scrypt_tmto      = 0;

  session_ctx->cwd              = NULL;
  session_ctx->install_dir      = NULL;
  session_ctx->profile_dir      = NULL;
  session_ctx->session_dir      = NULL;
  session_ctx->shared_dir       = NULL;
  session_ctx->cpath_real       = NULL;

  session_ctx->wordlist_mode    = 0;

  session_ctx->rule_buf_l       = NULL;
  session_ctx->rule_buf_r       = NULL;
  session_ctx->rule_len_l       = 0;
  session_ctx->rule_len_r       = 0;

  session_ctx->kernel_rules_buf = NULL;
  session_ctx->kernel_rules_cnt = 0;

  session_ctx->attack_mode      = 0;
  session_ctx->attack_kern      = 0;

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
