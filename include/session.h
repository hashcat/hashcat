/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _SESSION_H
#define _SESSION_H

void session_ctx_init (session_ctx_t *session_ctx, const bool quiet, const bool force, const bool benchmark, const u32 scrypt_tmto, char *cwd, char *install_dir, char *profile_dir, char *session_dir, char *shared_dir, char *cpath_real, const u32 wordlist_mode, char *rule_buf_l, char *rule_buf_r, const int rule_len_l, const int rule_len_r, const u32 kernel_rules_cnt, kernel_rule_t *kernel_rules_buf, const u32 attack_mode, const u32 attack_kern, const u32 bitmap_size, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, u32 *bitmap_s1_a, u32 *bitmap_s1_b, u32 *bitmap_s1_c, u32 *bitmap_s1_d, u32 *bitmap_s2_a, u32 *bitmap_s2_b, u32  *bitmap_s2_c, u32 *bitmap_s2_d);

void session_ctx_destroy (session_ctx_t *session_ctx);

#endif // _SESSION_H
