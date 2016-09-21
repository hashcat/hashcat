/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _SESSION_H
#define _SESSION_H

void session_ctx_init (session_ctx_t *session_ctx, char *cwd, char *install_dir, char *profile_dir, char *session_dir, char *shared_dir, char *cpath_real, const u32 kernel_rules_cnt, kernel_rule_t *kernel_rules_buf,const u32 bitmap_size, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, u32 *bitmap_s1_a, u32 *bitmap_s1_b, u32 *bitmap_s1_c, u32 *bitmap_s1_d, u32 *bitmap_s2_a, u32 *bitmap_s2_b, u32  *bitmap_s2_c, u32 *bitmap_s2_d);

void session_ctx_destroy (session_ctx_t *session_ctx);

#endif // _SESSION_H
