/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_RP_OPTIMIZED_H
#define INC_RP_OPTIMIZED_H

#include "inc_rp_common.h"

DECLSPEC u32 generate_cmask_optimized (const u32 value);
DECLSPEC void truncate_right_optimized (PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, const u32 offset);
DECLSPEC void truncate_left_optimized (PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, const u32 offset);
DECLSPEC void lshift_block_optimized (PRIVATE_AS const u32 *in0, PRIVATE_AS const u32 *in1, PRIVATE_AS u32 *out0, PRIVATE_AS u32 *out1);
DECLSPEC void rshift_block_optimized (PRIVATE_AS const u32 *in0, PRIVATE_AS const u32 *in1, PRIVATE_AS u32 *out0, PRIVATE_AS u32 *out1);
DECLSPEC void lshift_block_optimized_N (PRIVATE_AS const u32 *in0, PRIVATE_AS const u32 *in1, PRIVATE_AS u32 *out0, PRIVATE_AS u32 *out1, const u32 num);
DECLSPEC void rshift_block_optimized_N (PRIVATE_AS const u32 *in0, PRIVATE_AS const u32 *in1, PRIVATE_AS u32 *out0, PRIVATE_AS u32 *out1, const u32 num);
DECLSPEC void append_block1_optimized (const u32 offset, PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, const u32 src_r0);
DECLSPEC void append_block8_optimized (const u32 offset, PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, PRIVATE_AS const u32 *src_l0, PRIVATE_AS const u32 *src_l1, PRIVATE_AS const u32 *src_r0, PRIVATE_AS const u32 *src_r1);
DECLSPEC void reverse_block_optimized (PRIVATE_AS u32 *in0, PRIVATE_AS u32 *in1, PRIVATE_AS u32 *out0, PRIVATE_AS u32 *out1, const u32 len);
DECLSPEC void exchange_byte_optimized (PRIVATE_AS u32 *buf, const int off_src, const int off_dst);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_lrest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_urest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_lrest_ufirst (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_urest_lfirst (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_trest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_toggle_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_toggle_at_sep (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_reverse (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupeword (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupeword_times (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_reflect (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_append (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_prepend (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_rotate_left (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_rotate_right (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_delete_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_delete_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_delete_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_extract (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_omit (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_insert (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_overstrike (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_truncate_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC u32 search_on_register (const u32 in, const u32 p0);
DECLSPEC u32 replace_on_register (const u32 in, const u32 r, const u32 p1);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_class (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_purgechar (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_purgechar_class (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupechar_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupechar_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupechar_all (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_switch_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_switch_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_switch_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_chr_shiftl (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_chr_shiftr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_chr_incr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_chr_decr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_np1 (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_nm1 (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupeblock_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupeblock_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC u32 toggle_on_register (const u32 in, const u32 r);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_title_sep (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC HC_INLINE_RP u32 rule_op_mangle_title_sep_class (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC u32 apply_rule_optimized (const u32 name, const u32 p0, const u32 p1, PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, const u32 in_len);
DECLSPEC u32 apply_rules_optimized (CONSTANT_AS const u32 *cmds, PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, const u32 len);
DECLSPEC u32x apply_rules_vect_optimized (PRIVATE_AS const u32 *pw_buf0, PRIVATE_AS const u32 *pw_buf1, const u32 pw_len, CONSTANT_AS const kernel_rule_t *kernel_rules, const u32 il_pos, PRIVATE_AS u32x *buf0, PRIVATE_AS u32x *buf1);

#endif // INC_RP_OPTIMIZED_H
