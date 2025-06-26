/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_RP_H
#define INC_RP_H

#include "inc_rp_common.h"

DECLSPEC u32 generate_cmask (const u32 value);
DECLSPEC void append_four_byte (PRIVATE_AS const u32 *buf_src, const int off_src, PRIVATE_AS u32 *buf_dst, const int off_dst);
DECLSPEC void append_three_byte (PRIVATE_AS const u32 *buf_src, const int off_src, PRIVATE_AS u32 *buf_dst, const int off_dst);
DECLSPEC void append_two_byte (PRIVATE_AS const u32 *buf_src, const int off_src, PRIVATE_AS u32 *buf_dst, const int off_dst);
DECLSPEC void append_one_byte (PRIVATE_AS const u32 *buf_src, const int off_src, PRIVATE_AS u32 *buf_dst, const int off_dst);
DECLSPEC void append_block (PRIVATE_AS const u32 *buf_src, const int off_src, PRIVATE_AS u32 *buf_dst, const int off_dst, const int len);
DECLSPEC void exchange_byte (PRIVATE_AS u32 *buf, const int off_src, const int off_dst);
DECLSPEC int mangle_lrest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_lrest_ufirst (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_urest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_urest_lfirst (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_trest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_toggle_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_toggle_at_sep (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_reverse (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_dupeword (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_dupeword_times (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_reflect (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_append (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_prepend (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_rotate_left (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_rotate_right (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_delete_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_delete_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_delete_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_extract (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_omit (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_insert (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_overstrike (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_truncate_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_replace (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_replace_class (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_purgechar (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_purgechar_class (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_dupechar_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_dupechar_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_dupechar_all (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_switch_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_switch_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_switch_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_chr_shiftl (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_chr_shiftr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_chr_incr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_chr_decr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_replace_np1 (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_replace_nm1 (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_dupeblock_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_dupeblock_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u8 *buf, const int len);
DECLSPEC int mangle_title_sep (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int mangle_title_sep_class (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int len);
DECLSPEC int apply_rule (const u32 name, MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, PRIVATE_AS u32 *buf, const int in_len);
DECLSPEC int apply_rules (CONSTANT_AS const u32 *cmds, PRIVATE_AS u32 *buf, const int in_len);

#endif // INC_RP_H
