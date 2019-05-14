/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_RP_OPTIMIZED_H
#define _INC_RP_OPTIMIZED_H

#ifndef DECLSPEC
#define DECLSPEC
#endif

#ifndef MAYBE_UNUSED
#define MAYBE_UNUSED
#endif

#define RULE_OP_MANGLE_NOOP             ':'
#define RULE_OP_MANGLE_LREST            'l'
#define RULE_OP_MANGLE_UREST            'u'
#define RULE_OP_MANGLE_LREST_UFIRST     'c'
#define RULE_OP_MANGLE_UREST_LFIRST     'C'
#define RULE_OP_MANGLE_TREST            't'
#define RULE_OP_MANGLE_TOGGLE_AT        'T'
#define RULE_OP_MANGLE_REVERSE          'r'
#define RULE_OP_MANGLE_DUPEWORD         'd'
#define RULE_OP_MANGLE_DUPEWORD_TIMES   'p'
#define RULE_OP_MANGLE_REFLECT          'f'
#define RULE_OP_MANGLE_ROTATE_LEFT      '{'
#define RULE_OP_MANGLE_ROTATE_RIGHT     '}'
#define RULE_OP_MANGLE_APPEND           '$'
#define RULE_OP_MANGLE_PREPEND          '^'
#define RULE_OP_MANGLE_DELETE_FIRST     '['
#define RULE_OP_MANGLE_DELETE_LAST      ']'
#define RULE_OP_MANGLE_DELETE_AT        'D'
#define RULE_OP_MANGLE_EXTRACT          'x'
#define RULE_OP_MANGLE_OMIT             'O'
#define RULE_OP_MANGLE_INSERT           'i'
#define RULE_OP_MANGLE_OVERSTRIKE       'o'
#define RULE_OP_MANGLE_TRUNCATE_AT      '\''
#define RULE_OP_MANGLE_REPLACE          's'
#define RULE_OP_MANGLE_PURGECHAR        '@'
#define RULE_OP_MANGLE_TOGGLECASE_REC   'a'
#define RULE_OP_MANGLE_DUPECHAR_FIRST   'z'
#define RULE_OP_MANGLE_DUPECHAR_LAST    'Z'
#define RULE_OP_MANGLE_DUPECHAR_ALL     'q'
#define RULE_OP_MANGLE_TITLE_SEP        'e'

#define RULE_OP_REJECT_LESS             '<'
#define RULE_OP_REJECT_GREATER          '>'
#define RULE_OP_REJECT_CONTAIN          '!'
#define RULE_OP_REJECT_NOT_CONTAIN      '/'
#define RULE_OP_REJECT_EQUAL_FIRST      '('
#define RULE_OP_REJECT_EQUAL_LAST       ')'
#define RULE_OP_REJECT_EQUAL_AT         '='
#define RULE_OP_REJECT_CONTAINS         '%'

/* hashcat only */
#define RULE_OP_MANGLE_SWITCH_FIRST     'k'
#define RULE_OP_MANGLE_SWITCH_LAST      'K'
#define RULE_OP_MANGLE_SWITCH_AT        '*'
#define RULE_OP_MANGLE_CHR_SHIFTL       'L'
#define RULE_OP_MANGLE_CHR_SHIFTR       'R'
#define RULE_OP_MANGLE_CHR_INCR         '+'
#define RULE_OP_MANGLE_CHR_DECR         '-'
#define RULE_OP_MANGLE_REPLACE_NP1      '.'
#define RULE_OP_MANGLE_REPLACE_NM1      ','
#define RULE_OP_MANGLE_DUPEBLOCK_FIRST  'y'
#define RULE_OP_MANGLE_DUPEBLOCK_LAST   'Y'
#define RULE_OP_MANGLE_TITLE            'E'

DECLSPEC u32 generate_cmask_optimized (const u32 value);
DECLSPEC void truncate_right_optimized (u32 *buf0, u32 *buf1, const u32 offset);
DECLSPEC void truncate_left_optimized (u32 *buf0, u32 *buf1, const u32 offset);
DECLSPEC void lshift_block_optimized (const u32 *in0, const u32 *in1, u32 *out0, u32 *out1);
DECLSPEC void rshift_block_optimized (const u32 *in0, const u32 *in1, u32 *out0, u32 *out1);
DECLSPEC void lshift_block_optimized_N (const u32 *in0, const u32 *in1, u32 *out0, u32 *out1, const u32 num);
DECLSPEC void rshift_block_optimized_N (const u32 *in0, const u32 *in1, u32 *out0, u32 *out1, const u32 num);
DECLSPEC void append_block1_optimized (const u32 offset, u32 *buf0, u32 *buf1, const u32 src_r0);
DECLSPEC void append_block8_optimized (const u32 offset, u32 *buf0, u32 *buf1, const u32 *src_l0, const u32 *src_l1, const u32 *src_r0, const u32 *src_r1);
DECLSPEC void reverse_block_optimized (u32 *in0, u32 *in1, u32 *out0, u32 *out1, const u32 len);
DECLSPEC void exchange_byte_optimized (u32 *buf, const int off_src, const int off_dst);
DECLSPEC u32 rule_op_mangle_lrest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_urest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_lrest_ufirst (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_urest_lfirst (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_trest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_toggle_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_reverse (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_dupeword (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_dupeword_times (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_reflect (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_append (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_prepend (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_rotate_left (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_rotate_right (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_delete_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_delete_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_delete_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_extract (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_omit (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_insert (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_overstrike (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_truncate_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 search_on_register (const u32 in, const u32 p0);
DECLSPEC u32 replace_on_register (const u32 in, const u32 r, const u32 p1);
DECLSPEC u32 rule_op_mangle_replace (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_purgechar (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_dupechar_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_dupechar_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_dupechar_all (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_switch_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_switch_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_switch_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_chr_shiftl (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_chr_shiftr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_chr_incr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_chr_decr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_replace_np1 (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_replace_nm1 (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_dupeblock_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 rule_op_mangle_dupeblock_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 toggle_on_register (const u32 in, const u32 r);
DECLSPEC u32 rule_op_mangle_title_sep (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 *buf0, MAYBE_UNUSED u32 *buf1, const u32 in_len);
DECLSPEC u32 apply_rule_optimized (const u32 name, const u32 p0, const u32 p1, u32 *buf0, u32 *buf1, const u32 in_len);
DECLSPEC u32 apply_rules_optimized (CONSTANT_AS const u32 *cmds, u32 *buf0, u32 *buf1, const u32 len);
DECLSPEC u32x apply_rules_vect_optimized (const u32 *pw_buf0, const u32 *pw_buf1, const u32 pw_len, CONSTANT_AS const kernel_rule_t *kernel_rules, const u32 il_pos, u32x *buf0, u32x *buf1);

#endif // _INC_RP_OPTIMIZED_H
