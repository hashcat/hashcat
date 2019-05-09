/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_RP_H
#define _INC_RP_H

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

#define RP_PASSWORD_SIZE 256

DECLSPEC u32 generate_cmask (const u32 value);
DECLSPEC void append_four_byte (const u32 *buf_src, const int off_src, u32 *buf_dst, const int off_dst);
DECLSPEC void append_three_byte (const u32 *buf_src, const int off_src, u32 *buf_dst, const int off_dst);
DECLSPEC void append_two_byte (const u32 *buf_src, const int off_src, u32 *buf_dst, const int off_dst);
DECLSPEC void append_one_byte (const u32 *buf_src, const int off_src, u32 *buf_dst, const int off_dst);
DECLSPEC void append_block (const u32 *buf_src, const int off_src, u32 *buf_dst, const int off_dst, const int len);
DECLSPEC void exchange_byte (u32 *buf, const int off_src, const int off_dst);
DECLSPEC int mangle_lrest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_lrest_ufirst (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_urest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_urest_lfirst (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_trest (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_toggle_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_reverse (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_dupeword (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_dupeword_times (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_reflect (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_append (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_prepend (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_rotate_left (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_rotate_right (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_delete_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_delete_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_delete_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_extract (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_omit (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_insert (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_overstrike (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_truncate_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_replace (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_purgechar (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_dupechar_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_dupechar_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_dupechar_all (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_switch_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_switch_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_switch_at (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int mangle_chr_shiftl (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_chr_shiftr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_chr_incr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_chr_decr (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_replace_np1 (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_replace_nm1 (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_dupeblock_first (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_dupeblock_last (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u8 *buf, const int len);
DECLSPEC int mangle_title_sep (MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int len);
DECLSPEC int apply_rule (const u32 name, MAYBE_UNUSED const u8 p0, MAYBE_UNUSED const u8 p1, u32 *buf, const int in_len);
DECLSPEC int apply_rules (CONSTANT_AS const u32 *cmds, u32 *buf, const int in_len);

#endif // _INC_RP_H
