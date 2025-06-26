/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_RP_COMMON_H
#define INC_RP_COMMON_H

#ifndef DECLSPEC
#define DECLSPEC
#endif

#ifndef MAYBE_UNUSED
#define MAYBE_UNUSED
#endif

#ifdef IS_APPLE_SILICON
#define HC_INLINE_RP __attribute__ ((noinline))
#else
#define HC_INLINE_RP
#endif

#define RULE_OP_MANGLE_NOOP              ':'
#define RULE_OP_MANGLE_LREST             'l'
#define RULE_OP_MANGLE_UREST             'u'
#define RULE_OP_MANGLE_LREST_UFIRST      'c'
#define RULE_OP_MANGLE_UREST_LFIRST      'C'
#define RULE_OP_MANGLE_TREST             't'
#define RULE_OP_MANGLE_TOGGLE_AT         'T'
#define RULE_OP_MANGLE_TOGGLE_AT_SEP     '3'
#define RULE_OP_MANGLE_REVERSE           'r'
#define RULE_OP_MANGLE_DUPEWORD          'd'
#define RULE_OP_MANGLE_DUPEWORD_TIMES    'p'
#define RULE_OP_MANGLE_REFLECT           'f'
#define RULE_OP_MANGLE_ROTATE_LEFT       '{'
#define RULE_OP_MANGLE_ROTATE_RIGHT      '}'
#define RULE_OP_MANGLE_APPEND            '$'
#define RULE_OP_MANGLE_PREPEND           '^'
#define RULE_OP_MANGLE_DELETE_FIRST      '['
#define RULE_OP_MANGLE_DELETE_LAST       ']'
#define RULE_OP_MANGLE_DELETE_AT         'D'
#define RULE_OP_MANGLE_EXTRACT           'x'
#define RULE_OP_MANGLE_OMIT              'O'
#define RULE_OP_MANGLE_INSERT            'i'
#define RULE_OP_MANGLE_OVERSTRIKE        'o'
#define RULE_OP_MANGLE_TRUNCATE_AT       '\''
#define RULE_OP_MANGLE_REPLACE           's'
#define RULE_OP_MANGLE_PURGECHAR         '@'
#define RULE_OP_MANGLE_TOGGLECASE_REC    'a'
#define RULE_OP_MANGLE_DUPECHAR_FIRST    'z'
#define RULE_OP_MANGLE_DUPECHAR_LAST     'Z'
#define RULE_OP_MANGLE_DUPECHAR_ALL      'q'
#define RULE_OP_MANGLE_TITLE_SEP         'e'

#define RULE_OP_REJECT_LESS              '<'
#define RULE_OP_REJECT_GREATER           '>'
#define RULE_OP_REJECT_CONTAIN           '!'
#define RULE_OP_REJECT_NOT_CONTAIN       '/'
#define RULE_OP_REJECT_EQUAL_FIRST       '('
#define RULE_OP_REJECT_EQUAL_LAST        ')'
#define RULE_OP_REJECT_EQUAL_AT          '='
#define RULE_OP_REJECT_CONTAINS          '%'

/* hashcat only */
#define RULE_OP_MANGLE_SWITCH_FIRST      'k'
#define RULE_OP_MANGLE_SWITCH_LAST       'K'
#define RULE_OP_MANGLE_SWITCH_AT         '*'
#define RULE_OP_MANGLE_CHR_SHIFTL        'L'
#define RULE_OP_MANGLE_CHR_SHIFTR        'R'
#define RULE_OP_MANGLE_CHR_INCR          '+'
#define RULE_OP_MANGLE_CHR_DECR          '-'
#define RULE_OP_MANGLE_REPLACE_NP1       '.'
#define RULE_OP_MANGLE_REPLACE_NM1       ','
#define RULE_OP_MANGLE_DUPEBLOCK_FIRST   'y'
#define RULE_OP_MANGLE_DUPEBLOCK_LAST    'Y'
#define RULE_OP_MANGLE_TITLE             'E'

/* using character classes */
#define RULE_OP_MANGLE_REPLACE_CLASS     0x01
#define RULE_OP_MANGLE_PURGECHAR_CLASS   0x02
#define RULE_OP_MANGLE_TITLE_SEP_CLASS   0x03
#define RULE_OP_REJECT_CONTAIN_CLASS     0x04
#define RULE_OP_REJECT_NOT_CONTAIN_CLASS 0x05
#define RULE_OP_REJECT_EQUAL_FIRST_CLASS 0x06
#define RULE_OP_REJECT_EQUAL_LAST_CLASS  0x07
#define RULE_OP_REJECT_EQUAL_AT_CLASS    0x08
#define RULE_OP_REJECT_CONTAINS_CLASS    0x09

#define RP_PASSWORD_SIZE 256

DECLSPEC bool is_l (u8 c);
DECLSPEC bool is_u (u8 c);
DECLSPEC bool is_d (u8 c);
DECLSPEC bool is_lh (u8 c);
DECLSPEC bool is_uh (u8 c);
DECLSPEC bool is_s (u8 c);

DECLSPEC u32  generate_cmask (const u32 value);

#endif // INC_RP_COMMON_H
