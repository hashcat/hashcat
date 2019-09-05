/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "convert.h"
#include "event.h"
#include "shared.h"
#include "filehandling.h"
#include "rp.h"
#include "rp_cpu.h"

static const char grp_op_nop[] =
{
  RULE_OP_MANGLE_LREST,
  RULE_OP_MANGLE_UREST,
  RULE_OP_MANGLE_LREST_UFIRST,
  RULE_OP_MANGLE_UREST_LFIRST,
  RULE_OP_MANGLE_TREST,
  RULE_OP_MANGLE_REVERSE,
  RULE_OP_MANGLE_DUPEWORD,
  RULE_OP_MANGLE_REFLECT,
  RULE_OP_MANGLE_DELETE_FIRST,
  RULE_OP_MANGLE_DELETE_LAST,
  RULE_OP_MANGLE_ROTATE_LEFT,
  RULE_OP_MANGLE_ROTATE_RIGHT,
  RULE_OP_MANGLE_SWITCH_FIRST,
  RULE_OP_MANGLE_SWITCH_LAST,
  RULE_OP_MANGLE_DUPECHAR_ALL,
  RULE_OP_MANGLE_TITLE,
};

static const char grp_op_pos_p0[] =
{
  RULE_OP_MANGLE_TOGGLE_AT,
  RULE_OP_MANGLE_DELETE_AT,
  RULE_OP_MANGLE_TRUNCATE_AT,
  RULE_OP_MANGLE_CHR_INCR,
  RULE_OP_MANGLE_CHR_DECR,
  RULE_OP_MANGLE_CHR_SHIFTL,
  RULE_OP_MANGLE_CHR_SHIFTR,
  RULE_OP_MANGLE_REPLACE_NP1,
  RULE_OP_MANGLE_REPLACE_NM1
};

static const char grp_op_pos_p1[] =
{
  RULE_OP_MANGLE_DUPEWORD_TIMES,
  RULE_OP_MANGLE_DUPECHAR_FIRST,
  RULE_OP_MANGLE_DUPECHAR_LAST,
  RULE_OP_MANGLE_DUPEBLOCK_FIRST,
  RULE_OP_MANGLE_DUPEBLOCK_LAST
};

static const char grp_op_chr[] =
{
  RULE_OP_MANGLE_APPEND,
  RULE_OP_MANGLE_PREPEND,
  RULE_OP_MANGLE_PURGECHAR,
  RULE_OP_MANGLE_TITLE_SEP
};

static const char grp_op_chr_chr[] =
{
  RULE_OP_MANGLE_REPLACE
};

static const char grp_op_pos_chr[] =
{
  RULE_OP_MANGLE_INSERT,
  RULE_OP_MANGLE_OVERSTRIKE
};

static const char grp_op_pos_pos0[] =
{
  RULE_OP_MANGLE_SWITCH_AT
};

static const char grp_op_pos_pos1[] =
{
  RULE_OP_MANGLE_EXTRACT,
  RULE_OP_MANGLE_OMIT
};

static const char grp_pos[] =
{
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B'
};

bool class_num (const u8 c)
{
  return ((c >= '0') && (c <= '9'));
}

bool class_lower (const u8 c)
{
  return ((c >= 'a') && (c <= 'z'));
}

bool class_upper (const u8 c)
{
  return ((c >= 'A') && (c <= 'Z'));
}

bool class_alpha (const u8 c)
{
  return (class_lower (c) || class_upper (c));
}

int conv_ctoi (const u8 c)
{
  if (class_num (c)) return c - '0';
  if (class_upper (c)) return c - 'A' + 10;

  return -1;
}

int conv_itoc (const u8 c)
{
  if (c < 10) return c + '0';
  if (c < 37) return c + 'A' - 10;

  return -1;
}

int generate_random_rule (char rule_buf[RP_RULE_SIZE], const u32 rp_gen_func_min, const u32 rp_gen_func_max)
{
  u32 rp_gen_num = get_random_num (rp_gen_func_min, rp_gen_func_max);

  u32 j;

  u32 rule_pos = 0;

  for (j = 0; j < rp_gen_num; j++)
  {
    u32 r  = 0;
    u32 p1 = 0;
    u32 p2 = 0;

    switch ((char) get_random_num (0, 9))
    {
      case 0:
        r = get_random_num (0, sizeof (grp_op_nop));
        rule_buf[rule_pos++] = grp_op_nop[r];
        break;

      case 1:
        r = get_random_num (0, sizeof (grp_op_pos_p0));
        rule_buf[rule_pos++] = grp_op_pos_p0[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        break;

      case 2:
        r = get_random_num (0, sizeof (grp_op_pos_p1));
        rule_buf[rule_pos++] = grp_op_pos_p1[r];
        p1 = get_random_num (1, 6);
        rule_buf[rule_pos++] = grp_pos[p1];
        break;

      case 3:
        r = get_random_num (0, sizeof (grp_op_chr));
        rule_buf[rule_pos++] = grp_op_chr[r];
        p1 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p1;
        break;

      case 4:
        r = get_random_num (0, sizeof (grp_op_chr_chr));
        rule_buf[rule_pos++] = grp_op_chr_chr[r];
        p1 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p1;
        p2 = get_random_num (0x20, 0x7e);
        while (p1 == p2)
        p2 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p2;
        break;

      case 5:
        r = get_random_num (0, sizeof (grp_op_pos_chr));
        rule_buf[rule_pos++] = grp_op_pos_chr[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p2;
        break;

      case 6:
        r = get_random_num (0, sizeof (grp_op_pos_pos0));
        rule_buf[rule_pos++] = grp_op_pos_pos0[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (0, sizeof (grp_pos));
        while (p1 == p2)
        p2 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p2];
        break;

      case 7:
        r = get_random_num (0, sizeof (grp_op_pos_pos1));
        rule_buf[rule_pos++] = grp_op_pos_pos1[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (1, sizeof (grp_pos));
        while (p1 == p2)
        p2 = get_random_num (1, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p2];
        break;
    }
  }

  return (rule_pos);
}

#define INCR_POS if (++rule_pos == rule_len) return (-1)

#define SET_NAME(rule,val) (rule)->cmds[rule_cnt]  = ((val) & 0xff) <<  0
#define SET_P0(rule,val)   INCR_POS; if (is_hex_notation (rule_buf, rule_len, rule_pos) == true) { (rule)->cmds[rule_cnt] |= (hex_convert (rule_buf[rule_pos + 3] & 0xff) <<  8) | (hex_convert (rule_buf[rule_pos + 2] & 0xff) << 12); rule_pos += 3; } else { (rule)->cmds[rule_cnt] |= ((val) & 0xff) <<  8; }
#define SET_P1(rule,val)   INCR_POS; if (is_hex_notation (rule_buf, rule_len, rule_pos) == true) { (rule)->cmds[rule_cnt] |= (hex_convert (rule_buf[rule_pos + 3] & 0xff) << 16) | (hex_convert (rule_buf[rule_pos + 2] & 0xff) << 20); rule_pos += 3; } else { (rule)->cmds[rule_cnt] |= ((val) & 0xff) <<  16; }
#define GET_NAME(rule)     rule_cmd = (((rule)->cmds[rule_cnt] >>  0) & 0xff)
#define GET_P0(rule)       INCR_POS; rule_buf[rule_pos] = (((rule)->cmds[rule_cnt] >>  8) & 0xff)
#define GET_P1(rule)       INCR_POS; rule_buf[rule_pos] = (((rule)->cmds[rule_cnt] >> 16) & 0xff)

#define SET_P0_CONV(rule,val)  INCR_POS; (rule)->cmds[rule_cnt] |= ((conv_ctoi (val)) & 0xff) <<  8
#define SET_P1_CONV(rule,val)  INCR_POS; (rule)->cmds[rule_cnt] |= ((conv_ctoi (val)) & 0xff) << 16
#define GET_P0_CONV(rule)      INCR_POS; rule_buf[rule_pos] = (char) conv_itoc (((rule)->cmds[rule_cnt] >>  8) & 0xff)
#define GET_P1_CONV(rule)      INCR_POS; rule_buf[rule_pos] = (char) conv_itoc (((rule)->cmds[rule_cnt] >> 16) & 0xff)

bool is_hex_notation (const char *rule_buf, u32 rule_len, u32 rule_pos)
{
  if ((rule_pos + 4) > rule_len) return false;

  if (rule_buf[rule_pos + 0] != '\\') return false;
  if (rule_buf[rule_pos + 1] != 'x')  return false;

  if (is_valid_hex_char (rule_buf[rule_pos + 2]) == false) return false;
  if (is_valid_hex_char (rule_buf[rule_pos + 3]) == false) return false;

  return true;
}

int cpu_rule_to_kernel_rule (char *rule_buf, u32 rule_len, kernel_rule_t *rule)
{
  u32 rule_pos;
  u32 rule_cnt;

  for (rule_pos = 0, rule_cnt = 0; rule_pos < rule_len && rule_cnt < MAX_KERNEL_RULES; rule_pos++, rule_cnt++)
  {
    switch (rule_buf[rule_pos])
    {
      case ' ':
        rule_cnt--;
        break;

      case RULE_OP_MANGLE_NOOP:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_LREST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_UREST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_LREST_UFIRST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_UREST_LFIRST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_TREST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_TOGGLE_AT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_REVERSE:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPEWORD:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPEWORD_TIMES:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_REFLECT:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_ROTATE_LEFT:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_ROTATE_RIGHT:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_APPEND:
        SET_NAME (rule, rule_buf[rule_pos]);
        SET_P0   (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_PREPEND:
        SET_NAME (rule, rule_buf[rule_pos]);
        SET_P0   (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DELETE_FIRST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DELETE_LAST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DELETE_AT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_EXTRACT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        SET_P1_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_OMIT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        SET_P1_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_INSERT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        SET_P1      (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_OVERSTRIKE:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        SET_P1      (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_TRUNCATE_AT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_REPLACE:
        SET_NAME (rule, rule_buf[rule_pos]);
        SET_P0   (rule, rule_buf[rule_pos]);
        SET_P1   (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_PURGECHAR:
        SET_NAME (rule, rule_buf[rule_pos]);
        SET_P0   (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_TOGGLECASE_REC:
        return -1;

      case RULE_OP_MANGLE_DUPECHAR_FIRST:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPECHAR_LAST:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPECHAR_ALL:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_SWITCH_FIRST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_SWITCH_LAST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_SWITCH_AT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        SET_P1_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTL:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTR:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_CHR_INCR:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_CHR_DECR:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_REPLACE_NP1:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_REPLACE_NM1:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_FIRST:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_LAST:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_TITLE:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_TITLE_SEP:
        SET_NAME (rule, rule_buf[rule_pos]);
        SET_P0   (rule, rule_buf[rule_pos]);
        break;

      default:
        return -1;
    }
  }

  if (rule_pos < rule_len) return -1;

  return 0;
}

int kernel_rule_to_cpu_rule (char *rule_buf, kernel_rule_t *rule)
{
  u32 rule_cnt;
  u32 rule_pos;
  u32 rule_len = HCBUFSIZ_LARGE - 1; // maximum possible len

  for (rule_cnt = 0, rule_pos = 0; rule_pos < rule_len && rule_cnt < MAX_KERNEL_RULES; rule_pos++, rule_cnt++)
  {
    char rule_cmd;

    GET_NAME (rule);

    if (rule_cnt > 0) rule_buf[rule_pos++] = ' ';

    switch (rule_cmd)
    {
      case RULE_OP_MANGLE_NOOP:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_LREST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_UREST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_LREST_UFIRST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_UREST_LFIRST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_TREST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_TOGGLE_AT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_REVERSE:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_DUPEWORD:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_DUPEWORD_TIMES:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_REFLECT:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_ROTATE_LEFT:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_ROTATE_RIGHT:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_APPEND:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0 (rule);
        break;

      case RULE_OP_MANGLE_PREPEND:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0 (rule);
        break;

      case RULE_OP_MANGLE_DELETE_FIRST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_DELETE_LAST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_DELETE_AT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_EXTRACT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        GET_P1_CONV (rule);
        break;

      case RULE_OP_MANGLE_OMIT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        GET_P1_CONV (rule);
        break;

      case RULE_OP_MANGLE_INSERT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        GET_P1      (rule);
        break;

      case RULE_OP_MANGLE_OVERSTRIKE:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        GET_P1      (rule);
        break;

      case RULE_OP_MANGLE_TRUNCATE_AT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_REPLACE:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0 (rule);
        GET_P1 (rule);
        break;

      case RULE_OP_MANGLE_PURGECHAR:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0 (rule);
        break;

      case RULE_OP_MANGLE_TOGGLECASE_REC:
        return -1;

      case RULE_OP_MANGLE_DUPECHAR_FIRST:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_DUPECHAR_LAST:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_DUPECHAR_ALL:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_SWITCH_FIRST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_SWITCH_LAST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_SWITCH_AT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        GET_P1_CONV (rule);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTL:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTR:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_CHR_INCR:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_CHR_DECR:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_REPLACE_NP1:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_REPLACE_NM1:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_FIRST:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_LAST:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_TITLE:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_TITLE_SEP:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0 (rule);
        break;

      case 0:
        if (rule_pos == 0) return -1;
        return rule_pos - 1;

      default:
        return -1;
    }
  }

  return rule_pos;
}

bool kernel_rules_has_noop (const kernel_rule_t *kernel_rules_buf, const u32 kernel_rules_cnt)
{
  for (u32 kernel_rules_pos = 0; kernel_rules_pos < kernel_rules_cnt; kernel_rules_pos++)
  {
    if (kernel_rules_buf[kernel_rules_pos].cmds[0] != RULE_OP_MANGLE_NOOP) continue;
    if (kernel_rules_buf[kernel_rules_pos].cmds[1] != 0)                   continue;

    return true;
  }

  return false;
}

int kernel_rules_load (hashcat_ctx_t *hashcat_ctx, kernel_rule_t **out_buf, u32 *out_cnt)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  /**
   * load rules
   */

  u32 *all_kernel_rules_cnt = NULL;

  kernel_rule_t **all_kernel_rules_buf = NULL;

  if (user_options->rp_files_cnt)
  {
    all_kernel_rules_cnt = (u32 *) hccalloc (user_options->rp_files_cnt, sizeof (u32));

    all_kernel_rules_buf = (kernel_rule_t **) hccalloc (user_options->rp_files_cnt, sizeof (kernel_rule_t *));
  }

  char *rule_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  u32 rule_len = 0;

  for (u32 i = 0; i < user_options->rp_files_cnt; i++)
  {
    u32 kernel_rules_avail = 0;

    u32 kernel_rules_cnt = 0;

    kernel_rule_t *kernel_rules_buf = NULL;

    char *rp_file = user_options->rp_files[i];

    HCFILE fp;

    u32 rule_line = 0;

    if (hc_fopen (&fp, rp_file, "rb") == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", rp_file, strerror (errno));

      hcfree (all_kernel_rules_cnt);
      hcfree (all_kernel_rules_buf);

      hcfree (rule_buf);

      return -1;
    }

    while (!hc_feof (&fp))
    {
      rule_len = (u32) fgetl (&fp, rule_buf, HCBUFSIZ_LARGE);

      rule_line++;

      if (rule_len == 0) continue;

      if (rule_buf[0] == '#') continue;

      if (kernel_rules_avail == kernel_rules_cnt)
      {
        kernel_rules_buf = (kernel_rule_t *) hcrealloc (kernel_rules_buf, kernel_rules_avail * sizeof (kernel_rule_t), INCR_RULES * sizeof (kernel_rule_t));

        kernel_rules_avail += INCR_RULES;
      }

      char in[RP_PASSWORD_SIZE];
      char out[RP_PASSWORD_SIZE];

      memset (in,  0, sizeof (in));
      memset (out, 0, sizeof (out));

      int result = _old_apply_rule (rule_buf, rule_len, in, 1, out);

      if (result == -1)
      {
        event_log_warning (hashcat_ctx, "Skipping invalid or unsupported rule in file %s on line %u: %s", rp_file, rule_line, rule_buf);

        continue;
      }

      if (cpu_rule_to_kernel_rule (rule_buf, rule_len, &kernel_rules_buf[kernel_rules_cnt]) == -1)
      {
        event_log_warning (hashcat_ctx, "Cannot convert rule for use on OpenCL device in file %s on line %u: %s", rp_file, rule_line, rule_buf);

        memset (&kernel_rules_buf[kernel_rules_cnt], 0, sizeof (kernel_rule_t)); // needs to be cleared otherwise we could have some remaining data

        continue;
      }

      kernel_rules_cnt++;
    }

    hc_fclose (&fp);

    all_kernel_rules_cnt[i] = kernel_rules_cnt;
    all_kernel_rules_buf[i] = kernel_rules_buf;
  }

  hcfree (rule_buf);

  /**
   * merge rules
   */

  u32 kernel_rules_cnt = 1;

  u32 *repeats = (u32 *) hccalloc (user_options->rp_files_cnt + 1, sizeof (u32));

  repeats[0] = kernel_rules_cnt;

  for (u32 i = 0; i < user_options->rp_files_cnt; i++)
  {
    kernel_rules_cnt *= all_kernel_rules_cnt[i];

    repeats[i + 1] = kernel_rules_cnt;
  }

  kernel_rule_t *kernel_rules_buf = (kernel_rule_t *) hccalloc (kernel_rules_cnt, sizeof (kernel_rule_t));

  for (u32 i = 0; i < kernel_rules_cnt; i++)
  {
    u32 out_pos = 0;

    kernel_rule_t *out = &kernel_rules_buf[i];

    for (u32 j = 0; j < user_options->rp_files_cnt; j++)
    {
      u32 in_off = (i / repeats[j]) % all_kernel_rules_cnt[j];
      u32 in_pos;

      kernel_rule_t *in = &all_kernel_rules_buf[j][in_off];

      for (in_pos = 0; in->cmds[in_pos]; in_pos++, out_pos++)
      {
        if (out_pos == RULES_MAX - 1)
        {
          // event_log_warning (hashcat_ctx, "Truncated chaining of rule %d and rule %d - maximum functions per rule exceeded.", i, in_off);

          break;
        }

        out->cmds[out_pos] = in->cmds[in_pos];
      }
    }
  }

  hcfree (repeats);

  hcfree (all_kernel_rules_cnt);
  hcfree (all_kernel_rules_buf);

  if (kernel_rules_cnt == 0)
  {
    event_log_error (hashcat_ctx, "No valid rules left.");

    hcfree (kernel_rules_buf);

    return -1;
  }

  *out_cnt = kernel_rules_cnt;
  *out_buf = kernel_rules_buf;

  return 0;
}

int kernel_rules_generate (hashcat_ctx_t *hashcat_ctx, kernel_rule_t **out_buf, u32 *out_cnt)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  u32            kernel_rules_cnt = 0;
  kernel_rule_t *kernel_rules_buf = hccalloc (user_options->rp_gen, sizeof (kernel_rule_t));

  char *rule_buf = (char *) hcmalloc (RP_RULE_SIZE);

  for (kernel_rules_cnt = 0; kernel_rules_cnt < user_options->rp_gen; kernel_rules_cnt++)
  {
    memset (rule_buf, 0, RP_RULE_SIZE);

    int rule_len = generate_random_rule (rule_buf, user_options->rp_gen_func_min, user_options->rp_gen_func_max);

    if (cpu_rule_to_kernel_rule (rule_buf, rule_len, &kernel_rules_buf[kernel_rules_cnt]) == -1) continue;
  }

  hcfree (rule_buf);

  *out_cnt = kernel_rules_cnt;
  *out_buf = kernel_rules_buf;

  return 0;
}
