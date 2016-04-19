/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "cpu_rules.h"

extern int max_len;

/**
 * GPU rules
 */

#define INCR_POS           if (++rule_pos == rule_len) return (-1)
#define SET_NAME(rule,val) (rule)->cmds[rule_cnt]  = ((val) & 0xff) <<  0
#define SET_P0(rule,val)   INCR_POS; (rule)->cmds[rule_cnt] |= ((val) & 0xff) <<  8
#define SET_P1(rule,val)   INCR_POS; (rule)->cmds[rule_cnt] |= ((val) & 0xff) << 16
#define MAX_GPU_RULES      255
#define GET_NAME(rule)     rule_cmd = (((rule)->cmds[rule_cnt] >>  0) & 0xff)
#define GET_P0(rule)       INCR_POS; rule_buf[rule_pos] = (((rule)->cmds[rule_cnt] >>  8) & 0xff)
#define GET_P1(rule)       INCR_POS; rule_buf[rule_pos] = (((rule)->cmds[rule_cnt] >> 16) & 0xff)

#define SET_P0_CONV(rule,val)  INCR_POS; (rule)->cmds[rule_cnt] |= ((conv_ctoi (val)) & 0xff) <<  8
#define SET_P1_CONV(rule,val)  INCR_POS; (rule)->cmds[rule_cnt] |= ((conv_ctoi (val)) & 0xff) << 16
#define GET_P0_CONV(rule)      INCR_POS; rule_buf[rule_pos] = conv_itoc (((rule)->cmds[rule_cnt] >>  8) & 0xff)
#define GET_P1_CONV(rule)      INCR_POS; rule_buf[rule_pos] = conv_itoc (((rule)->cmds[rule_cnt] >> 16) & 0xff)

void gen_cmask (const u8 *word, u8 *cmask, const uint len)
{
  uint i;

  for (i = 0; i < len; i++)
  {
    if (class_alpha (word[i]) == 0)
    {
      cmask[i] = 0;
    }
    else
    {
      cmask[i] = 0xff;
    }
  }
}

/**
 * CPU rules
 */

#define NEXT_RULEPOS(rp)      if (++(rp) == rule_len) return (RULE_RC_SYNTAX_ERROR)
#define NEXT_RPTOI(r,rp,up)   if (((up) = conv_ctoi ((r)[(rp)])) == -1) return (RULE_RC_SYNTAX_ERROR)

#define MANGLE_TOGGLE_AT(a,p) if (class_alpha ((a)[(p)])) (a)[(p)] ^= 0x20
#define MANGLE_LOWER_AT(a,p)  if (class_upper ((a)[(p)])) (a)[(p)] ^= 0x20
#define MANGLE_UPPER_AT(a,p)  if (class_lower ((a)[(p)])) (a)[(p)] ^= 0x20

/* #define MANGLE_SWITCH(a,l,r)  { char c = (l); arr[(r)] = arr[(l)]; arr[(l)] = c; } */
/* #define MANGLE_SWITCH(a,l,r)  { char c = (l); (a)[(r)] = (a)[(l)]; (a)[(l)] = c; } */
#define MANGLE_SWITCH(a,l,r)  { char c = (a)[(r)]; (a)[(r)] = (a)[(l)]; (a)[(l)] = c; }

int mangle_lrest (char arr[BLOCK_SIZE], int arr_len)
{
  int pos;

  for (pos = 0; pos < arr_len; pos++) MANGLE_LOWER_AT (arr, pos);

  return (arr_len);
}

int mangle_urest (char arr[BLOCK_SIZE], int arr_len)
{
  int pos;

  for (pos = 0; pos < arr_len; pos++) MANGLE_UPPER_AT (arr, pos);

  return (arr_len);
}

int mangle_trest (char arr[BLOCK_SIZE], int arr_len)
{
  int pos;

  for (pos = 0; pos < arr_len; pos++) MANGLE_TOGGLE_AT (arr, pos);

  return (arr_len);
}

int mangle_reverse (char arr[BLOCK_SIZE], int arr_len)
{
  int l;
  int r;

  for (l = 0; l < arr_len; l++)
  {
    r = arr_len - 1 - l;

    if (l >= r) break;

    MANGLE_SWITCH (arr, l, r);
  }

  return (arr_len);
}

int mangle_double (char arr[BLOCK_SIZE], int arr_len)
{
  if ((arr_len * 2) >= BLOCK_SIZE) return (arr_len);

  memcpy (&arr[arr_len], arr, (size_t) arr_len);

  return (arr_len * 2);
}

int mangle_double_times (char arr[BLOCK_SIZE], int arr_len, int times)
{
  if (((arr_len * times) + arr_len) >= BLOCK_SIZE) return (arr_len);

  int orig_len = arr_len;

  int i;

  for (i = 0; i < times; i++)
  {
    memcpy (&arr[arr_len], arr, orig_len);

    arr_len += orig_len;
  }

  return (arr_len);
}

int mangle_reflect (char arr[BLOCK_SIZE], int arr_len)
{
  if ((arr_len * 2) >= BLOCK_SIZE) return (arr_len);

  mangle_double (arr, arr_len);

  mangle_reverse (arr + arr_len, arr_len);

  return (arr_len * 2);
}

int mangle_rotate_left (char arr[BLOCK_SIZE], int arr_len)
{
  int l;
  int r;

  for (l = 0, r = arr_len - 1; r > 0; r--)
  {
    MANGLE_SWITCH (arr, l, r);
  }

  return (arr_len);
}

int mangle_rotate_right (char arr[BLOCK_SIZE], int arr_len)
{
  int l;
  int r;

  for (l = 0, r = arr_len - 1; l < r; l++)
  {
    MANGLE_SWITCH (arr, l, r);
  }

  return (arr_len);
}

int mangle_append (char arr[BLOCK_SIZE], int arr_len, char c)
{
  if ((arr_len + 1) >= BLOCK_SIZE) return (arr_len);

  arr[arr_len] = c;

  return (arr_len + 1);
}

int mangle_prepend (char arr[BLOCK_SIZE], int arr_len, char c)
{
  if ((arr_len + 1) >= BLOCK_SIZE) return (arr_len);

  int arr_pos;

  for (arr_pos = arr_len - 1; arr_pos > -1; arr_pos--)
  {
    arr[arr_pos + 1] = arr[arr_pos];
  }

  arr[0] = c;

  return (arr_len + 1);
}

int mangle_delete_at (char arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  int arr_pos;

  for (arr_pos = upos; arr_pos < arr_len - 1; arr_pos++)
  {
    arr[arr_pos] = arr[arr_pos + 1];
  }

  return (arr_len - 1);
}

int mangle_extract (char arr[BLOCK_SIZE], int arr_len, int upos, int ulen)
{
  if (upos >= arr_len) return (arr_len);

  if ((upos + ulen) > arr_len) return (arr_len);

  int arr_pos;

  for (arr_pos = 0; arr_pos < ulen; arr_pos++)
  {
    arr[arr_pos] = arr[upos + arr_pos];
  }

  return (ulen);
}

int mangle_omit (char arr[BLOCK_SIZE], int arr_len, int upos, int ulen)
{
  if (upos >= arr_len) return (arr_len);

  if ((upos + ulen) > arr_len) return (arr_len);

  int arr_pos;

  for (arr_pos = upos; arr_pos < arr_len - ulen; arr_pos++)
  {
    arr[arr_pos] = arr[arr_pos + ulen];
  }

  return (arr_len - ulen);
}

int mangle_insert (char arr[BLOCK_SIZE], int arr_len, int upos, char c)
{
  if (upos > arr_len) return (arr_len);

  if ((arr_len + 1) >= BLOCK_SIZE) return (arr_len);

  int arr_pos;

  for (arr_pos = arr_len - 1; arr_pos > upos - 1; arr_pos--)
  {
    arr[arr_pos + 1] = arr[arr_pos];
  }

  arr[upos] = c;

  return (arr_len + 1);
}

int mangle_insert_multi (char arr[BLOCK_SIZE], int arr_len, int arr_pos, char arr2[BLOCK_SIZE], int arr2_len, int arr2_pos, int arr2_cpy)
{
  if ((arr_len + arr2_cpy) > BLOCK_SIZE) return (RULE_RC_REJECT_ERROR);

  if (arr_pos > arr_len) return (RULE_RC_REJECT_ERROR);

  if (arr2_pos > arr2_len) return (RULE_RC_REJECT_ERROR);

  if ((arr2_pos + arr2_cpy) > arr2_len) return (RULE_RC_REJECT_ERROR);

  if (arr2_cpy < 1) return (RULE_RC_SYNTAX_ERROR);

  memcpy (arr2, arr2 + arr2_pos, arr2_len - arr2_pos);

  memcpy (arr2 + arr2_cpy, arr + arr_pos, arr_len - arr_pos);

  memcpy (arr + arr_pos, arr2, arr_len - arr_pos + arr2_cpy);

  return (arr_len + arr2_cpy);
}

int mangle_overstrike (char arr[BLOCK_SIZE], int arr_len, int upos, char c)
{
  if (upos >= arr_len) return (arr_len);

  arr[upos] = c;

  return (arr_len);
}

int mangle_truncate_at (char arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  memset (arr + upos, 0, arr_len - upos);

  return (upos);
}

int mangle_replace (char arr[BLOCK_SIZE], int arr_len, char oldc, char newc)
{
  int arr_pos;

  for (arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (arr[arr_pos] != oldc) continue;

    arr[arr_pos] = newc;
  }

  return (arr_len);
}

int mangle_purgechar (char arr[BLOCK_SIZE], int arr_len, char c)
{
  int arr_pos;

  int ret_len;

  for (ret_len = 0, arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (arr[arr_pos] == c) continue;

    arr[ret_len] = arr[arr_pos];

    ret_len++;
  }

  return (ret_len);
}

int mangle_dupeblock_prepend (char arr[BLOCK_SIZE], int arr_len, int ulen)
{
  if (ulen > arr_len) return (arr_len);

  if ((arr_len + ulen) >= BLOCK_SIZE) return (arr_len);

  char cs[100];

  memcpy (cs, arr, ulen);

  int i;

  for (i = 0; i < ulen; i++)
  {
    char c = cs[i];

    arr_len = mangle_insert (arr, arr_len, i, c);
  }

  return (arr_len);
}

int mangle_dupeblock_append (char arr[BLOCK_SIZE], int arr_len, int ulen)
{
  if (ulen > arr_len) return (arr_len);

  if ((arr_len + ulen) >= BLOCK_SIZE) return (arr_len);

  int upos = arr_len - ulen;

  int i;

  for (i = 0; i < ulen; i++)
  {
    char c = arr[upos + i];

    arr_len = mangle_append (arr, arr_len, c);
  }

  return (arr_len);
}

int mangle_dupechar_at (char arr[BLOCK_SIZE], int arr_len, int upos, int ulen)
{
  if ( arr_len         ==  0) return (arr_len);
  if ((arr_len + ulen) >= BLOCK_SIZE) return (arr_len);

  char c = arr[upos];

  int i;

  for (i = 0; i < ulen; i++)
  {
    arr_len = mangle_insert (arr, arr_len, upos, c);
  }

  return (arr_len);
}

int mangle_dupechar (char arr[BLOCK_SIZE], int arr_len)
{
  if ( arr_len            ==  0) return (arr_len);
  if ((arr_len + arr_len) >= BLOCK_SIZE) return (arr_len);

  int arr_pos;

  for (arr_pos = arr_len - 1; arr_pos > -1; arr_pos--)
  {
    int new_pos = arr_pos * 2;

    arr[new_pos] = arr[arr_pos];

    arr[new_pos + 1] = arr[arr_pos];
  }

  return (arr_len * 2);
}

int mangle_switch_at_check (char arr[BLOCK_SIZE], int arr_len, int upos, int upos2)
{
  if (upos  >= arr_len) return (arr_len);
  if (upos2 >= arr_len) return (arr_len);

  MANGLE_SWITCH (arr, upos, upos2);

  return (arr_len);
}

int mangle_switch_at (char arr[BLOCK_SIZE], int arr_len, int upos, int upos2)
{
  MANGLE_SWITCH (arr, upos, upos2);

  return (arr_len);
}

int mangle_chr_shiftl (u8 arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  arr[upos] <<= 1;

  return (arr_len);
}

int mangle_chr_shiftr (u8 arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  arr[upos] >>= 1;

  return (arr_len);
}

int mangle_chr_incr (u8 arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  arr[upos] += 1;

  return (arr_len);
}

int mangle_chr_decr (u8 arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  arr[upos] -= 1;

  return (arr_len);
}

int mangle_title (char arr[BLOCK_SIZE], int arr_len)
{
  int upper_next = 1;

  int pos;

  for (pos = 0; pos < arr_len; pos++)
  {
    if (arr[pos] == ' ')
    {
      upper_next = 1;

      continue;
    }

    if (upper_next)
    {
      upper_next = 0;

      MANGLE_UPPER_AT (arr, pos);
    }
    else
    {
      MANGLE_LOWER_AT (arr, pos);
    }
  }

  return (arr_len);
}

int generate_random_rule (char *rule_buf, u32 rp_gen_func_min, u32 rp_gen_func_max)
{
  u32 rp_gen_num = get_random_num (rp_gen_func_min, rp_gen_func_max);

  u32 j;

  u32 rule_pos = 0;

  for (j = 0; j < rp_gen_num; j++)
  {
    u32 r  = 0;
    u32 p1 = 0;
    u32 p2 = 0;
    u32 p3 = 0;

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

      case 8:
        r = get_random_num (0, sizeof (grp_op_pos1_pos2_pos3));
        rule_buf[rule_pos++] = grp_op_pos1_pos2_pos3[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (1, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p3 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p3];
        break;
    }
  }

  return (rule_pos);
}

int apply_rule_cpu (char *rule, int rule_len, char in[BLOCK_SIZE], int in_len, char out[BLOCK_SIZE])
{
  char mem[BLOCK_SIZE];

  if (in == NULL) return (RULE_RC_REJECT_ERROR);

  if (out == NULL) return (RULE_RC_REJECT_ERROR);

  if (in_len < 1) return (RULE_RC_REJECT_ERROR);

  if (rule_len < 1) return (RULE_RC_REJECT_ERROR);

  int out_len = in_len;
  int mem_len = in_len;

  memcpy (out, in, out_len);

  int rule_pos;

  for (rule_pos = 0; rule_pos < rule_len; rule_pos++)
  {
    int upos; int upos2;
    int ulen;

    switch (rule[rule_pos])
    {
      case ' ':
        break;

      case RULE_OP_MANGLE_NOOP:
        break;

      case RULE_OP_MANGLE_LREST:
        out_len = mangle_lrest (out, out_len);
        break;

      case RULE_OP_MANGLE_UREST:
        out_len = mangle_urest (out, out_len);
        break;

      case RULE_OP_MANGLE_LREST_UFIRST:
        out_len = mangle_lrest (out, out_len);
        if (out_len) MANGLE_UPPER_AT (out, 0);
        break;

      case RULE_OP_MANGLE_UREST_LFIRST:
        out_len = mangle_urest (out, out_len);
        if (out_len) MANGLE_LOWER_AT (out, 0);
        break;

      case RULE_OP_MANGLE_TREST:
        out_len = mangle_trest (out, out_len);
        break;

      case RULE_OP_MANGLE_TOGGLE_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if (upos < out_len) MANGLE_TOGGLE_AT (out, upos);
        break;

      case RULE_OP_MANGLE_REVERSE:
        out_len = mangle_reverse (out, out_len);
        break;

      case RULE_OP_MANGLE_DUPEWORD:
        out_len = mangle_double (out, out_len);
        break;

      case RULE_OP_MANGLE_DUPEWORD_TIMES:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_double_times (out, out_len, ulen);
        break;

      case RULE_OP_MANGLE_REFLECT:
        out_len = mangle_reflect (out, out_len);
        break;

      case RULE_OP_MANGLE_ROTATE_LEFT:
        mangle_rotate_left (out, out_len);
        break;

      case RULE_OP_MANGLE_ROTATE_RIGHT:
        mangle_rotate_right (out, out_len);
        break;

      case RULE_OP_MANGLE_APPEND:
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_append (out, out_len, rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_PREPEND:
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_prepend (out, out_len, rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_DELETE_FIRST:
        out_len = mangle_delete_at (out, out_len, 0);
        break;

      case RULE_OP_MANGLE_DELETE_LAST:
        out_len = mangle_delete_at (out, out_len, (out_len) ? out_len - 1 : 0);
        break;

      case RULE_OP_MANGLE_DELETE_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        out_len = mangle_delete_at (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_EXTRACT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_extract (out, out_len, upos, ulen);
        break;

      case RULE_OP_MANGLE_OMIT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_omit (out, out_len, upos, ulen);
        break;

      case RULE_OP_MANGLE_INSERT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_insert (out, out_len, upos, rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_OVERSTRIKE:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_overstrike (out, out_len, upos, rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_TRUNCATE_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        out_len = mangle_truncate_at (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_REPLACE:
        NEXT_RULEPOS (rule_pos);
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_replace (out, out_len, rule[rule_pos - 1], rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_PURGECHAR:
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_purgechar (out, out_len, rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_TOGGLECASE_REC:
        /* todo */
        break;

      case RULE_OP_MANGLE_DUPECHAR_FIRST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_dupechar_at (out, out_len, 0, ulen);
        break;

      case RULE_OP_MANGLE_DUPECHAR_LAST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_dupechar_at (out, out_len, out_len - 1, ulen);
        break;

      case RULE_OP_MANGLE_DUPECHAR_ALL:
        out_len = mangle_dupechar (out, out_len);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_FIRST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_dupeblock_prepend (out, out_len, ulen);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_LAST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_dupeblock_append (out, out_len, ulen);
        break;

      case RULE_OP_MANGLE_SWITCH_FIRST:
        if (out_len >= 2) mangle_switch_at (out, out_len, 0, 1);
        break;

      case RULE_OP_MANGLE_SWITCH_LAST:
        if (out_len >= 2) mangle_switch_at (out, out_len, out_len - 1, out_len - 2);
        break;

      case RULE_OP_MANGLE_SWITCH_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos2);
        out_len = mangle_switch_at_check (out, out_len, upos, upos2);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTL:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        mangle_chr_shiftl ((u8 *) out, out_len, upos);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTR:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        mangle_chr_shiftr ((u8 *) out, out_len, upos);
        break;

      case RULE_OP_MANGLE_CHR_INCR:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        mangle_chr_incr ((u8 *) out, out_len, upos);
        break;

      case RULE_OP_MANGLE_CHR_DECR:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        mangle_chr_decr ((u8 *) out, out_len, upos);
        break;

      case RULE_OP_MANGLE_REPLACE_NP1:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if ((upos >= 0) && ((upos + 1) < out_len)) mangle_overstrike (out, out_len, upos, out[upos + 1]);
        break;

      case RULE_OP_MANGLE_REPLACE_NM1:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if ((upos >= 1) && ((upos + 0) < out_len)) mangle_overstrike (out, out_len, upos, out[upos - 1]);
        break;

      case RULE_OP_MANGLE_TITLE:
        mangle_title (out, out_len);
        break;

      case RULE_OP_MANGLE_EXTRACT_MEMORY:
        if (mem_len < 1) return (RULE_RC_REJECT_ERROR);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos2);
        if ((out_len = mangle_insert_multi (out, out_len, upos2, mem, mem_len, upos, ulen)) < 1) return (out_len);
        break;

      case RULE_OP_MANGLE_APPEND_MEMORY:
        if (mem_len < 1) return (RULE_RC_REJECT_ERROR);
        if ((out_len + mem_len) > BLOCK_SIZE) return (RULE_RC_REJECT_ERROR);
        memcpy (out + out_len, mem, mem_len);
        out_len += mem_len;
        break;

      case RULE_OP_MANGLE_PREPEND_MEMORY:
        if (mem_len < 1) return (RULE_RC_REJECT_ERROR);
        if ((mem_len + out_len) > BLOCK_SIZE) return (RULE_RC_REJECT_ERROR);
        memcpy (mem + mem_len, out, out_len);
        out_len += mem_len;
        memcpy (out, mem, out_len);
        break;

      case RULE_OP_MEMORIZE_WORD:
        memcpy (mem, out, out_len);
        mem_len = out_len;
        break;

      case RULE_OP_REJECT_LESS:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if (out_len > upos) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_GREATER:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if (out_len < upos) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_CONTAIN:
        NEXT_RULEPOS (rule_pos);
        if (strchr (out, rule[rule_pos]) != NULL) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_NOT_CONTAIN:
        NEXT_RULEPOS (rule_pos);
        if (strchr (out, rule[rule_pos]) == NULL) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_EQUAL_FIRST:
        NEXT_RULEPOS (rule_pos);
        if (out[0] != rule[rule_pos]) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_EQUAL_LAST:
        NEXT_RULEPOS (rule_pos);
        if (out[out_len - 1] != rule[rule_pos]) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_EQUAL_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if ((upos + 1) > out_len) return (RULE_RC_REJECT_ERROR);
        NEXT_RULEPOS (rule_pos);
        if (out[upos] != rule[rule_pos]) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_CONTAINS:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if ((upos + 1) > out_len) return (RULE_RC_REJECT_ERROR);
        NEXT_RULEPOS (rule_pos);
        int c; int cnt; for (c = 0, cnt = 0; c < out_len; c++) if (out[c] == rule[rule_pos]) cnt++;
        if (cnt < upos) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_MEMORY:
        if ((out_len == mem_len) && (memcmp (out, mem, out_len) == 0)) return (RULE_RC_REJECT_ERROR);
        break;

      default:
        return (RULE_RC_SYNTAX_ERROR);
        break;
    }

    max_len = (out_len > max_len) ? out_len : max_len;
  }

  memset (out + out_len, 0, BLOCK_SIZE - out_len);

  return (out_len);
}

int cpu_rule_to_kernel_rule (char *rule_buf, uint rule_len, kernel_rule_t *rule)
{
  uint rule_pos;
  uint rule_cnt;

  for (rule_pos = 0, rule_cnt = 0; rule_pos < rule_len && rule_cnt < MAX_GPU_RULES; rule_pos++, rule_cnt++)
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
        return (-1);
        break;

      case RULE_OP_MANGLE_TOGGLECASE_REC:
        return (-1);
        break;

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

      default:
        return (-1);
        break;
    }
  }

  if (rule_pos < rule_len) return (-1);

  return (0);
}

/**
 * rules common
 */

bool class_num (char c)
{
  return ((c >= '0') && (c <= '9'));
}

bool class_lower (char c)
{
  return ((c >= 'a') && (c <= 'z'));
}

bool class_upper (char c)
{
  return ((c >= 'A') && (c <= 'Z'));
}

bool class_alpha (char c)
{
  return (class_lower (c) || class_upper (c));
}

char conv_ctoi (char c)
{
  if (class_num (c))
  {
    return c - '0';
  }
  else if (class_upper (c))
  {
    return c - 'A' + (char) 10;
  }

  return (char) (-1);
}

char conv_itoc (char c)
{
  if (c < 10)
  {
    return c + '0';
  }
  else if (c < 37)
  {
    return c + 'A' - (char) 10;
  }

  return (char) (-1);
}

uint get_random_num (uint min, uint max)
{
  if (min == max) return (min);

  uint data;

  FILE *fp = fopen("/dev/urandom", "rb");

  if (fp == NULL) exit (1);

  if ((fread (&data, 1, sizeof (uint), fp)) != sizeof (uint))
  {
    exit (1);
  }

  fclose (fp);

  return (uint) ((data % (max - min)) + min);
}
