/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "convert.h"
#include "memory.h"
#include "rp.h"
#include "rp_cpu.h"

#define NEXT_RULEPOS(rp)      if (++(rp) == rule_len) return (RULE_RC_SYNTAX_ERROR)
#define NEXT_RPTOI(r,rp,up)   if (((up) = conv_pos ((r)[(rp)], pos_mem)) == -1) return (RULE_RC_SYNTAX_ERROR)

static int conv_pos (const u8 c, const int pos_mem)
{
  if (c == RULE_LAST_REJECTED_SAVED_POS)
  {
    return pos_mem;
  }

  return conv_ctoi (c);
}

static void MANGLE_TOGGLE_AT (char *arr, const int pos)
{
  if (class_alpha (arr[pos])) arr[pos] ^= 0x20;
}

static void MANGLE_LOWER_AT (char *arr, const int pos)
{
  if (class_upper (arr[pos])) arr[pos] ^= 0x20;
}

static void MANGLE_UPPER_AT (char *arr, const int pos)
{
  if (class_lower (arr[pos])) arr[pos] ^= 0x20;
}

static void MANGLE_SWITCH (char *arr, const int l, const int r)
{
  char c = arr[r];
  arr[r] = arr[l];
  arr[l] = c;
}

static int mangle_toggle_at_sep (char arr[RP_PASSWORD_SIZE], int arr_len, char c, int upos)
{
  int toggle_next = 0;
  int occurrence  = 0;

  for (int pos = 0; pos < arr_len; pos++)
  {
    if (arr[pos] == c)
    {
      if (occurrence == upos)
      {
        toggle_next = 1;
      }
      else
      {
        occurrence++;
      }

      continue;
    }

    if (toggle_next == 1)
    {
      MANGLE_TOGGLE_AT (arr, pos);

      break;
    }
  }

  return arr_len;
}

static int mangle_lrest (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  for (int pos = 0; pos < arr_len; pos++) MANGLE_LOWER_AT (arr, pos);

  return arr_len;
}

static int mangle_urest (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  for (int pos = 0; pos < arr_len; pos++) MANGLE_UPPER_AT (arr, pos);

  return arr_len;
}

static int mangle_trest (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  for (int pos = 0; pos < arr_len; pos++) MANGLE_TOGGLE_AT (arr, pos);

  return arr_len;
}

static int mangle_reverse (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  for (int l = 0; l < arr_len; l++)
  {
    int r = arr_len - 1 - l;

    if (l >= r) break;

    MANGLE_SWITCH (arr, l, r);
  }

  return arr_len;
}

static int mangle_double (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  if ((arr_len * 2) >= RP_PASSWORD_SIZE) return arr_len;

  memcpy (&arr[arr_len], arr, (size_t) arr_len);

  return (arr_len * 2);
}

static int mangle_double_times (char arr[RP_PASSWORD_SIZE], int arr_len, int times)
{
  if (((arr_len * times) + arr_len) >= RP_PASSWORD_SIZE) return arr_len;

  int orig_len = arr_len;

  for (int i = 0; i < times; i++)
  {
    memcpy (&arr[arr_len], arr, orig_len);

    arr_len += orig_len;
  }

  return arr_len;
}

static int mangle_reflect (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  if ((arr_len * 2) >= RP_PASSWORD_SIZE) return arr_len;

  mangle_double (arr, arr_len);

  mangle_reverse (arr + arr_len, arr_len);

  return (arr_len * 2);
}

static int mangle_rotate_left (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  for (int l = 0, r = arr_len - 1; r > 0; r--)
  {
    MANGLE_SWITCH (arr, l, r);
  }

  return arr_len;
}

static int mangle_rotate_right (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  for (int l = 0, r = arr_len - 1; l < r; l++)
  {
    MANGLE_SWITCH (arr, l, r);
  }

  return arr_len;
}

static int mangle_append (char arr[RP_PASSWORD_SIZE], int arr_len, char c)
{
  if ((arr_len + 1) >= RP_PASSWORD_SIZE) return arr_len;

  arr[arr_len] = c;

  return (arr_len + 1);
}

static int mangle_prepend (char arr[RP_PASSWORD_SIZE], int arr_len, char c)
{
  if ((arr_len + 1) >= RP_PASSWORD_SIZE) return arr_len;

  for (int arr_pos = arr_len - 1; arr_pos > -1; arr_pos--)
  {
    arr[arr_pos + 1] = arr[arr_pos];
  }

  arr[0] = c;

  return (arr_len + 1);
}

static int mangle_delete_at (char arr[RP_PASSWORD_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return arr_len;

  for (int arr_pos = upos; arr_pos < arr_len - 1; arr_pos++)
  {
    arr[arr_pos] = arr[arr_pos + 1];
  }

  return (arr_len - 1);
}

static int mangle_extract (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int ulen)
{
  if (upos >= arr_len) return arr_len;

  if ((upos + ulen) > arr_len) return arr_len;

  for (int arr_pos = 0; arr_pos < ulen; arr_pos++)
  {
    arr[arr_pos] = arr[upos + arr_pos];
  }

  return ulen;
}

static int mangle_omit (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int ulen)
{
  if (upos >= arr_len) return arr_len;

  if ((upos + ulen) > arr_len) return arr_len;

  for (int arr_pos = upos; arr_pos < arr_len - ulen; arr_pos++)
  {
    arr[arr_pos] = arr[arr_pos + ulen];
  }

  return (arr_len - ulen);
}

static int mangle_insert (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, char c)
{
  if (upos > arr_len) return arr_len;

  if ((arr_len + 1) >= RP_PASSWORD_SIZE) return arr_len;

  for (int arr_pos = arr_len - 1; arr_pos > upos - 1; arr_pos--)
  {
    arr[arr_pos + 1] = arr[arr_pos];
  }

  arr[upos] = c;

  return (arr_len + 1);
}

static int mangle_insert_multi (char arr[RP_PASSWORD_SIZE], int arr_len, int arr_pos, char arr2[RP_PASSWORD_SIZE], int arr2_len, int arr2_pos, int arr2_cpy)
{
  if ((arr_len + arr2_cpy) > RP_PASSWORD_SIZE) return (RULE_RC_REJECT_ERROR);

  if (arr_pos > arr_len) return (RULE_RC_REJECT_ERROR);

  if (arr2_pos > arr2_len) return (RULE_RC_REJECT_ERROR);

  if ((arr2_pos + arr2_cpy) > arr2_len) return (RULE_RC_REJECT_ERROR);

  if (arr2_cpy < 1) return (RULE_RC_SYNTAX_ERROR);

  memmove (arr2, arr2 + arr2_pos, arr2_len - arr2_pos);

  memcpy  (arr2 + arr2_cpy, arr + arr_pos, arr_len - arr_pos);

  memcpy  (arr + arr_pos, arr2, arr_len - arr_pos + arr2_cpy);

  return (arr_len + arr2_cpy);
}

static int mangle_overstrike (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, char c)
{
  if (upos >= arr_len) return arr_len;

  arr[upos] = c;

  return arr_len;
}

static int mangle_truncate_at (char arr[RP_PASSWORD_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return arr_len;

  memset (arr + upos, 0, arr_len - upos);

  return upos;
}

static int mangle_replace (char arr[RP_PASSWORD_SIZE], int arr_len, char oldc, char newc)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (arr[arr_pos] != oldc) continue;

    arr[arr_pos] = newc;
  }

  return arr_len;
}

static int mangle_replace_class_l (char arr[RP_PASSWORD_SIZE], int arr_len, char newc)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (!class_lower (arr[arr_pos])) continue;

    arr[arr_pos] = newc;
  }

  return arr_len;
}

static int mangle_replace_class_u (char arr[RP_PASSWORD_SIZE], int arr_len, char newc)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (!class_upper (arr[arr_pos])) continue;

    arr[arr_pos] = newc;
  }

  return arr_len;
}

static int mangle_replace_class_d (char arr[RP_PASSWORD_SIZE], int arr_len, char newc)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (!class_num (arr[arr_pos])) continue;

    arr[arr_pos] = newc;
  }

  return arr_len;
}

static int mangle_replace_class_lh (char arr[RP_PASSWORD_SIZE], int arr_len, char newc)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (!class_lower_hex (arr[arr_pos])) continue;

    arr[arr_pos] = newc;
  }

  return arr_len;
}

static int mangle_replace_class_uh (char arr[RP_PASSWORD_SIZE], int arr_len, char newc)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (!class_upper_hex (arr[arr_pos])) continue;

    arr[arr_pos] = newc;
  }

  return arr_len;
}

static int mangle_replace_class_s (char arr[RP_PASSWORD_SIZE], int arr_len, char newc)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (!class_sym (arr[arr_pos])) continue;

    arr[arr_pos] = newc;
  }

  return arr_len;
}

static int mangle_replace_class (char arr[RP_PASSWORD_SIZE], int arr_len, char oldc, char newc)
{
       if (oldc == 'l') return mangle_replace_class_l  (arr, arr_len, newc);
  else if (oldc == 'u') return mangle_replace_class_u  (arr, arr_len, newc);
  else if (oldc == 'd') return mangle_replace_class_d  (arr, arr_len, newc);
  else if (oldc == 'h') return mangle_replace_class_lh (arr, arr_len, newc);
  else if (oldc == 'H') return mangle_replace_class_uh (arr, arr_len, newc);
  else if (oldc == 's') return mangle_replace_class_s  (arr, arr_len, newc);

  return arr_len;
}

static int mangle_purgechar (char arr[RP_PASSWORD_SIZE], int arr_len, char c)
{
  int ret_len = 0;

  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (arr[arr_pos] == c) continue;

    arr[ret_len] = arr[arr_pos];

    ret_len++;
  }

  return ret_len;
}

static int mangle_purgechar_class_l (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int ret_len = 0;

  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_lower (arr[arr_pos])) continue;

    arr[ret_len] = arr[arr_pos];

    ret_len++;
  }

  return ret_len;
}

static int mangle_purgechar_class_u (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int ret_len = 0;

  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_upper (arr[arr_pos])) continue;

    arr[ret_len] = arr[arr_pos];

    ret_len++;
  }

  return ret_len;
}

static int mangle_purgechar_class_d (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int ret_len = 0;

  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_num (arr[arr_pos])) continue;

    arr[ret_len] = arr[arr_pos];

    ret_len++;
  }

  return ret_len;
}

static int mangle_purgechar_class_lh (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int ret_len = 0;

  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_lower_hex (arr[arr_pos])) continue;

    arr[ret_len] = arr[arr_pos];

    ret_len++;
  }

  return ret_len;
}

static int mangle_purgechar_class_uh (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int ret_len = 0;

  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_upper_hex (arr[arr_pos])) continue;

    arr[ret_len] = arr[arr_pos];

    ret_len++;
  }

  return ret_len;
}

static int mangle_purgechar_class_s (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int ret_len = 0;

  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_sym (arr[arr_pos])) continue;

    arr[ret_len] = arr[arr_pos];

    ret_len++;
  }

  return ret_len;
}

static int mangle_purgechar_class (char arr[RP_PASSWORD_SIZE], int arr_len, char c)
{
       if (c == 'l') return mangle_purgechar_class_l  (arr, arr_len);
  else if (c == 'u') return mangle_purgechar_class_u  (arr, arr_len);
  else if (c == 'd') return mangle_purgechar_class_d  (arr, arr_len);
  else if (c == 'h') return mangle_purgechar_class_lh (arr, arr_len);
  else if (c == 'H') return mangle_purgechar_class_uh (arr, arr_len);
  else if (c == 's') return mangle_purgechar_class_s  (arr, arr_len);

  return arr_len;
}

static int mangle_dupeblock_prepend (char arr[RP_PASSWORD_SIZE], int arr_len, int ulen)
{
  if (ulen > arr_len) return arr_len;

  if ((arr_len + ulen) >= RP_PASSWORD_SIZE) return arr_len;

  char cs[100];

  memset (cs, 0, sizeof (cs));
  memcpy (cs, arr, ulen);

  for (int i = 0; i < ulen; i++)
  {
    arr_len = mangle_insert (arr, arr_len, i, cs[i]);
  }

  return arr_len;
}

static int mangle_dupeblock_append (char arr[RP_PASSWORD_SIZE], int arr_len, int ulen)
{
  if (ulen > arr_len) return arr_len;

  if ((arr_len + ulen) >= RP_PASSWORD_SIZE) return arr_len;

  int upos = arr_len - ulen;

  for (int i = 0; i < ulen; i++)
  {
    char c = arr[upos + i];

    arr_len = mangle_append (arr, arr_len, c);
  }

  return arr_len;
}

static int mangle_dupechar_at (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int ulen)
{
  if ( arr_len         ==  0) return arr_len;
  if ((arr_len + ulen) >= RP_PASSWORD_SIZE) return arr_len;

  char c = arr[upos];

  for (int i = 0; i < ulen; i++)
  {
    arr_len = mangle_insert (arr, arr_len, upos, c);
  }

  return arr_len;
}

static int mangle_dupechar (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  if ( arr_len            ==  0) return arr_len;
  if ((arr_len + arr_len) >= RP_PASSWORD_SIZE) return arr_len;

  for (int arr_pos = arr_len - 1; arr_pos > -1; arr_pos--)
  {
    int new_pos = arr_pos * 2;

    arr[new_pos] = arr[arr_pos];

    arr[new_pos + 1] = arr[arr_pos];
  }

  return (arr_len * 2);
}

static int mangle_switch_at_check (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int upos2)
{
  if (upos  >= arr_len) return arr_len;
  if (upos2 >= arr_len) return arr_len;

  MANGLE_SWITCH (arr, upos, upos2);

  return arr_len;
}

static int mangle_switch_at (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int upos2)
{
  MANGLE_SWITCH (arr, upos, upos2);

  return arr_len;
}

static int mangle_chr_shiftl (char arr[RP_PASSWORD_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return arr_len;

  arr[upos] <<= 1;

  return arr_len;
}

static int mangle_chr_shiftr (char arr[RP_PASSWORD_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return arr_len;

  arr[upos] >>= 1;

  return arr_len;
}

static int mangle_chr_incr (char arr[RP_PASSWORD_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return arr_len;

  arr[upos] += 1;

  return arr_len;
}

static int mangle_chr_decr (char arr[RP_PASSWORD_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return arr_len;

  arr[upos] -= 1;

  return arr_len;
}

static int mangle_title_sep (char arr[RP_PASSWORD_SIZE], int arr_len, char c)
{
  int upper_next = 1;

  for (int pos = 0; pos < arr_len; pos++)
  {
    if (arr[pos] == c)
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

  MANGLE_UPPER_AT (arr, 0);

  return arr_len;
}

static int mangle_title_sep_class_l (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int upper_next = 1;

  for (int pos = 0; pos < arr_len; pos++)
  {
    if (class_lower (arr[pos]))
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

  MANGLE_UPPER_AT (arr, 0);

  return arr_len;
}

static int mangle_title_sep_class_u (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int upper_next = 1;

  for (int pos = 0; pos < arr_len; pos++)
  {
    if (class_upper (arr[pos]))
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

  MANGLE_UPPER_AT (arr, 0);

  return arr_len;
}

static int mangle_title_sep_class_d (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int upper_next = 1;

  for (int pos = 0; pos < arr_len; pos++)
  {
    if (class_num (arr[pos]))
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

  MANGLE_UPPER_AT (arr, 0);

  return arr_len;
}

static int mangle_title_sep_class_lh (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int upper_next = 1;

  for (int pos = 0; pos < arr_len; pos++)
  {
    if (class_lower_hex (arr[pos]))
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

  MANGLE_UPPER_AT (arr, 0);

  return arr_len;
}

static int mangle_title_sep_class_uh (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int upper_next = 1;

  for (int pos = 0; pos < arr_len; pos++)
  {
    if (class_upper_hex (arr[pos]))
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

  MANGLE_UPPER_AT (arr, 0);

  return arr_len;
}

static int mangle_title_sep_class_s (char arr[RP_PASSWORD_SIZE], int arr_len)
{
  int upper_next = 1;

  for (int pos = 0; pos < arr_len; pos++)
  {
    if (class_sym (arr[pos]))
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

  MANGLE_UPPER_AT (arr, 0);

  return arr_len;
}

static int mangle_title_sep_class (char arr[RP_PASSWORD_SIZE], int arr_len, char c)
{
       if (c == 'l') return mangle_title_sep_class_l  (arr, arr_len);
  else if (c == 'u') return mangle_title_sep_class_u  (arr, arr_len);
  else if (c == 'd') return mangle_title_sep_class_d  (arr, arr_len);
  else if (c == 'h') return mangle_title_sep_class_lh (arr, arr_len);
  else if (c == 'H') return mangle_title_sep_class_uh (arr, arr_len);
  else if (c == 's') return mangle_title_sep_class_s  (arr, arr_len);

  return arr_len;
}

static bool reject_contain_class_l (char arr[RP_PASSWORD_SIZE], int arr_len, int *pos_mem)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_lower (arr[arr_pos]))
    {
      *pos_mem = arr_pos;
      return true;
    }
  }

  return false;
}

static bool reject_contain_class_u (char arr[RP_PASSWORD_SIZE], int arr_len, int *pos_mem)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_upper (arr[arr_pos]))
    {
      *pos_mem = arr_pos;
      return true;
    }
  }

  return false;
}

static bool reject_contain_class_d (char arr[RP_PASSWORD_SIZE], int arr_len, int *pos_mem)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_num (arr[arr_pos]))
    {
      *pos_mem = arr_pos;
      return true;
    }
  }

  return false;
}

static bool reject_contain_class_lh (char arr[RP_PASSWORD_SIZE], int arr_len, int *pos_mem)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_lower_hex (arr[arr_pos]))
    {
      *pos_mem = arr_pos;
      return true;
    }
  }

  return false;
}

static bool reject_contain_class_uh (char arr[RP_PASSWORD_SIZE], int arr_len, int *pos_mem)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_upper_hex (arr[arr_pos]))
    {
      *pos_mem = arr_pos;
      return true;
    }
  }

  return false;
}

static bool reject_contain_class_s (char arr[RP_PASSWORD_SIZE], int arr_len, int *pos_mem)
{
  for (int arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (class_sym (arr[arr_pos]))
    {
      *pos_mem = arr_pos;
      return true;
    }
  }

  return false;
}

static bool reject_contain_class (char arr[RP_PASSWORD_SIZE], int arr_len, char c, int *pos_mem)
{
       if (c == 'l') return reject_contain_class_l  (arr, arr_len, pos_mem);
  else if (c == 'u') return reject_contain_class_u  (arr, arr_len, pos_mem);
  else if (c == 'd') return reject_contain_class_d  (arr, arr_len, pos_mem);
  else if (c == 'h') return reject_contain_class_lh (arr, arr_len, pos_mem);
  else if (c == 'H') return reject_contain_class_uh (arr, arr_len, pos_mem);
  else if (c == 's') return reject_contain_class_s  (arr, arr_len, pos_mem);

  return false;
}

static bool reject_contain (char arr[RP_PASSWORD_SIZE], char c, int *pos_mem)
{
  const char *match = strchr (arr, c);
  if (match == NULL) return false;

  *pos_mem = (int)(match - arr);

  return true;
}

static bool reject_contains_class_l (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int *pos_mem)
{
  int cnt = 0;

  for (int arr_pos = 0; arr_pos < arr_len && cnt < upos; arr_pos++)
  {
    if (class_lower (arr[arr_pos]))
    {
      cnt++;
      *pos_mem = arr_pos;
    }
  }

  return (cnt < upos);
}

static bool reject_contains_class_u (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int *pos_mem)
{
  int cnt = 0;

  for (int arr_pos = 0; arr_pos < arr_len && cnt < upos; arr_pos++)
  {
    if (class_upper (arr[arr_pos]))
    {
      cnt++;
      *pos_mem = arr_pos;
    }
  }

  return (cnt < upos);
}

static bool reject_contains_class_d (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int *pos_mem)
{
  int cnt = 0;

  for (int arr_pos = 0; arr_pos < arr_len && cnt < upos; arr_pos++)
  {
    if (class_num (arr[arr_pos]))
    {
      cnt++;
      *pos_mem = arr_pos;
    }
  }

  return (cnt < upos);
}

static bool reject_contains_class_lh (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int *pos_mem)
{
  int cnt = 0;

  for (int arr_pos = 0; arr_pos < arr_len && cnt < upos; arr_pos++)
  {
    if (class_lower_hex (arr[arr_pos]))
    {
      cnt++;
      *pos_mem = arr_pos;
    }
  }

  return (cnt < upos);
}

static bool reject_contains_class_uh (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int *pos_mem)
{
  int cnt = 0;

  for (int arr_pos = 0; arr_pos < arr_len && cnt < upos; arr_pos++)
  {
    if (class_upper_hex (arr[arr_pos]))
    {
      cnt++;
      *pos_mem = arr_pos;
    }
  }

  return (cnt < upos);
}

static bool reject_contains_class_s (char arr[RP_PASSWORD_SIZE], int arr_len, int upos, int *pos_mem)
{
  int cnt = 0;

  for (int arr_pos = 0; arr_pos < arr_len && cnt < upos; arr_pos++)
  {
    if (class_sym (arr[arr_pos]))
    {
      cnt++;
      *pos_mem = arr_pos;
    }
  }

  return (cnt < upos);
}

static bool reject_contains_class (char arr[RP_PASSWORD_SIZE], int arr_len, char c, int upos, int *pos_mem)
{
       if (c == 'l') return reject_contains_class_l  (arr, arr_len, upos, pos_mem);
  else if (c == 'u') return reject_contains_class_u  (arr, arr_len, upos, pos_mem);
  else if (c == 'd') return reject_contains_class_d  (arr, arr_len, upos, pos_mem);
  else if (c == 'h') return reject_contains_class_lh (arr, arr_len, upos, pos_mem);
  else if (c == 'H') return reject_contains_class_uh (arr, arr_len, upos, pos_mem);
  else if (c == 's') return reject_contains_class_s  (arr, arr_len, upos, pos_mem);

  return false;
}

static bool reject_contains (const char arr[RP_PASSWORD_SIZE], int arr_len, char c, int upos, int *pos_mem)
{
  int cnt = 0;

  for (int arr_pos = 0; arr_pos < arr_len && cnt < upos; arr_pos++)
  {
    if (arr[arr_pos] == c)
    {
      cnt++;
      *pos_mem = arr_pos;
    }
  }

  return (cnt < upos);
}

int _old_apply_rule (const char *rule, int rule_len, char in[RP_PASSWORD_SIZE], int in_len, char out[RP_PASSWORD_SIZE])
{
  char mem[RP_PASSWORD_SIZE];

  int pos_mem = -1;

  if (in == NULL) return (RULE_RC_REJECT_ERROR);

  if (out == NULL) return (RULE_RC_REJECT_ERROR);

  if (in_len < 0 || in_len > RP_PASSWORD_SIZE) return (RULE_RC_REJECT_ERROR);

  if (rule_len < 1) return (RULE_RC_REJECT_ERROR);

  int out_len = in_len;
  int mem_len = in_len;

  memset (mem, 0, sizeof (mem));

  memcpy (out, in, out_len);

  char *rule_new = (char *) hcmalloc (rule_len);

  #define HCFREE_AND_RETURN(x) { hcfree (rule_new); return (x); }

  int rule_len_new = 0;

  int rule_pos;

  for (rule_pos = 0; rule_pos < rule_len; rule_pos++)
  {
    if (is_hex_notation (rule, rule_len, rule_pos))
    {
      const u8 c = hex_to_u8 ((const u8 *) &rule[rule_pos + 2]);

      rule_pos += 3;

      rule_new[rule_len_new] = c;

      rule_len_new++;
    }
    else
    {
      rule_new[rule_len_new] = rule[rule_pos];

      rule_len_new++;
    }
  }

  for (rule_pos = 0; rule_pos < rule_len_new; rule_pos++)
  {
    int upos, upos2;
    int ulen;

    switch (rule_new[rule_pos])
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
        NEXT_RPTOI (rule_new, rule_pos, upos);
        if (upos < out_len) MANGLE_TOGGLE_AT (out, upos);
        break;

      case RULE_OP_MANGLE_TOGGLE_AT_SEP:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_toggle_at_sep (out, out_len, rule_new[rule_pos], upos);
        break;

      case RULE_OP_MANGLE_REVERSE:
        out_len = mangle_reverse (out, out_len);
        break;

      case RULE_OP_MANGLE_DUPEWORD:
        out_len = mangle_double (out, out_len);
        break;

      case RULE_OP_MANGLE_DUPEWORD_TIMES:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, ulen);
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
        out_len = mangle_append (out, out_len, rule_new[rule_pos]);
        break;

      case RULE_OP_MANGLE_PREPEND:
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_prepend (out, out_len, rule_new[rule_pos]);
        break;

      case RULE_OP_MANGLE_DELETE_FIRST:
        out_len = mangle_delete_at (out, out_len, 0);
        break;

      case RULE_OP_MANGLE_DELETE_LAST:
        out_len = mangle_delete_at (out, out_len, (out_len) ? out_len - 1 : 0);
        break;

      case RULE_OP_MANGLE_DELETE_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        out_len = mangle_delete_at (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_EXTRACT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, ulen);
        out_len = mangle_extract (out, out_len, upos, ulen);
        break;

      case RULE_OP_MANGLE_OMIT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, ulen);
        out_len = mangle_omit (out, out_len, upos, ulen);
        break;

      case RULE_OP_MANGLE_INSERT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_insert (out, out_len, upos, rule_new[rule_pos]);
        break;

      case RULE_OP_MANGLE_OVERSTRIKE:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_overstrike (out, out_len, upos, rule_new[rule_pos]);
        break;

      case RULE_OP_MANGLE_TRUNCATE_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        out_len = mangle_truncate_at (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_REPLACE:
        NEXT_RULEPOS (rule_pos);
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_replace (out, out_len, rule_new[rule_pos - 1], rule_new[rule_pos]);
        break;

      case RULE_OP_MANGLE_PURGECHAR:
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_purgechar (out, out_len, rule_new[rule_pos]);
        break;

      case RULE_OP_MANGLE_TOGGLECASE_REC:
        /* todo */
        break;

      case RULE_OP_MANGLE_DUPECHAR_FIRST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, ulen);
        out_len = mangle_dupechar_at (out, out_len, 0, ulen);
        break;

      case RULE_OP_MANGLE_DUPECHAR_LAST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, ulen);
        out_len = mangle_dupechar_at (out, out_len, out_len - 1, ulen);
        break;

      case RULE_OP_MANGLE_DUPECHAR_ALL:
        out_len = mangle_dupechar (out, out_len);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_FIRST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, ulen);
        out_len = mangle_dupeblock_prepend (out, out_len, ulen);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_LAST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, ulen);
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
        NEXT_RPTOI (rule_new, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos2);
        out_len = mangle_switch_at_check (out, out_len, upos, upos2);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTL:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        mangle_chr_shiftl (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTR:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        mangle_chr_shiftr (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_CHR_INCR:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        mangle_chr_incr (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_CHR_DECR:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        mangle_chr_decr (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_REPLACE_NP1:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        if ((upos >= 0) && ((upos + 1) < out_len)) mangle_overstrike (out, out_len, upos, out[upos + 1]);
        break;

      case RULE_OP_MANGLE_REPLACE_NM1:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        if ((upos >= 1) && ((upos + 0) < out_len)) mangle_overstrike (out, out_len, upos, out[upos - 1]);
        break;

      case RULE_OP_MANGLE_TITLE_SEP:
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_title_sep (out, out_len, rule_new[rule_pos]);
        break;

      case RULE_OP_MANGLE_TITLE:
        out_len = mangle_title_sep (out, out_len, ' ');
        break;

      case RULE_OP_MANGLE_EXTRACT_MEMORY:
        if (mem_len < 1) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, ulen);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos2);
        if ((out_len = mangle_insert_multi (out, out_len, upos2, mem, mem_len, upos, ulen)) < 1) HCFREE_AND_RETURN (out_len);
        break;

      case RULE_OP_MANGLE_APPEND_MEMORY:
        if (mem_len < 1) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        if ((out_len + mem_len) >= RP_PASSWORD_SIZE) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        memcpy (out + out_len, mem, mem_len);
        out_len += mem_len;
        break;

      case RULE_OP_MANGLE_PREPEND_MEMORY:
        if (mem_len < 1) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        if ((mem_len + out_len) >= RP_PASSWORD_SIZE) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
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
        NEXT_RPTOI (rule_new, rule_pos, upos);
        if (out_len > upos) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_GREATER:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        if (out_len < upos) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_EQUAL:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        if (out_len != upos) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_CONTAIN:
        NEXT_RULEPOS (rule_pos);
        if (reject_contain (out, rule_new[rule_pos], &pos_mem)) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_NOT_CONTAIN:
        NEXT_RULEPOS (rule_pos);
        if (!reject_contain (out, rule_new[rule_pos], &pos_mem)) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_EQUAL_FIRST:
        NEXT_RULEPOS (rule_pos);
        if (out[0] != rule_new[rule_pos]) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_EQUAL_LAST:
        NEXT_RULEPOS (rule_pos);
        if (out[out_len - 1] != rule_new[rule_pos]) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_EQUAL_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        if ((upos + 1) > out_len) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        NEXT_RULEPOS (rule_pos);
        if (out[upos] != rule_new[rule_pos]) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_CONTAINS:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule_new, rule_pos, upos);
        if ((upos + 1) > out_len) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        NEXT_RULEPOS (rule_pos);
        if (reject_contains (out, out_len, rule_new[rule_pos], upos, &pos_mem)) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_MEMORY:
        if ((out_len == mem_len) && (memcmp (out, mem, out_len) == 0)) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_CLASS_BASED:
        NEXT_RULEPOS (rule_pos);
        switch (rule_new[rule_pos])
        {
          case RULE_OP_MANGLE_REPLACE: // ~s?CY
            NEXT_RULEPOS (rule_pos);
            if (rule_new[rule_pos] != '?') HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);

            NEXT_RULEPOS (rule_pos);
            switch (rule_new[rule_pos])
            {
              case '?':
                NEXT_RULEPOS (rule_pos);
                out_len = mangle_replace (out, out_len, rule_new[rule_pos - 1], rule_new[rule_pos]);
                break;

              case 'l':
              case 'u':
              case 'd':
              case 'h':
              case 'H':
              case 's':
                NEXT_RULEPOS (rule_pos);
                out_len = mangle_replace_class (out, out_len, rule_new[rule_pos - 1], rule_new[rule_pos]);
                break;

              default :
                HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
            }

            break;

          case RULE_OP_MANGLE_PURGECHAR: // ~@?C
            NEXT_RULEPOS (rule_pos);
            if (rule_new[rule_pos] != '?') HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);

            NEXT_RULEPOS (rule_pos);
            switch (rule_new[rule_pos])
            {
              case '?':
                out_len = mangle_purgechar (out, out_len, rule_new[rule_pos]);
                break;

              case 'l':
              case 'u':
              case 'd':
              case 'h':
              case 'H':
              case 's':
                out_len = mangle_purgechar_class (out, out_len, rule_new[rule_pos]);
                break;

              default :
                HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
            }

            break;

          case RULE_OP_MANGLE_TITLE_SEP: // ~e?C
            NEXT_RULEPOS (rule_pos);
            if (rule_new[rule_pos] != '?') HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);

            NEXT_RULEPOS (rule_pos);
            switch (rule_new[rule_pos])
            {
              case '?':
                out_len = mangle_title_sep (out, out_len, rule_new[rule_pos]);
                break;

              case 'l':
              case 'u':
              case 'd':
              case 'h':
              case 'H':
              case 's':
                out_len = mangle_title_sep_class (out, out_len, rule_new[rule_pos]);
                break;

              default :
                HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
            }

            break;

          case RULE_OP_REJECT_CONTAIN: // ~!?C
            NEXT_RULEPOS (rule_pos);
            if (rule_new[rule_pos] != '?') HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);

            NEXT_RULEPOS (rule_pos);
            switch (rule_new[rule_pos])
            {
              case '?':
                if (reject_contain (out, rule_new[rule_pos], &pos_mem)) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'l':
              case 'u':
              case 'd':
              case 'h':
              case 'H':
              case 's':
                if (reject_contain_class (out, out_len, rule_new[rule_pos], &pos_mem)) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              default :
                HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
            }

            break;

          case RULE_OP_REJECT_NOT_CONTAIN: // ~/?C
            NEXT_RULEPOS (rule_pos);
            if (rule_new[rule_pos] != '?') HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);

            NEXT_RULEPOS (rule_pos);
            switch (rule_new[rule_pos])
            {
              case '?':
                if (!reject_contain (out, rule_new[rule_pos], &pos_mem)) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'l':
              case 'u':
              case 'd':
              case 'h':
              case 'H':
              case 's':
                if (!reject_contain_class (out, out_len, rule_new[rule_pos], &pos_mem)) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              default :
                HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
            }

            break;

          case RULE_OP_REJECT_EQUAL_FIRST: // ~(?C
            NEXT_RULEPOS (rule_pos);
            if (rule_new[rule_pos] != '?') HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);

            NEXT_RULEPOS (rule_pos);
            switch (rule_new[rule_pos])
            {
              case '?':
                if (out[0] != rule_new[rule_pos]) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'l':
                if (!class_lower (out[0])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'u':
                if (!class_upper (out[0])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'd':
                if (!class_num (out[0])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'h':
                if (!class_lower_hex (out[0])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'H':
                if (!class_upper_hex (out[0])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 's':
                if (!class_sym (out[0])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              default :
                HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
            }

            break;
          case RULE_OP_REJECT_EQUAL_LAST: // ~)?C
            NEXT_RULEPOS (rule_pos);
            if (rule_new[rule_pos] != '?') HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);

            NEXT_RULEPOS (rule_pos);
            switch (rule_new[rule_pos])
            {
              case '?':
                if (out[out_len - 1] != rule_new[rule_pos]) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'l':
                if (!class_lower (out[out_len - 1])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'u':
                if (!class_upper (out[out_len - 1])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'd':
                if (!class_num (out[out_len - 1])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'h':
                if (!class_lower_hex (out[out_len - 1])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'H':
                if (!class_upper_hex (out[out_len - 1])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 's':
                if (!class_sym (out[out_len - 1])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              default :
                HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
            }

            break;

          case RULE_OP_REJECT_EQUAL_AT: // ~=N?C
            NEXT_RULEPOS (rule_pos);
            NEXT_RPTOI (rule_new, rule_pos, upos);
            if ((upos + 1) > out_len) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);

            NEXT_RULEPOS (rule_pos);
            if (rule_new[rule_pos] != '?') HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);

            NEXT_RULEPOS (rule_pos);
            switch (rule_new[rule_pos])
            {
              case '?':
                if (out[upos] != rule_new[rule_pos]) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'l':
                if (!class_lower (out[upos])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'u':
                if (!class_upper (out[upos])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'd':
                if (!class_num (out[upos])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'h':
                if (!class_lower_hex (out[upos])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'H':
                if (!class_upper_hex (out[upos])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 's':
                if (!class_sym (out[upos])) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              default :
                HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
            }

            break;
          case RULE_OP_REJECT_CONTAINS: // ~%N?C
            NEXT_RULEPOS (rule_pos);
            NEXT_RPTOI (rule_new, rule_pos, upos);
            if ((upos + 1) > out_len) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);

            NEXT_RULEPOS (rule_pos);
            if (rule_new[rule_pos] != '?') HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);

            NEXT_RULEPOS (rule_pos);
            switch (rule_new[rule_pos])
            {
              case '?':
                if (reject_contains (out, out_len, rule_new[rule_pos], upos, &pos_mem)) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              case 'l':
              case 'u':
              case 'd':
              case 'h':
              case 'H':
              case 's':
                if (reject_contains_class (out, out_len, rule_new[rule_pos], upos, &pos_mem)) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
                break;

              default :
                HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
            }

            break;

          default:
            HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
        }

        break;

      default:
        HCFREE_AND_RETURN (RULE_RC_SYNTAX_ERROR);
    }
  }

  memset (out + out_len, 0, RP_PASSWORD_SIZE - out_len);

  HCFREE_AND_RETURN (out_len);

  #undef HCFREE_AND_RETURN
}

int run_rule_engine (const int rule_len, const char *rule_buf)
{
  if (rule_len == 0) return 0;

  if (rule_len == 1)
  {
    if (rule_buf[0] == RULE_OP_MANGLE_NOOP) return 0;
  }

  return 1;
}
