/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#ifdef __APPLE__
#include <stdio.h>
#endif

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "timer.h"
#include "memory.h"
#include "logging.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "convert.h"
#include "locking.h"
#include "thread.h"
#include "rp_cpu.h"
#include "terminal.h"
#include "hwmon.h"
#include "mpsp.h"
#include "rp_cpu.h"
#include "opencl.h"
#include "data.h"
#include "shared.h"

extern hc_global_data_t data;

void *rulefind (const void *key, void *base, int nmemb, size_t size, int (*compar) (const void *, const void *))
{
  char *element, *end;

  end = (char *) base + nmemb * size;

  for (element = (char *) base; element < end; element += size)
    if (!compar (element, key))
      return element;

  return NULL;
}

int sort_by_u32 (const void *v1, const void *v2)
{
  const u32 *s1 = (const u32 *) v1;
  const u32 *s2 = (const u32 *) v2;

  return *s1 - *s2;
}

int sort_by_salt (const void *v1, const void *v2)
{
  const salt_t *s1 = (const salt_t *) v1;
  const salt_t *s2 = (const salt_t *) v2;

  const int res1 = s1->salt_len - s2->salt_len;

  if (res1 != 0) return (res1);

  const int res2 = s1->salt_iter - s2->salt_iter;

  if (res2 != 0) return (res2);

  uint n;

  n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  n = 8;

  while (n--)
  {
    if (s1->salt_buf_pc[n] > s2->salt_buf_pc[n]) return ( 1);
    if (s1->salt_buf_pc[n] < s2->salt_buf_pc[n]) return -1;
  }

  return 0;
}

int sort_by_salt_buf (const void *v1, const void *v2)
{
  const pot_t *p1 = (const pot_t *) v1;
  const pot_t *p2 = (const pot_t *) v2;

  const hash_t *h1 = &p1->hash;
  const hash_t *h2 = &p2->hash;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  uint n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  return 0;
}

int sort_by_hash_t_salt (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  // testphase: this should work
  uint n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  /* original code, seems buggy since salt_len can be very big (had a case with 131 len)
     also it thinks salt_buf[x] is a char but its a uint so salt_len should be / 4
  if (s1->salt_len > s2->salt_len) return ( 1);
  if (s1->salt_len < s2->salt_len) return -1;

  uint n = s1->salt_len;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }
  */

  return 0;
}

int sort_by_hash_t_salt_hccap (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  // last 2: salt_buf[10] and salt_buf[11] contain the digest (skip them)

  uint n = 9; // 9 * 4 = 36 bytes (max length of ESSID)

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  return 0;
}

int sort_by_hash_no_salt (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return data.sort_by_digest (d1, d2);
}

int sort_by_hash (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  if (data.isSalted)
  {
    const salt_t *s1 = h1->salt;
    const salt_t *s2 = h2->salt;

    int res = sort_by_salt (s1, s2);

    if (res != 0) return (res);
  }

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return data.sort_by_digest (d1, d2);
}

int sort_by_pot (const void *v1, const void *v2)
{
  const pot_t *p1 = (const pot_t *) v1;
  const pot_t *p2 = (const pot_t *) v2;

  const hash_t *h1 = &p1->hash;
  const hash_t *h2 = &p2->hash;

  return sort_by_hash (h1, h2);
}

int sort_by_mtime (const void *p1, const void *p2)
{
  const char **f1 = (const char **) p1;
  const char **f2 = (const char **) p2;

  struct stat s1; stat (*f1, &s1);
  struct stat s2; stat (*f2, &s2);

  return s2.st_mtime - s1.st_mtime;
}

int sort_by_cpu_rule (const void *p1, const void *p2)
{
  const cpu_rule_t *r1 = (const cpu_rule_t *) p1;
  const cpu_rule_t *r2 = (const cpu_rule_t *) p2;

  return memcmp (r1, r2, sizeof (cpu_rule_t));
}

int sort_by_kernel_rule (const void *p1, const void *p2)
{
  const kernel_rule_t *r1 = (const kernel_rule_t *) p1;
  const kernel_rule_t *r2 = (const kernel_rule_t *) p2;

  return memcmp (r1, r2, sizeof (kernel_rule_t));
}

int sort_by_stringptr (const void *p1, const void *p2)
{
  const char **s1 = (const char **) p1;
  const char **s2 = (const char **) p2;

  return strcmp (*s1, *s2);
}

int sort_by_dictstat (const void *s1, const void *s2)
{
  dictstat_t *d1 = (dictstat_t *) s1;
  dictstat_t *d2 = (dictstat_t *) s2;

  #ifdef __linux__
  d2->stat.st_atim = d1->stat.st_atim;
  #else
  d2->stat.st_atime = d1->stat.st_atime;
  #endif

  return memcmp (&d1->stat, &d2->stat, sizeof (struct stat));
}

int sort_by_bitmap (const void *p1, const void *p2)
{
  const bitmap_result_t *b1 = (const bitmap_result_t *) p1;
  const bitmap_result_t *b2 = (const bitmap_result_t *) p2;

  return b1->collisions - b2->collisions;
}

int sort_by_digest_4_2 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 2;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_4 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 4;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_5 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 5;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_6 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 6;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_8 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 8;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_16 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 16;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_32 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 32;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_64 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 64;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_8_8 (const void *v1, const void *v2)
{
  const u64 *d1 = (const u64 *) v1;
  const u64 *d2 = (const u64 *) v2;

  uint n = 8;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_8_16 (const void *v1, const void *v2)
{
  const u64 *d1 = (const u64 *) v1;
  const u64 *d2 = (const u64 *) v2;

  uint n = 16;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_8_25 (const void *v1, const void *v2)
{
  const u64 *d1 = (const u64 *) v1;
  const u64 *d2 = (const u64 *) v2;

  uint n = 25;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_p0p1 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  const uint dgst_pos0 = data.dgst_pos0;
  const uint dgst_pos1 = data.dgst_pos1;
  const uint dgst_pos2 = data.dgst_pos2;
  const uint dgst_pos3 = data.dgst_pos3;

  if (d1[dgst_pos3] > d2[dgst_pos3]) return ( 1);
  if (d1[dgst_pos3] < d2[dgst_pos3]) return -1;
  if (d1[dgst_pos2] > d2[dgst_pos2]) return ( 1);
  if (d1[dgst_pos2] < d2[dgst_pos2]) return -1;
  if (d1[dgst_pos1] > d2[dgst_pos1]) return ( 1);
  if (d1[dgst_pos1] < d2[dgst_pos1]) return -1;
  if (d1[dgst_pos0] > d2[dgst_pos0]) return ( 1);
  if (d1[dgst_pos0] < d2[dgst_pos0]) return -1;

  return 0;
}

void format_debug (char *debug_file, uint debug_mode, unsigned char *orig_plain_ptr, uint orig_plain_len, unsigned char *mod_plain_ptr, uint mod_plain_len, char *rule_buf, int rule_len)
{
  uint outfile_autohex = data.outfile_autohex;

  unsigned char *rule_ptr = (unsigned char *) rule_buf;

  FILE *debug_fp = NULL;

  if (debug_file != NULL)
  {
    debug_fp = fopen (debug_file, "ab");

    lock_file (debug_fp);
  }
  else
  {
    debug_fp = stderr;
  }

  if (debug_fp == NULL)
  {
    log_info ("WARNING: Could not open debug-file for writing");
  }
  else
  {
    if ((debug_mode == 2) || (debug_mode == 3) || (debug_mode == 4))
    {
      format_plain (debug_fp, orig_plain_ptr, orig_plain_len, outfile_autohex);

      if ((debug_mode == 3) || (debug_mode == 4)) fputc (':', debug_fp);
    }

    fwrite (rule_ptr, rule_len, 1, debug_fp);

    if (debug_mode == 4)
    {
      fputc (':', debug_fp);

      format_plain (debug_fp, mod_plain_ptr, mod_plain_len, outfile_autohex);
    }

    fputc  ('\n', debug_fp);

    if (debug_file != NULL) fclose (debug_fp);
  }
}

void format_plain (FILE *fp, unsigned char *plain_ptr, uint plain_len, uint outfile_autohex)
{
  int needs_hexify = 0;

  if (outfile_autohex == 1)
  {
    for (uint i = 0; i < plain_len; i++)
    {
      if (plain_ptr[i] < 0x20)
      {
        needs_hexify = 1;

        break;
      }

      if (plain_ptr[i] > 0x7f)
      {
        needs_hexify = 1;

        break;
      }
    }
  }

  if (needs_hexify == 1)
  {
    fprintf (fp, "$HEX[");

    for (uint i = 0; i < plain_len; i++)
    {
      fprintf (fp, "%02x", plain_ptr[i]);
    }

    fprintf (fp, "]");
  }
  else
  {
    fwrite (plain_ptr, plain_len, 1, fp);
  }
}

void format_output (FILE *out_fp, char *out_buf, unsigned char *plain_ptr, const uint plain_len, const u64 crackpos, unsigned char *username, const uint user_len)
{
  uint outfile_format = data.outfile_format;

  char separator = data.separator;

  if (outfile_format & OUTFILE_FMT_HASH)
  {
    fprintf (out_fp, "%s", out_buf);

    if (outfile_format & (OUTFILE_FMT_PLAIN | OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
    {
      fputc (separator, out_fp);
    }
  }
  else if (data.username)
  {
    if (username != NULL)
    {
      for (uint i = 0; i < user_len; i++)
      {
        fprintf (out_fp, "%c", username[i]);
      }

      if (outfile_format & (OUTFILE_FMT_PLAIN | OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
      {
        fputc (separator, out_fp);
      }
    }
  }

  if (outfile_format & OUTFILE_FMT_PLAIN)
  {
    format_plain (out_fp, plain_ptr, plain_len, data.outfile_autohex);

    if (outfile_format & (OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
    {
      fputc (separator, out_fp);
    }
  }

  if (outfile_format & OUTFILE_FMT_HEXPLAIN)
  {
    for (uint i = 0; i < plain_len; i++)
    {
      fprintf (out_fp, "%02x", plain_ptr[i]);
    }

    if (outfile_format & (OUTFILE_FMT_CRACKPOS))
    {
      fputc (separator, out_fp);
    }
  }

  if (outfile_format & OUTFILE_FMT_CRACKPOS)
  {
    #ifdef _WIN
    __mingw_fprintf (out_fp, "%llu", crackpos);
    #endif

    #ifdef _POSIX
    #ifdef __x86_64__
    fprintf (out_fp, "%lu", (unsigned long) crackpos);
    #else
    fprintf (out_fp, "%llu", crackpos);
    #endif
    #endif
  }

  fputs (EOL, out_fp);
}

void handle_show_request (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *), FILE *out_fp)
{
  pot_t pot_key;

  pot_key.hash.salt   = hashes_buf->salt;
  pot_key.hash.digest = hashes_buf->digest;

  pot_t *pot_ptr = (pot_t *) bsearch (&pot_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  if (pot_ptr)
  {
    log_info_nn ("");

    input_buf[input_len] = 0;

    // user
    unsigned char *username = NULL;
    uint user_len = 0;

    if (data.username)
    {
      user_t *user = hashes_buf->hash_info->user;

      if (user)
      {
        username = (unsigned char *) (user->user_name);

        user_len = user->user_len;
      }
    }

    // do output the line
    format_output (out_fp, input_buf, (unsigned char *) pot_ptr->plain_buf, pot_ptr->plain_len, 0, username, user_len);
  }
}

#define LM_WEAK_HASH    "\x4e\xcf\x0d\x0c\x0a\xe2\xfb\xc1"
#define LM_MASKED_PLAIN "[notfound]"

void handle_show_request_lm (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *), FILE *out_fp)
{
  // left

  pot_t pot_left_key;

  pot_left_key.hash.salt   = hash_left->salt;
  pot_left_key.hash.digest = hash_left->digest;

  pot_t *pot_left_ptr = (pot_t *) bsearch (&pot_left_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  // right

  uint weak_hash_found = 0;

  pot_t pot_right_key;

  pot_right_key.hash.salt   = hash_right->salt;
  pot_right_key.hash.digest = hash_right->digest;

  pot_t *pot_right_ptr = (pot_t *) bsearch (&pot_right_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  if (pot_right_ptr == NULL)
  {
    // special case, if "weak hash"

    if (memcmp (hash_right->digest, LM_WEAK_HASH, 8) == 0)
    {
      weak_hash_found = 1;

      pot_right_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));

      // in theory this is not needed, but we are paranoia:

      memset (pot_right_ptr->plain_buf, 0, sizeof (pot_right_ptr->plain_buf));
      pot_right_ptr->plain_len = 0;
    }
  }

  if ((pot_left_ptr == NULL) && (pot_right_ptr == NULL))
  {
    if (weak_hash_found == 1) myfree (pot_right_ptr); // this shouldn't happen at all: if weak_hash_found == 1, than pot_right_ptr is not NULL for sure

    return;
  }

  // at least one half was found:

  log_info_nn ("");

  input_buf[input_len] = 0;

  // user

  unsigned char *username = NULL;
  uint user_len = 0;

  if (data.username)
  {
    user_t *user = hash_left->hash_info->user;

    if (user)
    {
      username = (unsigned char *) (user->user_name);

      user_len = user->user_len;
    }
  }

  // mask the part which was not found

  uint left_part_masked  = 0;
  uint right_part_masked = 0;

  uint mask_plain_len = strlen (LM_MASKED_PLAIN);

  if (pot_left_ptr == NULL)
  {
    left_part_masked = 1;

    pot_left_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));

    memset (pot_left_ptr->plain_buf, 0, sizeof (pot_left_ptr->plain_buf));

    memcpy (pot_left_ptr->plain_buf, LM_MASKED_PLAIN, mask_plain_len);
    pot_left_ptr->plain_len = mask_plain_len;
  }

  if (pot_right_ptr == NULL)
  {
    right_part_masked = 1;

    pot_right_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));

    memset (pot_right_ptr->plain_buf, 0, sizeof (pot_right_ptr->plain_buf));

    memcpy (pot_right_ptr->plain_buf, LM_MASKED_PLAIN, mask_plain_len);
    pot_right_ptr->plain_len = mask_plain_len;
  }

  // create the pot_ptr out of pot_left_ptr and pot_right_ptr

  pot_t pot_ptr;

  pot_ptr.plain_len = pot_left_ptr->plain_len + pot_right_ptr->plain_len;

  memcpy (pot_ptr.plain_buf, pot_left_ptr->plain_buf, pot_left_ptr->plain_len);

  memcpy (pot_ptr.plain_buf + pot_left_ptr->plain_len, pot_right_ptr->plain_buf, pot_right_ptr->plain_len);

  // do output the line

  format_output (out_fp, input_buf, (unsigned char *) pot_ptr.plain_buf, pot_ptr.plain_len, 0, username, user_len);

  if (weak_hash_found == 1) myfree (pot_right_ptr);

  if (left_part_masked  == 1) myfree (pot_left_ptr);
  if (right_part_masked == 1) myfree (pot_right_ptr);
}

void handle_left_request (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *), FILE *out_fp)
{
  pot_t pot_key;

  memcpy (&pot_key.hash, hashes_buf, sizeof (hash_t));

  pot_t *pot_ptr = (pot_t *) bsearch (&pot_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  if (pot_ptr == NULL)
  {
    log_info_nn ("");

    input_buf[input_len] = 0;

    format_output (out_fp, input_buf, NULL, 0, 0, NULL, 0);
  }
}

void handle_left_request_lm (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *), FILE *out_fp)
{
  // left

  pot_t pot_left_key;

  memcpy (&pot_left_key.hash, hash_left, sizeof (hash_t));

  pot_t *pot_left_ptr = (pot_t *) bsearch (&pot_left_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  // right

  pot_t pot_right_key;

  memcpy (&pot_right_key.hash, hash_right, sizeof (hash_t));

  pot_t *pot_right_ptr = (pot_t *) bsearch (&pot_right_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  uint weak_hash_found = 0;

  if (pot_right_ptr == NULL)
  {
    // special case, if "weak hash"

    if (memcmp (hash_right->digest, LM_WEAK_HASH, 8) == 0)
    {
      weak_hash_found = 1;

      // we just need that pot_right_ptr is not a NULL pointer

      pot_right_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));
    }
  }

  if ((pot_left_ptr != NULL) && (pot_right_ptr != NULL))
  {
    if (weak_hash_found == 1) myfree (pot_right_ptr);

    return;
  }

  // ... at least one part was not cracked

  log_info_nn ("");

  input_buf[input_len] = 0;

  // only show the hash part which is still not cracked

  uint user_len = (uint)input_len - 32u;

  char *hash_output = (char *) mymalloc (33);

  memcpy (hash_output, input_buf, input_len);

  if (pot_left_ptr != NULL)
  {
    // only show right part (because left part was already found)

    memcpy (hash_output + user_len, input_buf + user_len + 16, 16);

    hash_output[user_len + 16] = 0;
  }

  if (pot_right_ptr != NULL)
  {
    // only show left part (because right part was already found)

    memcpy (hash_output + user_len, input_buf + user_len, 16);

    hash_output[user_len + 16] = 0;
  }

  format_output (out_fp, hash_output, NULL, 0, 0, NULL, 0);

  myfree (hash_output);

  if (weak_hash_found == 1) myfree (pot_right_ptr);
}


u32 get_random_num (const u32 min, const u32 max)
{
  if (min == max) return (min);

  return ((rand () % (max - min)) + min);
}

u32 mydivc32 (const u32 dividend, const u32 divisor)
{
  u32 quotient = dividend / divisor;

  if (dividend % divisor) quotient++;

  return quotient;
}

u64 mydivc64 (const u64 dividend, const u64 divisor)
{
  u64 quotient = dividend / divisor;

  if (dividend % divisor) quotient++;

  return quotient;
}

void format_timer_display (struct tm *tm, char *buf, size_t len)
{
  const char *time_entities_s[] = { "year",  "day",  "hour",  "min",  "sec"  };
  const char *time_entities_m[] = { "years", "days", "hours", "mins", "secs" };

  if (tm->tm_year - 70)
  {
    char *time_entity1 = ((tm->tm_year - 70) == 1) ? (char *) time_entities_s[0] : (char *) time_entities_m[0];
    char *time_entity2 = ( tm->tm_yday       == 1) ? (char *) time_entities_s[1] : (char *) time_entities_m[1];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_year - 70, time_entity1, tm->tm_yday, time_entity2);
  }
  else if (tm->tm_yday)
  {
    char *time_entity1 = (tm->tm_yday == 1) ? (char *) time_entities_s[1] : (char *) time_entities_m[1];
    char *time_entity2 = (tm->tm_hour == 1) ? (char *) time_entities_s[2] : (char *) time_entities_m[2];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_yday, time_entity1, tm->tm_hour, time_entity2);
  }
  else if (tm->tm_hour)
  {
    char *time_entity1 = (tm->tm_hour == 1) ? (char *) time_entities_s[2] : (char *) time_entities_m[2];
    char *time_entity2 = (tm->tm_min  == 1) ? (char *) time_entities_s[3] : (char *) time_entities_m[3];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_hour, time_entity1, tm->tm_min, time_entity2);
  }
  else if (tm->tm_min)
  {
    char *time_entity1 = (tm->tm_min == 1) ? (char *) time_entities_s[3] : (char *) time_entities_m[3];
    char *time_entity2 = (tm->tm_sec == 1) ? (char *) time_entities_s[4] : (char *) time_entities_m[4];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_min, time_entity1, tm->tm_sec, time_entity2);
  }
  else
  {
    char *time_entity1 = (tm->tm_sec == 1) ? (char *) time_entities_s[4] : (char *) time_entities_m[4];

    snprintf (buf, len - 1, "%d %s", tm->tm_sec, time_entity1);
  }
}

void format_speed_display (double val, char *buf, size_t len)
{
  if (val <= 0)
  {
    buf[0] = '0';
    buf[1] = ' ';
    buf[2] = 0;

    return;
  }

  char units[7] = { ' ', 'k', 'M', 'G', 'T', 'P', 'E' };

  uint level = 0;

  while (val > 99999)
  {
    val /= 1000;

    level++;
  }

  /* generate output */

  if (level == 0)
  {
    snprintf (buf, len - 1, "%.0f ", val);
  }
  else
  {
    snprintf (buf, len - 1, "%.1f %c", val, units[level]);
  }
}





static void SuspendThreads ()
{
  if (data.devices_status != STATUS_RUNNING) return;

  hc_timer_set (&data.timer_paused);

  data.devices_status = STATUS_PAUSED;

  log_info ("Paused");
}

static void ResumeThreads ()
{
  if (data.devices_status != STATUS_PAUSED) return;

  double ms_paused;

  hc_timer_get (data.timer_paused, ms_paused);

  data.ms_paused += ms_paused;

  data.devices_status = STATUS_RUNNING;

  log_info ("Resumed");
}

static void bypass ()
{
  data.devices_status = STATUS_BYPASS;

  log_info ("Next dictionary / mask in queue selected, bypassing current one");
}

static void stop_at_checkpoint ()
{
  if (data.devices_status != STATUS_STOP_AT_CHECKPOINT)
  {
    if (data.devices_status != STATUS_RUNNING) return;
  }

  // this feature only makes sense if --restore-disable was not specified

  if (data.restore_disable == 1)
  {
    log_info ("WARNING: This feature is disabled when --restore-disable is specified");

    return;
  }

  // check if monitoring of Restore Point updates should be enabled or disabled

  if (data.devices_status != STATUS_STOP_AT_CHECKPOINT)
  {
    data.devices_status = STATUS_STOP_AT_CHECKPOINT;

    // save the current restore point value

    data.checkpoint_cur_words = get_lowest_words_done ();

    log_info ("Checkpoint enabled: Will quit at next Restore Point update");
  }
  else
  {
    data.devices_status = STATUS_RUNNING;

    // reset the global value for checkpoint checks

    data.checkpoint_cur_words = 0;

    log_info ("Checkpoint disabled: Restore Point updates will no longer be monitored");
  }
}

void myabort ()
{
  data.devices_status = STATUS_ABORTED;
}

void myquit ()
{
  data.devices_status = STATUS_QUIT;
}

void naive_replace (char *s, const u8 key_char, const u8 replace_char)
{
  const size_t len = strlen (s);

  for (size_t in = 0; in < len; in++)
  {
    const u8 c = s[in];

    if (c == key_char)
    {
      s[in] = replace_char;
    }
  }
}

void naive_escape (char *s, size_t s_max, const u8 key_char, const u8 escape_char)
{
  char s_escaped[1024] = { 0 };

  size_t s_escaped_max = sizeof (s_escaped);

  const size_t len = strlen (s);

  for (size_t in = 0, out = 0; in < len; in++, out++)
  {
    const u8 c = s[in];

    if (c == key_char)
    {
      s_escaped[out] = escape_char;

      out++;
    }

    if (out == s_escaped_max - 2) break;

    s_escaped[out] = c;
  }

  strncpy (s, s_escaped, s_max - 1);
}


/**
 * restore
 */

restore_data_t *init_restore (int argc, char **argv)
{
  restore_data_t *rd = (restore_data_t *) mymalloc (sizeof (restore_data_t));

  if (data.restore_disable == 0)
  {
    FILE *fp = fopen (data.eff_restore_file, "rb");

    if (fp)
    {
      size_t nread = fread (rd, sizeof (restore_data_t), 1, fp);

      if (nread != 1)
      {
        log_error ("ERROR: Cannot read %s", data.eff_restore_file);

        exit (-1);
      }

      fclose (fp);

      if (rd->pid)
      {
        char *pidbin = (char *) mymalloc (HCBUFSIZ);

        int pidbin_len = -1;

        #ifdef _POSIX
        snprintf (pidbin, HCBUFSIZ - 1, "/proc/%d/cmdline", rd->pid);

        FILE *fd = fopen (pidbin, "rb");

        if (fd)
        {
          pidbin_len = fread (pidbin, 1, HCBUFSIZ, fd);

          pidbin[pidbin_len] = 0;

          fclose (fd);

          char *argv0_r = strrchr (argv[0], '/');

          char *pidbin_r = strrchr (pidbin, '/');

          if (argv0_r == NULL) argv0_r = argv[0];

          if (pidbin_r == NULL) pidbin_r = pidbin;

          if (strcmp (argv0_r, pidbin_r) == 0)
          {
            log_error ("ERROR: Already an instance %s running on pid %d", pidbin, rd->pid);

            exit (-1);
          }
        }

        #elif _WIN
        HANDLE hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, rd->pid);

        char *pidbin2 = (char *) mymalloc (HCBUFSIZ);

        int pidbin2_len = -1;

        pidbin_len = GetModuleFileName (NULL, pidbin, HCBUFSIZ);
        pidbin2_len = GetModuleFileNameEx (hProcess, NULL, pidbin2, HCBUFSIZ);

        pidbin[pidbin_len] = 0;
        pidbin2[pidbin2_len] = 0;

        if (pidbin2_len)
        {
          if (strcmp (pidbin, pidbin2) == 0)
          {
            log_error ("ERROR: Already an instance %s running on pid %d", pidbin2, rd->pid);

            exit (-1);
          }
        }

        myfree (pidbin2);

        #endif

        myfree (pidbin);
      }

      if (rd->version_bin < RESTORE_MIN)
      {
        log_error ("ERROR: Cannot use outdated %s. Please remove it.", data.eff_restore_file);

        exit (-1);
      }
    }
  }

  memset (rd, 0, sizeof (restore_data_t));

  rd->version_bin = VERSION_BIN;

  #ifdef _POSIX
  rd->pid = getpid ();
  #elif _WIN
  rd->pid = GetCurrentProcessId ();
  #endif

  if (getcwd (rd->cwd, 255) == NULL)
  {
    myfree (rd);

    return (NULL);
  }

  rd->argc = argc;
  rd->argv = argv;

  return (rd);
}

void read_restore (const char *eff_restore_file, restore_data_t *rd)
{
  FILE *fp = fopen (eff_restore_file, "rb");

  if (fp == NULL)
  {
    log_error ("ERROR: Restore file '%s': %s", eff_restore_file, strerror (errno));

    exit (-1);
  }

  if (fread (rd, sizeof (restore_data_t), 1, fp) != 1)
  {
    log_error ("ERROR: Can't read %s", eff_restore_file);

    exit (-1);
  }

  rd->argv = (char **) mycalloc (rd->argc, sizeof (char *));

  char *buf = (char *) mymalloc (HCBUFSIZ);

  for (uint i = 0; i < rd->argc; i++)
  {
    if (fgets (buf, HCBUFSIZ - 1, fp) == NULL)
    {
      log_error ("ERROR: Can't read %s", eff_restore_file);

      exit (-1);
    }

    size_t len = strlen (buf);

    if (len) buf[len - 1] = 0;

    rd->argv[i] = mystrdup (buf);
  }

  myfree (buf);

  fclose (fp);

  log_info ("INFO: Changing current working directory to the path found within the .restore file: '%s'", rd->cwd);

  if (chdir (rd->cwd))
  {
    log_error ("ERROR: The directory '%s' does not exist. It is needed to restore (--restore) the session.\n"
               "       You could either create this directory (or link it) or update the .restore file using e.g. the analyze_hc_restore.pl tool:\n"
               "       https://github.com/philsmd/analyze_hc_restore\n"
               "       The directory must be relative to (or contain) all files/folders mentioned within the command line.", rd->cwd);

    exit (-1);
  }
}

u64 get_lowest_words_done ()
{
  u64 words_cur = -1llu;

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    const u64 words_done = device_param->words_done;

    if (words_done < words_cur) words_cur = words_done;
  }

  // It's possible that a device's workload isn't finished right after a restore-case.
  // In that case, this function would return 0 and overwrite the real restore point
  // There's also data.words_cur which is set to rd->words_cur but it changes while
  // the attack is running therefore we should stick to rd->words_cur.
  // Note that -s influences rd->words_cur we should keep a close look on that.

  if (words_cur < data.rd->words_cur) words_cur = data.rd->words_cur;

  return words_cur;
}

#ifdef _WIN
static void fsync (int fd)
{
  HANDLE h = (HANDLE) _get_osfhandle (fd);

  FlushFileBuffers (h);
}
#endif

void write_restore (const char *new_restore_file, restore_data_t *rd)
{
  u64 words_cur = get_lowest_words_done ();

  rd->words_cur = words_cur;

  FILE *fp = fopen (new_restore_file, "wb");

  if (fp == NULL)
  {
    log_error ("ERROR: %s: %s", new_restore_file, strerror (errno));

    exit (-1);
  }

  if (setvbuf (fp, NULL, _IONBF, 0))
  {
    log_error ("ERROR: setvbuf file '%s': %s", new_restore_file, strerror (errno));

    exit (-1);
  }

  fwrite (rd, sizeof (restore_data_t), 1, fp);

  for (uint i = 0; i < rd->argc; i++)
  {
    fprintf (fp, "%s", rd->argv[i]);
    fputc ('\n', fp);
  }

  fflush (fp);

  fsync (fileno (fp));

  fclose (fp);
}

void cycle_restore ()
{
  const char *eff_restore_file = data.eff_restore_file;
  const char *new_restore_file = data.new_restore_file;

  restore_data_t *rd = data.rd;

  write_restore (new_restore_file, rd);

  struct stat st;

  memset (&st, 0, sizeof(st));

  if (stat (eff_restore_file, &st) == 0)
  {
    if (unlink (eff_restore_file))
    {
      log_info ("WARN: Unlink file '%s': %s", eff_restore_file, strerror (errno));
    }
  }

  if (rename (new_restore_file, eff_restore_file))
  {
    log_info ("WARN: Rename file '%s' to '%s': %s", new_restore_file, eff_restore_file, strerror (errno));
  }
}

void check_checkpoint ()
{
  // if (data.restore_disable == 1) break;  (this is already implied by previous checks)

  u64 words_cur = get_lowest_words_done ();

  if (words_cur != data.checkpoint_cur_words)
  {
    myabort ();
  }
}


/**
 * parallel running threads
 */

#ifdef WIN

BOOL WINAPI sigHandler_default (DWORD sig)
{
  switch (sig)
  {
    case CTRL_CLOSE_EVENT:

      /*
       * special case see: https://stackoverflow.com/questions/3640633/c-setconsolectrlhandler-routine-issue/5610042#5610042
       * if the user interacts w/ the user-interface (GUI/cmd), we need to do the finalization job within this signal handler
       * function otherwise it is too late (e.g. after returning from this function)
       */

      myabort ();

      SetConsoleCtrlHandler (NULL, TRUE);

      hc_sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myabort ();

      SetConsoleCtrlHandler (NULL, TRUE);

      return TRUE;
  }

  return FALSE;
}

BOOL WINAPI sigHandler_benchmark (DWORD sig)
{
  switch (sig)
  {
    case CTRL_CLOSE_EVENT:

      myquit ();

      SetConsoleCtrlHandler (NULL, TRUE);

      hc_sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myquit ();

      SetConsoleCtrlHandler (NULL, TRUE);

      return TRUE;
  }

  return FALSE;
}

void hc_signal (BOOL WINAPI (callback) (DWORD))
{
  if (callback == NULL)
  {
    SetConsoleCtrlHandler ((PHANDLER_ROUTINE) callback, FALSE);
  }
  else
  {
    SetConsoleCtrlHandler ((PHANDLER_ROUTINE) callback, TRUE);
  }
}

#else

void sigHandler_default (int sig)
{
  myabort ();

  signal (sig, NULL);
}

void sigHandler_benchmark (int sig)
{
  myquit ();

  signal (sig, NULL);
}

void hc_signal (void (callback) (int))
{
  if (callback == NULL) callback = SIG_DFL;

  signal (SIGINT,  callback);
  signal (SIGTERM, callback);
  signal (SIGABRT, callback);
}

#endif

void status_display ();

void *thread_keypress (void *p)
{
  uint quiet = data.quiet;

  tty_break();

  while (data.shutdown_outer == 0)
  {
    int ch = tty_getchar();

    if (ch == -1) break;

    if (ch ==  0) continue;

    //https://github.com/hashcat/hashcat/issues/302
    //#ifdef _POSIX
    //if (ch != '\n')
    //#endif

    hc_thread_mutex_lock (mux_display);

    log_info ("");

    switch (ch)
    {
      case 's':
      case '\r':
      case '\n':

        log_info ("");

        status_display ();

        log_info ("");

        if (quiet == 0) fprintf (stdout, "%s", PROMPT);
        if (quiet == 0) fflush (stdout);

        break;

      case 'b':

        log_info ("");

        bypass ();

        log_info ("");

        if (quiet == 0) fprintf (stdout, "%s", PROMPT);
        if (quiet == 0) fflush (stdout);

        break;

      case 'p':

        log_info ("");

        SuspendThreads ();

        log_info ("");

        if (quiet == 0) fprintf (stdout, "%s", PROMPT);
        if (quiet == 0) fflush (stdout);

        break;

      case 'r':

        log_info ("");

        ResumeThreads ();

        log_info ("");

        if (quiet == 0) fprintf (stdout, "%s", PROMPT);
        if (quiet == 0) fflush (stdout);

        break;

      case 'c':

        log_info ("");

        stop_at_checkpoint ();

        log_info ("");

        if (quiet == 0) fprintf (stdout, "%s", PROMPT);
        if (quiet == 0) fflush (stdout);

        break;

      case 'q':

        log_info ("");

        myabort ();

        break;
    }

    //https://github.com/hashcat/hashcat/issues/302
    //#ifdef _POSIX
    //if (ch != '\n')
    //#endif

    hc_thread_mutex_unlock (mux_display);
  }

  tty_fix();

  return (p);
}
