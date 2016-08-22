#pragma once
#include <types.h>
#include <hc_global_data_t.h>
#include <hc_global.h>

int sort_by_u32(const void *v1, const void *v2)
{
  const u32 *s1 = (const u32 *)v1;
  const u32 *s2 = (const u32 *)v2;

  return *s1 - *s2;
}

int sort_by_salt(const void *v1, const void *v2)
{
  const salt_t *s1 = (const salt_t *)v1;
  const salt_t *s2 = (const salt_t *)v2;

  const int res1 = s1->salt_len - s2->salt_len;

  if (res1 != 0) return (res1);

  const int res2 = s1->salt_iter - s2->salt_iter;

  if (res2 != 0) return (res2);

  uint n;

  n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return (1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  n = 8;

  while (n--)
  {
    if (s1->salt_buf_pc[n] > s2->salt_buf_pc[n]) return (1);
    if (s1->salt_buf_pc[n] < s2->salt_buf_pc[n]) return -1;
  }

  return 0;
}

int sort_by_salt_buf(const void *v1, const void *v2)
{
  const pot_t *p1 = (const pot_t *)v1;
  const pot_t *p2 = (const pot_t *)v2;

  const hash_t *h1 = &p1->hash;
  const hash_t *h2 = &p2->hash;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  uint n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return (1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  return 0;
}

int sort_by_hash_t_salt(const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *)v1;
  const hash_t *h2 = (const hash_t *)v2;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  // testphase: this should work
  uint n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return (1);
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

int sort_by_hash_t_salt_hccap(const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *)v1;
  const hash_t *h2 = (const hash_t *)v2;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  // last 2: salt_buf[10] and salt_buf[11] contain the digest (skip them)

  uint n = 9; // 9 * 4 = 36 bytes (max length of ESSID)

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return (1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  return 0;
}

int sort_by_hash_no_salt(const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *)v1;
  const hash_t *h2 = (const hash_t *)v2;

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return data.sort_by_digest(d1, d2);
}

int sort_by_hash(const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *)v1;
  const hash_t *h2 = (const hash_t *)v2;

  if (data.isSalted)
  {
    const salt_t *s1 = h1->salt;
    const salt_t *s2 = h2->salt;

    int res = sort_by_salt(s1, s2);

    if (res != 0) return (res);
  }

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return data.sort_by_digest(d1, d2);
}

int sort_by_pot(const void *v1, const void *v2)
{
  const pot_t *p1 = (const pot_t *)v1;
  const pot_t *p2 = (const pot_t *)v2;

  const hash_t *h1 = &p1->hash;
  const hash_t *h2 = &p2->hash;

  return sort_by_hash(h1, h2);
}

int sort_by_mtime(const void *p1, const void *p2)
{
  const char **f1 = (const char **)p1;
  const char **f2 = (const char **)p2;

  struct stat s1; stat(*f1, &s1);
  struct stat s2; stat(*f2, &s2);

  return s2.st_mtime - s1.st_mtime;
}

int sort_by_cpu_rule(const void *p1, const void *p2)
{
  const cpu_rule_t *r1 = (const cpu_rule_t *)p1;
  const cpu_rule_t *r2 = (const cpu_rule_t *)p2;

  return memcmp(r1, r2, sizeof(cpu_rule_t));
}

int sort_by_kernel_rule(const void *p1, const void *p2)
{
  const kernel_rule_t *r1 = (const kernel_rule_t *)p1;
  const kernel_rule_t *r2 = (const kernel_rule_t *)p2;

  return memcmp(r1, r2, sizeof(kernel_rule_t));
}

int sort_by_stringptr(const void *p1, const void *p2)
{
  const char **s1 = (const char **)p1;
  const char **s2 = (const char **)p2;

  return strcmp(*s1, *s2);
}

int sort_by_dictstat(const void *s1, const void *s2)
{
  dictstat_t *d1 = (dictstat_t *)s1;
  dictstat_t *d2 = (dictstat_t *)s2;

#ifdef __linux__
  d2->stat.st_atim = d1->stat.st_atim;
#else
  d2->stat.st_atime = d1->stat.st_atime;
#endif

  return memcmp(&d1->stat, &d2->stat, sizeof(struct stat));
}

int sort_by_bitmap(const void *p1, const void *p2)
{
  const bitmap_result_t *b1 = (const bitmap_result_t *)p1;
  const bitmap_result_t *b2 = (const bitmap_result_t *)p2;

  return b1->collisions - b2->collisions;
}

int sort_by_digest_4_2(const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *)v1;
  const u32 *d2 = (const u32 *)v2;

  uint n = 2;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_4(const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *)v1;
  const u32 *d2 = (const u32 *)v2;

  uint n = 4;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_5(const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *)v1;
  const u32 *d2 = (const u32 *)v2;

  uint n = 5;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_6(const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *)v1;
  const u32 *d2 = (const u32 *)v2;

  uint n = 6;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_8(const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *)v1;
  const u32 *d2 = (const u32 *)v2;

  uint n = 8;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_16(const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *)v1;
  const u32 *d2 = (const u32 *)v2;

  uint n = 16;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_32(const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *)v1;
  const u32 *d2 = (const u32 *)v2;

  uint n = 32;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_4_64(const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *)v1;
  const u32 *d2 = (const u32 *)v2;

  uint n = 64;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_8_8(const void *v1, const void *v2)
{
  const u64 *d1 = (const u64 *)v1;
  const u64 *d2 = (const u64 *)v2;

  uint n = 8;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_8_16(const void *v1, const void *v2)
{
  const u64 *d1 = (const u64 *)v1;
  const u64 *d2 = (const u64 *)v2;

  uint n = 16;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_8_25(const void *v1, const void *v2)
{
  const u64 *d1 = (const u64 *)v1;
  const u64 *d2 = (const u64 *)v2;

  uint n = 25;

  while (n--)
  {
    if (d1[n] > d2[n]) return (1);
    if (d1[n] < d2[n]) return -1;
  }

  return 0;
}

int sort_by_digest_p0p1(const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *)v1;
  const u32 *d2 = (const u32 *)v2;

  const uint dgst_pos0 = data.dgst_pos0;
  const uint dgst_pos1 = data.dgst_pos1;
  const uint dgst_pos2 = data.dgst_pos2;
  const uint dgst_pos3 = data.dgst_pos3;

  if (d1[dgst_pos3] > d2[dgst_pos3]) return (1);
  if (d1[dgst_pos3] < d2[dgst_pos3]) return -1;
  if (d1[dgst_pos2] > d2[dgst_pos2]) return (1);
  if (d1[dgst_pos2] < d2[dgst_pos2]) return -1;
  if (d1[dgst_pos1] > d2[dgst_pos1]) return (1);
  if (d1[dgst_pos1] < d2[dgst_pos1]) return -1;
  if (d1[dgst_pos0] > d2[dgst_pos0]) return (1);
  if (d1[dgst_pos0] < d2[dgst_pos0]) return -1;

  return 0;
}

int sort_by_tuning_db_alias(const void *v1, const void *v2)
{
  const tuning_db_alias_t *t1 = (const tuning_db_alias_t *)v1;
  const tuning_db_alias_t *t2 = (const tuning_db_alias_t *)v2;

  const int res1 = strcmp(t1->device_name, t2->device_name);

  if (res1 != 0) return (res1);

  return 0;
}

int sort_by_tuning_db_entry(const void *v1, const void *v2)
{
  const tuning_db_entry_t *t1 = (const tuning_db_entry_t *)v1;
  const tuning_db_entry_t *t2 = (const tuning_db_entry_t *)v2;

  const int res1 = strcmp(t1->device_name, t2->device_name);

  if (res1 != 0) return (res1);

  const int res2 = t1->attack_mode
    - t2->attack_mode;

  if (res2 != 0) return (res2);

  const int res3 = t1->hash_type
    - t2->hash_type;

  if (res3 != 0) return (res3);

  return 0;
}
