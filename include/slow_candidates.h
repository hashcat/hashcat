/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _SLOW_CANDIDATES_H
#define _SLOW_CANDIDATES_H

typedef struct extra_info_straight
{
  u64 pos;

  FILE *fp;

  u64 rule_pos_prev;
  u64 rule_pos;

  u8  base_buf[256];
  u32 base_len;

  u8  out_buf[256];
  u32 out_len;

} extra_info_straight_t;

typedef struct extra_info_combi
{
  u64 pos;

  FILE *base_fp;
  FILE *combs_fp;

  u64 comb_pos_prev;
  u64 comb_pos;

  char *scratch_buf;

  u8  base_buf[256];
  u32 base_len;

  u8  out_buf[256];
  u32 out_len;

} extra_info_combi_t;

typedef struct extra_info_mask
{
  u64 pos;

  u8  out_buf[256];
  u32 out_len;

} extra_info_mask_t;

void slow_candidates_seek (hashcat_ctx_t *hashcat_ctx, void *extra_info, const u64 cur, const u64 end);
void slow_candidates_next (hashcat_ctx_t *hashcat_ctx, void *extra_info);

#endif // _SLOW_CANDIDATES_H
