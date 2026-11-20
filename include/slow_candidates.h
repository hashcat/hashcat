/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_SLOW_CANDIDATES_H
#define HC_SLOW_CANDIDATES_H

// A --slow-candidates reader carries its transform per device, because the iconv descriptor inside it
// holds conversion state and two device threads must not share one.

typedef struct extra_info_combi
{
  // A candidate position, base words times the amplifier, so it can pass 2^64 where the base does
  // not. The pos of the two structs below is the same kind of position.

  u128 pos;

  // Both sources are feed instances and a feed keeps one cursor per device, so this carries the
  // device rather than a pair of file handles.

  int device_id;

  u64 comb_pos_prev;
  u64 comb_pos;

  // Two flags because the two sides are rejected on different schedules. base_reject is set once per
  // base word and holds for every candidate that word makes. reject is this one candidate, and it is
  // set when either side was rejected.

  bool base_reject;
  bool reject;

  // Two transforms, because the two sides of a -a 1 candidate take different rules: -j belongs to the
  // base word and -k to the amplifier. Everything else in them is the same.

  pw_transform_t transform_base;
  pw_transform_t transform_amp;

  char *scratch_buf;

  u8  base_buf[256];
  u32 base_len;

  u8  out_buf[256];
  u32 out_len;

} extra_info_combi_t;

typedef struct extra_info_mask
{
  u128 pos;

  u8  out_buf[256];
  u32 out_len;

} extra_info_mask_t;

// The generic feed under --slow-candidates, which is also what --brain-client turns on. It is the
// straight reader with the wordlist replaced by the feed, so the amplifier runs on the host and the
// brain gets to see every final candidate.
//
// The feed is per device, so this carries the device id rather than a file handle. The reject flag is
// on all three readers for the same reason: a -j rule that throws a base word away must not make the
// source skip an offset, because the offset is what --skip, --restore and the brain all count in.

typedef struct extra_info_generic
{
  u128 pos;

  int device_id;

  u64 rule_pos_prev;
  u64 rule_pos;

  bool reject;

  pw_transform_t transform;

  u8  base_buf[256];
  u32 base_len;

  u8  out_buf[256];
  u32 out_len;

} extra_info_generic_t;

void slow_candidates_seek (hashcat_ctx_t *hashcat_ctx, void *extra_info, const u128 cur, const u128 end);
void slow_candidates_next (hashcat_ctx_t *hashcat_ctx, void *extra_info);

#endif // HC_SLOW_CANDIDATES_H
