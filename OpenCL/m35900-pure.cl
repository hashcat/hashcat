/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define HASHIDS_ALPHA_MAX  128
#define HASHIDS_SEPS_MAX   64
#define HASHIDS_VALUES_MAX 8
#define HASHIDS_OUT_MAX    128

#define HASHIDS_GUARDS_MAX 16
#define HASHIDS_SALT_MAX   256
#define HASHIDS_BUF_MAX    (HASHIDS_OUT_MAX + HASHIDS_ALPHA_MAX + 32)

typedef struct hashids
{
  u64 values[HASHIDS_VALUES_MAX];
  u32 values_cnt;
  u32 values_hash;

  u32 alpha[HASHIDS_ALPHA_MAX / 4];
  u32 alpha_len;

  u32 seps[HASHIDS_SEPS_MAX / 4];
  u32 seps_len;

  u32 extra[HASHIDS_SEPS_MAX / 4];
  u32 extra_len;

  u32 guards_cnt;
  u32 min_length;

  u32 target[HASHIDS_OUT_MAX / 4];
  u32 target_len;

  u32 alpha_in[HASHIDS_ALPHA_MAX / 4];
  u32 alpha_in_len;
  u32 alpha_given;

} hashids_t;

typedef struct hashids_tmp
{
  u32 unused;

} hashids_tmp_t;

// The consistent shuffle of Hashids: a pass from the back of s, swapping each position with one the
// salt picks. An empty salt leaves s as it is.

DECLSPEC void hashids_reorder (PRIVATE_AS u8 *s, const u32 s_len, PRIVATE_AS const u8 *salt, const u32 salt_len)
{
  if (salt_len == 0) return;
  if (s_len < 2) return;

  u32 index = 0;
  u32 total = 0;

  for (u32 i = s_len - 1; i > 0; i--)
  {
    const u32 c = salt[index];

    total += c;

    const u32 j = (c + index + total) % i;

    const u8 t = s[i];

    s[i] = s[j];
    s[j] = t;

    index++;

    if (index == salt_len) index = 0;
  }
}

KERNEL_FQ KERNEL_FA void m35900_init (KERN_ATTR_TMPS_ESALT (hashids_tmp_t, hashids_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].unused = 0;
}

KERNEL_FQ KERNEL_FA void m35900_loop (KERN_ATTR_TMPS_ESALT (hashids_tmp_t, hashids_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;
}

KERNEL_FQ KERNEL_FA void m35900_comp (KERN_ATTR_TMPS_ESALT (hashids_tmp_t, hashids_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 digest_pos = LOOP_POS;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  GLOBAL_AS const hashids_t *hashids = &esalt_bufs[digest_cur];

  GLOBAL_AS const u8 *esalt_alpha  = (GLOBAL_AS const u8 *) hashids->alpha;
  GLOBAL_AS const u8 *esalt_seps   = (GLOBAL_AS const u8 *) hashids->seps;
  GLOBAL_AS const u8 *esalt_extra  = (GLOBAL_AS const u8 *) hashids->extra;
  GLOBAL_AS const u8 *esalt_target = (GLOBAL_AS const u8 *) hashids->target;

  // the password is the Hashids salt

  const u32 salt_len = (pws[gid].pw_len < HASHIDS_SALT_MAX) ? pws[gid].pw_len : HASHIDS_SALT_MAX;

  GLOBAL_AS const u8 *pw = (GLOBAL_AS const u8 *) pws[gid].i;

  u8 salt[HASHIDS_SALT_MAX];

  for (u32 i = 0; i < salt_len; i++) salt[i] = pw[i];

  // The separators are shuffled before the alphabet characters that make up their minimum count are
  // added, and the alphabet is shuffled after those have left it. The host has done both splits.

  const u32 seps_len0 = hashids->seps_len;
  const u32 extra_len = hashids->extra_len;

  u8 seps[HASHIDS_SEPS_MAX];

  for (u32 i = 0; i < seps_len0; i++) seps[i] = esalt_seps[i];

  hashids_reorder (seps, seps_len0, salt, salt_len);

  for (u32 i = 0; i < extra_len; i++) seps[seps_len0 + i] = esalt_extra[i];

  u32 seps_len = seps_len0 + extra_len;

  u32 alpha_len = hashids->alpha_len;

  u8 alpha[HASHIDS_ALPHA_MAX];

  for (u32 i = 0; i < alpha_len; i++) alpha[i] = esalt_alpha[i];

  hashids_reorder (alpha, alpha_len, salt, salt_len);

  // the guards come off the front of the alphabet, or of the separators when the alphabet is tiny

  const u32 guards_cnt = hashids->guards_cnt;

  u8 guards[HASHIDS_GUARDS_MAX];

  if (alpha_len < 3)
  {
    for (u32 i = 0; i < guards_cnt; i++) guards[i] = seps[i];

    for (u32 i = guards_cnt; i < seps_len; i++) seps[i - guards_cnt] = seps[i];

    seps_len -= guards_cnt;
  }
  else
  {
    for (u32 i = 0; i < guards_cnt; i++) guards[i] = alpha[i];

    for (u32 i = guards_cnt; i < alpha_len; i++) alpha[i - guards_cnt] = alpha[i];

    alpha_len -= guards_cnt;
  }

  if (alpha_len == 0) return;
  if (seps_len  == 0) return;

  const u32 values_hash = hashids->values_hash;
  const u32 min_length  = hashids->min_length;
  const u32 target_len  = hashids->target_len;

  const u32 lottery = alpha[values_hash % alpha_len];

  // without padding the lottery character opens the hashid, which rejects most candidates here

  if ((min_length == 0) && (lottery != esalt_target[0])) return;

  u8 out[HASHIDS_BUF_MAX];

  u32 out_len = 0;

  out[out_len] = (u8) lottery;

  out_len++;

  const u32 values_cnt = hashids->values_cnt;

  for (u32 v = 0; v < values_cnt; v++)
  {
    // the shuffle salt is the lottery character, the salt and the alphabet, cut to the alphabet's length

    u8 asalt[HASHIDS_ALPHA_MAX];

    u32 k = 0;

    asalt[k] = (u8) lottery;

    k++;

    for (u32 i = 0; (i < salt_len)  && (k < alpha_len); i++, k++) asalt[k] = salt[i];
    for (u32 i = 0; (i < alpha_len) && (k < alpha_len); i++, k++) asalt[k] = alpha[i];

    hashids_reorder (alpha, alpha_len, asalt, alpha_len);

    const u64 value = hashids->values[v];

    u8 digits[64];

    u32 digits_cnt = 0;

    u64 x = value;

    do
    {
      digits[digits_cnt] = alpha[x % alpha_len];

      digits_cnt++;

      x /= alpha_len;

    } while ((x > 0) && (digits_cnt < 64));

    // the separator written after the last number is cut off again below, so it may take the slot past
    // the longest hashid

    if ((out_len + digits_cnt + 1) > (HASHIDS_OUT_MAX + 1)) return;

    for (u32 i = digits_cnt; i > 0; i--)
    {
      out[out_len] = digits[i - 1];

      out_len++;
    }

    const u32 first = digits[digits_cnt - 1];

    // An alphabet that holds byte 0 can make the divisor 0 for the first number. Hashids fails on
    // that salt, so it cannot be the answer.

    if ((first + v) == 0) return;

    out[out_len] = seps[(value % (first + v)) % seps_len];

    out_len++;
  }

  // the last separator is cut off

  out_len--;

  // --min_length pads with guards first and then with halves of the alphabet, reshuffled each time

  if (out_len < min_length)
  {
    for (u32 i = out_len; i > 0; i--) out[i] = out[i - 1];

    out[0] = guards[(values_hash + out[1]) % guards_cnt];

    out_len++;

    if (out_len < min_length)
    {
      out[out_len] = guards[(values_hash + out[2]) % guards_cnt];

      out_len++;
    }

    const u32 split_at = alpha_len / 2;

    while (out_len < min_length)
    {
      u8 tmp[HASHIDS_ALPHA_MAX];

      for (u32 i = 0; i < alpha_len; i++) tmp[i] = alpha[i];

      hashids_reorder (alpha, alpha_len, tmp, alpha_len);

      u8 buf[HASHIDS_BUF_MAX];

      u32 buf_len = 0;

      for (u32 i = split_at; i < alpha_len; i++, buf_len++) buf[buf_len] = alpha[i];
      for (u32 i = 0;        i < out_len;   i++, buf_len++) buf[buf_len] = out[i];
      for (u32 i = 0;        i < split_at;  i++, buf_len++) buf[buf_len] = alpha[i];

      u32 start = 0;

      if (buf_len > min_length)
      {
        start = (buf_len - min_length) / 2;

        buf_len = min_length;
      }

      for (u32 i = 0; i < buf_len; i++) out[i] = buf[start + i];

      out_len = buf_len;
    }
  }

  if (out_len != target_len) return;

  for (u32 i = 0; i < target_len; i++)
  {
    if (out[i] != esalt_target[i]) return;
  }

  // the hashid stands in for a digest, as the ciphertext block does in hash-modes 26610 and 37230

  const u32 r0 = hashids->target[0];
  const u32 r1 = hashids->target[1];
  const u32 r2 = hashids->target[2];
  const u32 r3 = hashids->target[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
