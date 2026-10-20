/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
// PoCL 6.0 needs this DES call chain inlined for correct fused digest checks.
#if defined(MULTI_SALT_WINDOW) && defined(IS_POCL) && defined(IS_CPU)
DECLSPEC HC_INLINE_ALWAYS void _des_crypt_keysetup_lm (u32 c, u32 d, PRIVATE_AS u32 *Kc, PRIVATE_AS u32 *Kd, SHM_TYPE u32 (*s_skb)[64]);
DECLSPEC HC_INLINE_ALWAYS void _des_crypt_encrypt_lm (PRIVATE_AS u32 *iv, PRIVATE_AS const u32 *data, PRIVATE_AS const u32 *Kc, PRIVATE_AS const u32 *Kd, SHM_TYPE u32 (*s_SPtrans)[64]);
#endif
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

typedef struct netntlm
{
  u32 user_len;
  u32 domain_len;
  u32 srvchall_len;
  u32 clichall_len;

  u32 userdomain_buf[64];
  u32 chall_buf[256];

} netntlm_t;

DECLSPEC void transform_netntlmv1_key (const u32x w0, const u32x w1, PRIVATE_AS u32x *out)
{
  u32x t[8];

  t[0] = (w0 >>  0) & 0xff;
  t[1] = (w0 >>  8) & 0xff;
  t[2] = (w0 >> 16) & 0xff;
  t[3] = (w0 >> 24) & 0xff;
  t[4] = (w1 >>  0) & 0xff;
  t[5] = (w1 >>  8) & 0xff;
  t[6] = (w1 >> 16) & 0xff;
  t[7] = (w1 >> 24) & 0xff;

  u32x k[8];

  k[0] =               (t[0] >> 0);
  k[1] = (t[0] << 7) | (t[1] >> 1);
  k[2] = (t[1] << 6) | (t[2] >> 2);
  k[3] = (t[2] << 5) | (t[3] >> 3);
  k[4] = (t[3] << 4) | (t[4] >> 4);
  k[5] = (t[4] << 3) | (t[5] >> 5);
  k[6] = (t[5] << 2) | (t[6] >> 6);
  k[7] = (t[6] << 1);

  out[0] = ((k[0] & 0xff) <<  0)
         | ((k[1] & 0xff) <<  8)
         | ((k[2] & 0xff) << 16)
         | ((k[3] & 0xff) << 24);

  out[1] = ((k[4] & 0xff) <<  0)
         | ((k[5] & 0xff) <<  8)
         | ((k[6] & 0xff) << 16)
         | ((k[7] & 0xff) << 24);
}

// Hash tail16 into 1024 buckets. Each chain contains every session in its
// bucket, so the walk must still compare the full tail16 value.

#define NN_FUSE_TI_BUCKETS 1024
#define NN_FUSE_TI_SHIFT   22
#define NN_FUSE_TI_NIL     0xffffffffu
#define NN_FUSE_TI_BUCKET(v) (((v) * 0x9E3779B1u) >> NN_FUSE_TI_SHIFT)

// Stage at most MULTI_SALT_WINDOW sessions per window. Recompute each candidate's
// MD4 once per window, then test it against the sessions in that window.

#define NN_FUSE_GS(n)   ((n) + nn_base)
#define NN_FUSE_LS(n)   ((n) - nn_base)
#define NN_FUSE_WINS    ((kernel_param->salts_cnt / MULTI_SALT_WINDOW) + ((kernel_param->salts_cnt % MULTI_SALT_WINDOW) != 0))

#if defined(MULTI_SALT_WINDOW) && (VECT_SIZE != 1) && (VECT_SIZE != 2) && (VECT_SIZE != 4) && (VECT_SIZE != 8) && (VECT_SIZE != 16)
#error unsupported fused 5500 vector width
#endif

// Fusion requires shared memory for the filter bitmap and bucket index.
#if defined(MULTI_SALT_WINDOW) && !defined(REAL_SHM)
#error fused 5500 kernels stage their filter map in shared memory; build them with REAL_SHM
#endif
#if defined(IS_CUDA) || defined(IS_HIP)
#define NN_FUSE_TI_XCHG(p,v)  atomicExch ((p), (v))
#else
#define NN_FUSE_TI_XCHG(p,v)  atomic_xchg ((p), (v))
#endif

#if defined(MULTI_SALT_WINDOW)

// The bitmap rejects tail16 values absent from the current window before
// the final two MD4 steps. Bucket chains then locate the matching sessions.

#define NN_FUSE_BITS_W 2048

// The staged arrays travel to m05500m the way the DES tables do: as parameters.  Shared
// arrays are declared in each kernel body, so a function cannot name them itself.  The index's
// own two tables travel the same way.

#define NN_FUSE_PARAMS , SHM_TYPE u32 *nn_sf, SHM_TYPE u32 *nn_sb, SHM_TYPE u32 *nn_th, SHM_TYPE u32 *nn_tn
#define NN_FUSE_ARGS   , s_nn_filt, s_nn_bits, s_ti_head, s_ti_next

// Atomic OR preserves bits set by different threads in the same bitmap word.

#if defined(IS_CUDA) || defined(IS_HIP)
#define NN_FUSE_OR(p, v)  atomicOr ((p), (v))
#else
#define NN_FUSE_OR(p, v)  atomic_or ((p), (v))
#endif

DECLSPEC void nn_fuse_stage (SHM_TYPE u32 *s_nn_filt, SHM_TYPE u32 *s_nn_bits, GLOBAL_AS const salt_t *salt_bufs, const u32 nn_base, const u32 nn_len, const u64 lid, const u64 lsz)
{
  for (u32 i = lid; i < nn_len; i += lsz) s_nn_filt[i] = salt_bufs[nn_base + i].salt_buf[2];


  for (u32 i = lid; i < NN_FUSE_BITS_W; i += lsz) s_nn_bits[i] = 0;

  SYNC_THREADS ();

  for (u32 i = lid; i < nn_len; i += lsz)
  {
    const u32 v = s_nn_filt[i] & 0xffff;

    NN_FUSE_OR (&s_nn_bits[v >> 5], 1u << (v & 31));
  }

  SYNC_THREADS ();
}

#define NN_FUSE_FILT(i)   (nn_sf[i])
#define NN_FUSE_REJECT(v) (((nn_sb[(v) >> 5] >> ((v) & 31)) & 1u) == 0)

// Staged filters use window-local indices. Salt buffers use global indices.

#define NN_FUSE_WALK_ONE(nn_s)                                                                      \
{                                                                                                   \
  if (MATCHES_NONE_VS (nn_dd, NN_FUSE_FILT (NN_FUSE_LS (nn_s)))) continue;                          \
                                                                                                    \
  NN_FUSE_WALK_BODY (nn_s)                                                                          \
}

typedef struct nn_fuse_des_result
{
  u32 v[4];

} nn_fuse_des_result_t;

#if defined(IS_POCL) && defined(IS_CPU)
#define NN_FUSE_DES_ATTR HC_INLINE_ALWAYS
#else
#define NN_FUSE_DES_ATTR HC_NOINLINE_ALWAYS
#endif

#if VECT_SIZE > 1
#define NN_FUSE_HEAD(i) (nn_th[i])
#define NN_FUSE_NEXT(i) (nn_tn[i])
#include M2S(INCLUDE_PATH/inc_netntlmv1_fused.cl)
#else
// Keep the DES schedules out of the candidate loop's register budget.
DECLSPEC NN_FUSE_DES_ATTR nn_fuse_des_result_t nn_fuse_des (const u32 a, const u32 b, const u32 c, const u32 d, const u32 s0, const u32 s1, SHM_TYPE u32 (*s_skb)[64], SHM_TYPE u32 (*s_SPtrans)[64])
{
  u32 key[2];
  u32 Kc[16];
  u32 Kd[16];
  u32 data[2] = { s0, s1 };

  transform_netntlmv1_key (a, b, key);

  _des_crypt_keysetup_lm_vect (key[0], key[1], Kc, Kd, s_skb);

  u32 iv1[2];

  _des_crypt_encrypt_lm_vect (iv1, data, Kc, Kd, s_SPtrans);

  transform_netntlmv1_key (((b >> 24) | (c << 8)), ((c >> 24) | (d << 8)), key);

  _des_crypt_keysetup_lm_vect (key[0], key[1], Kc, Kd, s_skb);

  u32 iv2[2];

  _des_crypt_encrypt_lm_vect (iv2, data, Kc, Kd, s_SPtrans);

  nn_fuse_des_result_t result;

  result.v[0] = iv1[0];
  result.v[1] = iv1[1];
  result.v[2] = iv2[0];
  result.v[3] = iv2[1];

  return result;
}

#endif

#define NN_FUSE_WALK_BODY(nn_s)                                                                     \
{                                                                                                   \
  const nn_fuse_des_result_t nn_result = nn_fuse_des (a, b, c, d, salt_bufs[nn_s].salt_buf[0], salt_bufs[nn_s].salt_buf[1], s_skb, s_SPtrans);\
                                                                                                    \
  const u32 nn_digests_cnt = salt_bufs[nn_s].digests_cnt;                                           \
  const u32 nn_digests_off = salt_bufs[nn_s].digests_offset;                                        \
                                                                                                    \
  for (u32 nn_d = 0; nn_d < nn_digests_cnt; nn_d++)                                                 \
  {                                                                                                 \
    u32 digest_tp[4];                                                                               \
                                                                                                    \
    digest_tp[0] = nn_result.v[0];                                                                       \
    digest_tp[1] = nn_result.v[1];                                                                       \
    digest_tp[2] = nn_result.v[2];                                                                       \
    digest_tp[3] = nn_result.v[3];                                                                       \
                                                                                                    \
    const u32 nn_hash_pos = nn_digests_off + nn_d;                                                  \
                                                                                                    \
    if (find_hash (digest_tp, 1, &digests_buf[nn_hash_pos]) != 0) continue;                         \
                                                                                                    \
    if (hc_atomic_inc (&hashes_shown[nn_hash_pos]) == 0)                                            \
    {                                                                                               \
      mark_hash (plains_buf, d_return_buf, nn_s, kernel_param->digests_cnt, nn_d, nn_hash_pos, gid, il_pos, 0, 0);\
    }                                                                                               \
  }                                                                                                 \
}

// Build the bucket index once per window, after staging the filter array.

DECLSPEC void nn_fuse_ti_stage (SHM_TYPE u32 *s_nn_filt, SHM_TYPE u32 *s_ti_head, SHM_TYPE u32 *s_ti_next, const u32 nn_len, const u64 lid, const u64 lsz)
{
  for (u32 i = lid; i < NN_FUSE_TI_BUCKETS; i += lsz) s_ti_head[i] = NN_FUSE_TI_NIL;

  SYNC_THREADS ();

  for (u32 i = lid; i < nn_len; i += lsz)
  {
    const u32 b = NN_FUSE_TI_BUCKET (s_nn_filt[i] & 0xffff);

    // the exchange returns the previous head, so the bucket becomes a list of every session
    // that landed in it, in an order the block does not fix.  Every session i < MULTI_SALT_WINDOW
    // is written once here, so every link the walk can follow is defined.

    s_ti_next[i] = NN_FUSE_TI_XCHG (&s_ti_head[b], i);
  }

  SYNC_THREADS ();
}

#else

// The unfused helper has no staged-array parameters.

#define NN_FUSE_PARAMS
#define NN_FUSE_ARGS

#endif

DECLSPEC void m05500m (SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64], PRIVATE_AS u32 *w, const u32 pw_len NN_FUSE_PARAMS, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  const u32 s0 = salt_bufs[SALT_POS_HOST].salt_buf[0];
  const u32 s1 = salt_bufs[SALT_POS_HOST].salt_buf[1];
  const u32 s2 = salt_bufs[SALT_POS_HOST].salt_buf[2];

  /**
   * loop
   */

  u32 w0l = w[0];

#if defined(MULTI_SALT_WINDOW)
  for (u32 nn_w = 0; nn_w < NN_FUSE_WINS; nn_w++)
  {
    const u32 nn_base = nn_w * MULTI_SALT_WINDOW;

    // Self-test buffers contain one salt, even when the real attack is fused.
    if (nn_base >= kernel_param->salts_cnt) break;

    const u32 nn_left = kernel_param->salts_cnt - nn_base;
    const u32 nn_len  = (nn_left < MULTI_SALT_WINDOW) ? nn_left : (u32) MULTI_SALT_WINDOW;

    nn_fuse_stage (nn_sf, nn_sb, salt_bufs, nn_base, nn_len, lid, lsz);

    nn_fuse_ti_stage (nn_sf, nn_th, nn_tn, nn_len, lid, lsz);
#endif

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = w0;
    w0_t[1] = w[ 1];
    w0_t[2] = w[ 2];
    w0_t[3] = w[ 3];
    w1_t[0] = w[ 4];
    w1_t[1] = w[ 5];
    w1_t[2] = w[ 6];
    w1_t[3] = w[ 7];
    w2_t[0] = w[ 8];
    w2_t[1] = w[ 9];
    w2_t[2] = w[10];
    w2_t[3] = w[11];
    w3_t[0] = w[12];
    w3_t[1] = w[13];
    w3_t[2] = w[14];
    w3_t[3] = w[15];

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3_t[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0_t[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0_t[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[3], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[3], MD4C02, MD4S21);

    // Step 46 is the final update of d. Its high half after feed-forward
    // is the NT-hash tail16, so reject before completing c and b.

#ifdef MULTI_SALT_WINDOW

    // A bitmap miss skips this candidate, not the remaining amplifier loop.

    const u32x nn_dd = (d + make_u32x (MD4M_D)) >> 16;

#if VECT_SIZE > 1
    u32 nn_mask = 0;

    NN_FUSE_LANES (NN_FUSE_CHECK_LANE)

    if (nn_mask == 0) continue;
#else
    if (NN_FUSE_REJECT (nn_dd & 0xffff)) continue;
#endif
#else
    // upstream: abandon the candidate as soon as the 16-bit filter misses
    if (MATCHES_NONE_VS (((d + make_u32x (MD4M_D)) >> 16), s2)) continue;
#endif

    MD4_STEP (MD4_H , c, d, a, b, w1_t[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[3], MD4C02, MD4S23);

    a += make_u32x (MD4M_A);
    b += make_u32x (MD4M_B);
    c += make_u32x (MD4M_C);
    d += make_u32x (MD4M_D);
#ifdef MULTI_SALT_WINDOW

#if VECT_SIZE > 1
    const u32x nn_a = a;
    const u32x nn_b = b;
    const u32x nn_c = c;
    const u32x nn_d = d;
    const u32 nn_il_pos = il_pos;

    NN_FUSE_LANES (NN_FUSE_VERIFY_LANE)
#else
    // Reuse this candidate's NT hash across the current session window.

    // Walk the complete bucket and verify each exact tail16 match inline.

    const u32 nn_ti_b = NN_FUSE_TI_BUCKET (nn_dd & 0xffff);

    for (u32 nn_sl = nn_th[nn_ti_b]; nn_sl != NN_FUSE_TI_NIL; nn_sl = nn_tn[nn_sl])
    {
      NN_FUSE_WALK_ONE (NN_FUSE_GS (nn_sl))
    }

#endif

#else

    /**
     * DES1
     */

    u32x key[2];

    transform_netntlmv1_key (a, b, key);

    u32x Kc[16];
    u32x Kd[16];

    _des_crypt_keysetup_lm_vect (key[0], key[1], Kc, Kd, s_skb);

    u32x data[2];

    data[0] = s0;
    data[1] = s1;

    u32x iv1[2];

    _des_crypt_encrypt_lm_vect (iv1, data, Kc, Kd, s_SPtrans);

    /**
     * DES2
     */

    transform_netntlmv1_key (((b >> 24) | (c << 8)), ((c >> 24) | (d << 8)), key);

    _des_crypt_keysetup_lm_vect (key[0], key[1], Kc, Kd, s_skb);

    u32x iv2[2];

    _des_crypt_encrypt_lm_vect (iv2, data, Kc, Kd, s_SPtrans);

    /**
     * compare
     */

    COMPARE_M_SIMD (iv1[0], iv1[1], iv2[0], iv2[1]);
#endif
  }
#if defined(MULTI_SALT_WINDOW)
    // before the next window stages over the arrays the walk was reading
    SYNC_THREADS ();
  }
#endif
}

DECLSPEC void m05500s (SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64], PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  const u32 s0 = salt_bufs[SALT_POS_HOST].salt_buf[0];
  const u32 s1 = salt_bufs[SALT_POS_HOST].salt_buf[1];
  const u32 s2 = salt_bufs[SALT_POS_HOST].salt_buf[2];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = w0;
    w0_t[1] = w[ 1];
    w0_t[2] = w[ 2];
    w0_t[3] = w[ 3];
    w1_t[0] = w[ 4];
    w1_t[1] = w[ 5];
    w1_t[2] = w[ 6];
    w1_t[3] = w[ 7];
    w2_t[0] = w[ 8];
    w2_t[1] = w[ 9];
    w2_t[2] = w[10];
    w2_t[3] = w[11];
    w3_t[0] = w[12];
    w3_t[1] = w[13];
    w3_t[2] = w[14];
    w3_t[3] = w[15];

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3_t[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0_t[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0_t[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[3], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[3], MD4C02, MD4S21);

    if (MATCHES_NONE_VS (((d + make_u32x (MD4M_D)) >> 16), s2)) continue;

    MD4_STEP (MD4_H , c, d, a, b, w1_t[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[3], MD4C02, MD4S23);

    a += make_u32x (MD4M_A);
    b += make_u32x (MD4M_B);
    c += make_u32x (MD4M_C);
    d += make_u32x (MD4M_D);

    /**
     * DES1
     */

    u32x key[2];

    transform_netntlmv1_key (a, b, key);

    u32x Kc[16];
    u32x Kd[16];

    _des_crypt_keysetup_lm_vect (key[0], key[1], Kc, Kd, s_skb);

    u32x data[2];

    data[0] = s0;
    data[1] = s1;

    u32x iv1[2];

    _des_crypt_encrypt_lm_vect (iv1, data, Kc, Kd, s_SPtrans);

    /**
     * DES2
     */

    /*
    transform_netntlmv1_key (((b >> 24) | (c << 8)), ((c >> 24) | (d << 8)), key);

    _des_crypt_keysetup_lm_vect (key[0], key[1], Kc, Kd, s_skb);

    u32x iv2[2];

    _des_crypt_encrypt_lm_vect (iv2, data, Kc, Kd, s_SPtrans);
    */

    u32x iv2[2];

    iv2[0] = search[2];
    iv2[1] = search[3];

    /**
     * compare
     */

    COMPARE_S_SIMD (iv1[0], iv1[1], iv2[0], iv2[1]);
  }
}

// Budget HIP registers for at least two waves per execution unit.
KERNEL_FQ KERNEL_FA
#if defined(MULTI_SALT_WINDOW) && defined(IS_HIP)
  __launch_bounds__(256, 2)
#elif defined(MULTI_SALT_WINDOW) && defined(IS_CUDA)
  __launch_bounds__(256)
#endif
  void m05500_m04 (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
#ifdef MULTI_SALT_WINDOW
  // Keep every thread alive for shared staging and window barriers.
  // Extra lanes repeat the last candidate. Atomic hit reporting deduplicates it.
  const u64 gid = (get_global_id (0) < (u64) GID_CNT) ? get_global_id (0) : (u64) (GID_CNT - 1);
#else
  const u64 gid = get_global_id (0);
#endif
  const u64 lsz = get_local_size (0);

#ifdef MULTI_SALT_WINDOW
  // fused kernel: the fused kernel covers every session in the file, so the other
  // launches of this candidate chunk would repeat its work.  salt_pos_host 0
  // is the launch that runs the whole search.
  if (SALT_POS_HOST != 0) return;
#endif

  /**
   * sbox, kbox
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

#ifdef MULTI_SALT_WINDOW
  LOCAL_VK u32 s_nn_filt[MULTI_SALT_WINDOW];
  LOCAL_VK u32 s_nn_bits[NN_FUSE_BITS_W];

  LOCAL_VK u32 s_ti_head[NN_FUSE_TI_BUCKETS];
  LOCAL_VK u32 s_ti_next[MULTI_SALT_WINDOW];

  // the staging runs inside m05500m, once per window
#endif

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05500m (s_SPtrans, s_skb, w, pw_len NN_FUSE_ARGS, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA
#if defined(MULTI_SALT_WINDOW) && defined(IS_HIP)
  __launch_bounds__(256, 2)
#elif defined(MULTI_SALT_WINDOW) && defined(IS_CUDA)
  __launch_bounds__(256)
#endif
  void m05500_m08 (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
#ifdef MULTI_SALT_WINDOW
  // Keep every thread alive for shared staging and window barriers.
  // Extra lanes repeat the last candidate. Atomic hit reporting deduplicates it.
  const u64 gid = (get_global_id (0) < (u64) GID_CNT) ? get_global_id (0) : (u64) (GID_CNT - 1);
#else
  const u64 gid = get_global_id (0);
#endif
  const u64 lsz = get_local_size (0);

#ifdef MULTI_SALT_WINDOW
  // fused kernel: the fused kernel covers every session in the file, so the other
  // launches of this candidate chunk would repeat its work.  salt_pos_host 0
  // is the launch that runs the whole search.
  if (SALT_POS_HOST != 0) return;
#endif

  /**
   * sbox, kbox
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

#ifdef MULTI_SALT_WINDOW
  LOCAL_VK u32 s_nn_filt[MULTI_SALT_WINDOW];
  LOCAL_VK u32 s_nn_bits[NN_FUSE_BITS_W];

  LOCAL_VK u32 s_ti_head[NN_FUSE_TI_BUCKETS];
  LOCAL_VK u32 s_ti_next[MULTI_SALT_WINDOW];

  // the staging runs inside m05500m, once per window
#endif

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];
  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  m05500m (s_SPtrans, s_skb, w, pw_len NN_FUSE_ARGS, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA
#if defined(MULTI_SALT_WINDOW) && defined(IS_HIP)
  __launch_bounds__(256, 2)
#elif defined(MULTI_SALT_WINDOW) && defined(IS_CUDA)
  __launch_bounds__(256)
#endif
  void m05500_m16 (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
#ifdef MULTI_SALT_WINDOW
  // Keep every thread alive for shared staging and window barriers.
  // Extra lanes repeat the last candidate. Atomic hit reporting deduplicates it.
  const u64 gid = (get_global_id (0) < (u64) GID_CNT) ? get_global_id (0) : (u64) (GID_CNT - 1);
#else
  const u64 gid = get_global_id (0);
#endif
  const u64 lsz = get_local_size (0);

#ifdef MULTI_SALT_WINDOW
  // fused kernel: the fused kernel covers every session in the file, so the other
  // launches of this candidate chunk would repeat its work.  salt_pos_host 0
  // is the launch that runs the whole search.
  if (SALT_POS_HOST != 0) return;
#endif

  /**
   * sbox, kbox
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

#ifdef MULTI_SALT_WINDOW
  LOCAL_VK u32 s_nn_filt[MULTI_SALT_WINDOW];
  LOCAL_VK u32 s_nn_bits[NN_FUSE_BITS_W];

  LOCAL_VK u32 s_ti_head[NN_FUSE_TI_BUCKETS];
  LOCAL_VK u32 s_ti_next[MULTI_SALT_WINDOW];

  // the staging runs inside m05500m, once per window
#endif

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05500m (s_SPtrans, s_skb, w, pw_len NN_FUSE_ARGS, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m05500_s04 (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05500s (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m05500_s08 (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05500s (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m05500_s16 (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m05500s (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
