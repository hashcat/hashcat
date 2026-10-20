/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Scalar verification keeps DES schedules independent of the MD4 vector width.

DECLSPEC void nn_fuse_transform_key (const u32 w0, const u32 w1, PRIVATE_AS u32 *out)
{
  u32 t[8];

  t[0] = (w0 >>  0) & 0xff;
  t[1] = (w0 >>  8) & 0xff;
  t[2] = (w0 >> 16) & 0xff;
  t[3] = (w0 >> 24) & 0xff;
  t[4] = (w1 >>  0) & 0xff;
  t[5] = (w1 >>  8) & 0xff;
  t[6] = (w1 >> 16) & 0xff;
  t[7] = (w1 >> 24) & 0xff;

  u32 k[8];

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

DECLSPEC NN_FUSE_DES_ATTR nn_fuse_des_result_t nn_fuse_des (const u32 a, const u32 b, const u32 c, const u32 d, const u32 s0, const u32 s1, SHM_TYPE u32 (*s_skb)[64], SHM_TYPE u32 (*s_SPtrans)[64])
{
  u32 key[2];
  u32 Kc[16];
  u32 Kd[16];
  u32 data[2] = { s0, s1 };

  nn_fuse_transform_key (a, b, key);

  _des_crypt_keysetup_lm (key[0], key[1], Kc, Kd, s_skb);

  u32 iv1[2];

  _des_crypt_encrypt_lm (iv1, data, Kc, Kd, s_SPtrans);

  nn_fuse_transform_key (((b >> 24) | (c << 8)), ((c >> 24) | (d << 8)), key);

  _des_crypt_keysetup_lm (key[0], key[1], Kc, Kd, s_skb);

  u32 iv2[2];

  _des_crypt_encrypt_lm (iv2, data, Kc, Kd, s_SPtrans);

  nn_fuse_des_result_t result;

  result.v[0] = iv1[0];
  result.v[1] = iv1[1];
  result.v[2] = iv2[0];
  result.v[3] = iv2[1];

  return result;
}

#define NN_FUSE_LANES_2(f)  f (0) f (1)
#define NN_FUSE_LANES_4(f)  NN_FUSE_LANES_2 (f) f (2) f (3)
#define NN_FUSE_LANES_8(f)  NN_FUSE_LANES_4 (f) f (4) f (5) f (6) f (7)
#define NN_FUSE_LANES_16(f) NN_FUSE_LANES_8 (f) f (8) f (9) f (10) f (11) f (12) f (13) f (14) f (15)

#if VECT_SIZE == 2
#define NN_FUSE_LANES(f) NN_FUSE_LANES_2 (f)
#elif VECT_SIZE == 4
#define NN_FUSE_LANES(f) NN_FUSE_LANES_4 (f)
#elif VECT_SIZE == 8
#define NN_FUSE_LANES(f) NN_FUSE_LANES_8 (f)
#elif VECT_SIZE == 16
#define NN_FUSE_LANES(f) NN_FUSE_LANES_16 (f)
#endif

#define NN_FUSE_CHECK_LANE(n)                                                        \
{                                                                                   \
  if (vector_accessible (il_pos, IL_CNT, n))                                          \
  {                                                                                 \
    const u32 nn_tail = VECTOR_ELEMENT (nn_dd, n) & 0xffff;                           \
    if (NN_FUSE_REJECT (nn_tail) == 0) nn_mask |= 1u << n;                            \
  }                                                                                 \
}

#define NN_FUSE_VERIFY_LANE(n)                                                       \
if ((nn_mask & (1u << n)) != 0)                                                      \
{                                                                                   \
  const u32 a = VECTOR_ELEMENT (nn_a, n);                                            \
  const u32 b = VECTOR_ELEMENT (nn_b, n);                                            \
  const u32 c = VECTOR_ELEMENT (nn_c, n);                                            \
  const u32 d = VECTOR_ELEMENT (nn_d, n);                                            \
  const u32 il_pos = nn_il_pos + n;                                                 \
  const u32 nn_tail = VECTOR_ELEMENT (nn_dd, n) & 0xffff;                            \
  const u32 nn_bucket = NN_FUSE_TI_BUCKET (nn_tail);                                 \
                                                                                    \
  for (u32 nn_sl = NN_FUSE_HEAD (nn_bucket); nn_sl != NN_FUSE_TI_NIL; nn_sl = NN_FUSE_NEXT (nn_sl)) \
  {                                                                                 \
    if (nn_tail != NN_FUSE_FILT (nn_sl)) continue;                                   \
                                                                                    \
    const u32 nn_s = NN_FUSE_GS (nn_sl);                                            \
                                                                                    \
    NN_FUSE_WALK_BODY (nn_s)                                                        \
  }                                                                                 \
}
