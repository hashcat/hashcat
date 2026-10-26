/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct md5sun_tmp
{
  u32 digest_buf[4];

} md5sun_tmp_t;

#define CONSTANT_PHRASE_LEN 1517

CONSTANT_VK u32a constant_phrase[380] =
{
  0x62206f54, 0x6f202c65, 0x6f6e2072, 0x6f742074, 0x2c656220, 0x68742d2d, 0x69207461, 0x68742073,
  0x75712065, 0x69747365, 0x2d3a6e6f, 0x68570a2d, 0x65687465, 0x74272072, 0x6e207369, 0x656c626f,
  0x6e692072, 0x65687420, 0x6e696d20, 0x6f742064, 0x66757320, 0x0a726566, 0x20656854, 0x6e696c73,
  0x61207367, 0x6120646e, 0x776f7272, 0x666f2073, 0x74756f20, 0x65676172, 0x2073756f, 0x74726f66,
  0x0a656e75, 0x7420724f, 0x6174206f, 0x6120656b, 0x20736d72, 0x69616761, 0x2074736e, 0x65732061,
  0x666f2061, 0x6f727420, 0x656c6275, 0x410a2c73, 0x6220646e, 0x706f2079, 0x69736f70, 0x6520676e,
  0x7420646e, 0x3f6d6568, 0x6f542d2d, 0x65696420, 0x742d2d2c, 0x6c73206f, 0x2c706565, 0x4e0a2d2d,
  0x6f6d206f, 0x203b6572, 0x20646e61, 0x61207962, 0x656c7320, 0x74207065, 0x6173206f, 0x65772079,
  0x646e6520, 0x6568540a, 0x61656820, 0x63617472, 0x202c6568, 0x20646e61, 0x20656874, 0x756f6874,
  0x646e6173, 0x74616e20, 0x6c617275, 0x6f687320, 0x0a736b63, 0x74616854, 0x656c6620, 0x69206873,
  0x65682073, 0x74207269, 0x2d2d2c6f, 0x73697427, 0x63206120, 0x75736e6f, 0x74616d6d, 0x0a6e6f69,
  0x6f766544, 0x796c7475, 0x206f7420, 0x77206562, 0x27687369, 0x54202e64, 0x6964206f, 0x2d2d2c65,
  0x73206f74, 0x7065656c, 0x0a2d2d3b, 0x73206f54, 0x7065656c, 0x65702021, 0x61686372, 0x2065636e,
  0x64206f74, 0x6d616572, 0x612d2d3a, 0x74202c79, 0x65726568, 0x74207327, 0x72206568, 0x0a3b6275,
  0x20726f46, 0x74206e69, 0x20746168, 0x65656c73, 0x666f2070, 0x61656420, 0x77206874, 0x20746168,
  0x61657264, 0x6d20736d, 0x63207961, 0x2c656d6f, 0x6568570a, 0x6577206e, 0x76616820, 0x68732065,
  0x6c666675, 0x6f206465, 0x74206666, 0x20736968, 0x74726f6d, 0x63206c61, 0x2c6c696f, 0x73754d0a,
  0x69672074, 0x75206576, 0x61702073, 0x3a657375, 0x65687420, 0x73276572, 0x65687420, 0x73657220,
  0x74636570, 0x6168540a, 0x616d2074, 0x2073656b, 0x616c6163, 0x7974696d, 0x20666f20, 0x6c206f73,
  0x20676e6f, 0x6566696c, 0x6f460a3b, 0x68772072, 0x6f77206f, 0x20646c75, 0x72616562, 0x65687420,
  0x69687720, 0x61207370, 0x7320646e, 0x6e726f63, 0x666f2073, 0x6d697420, 0x540a2c65, 0x6f206568,
  0x65727070, 0x726f7373, 0x77207327, 0x676e6f72, 0x6874202c, 0x72702065, 0x2064756f, 0x276e616d,
  0x6f632073, 0x6d75746e, 0x2c796c65, 0x6568540a, 0x6e617020, 0x6f207367, 0x65642066, 0x73697073,
  0x6c206427, 0x2c65766f, 0x65687420, 0x77616c20, 0x64207327, 0x79616c65, 0x68540a2c, 0x6e692065,
  0x656c6f73, 0x2065636e, 0x6f20666f, 0x63696666, 0x61202c65, 0x7420646e, 0x73206568, 0x6e727570,
  0x68540a73, 0x70207461, 0x65697461, 0x6d20746e, 0x74697265, 0x20666f20, 0x20656874, 0x6f776e75,
  0x79687472, 0x6b617420, 0x0a2c7365, 0x6e656857, 0x20656820, 0x736d6968, 0x20666c65, 0x6867696d,
  0x69682074, 0x75712073, 0x75746569, 0x616d2073, 0x570a656b, 0x20687469, 0x61622061, 0x62206572,
  0x696b646f, 0x77203f6e, 0x77206f68, 0x646c756f, 0x65687420, 0x66206573, 0x65647261, 0x6220736c,
  0x2c726165, 0x206f540a, 0x6e757267, 0x6e612074, 0x77732064, 0x20746165, 0x65646e75, 0x20612072,
  0x72616577, 0x696c2079, 0x0a2c6566, 0x20747542, 0x74616874, 0x65687420, 0x65726420, 0x6f206461,
  0x6f732066, 0x6874656d, 0x20676e69, 0x65746661, 0x65642072, 0x2c687461, 0x540a2d2d, 0x75206568,
  0x7369646e, 0x65766f63, 0x20642772, 0x6e756f63, 0x2c797274, 0x6f726620, 0x6877206d, 0x2065736f,
  0x72756f62, 0x6f4e0a6e, 0x61727420, 0x6c6c6576, 0x72207265, 0x72757465, 0x2d2c736e, 0x7a75702d,
  0x73656c7a, 0x65687420, 0x6c697720, 0x410a2c6c, 0x6d20646e, 0x73656b61, 0x20737520, 0x68746172,
  0x62207265, 0x20726165, 0x736f6874, 0x6c692065, 0x7720736c, 0x61682065, 0x540a6576, 0x206e6168,
  0x20796c66, 0x6f206f74, 0x72656874, 0x68742073, 0x77207461, 0x6e6b2065, 0x6e20776f, 0x6f20746f,
  0x540a3f66, 0x20737568, 0x736e6f63, 0x6e656963, 0x64206563, 0x2073656f, 0x656b616d, 0x776f6320,
  0x73647261, 0x20666f20, 0x61207375, 0x0a3b6c6c, 0x20646e41, 0x73756874, 0x65687420, 0x74616e20,
  0x20657669, 0x20657568, 0x7220666f, 0x6c6f7365, 0x6f697475, 0x73490a6e, 0x63697320, 0x65696c6b,
  0x276f2064, 0x77207265, 0x20687469, 0x20656874, 0x656c6170, 0x73616320, 0x666f2074, 0x6f687420,
  0x74686775, 0x6e410a3b, 0x6e652064, 0x70726574, 0x65736972, 0x666f2073, 0x65726720, 0x70207461,
  0x20687469, 0x20646e61, 0x656d6f6d, 0x0a2c746e, 0x68746957, 0x69687420, 0x65722073, 0x64726167,
  0x6874202c, 0x20726965, 0x72727563, 0x73746e65, 0x72757420, 0x7761206e, 0x0a2c7972, 0x20646e41,
  0x65736f6c, 0x65687420, 0x6d616e20, 0x666f2065, 0x74636120, 0x2e6e6f69, 0x6f532d2d, 0x79207466,
  0x6e20756f, 0x0a21776f, 0x20656854, 0x72696166, 0x68704f20, 0x61696c65, 0x4e2d2d21, 0x68706d79,
  0x6e69202c, 0x79687420, 0x69726f20, 0x736e6f73, 0x2065420a, 0x206c6c61, 0x7320796d, 0x20736e69,
  0x656d6572, 0x7265626d, 0x0a2e6427, 0x00000000,
};

DECLSPEC u32 sunmd5_getbyte (PRIVATE_AS const u32 *d, const int idx)
{
  return (d[idx >> 2] >> ((idx & 3) << 3)) & 0xff;
}

DECLSPEC int sunmd5_getbit (PRIVATE_AS const u32 *d, const int n)
{
  const int bn = n & 127;

  return (d[bn >> 5] >> (bn & 31)) & 1;
}

DECLSPEC int sunmd5_coin (PRIVATE_AS const u32 *digest, const int round_num)
{
  u32 x = 0;
  u32 y = 0;

  for (int i = 0; i < 8; i++)
  {
    u32 a, b, r, v;

    a = sunmd5_getbyte (digest, (i + 0) % 16);
    b = sunmd5_getbyte (digest, (i + 3) % 16);
    r = a >> (b % 5);
    v = sunmd5_getbyte (digest, r % 16);

    if (b & (1u << (a % 8)))
    {
      v >>= 1;
    }

    x |= ((u32) sunmd5_getbit (digest, v)) << i;

    a = sunmd5_getbyte (digest, (i + 8) % 16);
    b = sunmd5_getbyte (digest, (i + 11) % 16);
    r = a >> (b % 5);
    v = sunmd5_getbyte (digest, r % 16);

    if (b & (1u << (a % 8)))
    {
      v >>= 1;
    }

    y |= ((u32) sunmd5_getbit (digest, v)) << i;
  }

  if (sunmd5_getbit (digest, round_num))
  {
    x >>= 1;
  }

  if (sunmd5_getbit (digest, round_num + 64))
  {
    y >>= 1;
  }

  return sunmd5_getbit (digest, x & 0x7f) ^ sunmd5_getbit (digest, y & 0x7f);
}

DECLSPEC void sunmd5_update_constant_phrase (PRIVATE_AS md5_ctx_t *ctx)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  for (int i = 0; i < 23; i++)
  {
    const int off = i * 16;

    w0[0] = constant_phrase[off +  0];
    w0[1] = constant_phrase[off +  1];
    w0[2] = constant_phrase[off +  2];
    w0[3] = constant_phrase[off +  3];
    w1[0] = constant_phrase[off +  4];
    w1[1] = constant_phrase[off +  5];
    w1[2] = constant_phrase[off +  6];
    w1[3] = constant_phrase[off +  7];
    w2[0] = constant_phrase[off +  8];
    w2[1] = constant_phrase[off +  9];
    w2[2] = constant_phrase[off + 10];
    w2[3] = constant_phrase[off + 11];
    w3[0] = constant_phrase[off + 12];
    w3[1] = constant_phrase[off + 13];
    w3[2] = constant_phrase[off + 14];
    w3[3] = constant_phrase[off + 15];

    md5_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  const int off = 23 * 16;

  w0[0] = constant_phrase[off +  0];
  w0[1] = constant_phrase[off +  1];
  w0[2] = constant_phrase[off +  2];
  w0[3] = constant_phrase[off +  3];
  w1[0] = constant_phrase[off +  4];
  w1[1] = constant_phrase[off +  5];
  w1[2] = constant_phrase[off +  6];
  w1[3] = constant_phrase[off +  7];
  w2[0] = constant_phrase[off +  8];
  w2[1] = constant_phrase[off +  9];
  w2[2] = constant_phrase[off + 10];
  w2[3] = constant_phrase[off + 11];
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  md5_update_64 (ctx, w0, w1, w2, w3, 45);
}

DECLSPEC int sunmd5_itoa (const u32 num, PRIVATE_AS u32 *buf)
{
  buf[0] = 0;
  buf[1] = 0;

  int num_digits = 0;
  u32 tmp = num;

  do
  {
    num_digits++;
    tmp /= 10;
  } while (tmp > 0);

  u32 divisor = 1;

  for (int i = 1; i < num_digits; i++)
  {
    divisor *= 10;
  }

  tmp = num;

  for (int k = 0; k < num_digits; k++)
  {
    const u32 d = tmp / divisor;

    tmp %= divisor;
    divisor /= 10;

    buf[k >> 2] |= (d + 0x30) << ((k & 3) << 3);
  }

  return num_digits;
}

KERNEL_FQ KERNEL_FA void m03300_init (KERN_ATTR_TMPS (md5sun_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  /**
   * digest = MD5 (password || puresalt)
   */

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update (&md5_ctx, w, pw_len);

  md5_update (&md5_ctx, s, salt_len);

  md5_final (&md5_ctx);

  tmps[gid].digest_buf[0] = md5_ctx.h[0];
  tmps[gid].digest_buf[1] = md5_ctx.h[1];
  tmps[gid].digest_buf[2] = md5_ctx.h[2];
  tmps[gid].digest_buf[3] = md5_ctx.h[3];
}

KERNEL_FQ KERNEL_FA void m03300_loop (KERN_ATTR_TMPS (md5sun_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * digest
   */

  u32 digest[4];

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];

  /**
   * loop
   */

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    const int coin = sunmd5_coin (digest, j);

    md5_ctx_t md5_ctx;

    md5_init (&md5_ctx);

    u32 d[16] = { 0 };

    d[0] = digest[0];
    d[1] = digest[1];
    d[2] = digest[2];
    d[3] = digest[3];

    md5_update (&md5_ctx, d, 16);

    if (coin == 1)
    {
      sunmd5_update_constant_phrase (&md5_ctx);
    }

    u32 round_buf[4] = { 0 };

    const int round_len = sunmd5_itoa (j, round_buf);

    md5_update (&md5_ctx, round_buf, round_len);

    md5_final (&md5_ctx);

    digest[0] = md5_ctx.h[0];
    digest[1] = md5_ctx.h[1];
    digest[2] = md5_ctx.h[2];
    digest[3] = md5_ctx.h[3];
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

KERNEL_FQ KERNEL_FA void m03300_comp (KERN_ATTR_TMPS (md5sun_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = tmps[gid].digest_buf[DGST_R0];
  const u32 r1 = tmps[gid].digest_buf[DGST_R1];
  const u32 r2 = tmps[gid].digest_buf[DGST_R2];
  const u32 r3 = tmps[gid].digest_buf[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
