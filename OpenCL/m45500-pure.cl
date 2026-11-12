/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha3.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake.cl)
#include M2S(INCLUDE_PATH/inc_hash_groestl.cl)
#include M2S(INCLUDE_PATH/inc_hash_jh.cl)
#include M2S(INCLUDE_PATH/inc_hash_skein512.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// cn_slow_hash v0 (CryptoNight): 2 MiB scratchpad, 2^19 main-loop iterations

#define CN_MEMORY       (2 * 1024 * 1024)
#define CN_MEMORY_WORDS (CN_MEMORY / 4)
#define CN_TOTALBLOCKS  (CN_MEMORY / 16)

typedef struct monero
{
  u32 iv[2];       // blob[0..7]
  u32 ct[8];       // blob[10..41], first 32 bytes of ciphertext
  u32 data[1024];  // full blob
  u32 data_len;
  u32 type;

} monero_t;

typedef struct monero_tmp
{
  u32 a[4];
  u32 b[4];

} monero_tmp_t;

// one 2 MiB scratchpad per candidate; the extra buffer is split into the four
// sub-buffers d_extra0 to d_extra3 and candidates stripe across them by work-group id.
// The mode sets OPTS_TYPE_THREAD_MULTI_DISABLE, so a launch gives each candidate a whole
// work group; the main loop is strictly sequential, so only lane 0 works

DECLSPEC GLOBAL_AS u32 *cn_scratchpad (GLOBAL_AS void *d_extra0_buf, GLOBAL_AS void *d_extra1_buf, GLOBAL_AS void *d_extra2_buf, GLOBAL_AS void *d_extra3_buf, const u64 id)
{
  GLOBAL_AS void *V;

  switch (id % 4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  GLOBAL_AS u32 *ls = (GLOBAL_AS u32 *) V;

  return ls + ((id / 4) * CN_MEMORY_WORDS);
}

// keccak1600 sponge (monero keccak.c: rate 136, pad 0x01 ... 0x80, permutation
// also runs on the final block) over hashcat's sha3_transform

DECLSPEC void cn_keccak1600 (PRIVATE_AS u64 *st, GLOBAL_AS const u32 *pw, const u32 pw_len)
{
  for (int i = 0; i < 25; i++) st[i] = 0;

  u32 off = 0;

  while (pw_len - off >= 136)
  {
    for (int i = 0; i < 17; i++)
    {
      st[i] ^= ((u64) pw[(off / 4) + 2 * i + 1] << 32) | pw[(off / 4) + 2 * i + 0];
    }

    sha3_transform (st);

    off += 136;
  }

  u32 w[34];

  for (int i = 0; i < 34; i++) w[i] = 0;

  const u32 left = pw_len - off;

  for (u32 i = 0; i < left; i++)
  {
    const u32 b = (pw[(off + i) / 4] >> (((off + i) & 3) * 8)) & 0xff;

    w[i / 4] |= b << ((i & 3) * 8);
  }

  w[left / 4] ^= 0x01u << ((left & 3) * 8);
  w[33]       ^= 0x80000000u;

  for (int i = 0; i < 17; i++)
  {
    st[i] ^= ((u64) w[2 * i + 1] << 32) | w[2 * i + 0];
  }

  sha3_transform (st);
}

// AES T-table round in hashcat's big-endian-word form. A monero 16-byte block is
// four little-endian u32 words; swapping each word to big-endian form makes
// hashcat's te0..te3 compute exactly monero's aesb round

DECLSPEC void cn_aesb_round_be (PRIVATE_AS const u32 *x, PRIVATE_AS u32 *y, PRIVATE_AS const u32 *rk, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3)
{
  y[0] = s_te0[(x[0] >> 24) & 0xff] ^ s_te1[(x[1] >> 16) & 0xff] ^ s_te2[(x[2] >>  8) & 0xff] ^ s_te3[(x[3] >>  0) & 0xff] ^ rk[0];
  y[1] = s_te0[(x[1] >> 24) & 0xff] ^ s_te1[(x[2] >> 16) & 0xff] ^ s_te2[(x[3] >>  8) & 0xff] ^ s_te3[(x[0] >>  0) & 0xff] ^ rk[1];
  y[2] = s_te0[(x[2] >> 24) & 0xff] ^ s_te1[(x[3] >> 16) & 0xff] ^ s_te2[(x[0] >>  8) & 0xff] ^ s_te3[(x[1] >>  0) & 0xff] ^ rk[2];
  y[3] = s_te0[(x[3] >> 24) & 0xff] ^ s_te1[(x[0] >> 16) & 0xff] ^ s_te2[(x[1] >>  8) & 0xff] ^ s_te3[(x[2] >>  0) & 0xff] ^ rk[3];
}

// 10 rounds, no initial AddRoundKey (aesb_pseudo_round); blk = 4 LE words

DECLSPEC void cn_aesb_pseudo_round (PRIVATE_AS u32 *blk, PRIVATE_AS const u32 *ks, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3)
{
  u32 x[4];
  u32 y[4];

  x[0] = hc_swap32_S (blk[0]);
  x[1] = hc_swap32_S (blk[1]);
  x[2] = hc_swap32_S (blk[2]);
  x[3] = hc_swap32_S (blk[3]);

  for (int r = 0; r < 10; r++)
  {
    cn_aesb_round_be (x, y, ks + 4 * r, s_te0, s_te1, s_te2, s_te3);

    x[0] = y[0];
    x[1] = y[1];
    x[2] = y[2];
    x[3] = y[3];
  }

  blk[0] = hc_swap32_S (y[0]);
  blk[1] = hc_swap32_S (y[1]);
  blk[2] = hc_swap32_S (y[2]);
  blk[3] = hc_swap32_S (y[3]);
}

// 1 round with a 16-byte key block (aesb_single_round); blk/key = LE words

DECLSPEC void cn_aesb_single_round (PRIVATE_AS u32 *blk, PRIVATE_AS const u32 *key_le, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3)
{
  u32 x[4];
  u32 y[4];
  u32 rk[4];

  x[0] = hc_swap32_S (blk[0]);
  x[1] = hc_swap32_S (blk[1]);
  x[2] = hc_swap32_S (blk[2]);
  x[3] = hc_swap32_S (blk[3]);

  rk[0] = hc_swap32_S (key_le[0]);
  rk[1] = hc_swap32_S (key_le[1]);
  rk[2] = hc_swap32_S (key_le[2]);
  rk[3] = hc_swap32_S (key_le[3]);

  cn_aesb_round_be (x, y, rk, s_te0, s_te1, s_te2, s_te3);

  blk[0] = hc_swap32_S (y[0]);
  blk[1] = hc_swap32_S (y[1]);
  blk[2] = hc_swap32_S (y[2]);
  blk[3] = hc_swap32_S (y[3]);
}

// key_le = the raw 32 key bytes as LE words; aes256_set_encrypt_key swaps its input
// words, so the resulting ks holds the round keys in the BE form the round wants

DECLSPEC void cn_aes256_set_key (PRIVATE_AS u32 *ks_be, PRIVATE_AS const u32 *key_le, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3)
{
  aes256_set_encrypt_key (ks_be, key_le, s_te0, s_te1, s_te2, s_te3);
}

// 64x64 -> 128 multiply with 32-bit limbs (OpenCL has no 128-bit type)

DECLSPEC void cn_mul128 (const u64 m0, const u64 m1, PRIVATE_AS u64 *hi, PRIVATE_AS u64 *lo)
{
  const u64 a0 = (u32) m0;
  const u64 a1 = m0 >> 32;
  const u64 b0 = (u32) m1;
  const u64 b1 = m1 >> 32;

  const u64 p0 = a0 * b0;
  const u64 p1 = a0 * b1;
  const u64 p2 = a1 * b0;
  const u64 p3 = a1 * b1;

  const u64 t = (p0 >> 32) + (u32) p1 + (u32) p2;

  *lo = (p0 & 0xffffffffUL) | (t << 32);
  *hi = p3 + (p1 >> 32) + (p2 >> 32) + (t >> 32);
}

// extra hash dispatch; note monero's "skein" is really Skein-512 with a 256-bit
// digest (skein.c has SKEIN_256_NIST_MAX_HASHBITS = 0)

DECLSPEC void cn_extra_hash (PRIVATE_AS const u32 *state200, PRIVATE_AS u32 *out, SHM_TYPE u64a *s_groestl)
{
  const u32 sel = state200[0] & 3;

  if (sel == 0)
  {
    blake256_ctx_t ctx;

    blake256_init (&ctx, 32);
    blake256_update (&ctx, state200, 200);
    blake256_final (&ctx);

    for (int i = 0; i < 8; i++) out[i] = hc_swap32_S (ctx.h[i]);
  }
  else if (sel == 1)
  {
    groestl256_ctx_t ctx;

    groestl256_init (&ctx, 32, s_groestl);
    groestl256_update (&ctx, state200, 200);
    groestl256_final (&ctx);

    for (int i = 0; i < 4; i++)
    {
      out[2 * i + 0] = (u32) (ctx.h[i] >>  0);
      out[2 * i + 1] = (u32) (ctx.h[i] >> 32);
    }
  }
  else if (sel == 2)
  {
    jh_ctx_t ctx;

    jh_init (&ctx, 32);
    jh_update (&ctx, state200, 200);
    jh_final (&ctx);

    for (int i = 0; i < 4; i++)
    {
      out[2 * i + 0] = (u32) (ctx.h[12 + i] >>  0);
      out[2 * i + 1] = (u32) (ctx.h[12 + i] >> 32);
    }
  }
  else
  {
    skein512_ctx_t ctx;

    skein512_init (&ctx, 32);
    skein512_update (&ctx, state200, 200);
    skein512_final (&ctx);

    for (int i = 0; i < 4; i++)
    {
      out[2 * i + 0] = (u32) (ctx.h[i] >>  0);
      out[2 * i + 1] = (u32) (ctx.h[i] >> 32);
    }
  }
}

// chacha (monero chacha.c, DJB, 8-byte iv, 64-bit counter from 0); only the first
// 32 bytes of the stream are needed for the password verify

DECLSPEC void cn_chacha (const u32 rounds, PRIVATE_AS const u32 *ct8, PRIVATE_AS const u32 *key8, PRIVATE_AS const u32 *iv2, PRIVATE_AS u32 *pt8)
{
  u32 j[16];

  j[ 0] = 0x61707865;   // "expand 32-byte k"
  j[ 1] = 0x3320646e;
  j[ 2] = 0x79622d32;
  j[ 3] = 0x6b206574;

  for (int i = 0; i < 8; i++) j[4 + i] = key8[i];

  j[12] = 0;
  j[13] = 0;
  j[14] = iv2[0];
  j[15] = iv2[1];

  u32 x[16];

  for (int i = 0; i < 16; i++) x[i] = j[i];

  for (u32 i = rounds; i > 0; i -= 2)
  {
    #define QR(a,b,c,d) \
      x[a] += x[b]; x[d] = hc_rotl32_S (x[d] ^ x[a], 16); \
      x[c] += x[d]; x[b] = hc_rotl32_S (x[b] ^ x[c], 12); \
      x[a] += x[b]; x[d] = hc_rotl32_S (x[d] ^ x[a],  8); \
      x[c] += x[d]; x[b] = hc_rotl32_S (x[b] ^ x[c],  7);

    QR (0, 4,  8, 12)
    QR (1, 5,  9, 13)
    QR (2, 6, 10, 14)
    QR (3, 7, 11, 15)
    QR (0, 5, 10, 15)
    QR (1, 6, 11, 12)
    QR (2, 7,  8, 13)
    QR (3, 4,  9, 14)

    #undef QR
  }

  for (int i = 0; i < 16; i++) x[i] += j[i];

  for (int i = 0; i < 8; i++) pt8[i] = ct8[i] ^ x[i];
}

DECLSPEC u32 cn_pt_byte (PRIVATE_AS const u32 *pt, const u32 i)
{
  return (pt[i / 4] >> ((i & 3) * 8)) & 0xff;
}

DECLSPEC bool cn_verify_pt (PRIVATE_AS const u32 *pt)
{
  // memmem (pt, 32, "key_data", 8) || memmem (pt, 32, "m_creation_timestamp", 20)

  const u8 sig1[8]  = { 'k', 'e', 'y', '_', 'd', 'a', 't', 'a' };
  const u8 sig2[20] = { 'm', '_', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', '_', 't', 'i', 'm', 'e', 's', 't', 'a', 'm', 'p' };

  for (u32 i = 0; i <= 32 - 8; i++)
  {
    bool ok = true;

    for (u32 j = 0; j < 8; j++)
    {
      if (cn_pt_byte (pt, i + j) != sig1[j])
      {
        ok = false;
        break;
      }
    }

    if (ok == true) return true;
  }

  for (u32 i = 0; i <= 32 - 20; i++)
  {
    bool ok = true;

    for (u32 j = 0; j < 20; j++)
    {
      if (cn_pt_byte (pt, i + j) != sig2[j])
      {
        ok = false;
        break;
      }
    }

    if (ok == true) return true;
  }

  return false;
}

KERNEL_FQ KERNEL_FA void m45500_init (KERN_ATTR_TMPS_ESALT (monero_tmp_t, monero_t))
{
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;

  #endif

  if (bid >= GID_CNT) return;

  if (lid != 0) return;

  // keccak1600 (password)

  u64 st[25];

  cn_keccak1600 (st, pws[bid].i, pws[bid].pw_len);

  PRIVATE_AS const u32 *st32 = (PRIVATE_AS const u32 *) st;

  // scratchpad fill: key = state[0:32], text = state[64:192]

  GLOBAL_AS u32 *ls = cn_scratchpad (d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bid);

  u32 ks1[60];

  cn_aes256_set_key (ks1, st32 + 0, s_te0, s_te1, s_te2, s_te3);

  u32 text[32];

  for (int i = 0; i < 32; i++) text[i] = st32[16 + i];

  for (u32 i = 0; i < CN_MEMORY / 128; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      cn_aesb_pseudo_round (text + 4 * j, ks1, s_te0, s_te1, s_te2, s_te3);
    }

    for (int j = 0; j < 32; j++) ls[32 * i + j] = text[j];
  }

  // a = state[0:16] ^ state[32:48]; b = state[16:32] ^ state[48:64]

  for (int i = 0; i < 4; i++)
  {
    tmps[bid].a[i] = st32[i + 0] ^ st32[i +  8];
    tmps[bid].b[i] = st32[i + 4] ^ st32[i + 12];
  }
}

KERNEL_FQ KERNEL_FA void m45500_loop (KERN_ATTR_TMPS_ESALT (monero_tmp_t, monero_t))
{
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;

  #endif

  if (bid >= GID_CNT) return;

  if (lid != 0) return;

  GLOBAL_AS u32 *ls = cn_scratchpad (d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bid);

  u32 a[4];
  u32 b[4];

  for (int i = 0; i < 4; i++)
  {
    a[i] = tmps[bid].a[i];
    b[i] = tmps[bid].b[i];
  }

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    // iteration 1: c1 = aesb_single_round (ls[e2i(a)], a); ls[e2i(a)] = c1 ^ b

    const u64 a64_0 = ((u64) a[1] << 32) | a[0];
    const u64 a64_1 = ((u64) a[3] << 32) | a[2];

    u32 j = ((u32) ((a64_0 >> 4) & (CN_TOTALBLOCKS - 1))) * 4;

    u32 c1[4];

    c1[0] = ls[j + 0];
    c1[1] = ls[j + 1];
    c1[2] = ls[j + 2];
    c1[3] = ls[j + 3];

    cn_aesb_single_round (c1, a, s_te0, s_te1, s_te2, s_te3);

    ls[j + 0] = c1[0] ^ b[0];
    ls[j + 1] = c1[1] ^ b[1];
    ls[j + 2] = c1[2] ^ b[2];
    ls[j + 3] = c1[3] ^ b[3];

    // iteration 2: 128-bit mul, a += d, ls[e2i(c1)] = a, a = c2 ^ a, b = c1

    const u64 c164 = ((u64) c1[1] << 32) | c1[0];

    j = ((u32) ((c164 >> 4) & (CN_TOTALBLOCKS - 1))) * 4;

    u32 c2[4];

    c2[0] = ls[j + 0];
    c2[1] = ls[j + 1];
    c2[2] = ls[j + 2];
    c2[3] = ls[j + 3];

    const u64 m1 = ((u64) c2[1] << 32) | c2[0];

    u64 hi = 0;
    u64 lo = 0;

    cn_mul128 (c164, m1, &hi, &lo);

    const u64 na0 = a64_0 + hi;
    const u64 na1 = a64_1 + lo;

    ls[j + 0] = (u32) (na0 >>  0);
    ls[j + 1] = (u32) (na0 >> 32);
    ls[j + 2] = (u32) (na1 >>  0);
    ls[j + 3] = (u32) (na1 >> 32);

    a[0] = c2[0] ^ (u32) (na0 >>  0);
    a[1] = c2[1] ^ (u32) (na0 >> 32);
    a[2] = c2[2] ^ (u32) (na1 >>  0);
    a[3] = c2[3] ^ (u32) (na1 >> 32);

    b[0] = c1[0];
    b[1] = c1[1];
    b[2] = c1[2];
    b[3] = c1[3];
  }

  for (int i = 0; i < 4; i++)
  {
    tmps[bid].a[i] = a[i];
    tmps[bid].b[i] = b[i];
  }
}

KERNEL_FQ KERNEL_FA void m45500_comp (KERN_ATTR_TMPS_ESALT (monero_tmp_t, monero_t))
{
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];

  LOCAL_VK u64a s_groestl[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];

    s_groestl[i] = groestl_t0[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;

  CONSTANT_AS u64a *s_groestl = groestl_t0;

  #endif

  if (bid >= GID_CNT) return;

  if (lid != 0) return;

  // recompute keccak1600 (password): the reassembly needs the AES key from
  // state[32:64] and the original text from state[64:192], keeping tmps tiny

  u64 st[25];

  cn_keccak1600 (st, pws[bid].i, pws[bid].pw_len);

  PRIVATE_AS u32 *st32 = (PRIVATE_AS u32 *) st;

  // reassembly: text ^= scratchpad, pseudo_round with key from state[32:64]

  GLOBAL_AS u32 *ls = cn_scratchpad (d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bid);

  u32 ks2[60];

  cn_aes256_set_key (ks2, st32 + 8, s_te0, s_te1, s_te2, s_te3);

  u32 text[32];

  for (int i = 0; i < 32; i++) text[i] = st32[16 + i];

  for (u32 i = 0; i < CN_MEMORY / 128; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      text[4 * j + 0] ^= ls[32 * i + 4 * j + 0];
      text[4 * j + 1] ^= ls[32 * i + 4 * j + 1];
      text[4 * j + 2] ^= ls[32 * i + 4 * j + 2];
      text[4 * j + 3] ^= ls[32 * i + 4 * j + 3];

      cn_aesb_pseudo_round (text + 4 * j, ks2, s_te0, s_te1, s_te2, s_te3);
    }
  }

  for (int i = 0; i < 16; i++) st[8 + i] = ((u64) text[2 * i + 1] << 32) | text[2 * i + 0];

  // hash_permutation + extra hash

  sha3_transform (st);

  u32 key[8];

  cn_extra_hash ((PRIVATE_AS const u32 *) st, key, s_groestl);

  // verify: decrypt 32 bytes at blob offset 10 with chacha20, fall back to chacha8

  u32 iv[2];
  u32 ct[8];

  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST_BID].iv[0];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST_BID].iv[1];

  for (int i = 0; i < 8; i++) ct[i] = esalt_bufs[DIGESTS_OFFSET_HOST_BID].ct[i];

  u32 pt[8];

  cn_chacha (20, ct, key, iv, pt);

  if (cn_verify_pt (pt) == false)
  {
    cn_chacha (8, ct, key, iv, pt);

    if (cn_verify_pt (pt) == false) return;
  }

  if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST_BID]) == 0)
  {
    mark_hash (plains_buf, d_return_buf, SALT_POS_HOST_BID, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST_BID + 0, bid, 0, 0, 0);
  }

  return;
}
