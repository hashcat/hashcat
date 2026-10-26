/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_FPGA_AEAD_H
#define HC_FPGA_AEAD_H

#define HCFPGA_AEAD_KEY_BYTES    32
#define HCFPGA_AEAD_NONCE_BYTES  12
#define HCFPGA_AEAD_TAG_BYTES    16

static u32 hcfpga_aead_rd32 (const u8 *p)
{
  const u32 v = ((u32) p[0] << 0) | ((u32) p[1] << 8) | ((u32) p[2] << 16) | ((u32) p[3] << 24);

  return v;
}

static void hcfpga_aead_wr32 (u8 *p, const u32 v)
{
  p[0] = (u8) (v >>  0);
  p[1] = (u8) (v >>  8);
  p[2] = (u8) (v >> 16);
  p[3] = (u8) (v >> 24);
}

static u32 hcfpga_aead_rotl (const u32 v, const u32 n)
{
  const u32 r = (v << n) | (v >> (32 - n));

  return r;
}

static void hcfpga_chacha20_qr (u32 *x, const u32 a, const u32 b, const u32 c, const u32 d)
{
  x[a] += x[b];
  x[d]  = hcfpga_aead_rotl (x[d] ^ x[a], 16);
  x[c] += x[d];
  x[b]  = hcfpga_aead_rotl (x[b] ^ x[c], 12);
  x[a] += x[b];
  x[d]  = hcfpga_aead_rotl (x[d] ^ x[a],  8);
  x[c] += x[d];
  x[b]  = hcfpga_aead_rotl (x[b] ^ x[c],  7);
}

static void hcfpga_chacha20_block (u8 *out, const u8 *key, const u32 counter, const u8 *nonce)
{
  u32 s[16];

  s[ 0] = 0x61707865;
  s[ 1] = 0x3320646e;
  s[ 2] = 0x79622d32;
  s[ 3] = 0x6b206574;

  for (u32 i = 0; i < 8; i++) s[4 + i] = hcfpga_aead_rd32 (&key[i * 4]);

  s[12] = counter;
  s[13] = hcfpga_aead_rd32 (&nonce[0]);
  s[14] = hcfpga_aead_rd32 (&nonce[4]);
  s[15] = hcfpga_aead_rd32 (&nonce[8]);

  u32 x[16];

  for (u32 i = 0; i < 16; i++) x[i] = s[i];

  for (u32 i = 0; i < 10; i++)
  {
    hcfpga_chacha20_qr (x, 0, 4,  8, 12);
    hcfpga_chacha20_qr (x, 1, 5,  9, 13);
    hcfpga_chacha20_qr (x, 2, 6, 10, 14);
    hcfpga_chacha20_qr (x, 3, 7, 11, 15);

    hcfpga_chacha20_qr (x, 0, 5, 10, 15);
    hcfpga_chacha20_qr (x, 1, 6, 11, 12);
    hcfpga_chacha20_qr (x, 2, 7,  8, 13);
    hcfpga_chacha20_qr (x, 3, 4,  9, 14);
  }

  for (u32 i = 0; i < 16; i++) hcfpga_aead_wr32 (&out[i * 4], x[i] + s[i]);
}

static void hcfpga_chacha20_xor (u8 *buf, const u32 len, const u8 *key, const u8 *nonce)
{
  u8 ks[64];

  for (u32 off = 0; off < len; off += 64)
  {
    hcfpga_chacha20_block (ks, key, 1 + (off / 64), nonce);

    const u32 n = ((len - off) >= 64) ? 64 : (len - off);

    for (u32 i = 0; i < n; i++) buf[off + i] ^= ks[i];
  }
}

typedef struct hcfpga_poly1305
{
  u32 r[5];
  u32 h[5];
  u32 s[4];

} hcfpga_poly1305_t;

static void hcfpga_poly1305_init (hcfpga_poly1305_t *p, const u8 *otk)
{
  const u32 t0 = hcfpga_aead_rd32 (&otk[ 0]);
  const u32 t1 = hcfpga_aead_rd32 (&otk[ 4]);
  const u32 t2 = hcfpga_aead_rd32 (&otk[ 8]);
  const u32 t3 = hcfpga_aead_rd32 (&otk[12]);

  p->r[0] = ((t0 >>  0)             ) & 0x3ffffff;
  p->r[1] = ((t0 >> 26) | (t1 <<  6)) & 0x3ffff03;
  p->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
  p->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
  p->r[4] = ((t3 >>  8)             ) & 0x00fffff;

  for (u32 i = 0; i < 5; i++) p->h[i] = 0;

  for (u32 i = 0; i < 4; i++) p->s[i] = hcfpga_aead_rd32 (&otk[16 + (i * 4)]);
}

static void hcfpga_poly1305_block (hcfpga_poly1305_t *p, const u8 *m)
{
  const u32 t0 = hcfpga_aead_rd32 (&m[ 0]);
  const u32 t1 = hcfpga_aead_rd32 (&m[ 4]);
  const u32 t2 = hcfpga_aead_rd32 (&m[ 8]);
  const u32 t3 = hcfpga_aead_rd32 (&m[12]);

  const u32 h0 = p->h[0] + (((t0 >>  0)             ) & 0x3ffffff);
  const u32 h1 = p->h[1] + (((t0 >> 26) | (t1 <<  6)) & 0x3ffffff);
  const u32 h2 = p->h[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
  const u32 h3 = p->h[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
  const u32 h4 = p->h[4] + (((t3 >>  8)             ) | (1u << 24));

  const u32 r0 = p->r[0];
  const u32 r1 = p->r[1];
  const u32 r2 = p->r[2];
  const u32 r3 = p->r[3];
  const u32 r4 = p->r[4];

  const u32 s1 = r1 * 5;
  const u32 s2 = r2 * 5;
  const u32 s3 = r3 * 5;
  const u32 s4 = r4 * 5;

  const u64 d0 = ((u64) h0 * r0) + ((u64) h1 * s4) + ((u64) h2 * s3) + ((u64) h3 * s2) + ((u64) h4 * s1);
  const u64 d1 = ((u64) h0 * r1) + ((u64) h1 * r0) + ((u64) h2 * s4) + ((u64) h3 * s3) + ((u64) h4 * s2);
  const u64 d2 = ((u64) h0 * r2) + ((u64) h1 * r1) + ((u64) h2 * r0) + ((u64) h3 * s4) + ((u64) h4 * s3);
  const u64 d3 = ((u64) h0 * r3) + ((u64) h1 * r2) + ((u64) h2 * r1) + ((u64) h3 * r0) + ((u64) h4 * s4);
  const u64 d4 = ((u64) h0 * r4) + ((u64) h1 * r3) + ((u64) h2 * r2) + ((u64) h3 * r1) + ((u64) h4 * r0);

  u64 e = d0;

  p->h[0] = (u32) e & 0x3ffffff; e = d1 + (e >> 26);
  p->h[1] = (u32) e & 0x3ffffff; e = d2 + (e >> 26);
  p->h[2] = (u32) e & 0x3ffffff; e = d3 + (e >> 26);
  p->h[3] = (u32) e & 0x3ffffff; e = d4 + (e >> 26);
  p->h[4] = (u32) e & 0x3ffffff;

  const u32 top = (u32) (e >> 26);

  p->h[0] += top * 5;
  p->h[1] += p->h[0] >> 26;
  p->h[0] &= 0x3ffffff;
}

static void hcfpga_poly1305_finish (hcfpga_poly1305_t *p, u8 *tag)
{
  u32 h0 = p->h[0];
  u32 h1 = p->h[1];
  u32 h2 = p->h[2];
  u32 h3 = p->h[3];
  u32 h4 = p->h[4];

  h2 += h1 >> 26; h1 &= 0x3ffffff;
  h3 += h2 >> 26; h2 &= 0x3ffffff;
  h4 += h3 >> 26; h3 &= 0x3ffffff;
  h0 += (h4 >> 26) * 5; h4 &= 0x3ffffff;
  h1 += h0 >> 26; h0 &= 0x3ffffff;

  u32 g0 = h0 + 5;
  u32 g1 = h1 + (g0 >> 26); g0 &= 0x3ffffff;
  u32 g2 = h2 + (g1 >> 26); g1 &= 0x3ffffff;
  u32 g3 = h3 + (g2 >> 26); g2 &= 0x3ffffff;
  u32 g4 = h4 + (g3 >> 26) - (1u << 26); g3 &= 0x3ffffff;

  const u32 keep_g = (g4 >> 31) - 1;
  const u32 keep_h = ~keep_g;

  h0 = (h0 & keep_h) | (g0 & keep_g);
  h1 = (h1 & keep_h) | (g1 & keep_g);
  h2 = (h2 & keep_h) | (g2 & keep_g);
  h3 = (h3 & keep_h) | (g3 & keep_g);
  h4 = (h4 & keep_h) | (g4 & keep_g);

  const u32 w0 = (h0 >>  0) | (h1 << 26);
  const u32 w1 = (h1 >>  6) | (h2 << 20);
  const u32 w2 = (h2 >> 12) | (h3 << 14);
  const u32 w3 = (h3 >> 18) | (h4 <<  8);

  u64 f = 0;

  f = (u64) w0 + p->s[0] + (f >> 32); hcfpga_aead_wr32 (&tag[ 0], (u32) f);
  f = (u64) w1 + p->s[1] + (f >> 32); hcfpga_aead_wr32 (&tag[ 4], (u32) f);
  f = (u64) w2 + p->s[2] + (f >> 32); hcfpga_aead_wr32 (&tag[ 8], (u32) f);
  f = (u64) w3 + p->s[3] + (f >> 32); hcfpga_aead_wr32 (&tag[12], (u32) f);
}

static void hcfpga_poly1305_padded (hcfpga_poly1305_t *p, const u8 *m, const u32 len)
{
  u32 off = 0;

  for (; (off + 16) <= len; off += 16) hcfpga_poly1305_block (p, &m[off]);

  if (off >= len) return;

  u8 last[16];

  for (u32 i = 0; i < 16; i++) last[i] = 0;

  for (u32 i = 0; i < (len - off); i++) last[i] = m[off + i];

  hcfpga_poly1305_block (p, last);
}

static void hcfpga_aead_tag (u8 *tag, const u8 *key, const u8 *nonce, const u8 *aad, const u32 aad_len, const u8 *ct, const u32 ct_len)
{
  u8 otk[64];

  hcfpga_chacha20_block (otk, key, 0, nonce);

  hcfpga_poly1305_t p;

  hcfpga_poly1305_init (&p, otk);

  hcfpga_poly1305_padded (&p, aad, aad_len);
  hcfpga_poly1305_padded (&p, ct,  ct_len);

  u8 lens[16];

  hcfpga_aead_wr32 (&lens[ 0], aad_len);
  hcfpga_aead_wr32 (&lens[ 4], 0);
  hcfpga_aead_wr32 (&lens[ 8], ct_len);
  hcfpga_aead_wr32 (&lens[12], 0);

  hcfpga_poly1305_block (&p, lens);

  hcfpga_poly1305_finish (&p, tag);
}

static void hcfpga_aead_seal (const u8 *key, const u8 *nonce, const u8 *aad, const u32 aad_len, u8 *buf, const u32 len, u8 *tag)
{
  hcfpga_chacha20_xor (buf, len, key, nonce);

  hcfpga_aead_tag (tag, key, nonce, aad, aad_len, buf, len);
}

static bool hcfpga_aead_open (const u8 *key, const u8 *nonce, const u8 *aad, const u32 aad_len, u8 *buf, const u32 len, const u8 *tag)
{
  u8 want[HCFPGA_AEAD_TAG_BYTES];

  hcfpga_aead_tag (want, key, nonce, aad, aad_len, buf, len);

  u32 diff = 0;

  for (u32 i = 0; i < HCFPGA_AEAD_TAG_BYTES; i++) diff |= (u32) (want[i] ^ tag[i]);

  if (diff != 0) return false;

  hcfpga_chacha20_xor (buf, len, key, nonce);

  return true;
}

#endif
