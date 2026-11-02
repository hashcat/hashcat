/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 */

#ifndef HCFPGA_BCRYPT_REF_H
#define HCFPGA_BCRYPT_REF_H

#include <stdint.h>
#include <string.h>

#include "fpga/hcfpga_bf_const.h"

typedef struct { uint32_t P[18]; uint32_t S[4][256]; } hcfpga_bf_t;

static uint32_t hcfpga_bf_F (const hcfpga_bf_t *st, uint32_t x)
{
  uint32_t a = (x >> 24) & 0xff, b = (x >> 16) & 0xff, c = (x >> 8) & 0xff, d = x & 0xff;

  return ((st->S[0][a] + st->S[1][b]) ^ st->S[2][c]) + st->S[3][d];
}

static void hcfpga_bf_enc (const hcfpga_bf_t *st, uint32_t *l_, uint32_t *r_)
{
  uint32_t l = *l_, r = *r_;

  for (int i = 0; i < 16; i++) { l ^= st->P[i]; r ^= hcfpga_bf_F (st, l); uint32_t t = l; l = r; r = t; }

  uint32_t t = l; l = r; r = t;

  r ^= st->P[16]; l ^= st->P[17];

  *l_ = l; *r_ = r;
}

static void hcfpga_bf_expandkey (hcfpga_bf_t *st, const uint32_t *key, int keyw, const uint32_t *salt, int nsalt)
{
  for (int i = 0; i < 18; i++) st->P[i] ^= key[i % keyw];

  uint32_t l = 0, r = 0; int si = 0;

  for (int i = 0; i < 18; i += 2)
  {
    if (nsalt) { l ^= salt[si % nsalt]; r ^= salt[(si + 1) % nsalt]; si = (si + 2) % nsalt; }
    hcfpga_bf_enc (st, &l, &r); st->P[i] = l; st->P[i + 1] = r;
  }

  for (int bi = 0; bi < 4; bi++) for (int j = 0; j < 256; j += 2)
  {
    if (nsalt) { l ^= salt[si % nsalt]; r ^= salt[(si + 1) % nsalt]; si = (si + 2) % nsalt; }
    hcfpga_bf_enc (st, &l, &r); st->S[bi][j] = l; st->S[bi][j + 1] = r;
  }
}

static void hcfpga_bcrypt_canary (const uint32_t ek18[18], const uint32_t salt4[4], int rounds, uint32_t out[6])
{
  hcfpga_bf_t st; memcpy (st.P, BF_P_INIT, sizeof st.P); memcpy (st.S, BF_S_INIT, sizeof st.S);

  hcfpga_bf_expandkey (&st, ek18, 18, salt4, 4);

  for (int it = 0; it < rounds; it++) { hcfpga_bf_expandkey (&st, ek18, 18, 0, 0); hcfpga_bf_expandkey (&st, salt4, 4, 0, 0); }

  const char *mag = "OrpheanBeholderScryDoubt";

  uint32_t ct[6];

  for (int k = 0; k < 6; k++) ct[k] = ((uint32_t)(uint8_t)mag[4*k] << 24) | ((uint32_t)(uint8_t)mag[4*k+1] << 16) | ((uint32_t)(uint8_t)mag[4*k+2] << 8) | (uint8_t)mag[4*k+3];

  for (int r = 0; r < 64; r++) for (int k = 0; k < 6; k += 2) hcfpga_bf_enc (&st, &ct[k], &ct[k+1]);

  for (int k = 0; k < 6; k++) out[k] = ct[k];
}

#endif
