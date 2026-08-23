/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg.h)
#include M2S(INCLUDE_PATH/inc_pcfg.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_bignum_operations.cl)
#include M2S(INCLUDE_PATH/inc_radmin3_constants.h)
#endif

typedef struct radmin3
{
  u32 user[64];
  u32 user_len;

  u32 pre[PRECOMP_DATALEN];

} radmin3_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (radmin3_t)

typedef struct pcfg_hash_ctx
{
  sha1_ctx_t ctx0;
  sha1_ctx_t ctx1;
  u32 m[128];
  u32 fact[64];
  GLOBAL_AS const radmin3_t *esalt_bufs;
  u32 digest_pos;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const radmin3_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->esalt_bufs = esalt_bufs;
  hc->digest_pos = digest_pos;

  sha1_init (&hc->ctx0);

  sha1_update_global (&hc->ctx0, esalt_bufs[digest_pos].user, esalt_bufs[digest_pos].user_len);

  sha1_init (&hc->ctx1);

  sha1_update_global (&hc->ctx1, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  hc->m[0] = RADMIN3_M[  0];
  hc->m[1] = RADMIN3_M[  1];
  hc->m[2] = RADMIN3_M[  2];
  hc->m[3] = RADMIN3_M[  3];
  hc->m[4] = RADMIN3_M[  4];
  hc->m[5] = RADMIN3_M[  5];
  hc->m[6] = RADMIN3_M[  6];
  hc->m[7] = RADMIN3_M[  7];
  hc->m[8] = RADMIN3_M[  8];
  hc->m[9] = RADMIN3_M[  9];
  hc->m[10] = RADMIN3_M[ 10];
  hc->m[11] = RADMIN3_M[ 11];
  hc->m[12] = RADMIN3_M[ 12];
  hc->m[13] = RADMIN3_M[ 13];
  hc->m[14] = RADMIN3_M[ 14];
  hc->m[15] = RADMIN3_M[ 15];
  hc->m[16] = RADMIN3_M[ 16];
  hc->m[17] = RADMIN3_M[ 17];
  hc->m[18] = RADMIN3_M[ 18];
  hc->m[19] = RADMIN3_M[ 19];
  hc->m[20] = RADMIN3_M[ 20];
  hc->m[21] = RADMIN3_M[ 21];
  hc->m[22] = RADMIN3_M[ 22];
  hc->m[23] = RADMIN3_M[ 23];
  hc->m[24] = RADMIN3_M[ 24];
  hc->m[25] = RADMIN3_M[ 25];
  hc->m[26] = RADMIN3_M[ 26];
  hc->m[27] = RADMIN3_M[ 27];
  hc->m[28] = RADMIN3_M[ 28];
  hc->m[29] = RADMIN3_M[ 29];
  hc->m[30] = RADMIN3_M[ 30];
  hc->m[31] = RADMIN3_M[ 31];
  hc->m[32] = RADMIN3_M[ 32];
  hc->m[33] = RADMIN3_M[ 33];
  hc->m[34] = RADMIN3_M[ 34];
  hc->m[35] = RADMIN3_M[ 35];
  hc->m[36] = RADMIN3_M[ 36];
  hc->m[37] = RADMIN3_M[ 37];
  hc->m[38] = RADMIN3_M[ 38];
  hc->m[39] = RADMIN3_M[ 39];
  hc->m[40] = RADMIN3_M[ 40];
  hc->m[41] = RADMIN3_M[ 41];
  hc->m[42] = RADMIN3_M[ 42];
  hc->m[43] = RADMIN3_M[ 43];
  hc->m[44] = RADMIN3_M[ 44];
  hc->m[45] = RADMIN3_M[ 45];
  hc->m[46] = RADMIN3_M[ 46];
  hc->m[47] = RADMIN3_M[ 47];
  hc->m[48] = RADMIN3_M[ 48];
  hc->m[49] = RADMIN3_M[ 49];
  hc->m[50] = RADMIN3_M[ 50];
  hc->m[51] = RADMIN3_M[ 51];
  hc->m[52] = RADMIN3_M[ 52];
  hc->m[53] = RADMIN3_M[ 53];
  hc->m[54] = RADMIN3_M[ 54];
  hc->m[55] = RADMIN3_M[ 55];
  hc->m[56] = RADMIN3_M[ 56];
  hc->m[57] = RADMIN3_M[ 57];
  hc->m[58] = RADMIN3_M[ 58];
  hc->m[59] = RADMIN3_M[ 59];
  hc->m[60] = RADMIN3_M[ 60];
  hc->m[61] = RADMIN3_M[ 61];
  hc->m[62] = RADMIN3_M[ 62];
  hc->m[63] = RADMIN3_M[ 63];
  hc->m[64] = RADMIN3_M[ 64];
  hc->m[65] = RADMIN3_M[ 65];
  hc->m[66] = RADMIN3_M[ 66];
  hc->m[67] = RADMIN3_M[ 67];
  hc->m[68] = RADMIN3_M[ 68];
  hc->m[69] = RADMIN3_M[ 69];
  hc->m[70] = RADMIN3_M[ 70];
  hc->m[71] = RADMIN3_M[ 71];
  hc->m[72] = RADMIN3_M[ 72];
  hc->m[73] = RADMIN3_M[ 73];
  hc->m[74] = RADMIN3_M[ 74];
  hc->m[75] = RADMIN3_M[ 75];
  hc->m[76] = RADMIN3_M[ 76];
  hc->m[77] = RADMIN3_M[ 77];
  hc->m[78] = RADMIN3_M[ 78];
  hc->m[79] = RADMIN3_M[ 79];
  hc->m[80] = RADMIN3_M[ 80];
  hc->m[81] = RADMIN3_M[ 81];
  hc->m[82] = RADMIN3_M[ 82];
  hc->m[83] = RADMIN3_M[ 83];
  hc->m[84] = RADMIN3_M[ 84];
  hc->m[85] = RADMIN3_M[ 85];
  hc->m[86] = RADMIN3_M[ 86];
  hc->m[87] = RADMIN3_M[ 87];
  hc->m[88] = RADMIN3_M[ 88];
  hc->m[89] = RADMIN3_M[ 89];
  hc->m[90] = RADMIN3_M[ 90];
  hc->m[91] = RADMIN3_M[ 91];
  hc->m[92] = RADMIN3_M[ 92];
  hc->m[93] = RADMIN3_M[ 93];
  hc->m[94] = RADMIN3_M[ 94];
  hc->m[95] = RADMIN3_M[ 95];
  hc->m[96] = RADMIN3_M[ 96];
  hc->m[97] = RADMIN3_M[ 97];
  hc->m[98] = RADMIN3_M[ 98];
  hc->m[99] = RADMIN3_M[ 99];
  hc->m[100] = RADMIN3_M[100];
  hc->m[101] = RADMIN3_M[101];
  hc->m[102] = RADMIN3_M[102];
  hc->m[103] = RADMIN3_M[103];
  hc->m[104] = RADMIN3_M[104];
  hc->m[105] = RADMIN3_M[105];
  hc->m[106] = RADMIN3_M[106];
  hc->m[107] = RADMIN3_M[107];
  hc->m[108] = RADMIN3_M[108];
  hc->m[109] = RADMIN3_M[109];
  hc->m[110] = RADMIN3_M[110];
  hc->m[111] = RADMIN3_M[111];
  hc->m[112] = RADMIN3_M[112];
  hc->m[113] = RADMIN3_M[113];
  hc->m[114] = RADMIN3_M[114];
  hc->m[115] = RADMIN3_M[115];
  hc->m[116] = RADMIN3_M[116];
  hc->m[117] = RADMIN3_M[117];
  hc->m[118] = RADMIN3_M[118];
  hc->m[119] = RADMIN3_M[119];
  hc->m[120] = RADMIN3_M[120];
  hc->m[121] = RADMIN3_M[121];
  hc->m[122] = RADMIN3_M[122];
  hc->m[123] = RADMIN3_M[123];
  hc->m[124] = RADMIN3_M[124];
  hc->m[125] = RADMIN3_M[125];
  hc->m[126] = RADMIN3_M[126];
  hc->m[127] = RADMIN3_M[127];

  hc->fact[0] = RADMIN3_FACT[ 0];
  hc->fact[1] = RADMIN3_FACT[ 1];
  hc->fact[2] = RADMIN3_FACT[ 2];
  hc->fact[3] = RADMIN3_FACT[ 3];
  hc->fact[4] = RADMIN3_FACT[ 4];
  hc->fact[5] = RADMIN3_FACT[ 5];
  hc->fact[6] = RADMIN3_FACT[ 6];
  hc->fact[7] = RADMIN3_FACT[ 7];
  hc->fact[8] = RADMIN3_FACT[ 8];
  hc->fact[9] = RADMIN3_FACT[ 9];
  hc->fact[10] = RADMIN3_FACT[10];
  hc->fact[11] = RADMIN3_FACT[11];
  hc->fact[12] = RADMIN3_FACT[12];
  hc->fact[13] = RADMIN3_FACT[13];
  hc->fact[14] = RADMIN3_FACT[14];
  hc->fact[15] = RADMIN3_FACT[15];
  hc->fact[16] = RADMIN3_FACT[16];
  hc->fact[17] = RADMIN3_FACT[17];
  hc->fact[18] = RADMIN3_FACT[18];
  hc->fact[19] = RADMIN3_FACT[19];
  hc->fact[20] = RADMIN3_FACT[20];
  hc->fact[21] = RADMIN3_FACT[21];
  hc->fact[22] = RADMIN3_FACT[22];
  hc->fact[23] = RADMIN3_FACT[23];
  hc->fact[24] = RADMIN3_FACT[24];
  hc->fact[25] = RADMIN3_FACT[25];
  hc->fact[26] = RADMIN3_FACT[26];
  hc->fact[27] = RADMIN3_FACT[27];
  hc->fact[28] = RADMIN3_FACT[28];
  hc->fact[29] = RADMIN3_FACT[29];
  hc->fact[30] = RADMIN3_FACT[30];
  hc->fact[31] = RADMIN3_FACT[31];
  hc->fact[32] = RADMIN3_FACT[32];
  hc->fact[33] = RADMIN3_FACT[33];
  hc->fact[34] = RADMIN3_FACT[34];
  hc->fact[35] = RADMIN3_FACT[35];
  hc->fact[36] = RADMIN3_FACT[36];
  hc->fact[37] = RADMIN3_FACT[37];
  hc->fact[38] = RADMIN3_FACT[38];
  hc->fact[39] = RADMIN3_FACT[39];
  hc->fact[40] = RADMIN3_FACT[40];
  hc->fact[41] = RADMIN3_FACT[41];
  hc->fact[42] = RADMIN3_FACT[42];
  hc->fact[43] = RADMIN3_FACT[43];
  hc->fact[44] = RADMIN3_FACT[44];
  hc->fact[45] = RADMIN3_FACT[45];
  hc->fact[46] = RADMIN3_FACT[46];
  hc->fact[47] = RADMIN3_FACT[47];
  hc->fact[48] = RADMIN3_FACT[48];
  hc->fact[49] = RADMIN3_FACT[49];
  hc->fact[50] = RADMIN3_FACT[50];
  hc->fact[51] = RADMIN3_FACT[51];
  hc->fact[52] = RADMIN3_FACT[52];
  hc->fact[53] = RADMIN3_FACT[53];
  hc->fact[54] = RADMIN3_FACT[54];
  hc->fact[55] = RADMIN3_FACT[55];
  hc->fact[56] = RADMIN3_FACT[56];
  hc->fact[57] = RADMIN3_FACT[57];
  hc->fact[58] = RADMIN3_FACT[58];
  hc->fact[59] = RADMIN3_FACT[59];
  hc->fact[60] = RADMIN3_FACT[60];
  hc->fact[61] = RADMIN3_FACT[61];
  hc->fact[62] = RADMIN3_FACT[62];
  hc->fact[63] = RADMIN3_FACT[63];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{

  sha1_ctx_t c0 = hc->ctx0;

  sha1_update_utf16le_swap (&c0, w, len);

  sha1_final (&c0);

  sha1_ctx_t c1 = hc->ctx1;

  u32 w0[4] = { 0 };
  u32 w1[4] = { 0 };
  u32 w2[4] = { 0 };
  u32 w3[4] = { 0 };

  w0[0] = c0.h[0];
  w0[1] = c0.h[1];
  w0[2] = c0.h[2];
  w0[3] = c0.h[3];
  w1[0] = c0.h[4];

  sha1_update_64 (&c1, w0, w1, w2, w3, 20);

  sha1_final (&c1);

  const u32 e[5] = { c1.h[4], c1.h[3], c1.h[2], c1.h[1], c1.h[0] };

  u32 r_t[64] =
  {
    RADMIN3_R[ 0], RADMIN3_R[ 1], RADMIN3_R[ 2], RADMIN3_R[ 3],
    RADMIN3_R[ 4], RADMIN3_R[ 5], RADMIN3_R[ 6], RADMIN3_R[ 7],
    RADMIN3_R[ 8], RADMIN3_R[ 9], RADMIN3_R[10], RADMIN3_R[11],
    RADMIN3_R[12], RADMIN3_R[13], RADMIN3_R[14], RADMIN3_R[15],
    RADMIN3_R[16], RADMIN3_R[17], RADMIN3_R[18], RADMIN3_R[19],
    RADMIN3_R[20], RADMIN3_R[21], RADMIN3_R[22], RADMIN3_R[23],
    RADMIN3_R[24], RADMIN3_R[25], RADMIN3_R[26], RADMIN3_R[27],
    RADMIN3_R[28], RADMIN3_R[29], RADMIN3_R[30], RADMIN3_R[31],
    RADMIN3_R[32], RADMIN3_R[33], RADMIN3_R[34], RADMIN3_R[35],
    RADMIN3_R[36], RADMIN3_R[37], RADMIN3_R[38], RADMIN3_R[39],
    RADMIN3_R[40], RADMIN3_R[41], RADMIN3_R[42], RADMIN3_R[43],
    RADMIN3_R[44], RADMIN3_R[45], RADMIN3_R[46], RADMIN3_R[47],
    RADMIN3_R[48], RADMIN3_R[49], RADMIN3_R[50], RADMIN3_R[51],
    RADMIN3_R[52], RADMIN3_R[53], RADMIN3_R[54], RADMIN3_R[55],
    RADMIN3_R[56], RADMIN3_R[57], RADMIN3_R[58], RADMIN3_R[59],
    RADMIN3_R[60], RADMIN3_R[61], RADMIN3_R[62], RADMIN3_R[63],
  };

  for (u32 i = 0, j = 0; i < PRECOMP_SLOTS; i += 1, j += PRECOMP_ENTRIES - 1)
  {
    const u32 div   = (PRECOMP_BITS * i) / 32;
    const u32 shift = (PRECOMP_BITS * i) % 32;

    u32 cur_sel = (e[div] >> shift) & PRECOMP_MASK;

    if (32 - shift < PRECOMP_BITS)
    {
      cur_sel |= (e[div + 1] << (32 - shift)) & PRECOMP_MASK;
    }

    if (cur_sel == 0) continue;

    const u32 pre_idx = (j + cur_sel - 1) * PRECOMP_ENTRYLEN;

    const u32 pre[64] =
    {
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  0],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  1],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  2],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  3],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  4],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  5],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  6],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  7],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  8],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  9],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 10],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 11],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 12],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 13],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 14],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 15],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 16],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 17],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 18],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 19],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 20],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 21],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 22],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 23],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 24],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 25],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 26],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 27],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 28],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 29],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 30],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 31],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 32],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 33],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 34],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 35],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 36],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 37],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 38],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 39],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 40],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 41],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 42],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 43],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 44],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 45],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 46],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 47],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 48],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 49],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 50],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 51],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 52],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 53],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 54],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 55],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 56],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 57],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 58],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 59],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 60],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 61],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 62],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 63],
    };

    mul_mod128 (r_t, pre, hc->m, hc->fact);
  }

  dgst[0] = r_t[0];
  dgst[1] = r_t[1];
  dgst[2] = r_t[2];
  dgst[3] = r_t[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{

  sha1_ctx_t c0 = hc->ctx0;

  sha1_update_global_utf16le_swap (&c0, w, len);

  sha1_final (&c0);

  sha1_ctx_t c1 = hc->ctx1;

  u32 w0[4] = { 0 };
  u32 w1[4] = { 0 };
  u32 w2[4] = { 0 };
  u32 w3[4] = { 0 };

  w0[0] = c0.h[0];
  w0[1] = c0.h[1];
  w0[2] = c0.h[2];
  w0[3] = c0.h[3];
  w1[0] = c0.h[4];

  sha1_update_64 (&c1, w0, w1, w2, w3, 20);

  sha1_final (&c1);

  const u32 e[5] = { c1.h[4], c1.h[3], c1.h[2], c1.h[1], c1.h[0] };

  u32 r_t[64] =
  {
    RADMIN3_R[ 0], RADMIN3_R[ 1], RADMIN3_R[ 2], RADMIN3_R[ 3],
    RADMIN3_R[ 4], RADMIN3_R[ 5], RADMIN3_R[ 6], RADMIN3_R[ 7],
    RADMIN3_R[ 8], RADMIN3_R[ 9], RADMIN3_R[10], RADMIN3_R[11],
    RADMIN3_R[12], RADMIN3_R[13], RADMIN3_R[14], RADMIN3_R[15],
    RADMIN3_R[16], RADMIN3_R[17], RADMIN3_R[18], RADMIN3_R[19],
    RADMIN3_R[20], RADMIN3_R[21], RADMIN3_R[22], RADMIN3_R[23],
    RADMIN3_R[24], RADMIN3_R[25], RADMIN3_R[26], RADMIN3_R[27],
    RADMIN3_R[28], RADMIN3_R[29], RADMIN3_R[30], RADMIN3_R[31],
    RADMIN3_R[32], RADMIN3_R[33], RADMIN3_R[34], RADMIN3_R[35],
    RADMIN3_R[36], RADMIN3_R[37], RADMIN3_R[38], RADMIN3_R[39],
    RADMIN3_R[40], RADMIN3_R[41], RADMIN3_R[42], RADMIN3_R[43],
    RADMIN3_R[44], RADMIN3_R[45], RADMIN3_R[46], RADMIN3_R[47],
    RADMIN3_R[48], RADMIN3_R[49], RADMIN3_R[50], RADMIN3_R[51],
    RADMIN3_R[52], RADMIN3_R[53], RADMIN3_R[54], RADMIN3_R[55],
    RADMIN3_R[56], RADMIN3_R[57], RADMIN3_R[58], RADMIN3_R[59],
    RADMIN3_R[60], RADMIN3_R[61], RADMIN3_R[62], RADMIN3_R[63],
  };

  for (u32 i = 0, j = 0; i < PRECOMP_SLOTS; i += 1, j += PRECOMP_ENTRIES - 1)
  {
    const u32 div   = (PRECOMP_BITS * i) / 32;
    const u32 shift = (PRECOMP_BITS * i) % 32;

    u32 cur_sel = (e[div] >> shift) & PRECOMP_MASK;

    if (32 - shift < PRECOMP_BITS)
    {
      cur_sel |= (e[div + 1] << (32 - shift)) & PRECOMP_MASK;
    }

    if (cur_sel == 0) continue;

    const u32 pre_idx = (j + cur_sel - 1) * PRECOMP_ENTRYLEN;

    const u32 pre[64] =
    {
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  0],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  1],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  2],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  3],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  4],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  5],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  6],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  7],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  8],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  9],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 10],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 11],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 12],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 13],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 14],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 15],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 16],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 17],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 18],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 19],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 20],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 21],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 22],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 23],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 24],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 25],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 26],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 27],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 28],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 29],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 30],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 31],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 32],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 33],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 34],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 35],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 36],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 37],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 38],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 39],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 40],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 41],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 42],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 43],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 44],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 45],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 46],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 47],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 48],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 49],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 50],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 51],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 52],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 53],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 54],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 55],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 56],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 57],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 58],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 59],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 60],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 61],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 62],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 63],
    };

    mul_mod128 (r_t, pre, hc->m, hc->fact);
  }

  dgst[0] = r_t[0];
  dgst[1] = r_t[1];
  dgst[2] = r_t[2];
  dgst[3] = r_t[3];

  return true;
}

#define PCFG_KERNEL_MXX m29200_mxx
#define PCFG_KERNEL_SXX m29200_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
