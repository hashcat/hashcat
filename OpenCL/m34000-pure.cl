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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct pbkdf2_sha256_tmpx
{
  u32x  ipad[8];
  u32x  opad[8];

  u32x  dgst[32];
  u32x  out[32];

} pbkdf2_sha256_tmpx_t;

typedef struct racf_kdfaes_tmp
{
  u32  key[16];
  u32  salt_buf[16];
  u32  salt_len;

  u32  out[256]; // change for mem_fact > 10
  u32  out_len;

  pbkdf2_sha256_tmp_t pbkdf2_tmps;
} racf_kdfaes_tmp_t;

typedef struct racf_kdfaes
{
  u32 salt_buf[64];
  u32 mem_fac;
  u32 rep_fac;

} racf_kdfaes_t;

CONSTANT_VK u32a c_ascii_to_ebcdic_pc[256] =
{
  // little hack, can't crack 0-bytes in password, but who cares
  //    0xab, 0xa8, 0xae, 0xad, 0xc4, 0xf1, 0xf7, 0xf4, 0x86, 0xa1, 0xe0, 0xbc, 0xb3, 0xb0, 0xb6, 0xb5,
  0x2a, 0xa8, 0xae, 0xad, 0xc4, 0xf1, 0xf7, 0xf4, 0x86, 0xa1, 0xe0, 0xbc, 0xb3, 0xb0, 0xb6, 0xb5,
  0x8a, 0x89, 0x8f, 0x8c, 0xd3, 0xd0, 0xce, 0xe6, 0x9b, 0x98, 0xd5, 0xe5, 0x92, 0x91, 0x97, 0x94,
  0x2a, 0x34, 0x54, 0x5d, 0x1c, 0x73, 0x0b, 0x51, 0x31, 0x10, 0x13, 0x37, 0x7c, 0x6b, 0x3d, 0x68,
  0x4a, 0x49, 0x4f, 0x4c, 0x43, 0x40, 0x46, 0x45, 0x5b, 0x58, 0x5e, 0x16, 0x32, 0x57, 0x76, 0x75,
  0x52, 0x29, 0x2f, 0x2c, 0x23, 0x20, 0x26, 0x25, 0x3b, 0x38, 0x08, 0x0e, 0x0d, 0x02, 0x01, 0x07,
  0x04, 0x1a, 0x19, 0x6e, 0x6d, 0x62, 0x61, 0x67, 0x64, 0x7a, 0x79, 0x3e, 0x6b, 0x1f, 0x15, 0x70,
  0x58, 0xa8, 0xae, 0xad, 0xa2, 0xa1, 0xa7, 0xa4, 0xba, 0xb9, 0x89, 0x8f, 0x8c, 0x83, 0x80, 0x86,
  0x85, 0x9b, 0x98, 0xef, 0xec, 0xe3, 0xe0, 0xe6, 0xe5, 0xfb, 0xf8, 0x2a, 0x7f, 0x0b, 0xe9, 0xa4,
  0xea, 0xe9, 0xef, 0xec, 0xe3, 0x80, 0xa7, 0x85, 0xfb, 0xf8, 0xfe, 0xfd, 0xf2, 0xb9, 0xbf, 0x9d,
  0xcb, 0xc8, 0x9e, 0xcd, 0xc2, 0xc1, 0xc7, 0xba, 0xda, 0xd9, 0xdf, 0xdc, 0xa2, 0x83, 0xd6, 0x68,
  0x29, 0x2f, 0x2c, 0x23, 0x20, 0x26, 0x25, 0x3b, 0x38, 0x08, 0x0e, 0x0d, 0x02, 0x01, 0x07, 0x04,
  0x1a, 0x19, 0x6e, 0x6d, 0x62, 0x61, 0x67, 0x64, 0x7a, 0x79, 0x4a, 0x49, 0x4f, 0x4c, 0x43, 0x40,
  0x46, 0x45, 0x5b, 0xab, 0xbf, 0xbc, 0xb3, 0xb0, 0xb6, 0xb5, 0x8a, 0x9e, 0x9d, 0x92, 0x91, 0x97,
  0x94, 0xea, 0xfe, 0xfd, 0xf2, 0xf1, 0xf7, 0xf4, 0xcb, 0xc8, 0xce, 0xcd, 0xc2, 0xc1, 0xc7, 0xc4,
  0xda, 0xd9, 0xdf, 0xdc, 0xd3, 0xd0, 0xd6, 0xd5, 0x3e, 0x3d, 0x32, 0x31, 0x37, 0x34, 0x1f, 0x1c,
  0x13, 0x10, 0x16, 0x15, 0x7f, 0x7c, 0x73, 0x70, 0x76, 0x75, 0x5e, 0x5d, 0x52, 0x51, 0x57, 0x54,
};

#if   VECT_SIZE == 1
#define pbkdf2_sha256_packv(arr,var,idx) make_u32x ((arr)[0].var[(idx)])
#elif   VECT_SIZE == 2
#define pbkdf2_sha256_packv(arr,var,idx) make_u32x ((arr)[0].var[(idx)], ((arr)[1].var[(idx)]))
#elif   VECT_SIZE == 4
#define pbkdf2_sha256_packv(arr,var,idx) make_u32x ((arr)[0].var[(idx)], ((arr)[1].var[(idx)]), (arr)[2].var[(idx)], ((arr)[3].var[(idx)]))
#elif   VECT_SIZE == 8
#define pbkdf2_sha256_packv(arr,var,idx) make_u32x ((arr)[0].var[(idx)], ((arr)[1].var[(idx)]), (arr)[2].var[(idx)], ((arr)[3].var[(idx)]), (arr)[4].var[(idx)], ((arr)[5].var[(idx)]), (arr)[6].var[(idx)], ((arr)[7].var[(idx)]))
#elif   VECT_SIZE == 16
#define pbkdf2_sha256_packv(arr,var,idx) make_u32x ((arr)[0].var[(idx)], ((arr)[1].var[(idx)]), (arr)[2].var[(idx)], ((arr)[3].var[(idx)]), (arr)[4].var[(idx)], ((arr)[5].var[(idx)]), (arr)[6].var[(idx)], ((arr)[7].var[(idx)]), (arr)[8].var[(idx)], ((arr)[9].var[(idx)]), (arr)[10].var[(idx)], ((arr)[11].var[(idx)]), (arr)[12].var[(idx)], ((arr)[13].var[(idx)]), (arr)[14].var[(idx)], ((arr)[15].var[(idx)]))
#endif

#if   VECT_SIZE == 1
#define pbkdf2_sha256_unpackv(arr,var,idx,val) (arr)[0].var[(idx)] = val[(idx)];
#elif   VECT_SIZE == 2
#define pbkdf2_sha256_unpackv(arr,var,idx,val) (arr)[0].var[(idx)] = val[(idx)].s0; (arr)[1].var[(idx)] = val[(idx)].s1;
#elif   VECT_SIZE == 4
#define pbkdf2_sha256_unpackv(arr,var,idx,val) (arr)[0].var[(idx)] = val[(idx)].s0; (arr)[1].var[(idx)] = val[(idx)].s1; (arr)[2].var[(idx)] = val[(idx)].s2; (arr)[3].var[(idx)] = val[(idx)].s3;
#elif   VECT_SIZE == 8
#define pbkdf2_sha256_unpackv(arr,var,idx,val) (arr)[0].var[(idx)] = val[(idx)].s0; (arr)[1].var[(idx)] = val[(idx)].s1; (arr)[2].var[(idx)] = val[(idx)].s2; (arr)[3].var[(idx)] = val[(idx)].s3; (arr)[4].var[(idx)] = val[(idx)].s4; (arr)[5].var[(idx)] = val[(idx)].s5; (arr)[6].var[(idx)] = val[(idx)].s6; (arr)[7].var[(idx)] = val[(idx)].s7;
#elif   VECT_SIZE == 16
#define pbkdf2_sha256_unpackv(arr,var,idx,val) (arr)[0].var[(idx)] = val[(idx)].s0; (arr)[1].var[(idx)] = val[(idx)].s1; (arr)[2].var[(idx)] = val[(idx)].s2; (arr)[3].var[(idx)] = val[(idx)].s3; (arr)[4].var[(idx)] = val[(idx)].s4; (arr)[5].var[(idx)] = val[(idx)].s5; (arr)[6].var[(idx)] = val[(idx)].s6; (arr)[7].var[(idx)] = val[(idx)].s7; (arr)[8].var[(idx)] = val[(idx)].s8; (arr)[9].var[(idx)] = val[(idx)].s9; (arr)[10].var[(idx)] = val[(idx)].sa; (arr)[11].var[(idx)] = val[(idx)].sb; (arr)[12].var[(idx)] = val[(idx)].sc; (arr)[13].var[(idx)] = val[(idx)].sd; (arr)[14].var[(idx)] = val[(idx)].se; (arr)[15].var[(idx)] = val[(idx)].sf;
#endif

DECLSPEC void convert_pbkdf2_sha256_from_V(pbkdf2_sha256_tmpx_t *tmpx, pbkdf2_sha256_tmp_t *tmps)
{
  pbkdf2_sha256_unpackv (tmps, ipad, 0, tmpx->ipad);
  pbkdf2_sha256_unpackv (tmps, ipad, 1, tmpx->ipad);
  pbkdf2_sha256_unpackv (tmps, ipad, 2, tmpx->ipad);
  pbkdf2_sha256_unpackv (tmps, ipad, 3, tmpx->ipad);
  pbkdf2_sha256_unpackv (tmps, ipad, 4, tmpx->ipad);
  pbkdf2_sha256_unpackv (tmps, ipad, 5, tmpx->ipad);
  pbkdf2_sha256_unpackv (tmps, ipad, 6, tmpx->ipad);
  pbkdf2_sha256_unpackv (tmps, ipad, 7, tmpx->ipad);

  pbkdf2_sha256_unpackv (tmps, opad, 0, tmpx->opad);
  pbkdf2_sha256_unpackv (tmps, opad, 1, tmpx->opad);
  pbkdf2_sha256_unpackv (tmps, opad, 2, tmpx->opad);
  pbkdf2_sha256_unpackv (tmps, opad, 3, tmpx->opad);
  pbkdf2_sha256_unpackv (tmps, opad, 4, tmpx->opad);
  pbkdf2_sha256_unpackv (tmps, opad, 5, tmpx->opad);
  pbkdf2_sha256_unpackv (tmps, opad, 6, tmpx->opad);
  pbkdf2_sha256_unpackv (tmps, opad, 7, tmpx->opad);

  pbkdf2_sha256_unpackv (tmps, dgst, 0, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 1, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 2, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 3, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 4, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 5, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 6, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 7, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 8, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 9, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 10, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 11, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 12, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 13, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 14, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 15, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 16, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 17, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 18, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 19, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 20, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 21, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 22, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 23, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 24, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 25, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 26, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 27, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 28, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 29, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 30, tmpx->dgst);
  pbkdf2_sha256_unpackv (tmps, dgst, 31, tmpx->dgst);

  pbkdf2_sha256_unpackv (tmps, out, 0, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 1, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 2, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 3, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 4, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 5, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 6, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 7, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 8, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 9, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 10, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 11, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 12, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 13, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 14, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 15, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 16, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 17, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 18, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 19, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 20, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 21, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 22, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 23, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 24, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 25, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 26, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 27, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 28, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 29, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 30, tmpx->out);
  pbkdf2_sha256_unpackv (tmps, out, 31, tmpx->out);
}

DECLSPEC void convert_pbkdf2_sha256_to_V(pbkdf2_sha256_tmp_t *tmps, pbkdf2_sha256_tmpx_t *tmpx)
{
  tmpx->ipad[0] = pbkdf2_sha256_packv (tmps, ipad, 0);
  tmpx->ipad[1] = pbkdf2_sha256_packv (tmps, ipad, 1);
  tmpx->ipad[2] = pbkdf2_sha256_packv (tmps, ipad, 2);
  tmpx->ipad[3] = pbkdf2_sha256_packv (tmps, ipad, 3);
  tmpx->ipad[4] = pbkdf2_sha256_packv (tmps, ipad, 4);
  tmpx->ipad[5] = pbkdf2_sha256_packv (tmps, ipad, 5);
  tmpx->ipad[6] = pbkdf2_sha256_packv (tmps, ipad, 6);
  tmpx->ipad[7] = pbkdf2_sha256_packv (tmps, ipad, 7);

  tmpx->opad[0] = pbkdf2_sha256_packv (tmps, opad, 0);
  tmpx->opad[1] = pbkdf2_sha256_packv (tmps, opad, 1);
  tmpx->opad[2] = pbkdf2_sha256_packv (tmps, opad, 2);
  tmpx->opad[3] = pbkdf2_sha256_packv (tmps, opad, 3);
  tmpx->opad[4] = pbkdf2_sha256_packv (tmps, opad, 4);
  tmpx->opad[5] = pbkdf2_sha256_packv (tmps, opad, 5);
  tmpx->opad[6] = pbkdf2_sha256_packv (tmps, opad, 6);
  tmpx->opad[7] = pbkdf2_sha256_packv (tmps, opad, 7);

  tmpx->dgst[0] = pbkdf2_sha256_packv (tmps, dgst, 0);
  tmpx->dgst[1] = pbkdf2_sha256_packv (tmps, dgst, 1);
  tmpx->dgst[2] = pbkdf2_sha256_packv (tmps, dgst, 2);
  tmpx->dgst[3] = pbkdf2_sha256_packv (tmps, dgst, 3);
  tmpx->dgst[4] = pbkdf2_sha256_packv (tmps, dgst, 4);
  tmpx->dgst[5] = pbkdf2_sha256_packv (tmps, dgst, 5);
  tmpx->dgst[6] = pbkdf2_sha256_packv (tmps, dgst, 6);
  tmpx->dgst[7] = pbkdf2_sha256_packv (tmps, dgst, 7);
  tmpx->dgst[8] = pbkdf2_sha256_packv (tmps, dgst, 8);
  tmpx->dgst[9] = pbkdf2_sha256_packv (tmps, dgst, 9);
  tmpx->dgst[10] = pbkdf2_sha256_packv (tmps, dgst, 10);
  tmpx->dgst[11] = pbkdf2_sha256_packv (tmps, dgst, 11);
  tmpx->dgst[12] = pbkdf2_sha256_packv (tmps, dgst, 12);
  tmpx->dgst[13] = pbkdf2_sha256_packv (tmps, dgst, 13);
  tmpx->dgst[14] = pbkdf2_sha256_packv (tmps, dgst, 14);
  tmpx->dgst[15] = pbkdf2_sha256_packv (tmps, dgst, 15);
  tmpx->dgst[16] = pbkdf2_sha256_packv (tmps, dgst, 16);
  tmpx->dgst[17] = pbkdf2_sha256_packv (tmps, dgst, 17);
  tmpx->dgst[18] = pbkdf2_sha256_packv (tmps, dgst, 18);
  tmpx->dgst[19] = pbkdf2_sha256_packv (tmps, dgst, 19);
  tmpx->dgst[20] = pbkdf2_sha256_packv (tmps, dgst, 20);
  tmpx->dgst[21] = pbkdf2_sha256_packv (tmps, dgst, 21);
  tmpx->dgst[22] = pbkdf2_sha256_packv (tmps, dgst, 22);
  tmpx->dgst[23] = pbkdf2_sha256_packv (tmps, dgst, 23);
  tmpx->dgst[24] = pbkdf2_sha256_packv (tmps, dgst, 24);
  tmpx->dgst[25] = pbkdf2_sha256_packv (tmps, dgst, 25);
  tmpx->dgst[26] = pbkdf2_sha256_packv (tmps, dgst, 26);
  tmpx->dgst[27] = pbkdf2_sha256_packv (tmps, dgst, 27);
  tmpx->dgst[28] = pbkdf2_sha256_packv (tmps, dgst, 28);
  tmpx->dgst[29] = pbkdf2_sha256_packv (tmps, dgst, 29);
  tmpx->dgst[30] = pbkdf2_sha256_packv (tmps, dgst, 30);
  tmpx->dgst[31] = pbkdf2_sha256_packv (tmps, dgst, 31);

  tmpx->out[0] = pbkdf2_sha256_packv (tmps, out, 0);
  tmpx->out[1] = pbkdf2_sha256_packv (tmps, out, 1);
  tmpx->out[2] = pbkdf2_sha256_packv (tmps, out, 2);
  tmpx->out[3] = pbkdf2_sha256_packv (tmps, out, 3);
  tmpx->out[4] = pbkdf2_sha256_packv (tmps, out, 4);
  tmpx->out[5] = pbkdf2_sha256_packv (tmps, out, 5);
  tmpx->out[6] = pbkdf2_sha256_packv (tmps, out, 6);
  tmpx->out[7] = pbkdf2_sha256_packv (tmps, out, 7);
  tmpx->out[8] = pbkdf2_sha256_packv (tmps, out, 8);
  tmpx->out[9] = pbkdf2_sha256_packv (tmps, out, 9);
  tmpx->out[10] = pbkdf2_sha256_packv (tmps, out, 10);
  tmpx->out[11] = pbkdf2_sha256_packv (tmps, out, 11);
  tmpx->out[12] = pbkdf2_sha256_packv (tmps, out, 12);
  tmpx->out[13] = pbkdf2_sha256_packv (tmps, out, 13);
  tmpx->out[14] = pbkdf2_sha256_packv (tmps, out, 14);
  tmpx->out[15] = pbkdf2_sha256_packv (tmps, out, 15);
  tmpx->out[16] = pbkdf2_sha256_packv (tmps, out, 16);
  tmpx->out[17] = pbkdf2_sha256_packv (tmps, out, 17);
  tmpx->out[18] = pbkdf2_sha256_packv (tmps, out, 18);
  tmpx->out[19] = pbkdf2_sha256_packv (tmps, out, 19);
  tmpx->out[20] = pbkdf2_sha256_packv (tmps, out, 20);
  tmpx->out[21] = pbkdf2_sha256_packv (tmps, out, 21);
  tmpx->out[22] = pbkdf2_sha256_packv (tmps, out, 22);
  tmpx->out[23] = pbkdf2_sha256_packv (tmps, out, 23);
  tmpx->out[24] = pbkdf2_sha256_packv (tmps, out, 24);
  tmpx->out[25] = pbkdf2_sha256_packv (tmps, out, 25);
  tmpx->out[26] = pbkdf2_sha256_packv (tmps, out, 26);
  tmpx->out[27] = pbkdf2_sha256_packv (tmps, out, 27);
  tmpx->out[28] = pbkdf2_sha256_packv (tmps, out, 28);
  tmpx->out[29] = pbkdf2_sha256_packv (tmps, out, 29);
  tmpx->out[30] = pbkdf2_sha256_packv (tmps, out, 30);
  tmpx->out[31] = pbkdf2_sha256_packv (tmps, out, 31);
}

DECLSPEC void transform_racf_key (const u32 w0, const u32 w1, PRIVATE_AS u32 *key)
{
  key[0] = c_ascii_to_ebcdic_pc[((w0 >>  0) & 0xff)] << 0
         | c_ascii_to_ebcdic_pc[((w0 >>  8) & 0xff)] << 8
         | c_ascii_to_ebcdic_pc[((w0 >>  16) & 0xff)] << 16
         | c_ascii_to_ebcdic_pc[((w0 >>  24) & 0xff)] << 24;

  key[1] = c_ascii_to_ebcdic_pc[((w1 >>  0) & 0xff)] << 0
         | c_ascii_to_ebcdic_pc[((w1 >>  8) & 0xff)] << 8
         | c_ascii_to_ebcdic_pc[((w1 >>  16) & 0xff)] << 16
         | c_ascii_to_ebcdic_pc[((w1 >>  24) & 0xff)] << 24;
}

KERNEL_FQ void m34000_init (KERN_ATTR_TMPS_ESALT (racf_kdfaes_tmp_t, racf_kdfaes_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * DES shared
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

  // DES
  u32 key[2];

  transform_racf_key (pws[gid].i[ 0], pws[gid].i[ 1], key);

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup (key[0], key[1], Kc, Kd, s_skb);

  u32 data[2];

  data[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  data[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];

  u32 des_output[2];
  _des_crypt_encrypt (des_output, data, Kc, Kd, s_SPtrans);
  
  // set tmps->key
  tmps[gid].key[0] = hc_swap32_S(des_output[0]);
  tmps[gid].key[1] = hc_swap32_S(des_output[1]);
  tmps[gid].key[2] = 0;
  tmps[gid].key[3] = 0;
  tmps[gid].key[4] = 0;
  tmps[gid].key[5] = 0;
  tmps[gid].key[6] = 0;
  tmps[gid].key[7] = 0;

  // set tmps->salt_buf
  tmps[gid].salt_buf[0] = hc_swap32_S(esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[0]);
  tmps[gid].salt_buf[1] = hc_swap32_S(esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[1]);
  tmps[gid].salt_buf[2] = hc_swap32_S(esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[2]);
  tmps[gid].salt_buf[3] = hc_swap32_S(esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[3]);
  tmps[gid].salt_buf[4] = esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac; // todo: WHY? just set 0. Need to try
  tmps[gid].salt_buf[5] = 0;
  tmps[gid].salt_buf[6] = 0;
  tmps[gid].salt_buf[7] = 0;
  tmps[gid].salt_buf[8] = 0;
  tmps[gid].salt_buf[9] = 0;
  tmps[gid].salt_buf[10] = 0;
  tmps[gid].salt_buf[11] = 0;
  tmps[gid].salt_buf[12] = 0;
  tmps[gid].salt_buf[13] = 0;
  tmps[gid].salt_buf[14] = 0;
  tmps[gid].salt_buf[15] = 0;
  tmps[gid].salt_len = 20;

  tmps[gid].out_len = 0;

}

DECLSPEC void hmac_sha256_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}


DECLSPEC void racf_pbkdf_sha256_hmac_V(u32x *key, u32 key_len, u32x *salt, u32 salt_len, u32 iteration, pbkdf2_sha256_tmpx_t* tmpx)
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * PBKDF2-SHA256-HMAC init  
   */

  sha256_hmac_ctx_vector_t sha256_hmac_ctx;

  sha256_hmac_init_vector (&sha256_hmac_ctx, key, key_len);

  tmpx->ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmpx->ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmpx->ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmpx->ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmpx->ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmpx->ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmpx->ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmpx->ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmpx->opad[0] = sha256_hmac_ctx.opad.h[0];
  tmpx->opad[1] = sha256_hmac_ctx.opad.h[1];
  tmpx->opad[2] = sha256_hmac_ctx.opad.h[2];
  tmpx->opad[3] = sha256_hmac_ctx.opad.h[3];
  tmpx->opad[4] = sha256_hmac_ctx.opad.h[4];
  tmpx->opad[5] = sha256_hmac_ctx.opad.h[5];
  tmpx->opad[6] = sha256_hmac_ctx.opad.h[6];
  tmpx->opad[7] = sha256_hmac_ctx.opad.h[7];

  sha256_hmac_update_vector (&sha256_hmac_ctx, salt, salt_len);

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w0[0] = 1;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_update_vector_64 (&sha256_hmac_ctx, w0, w1, w2, w3, 4);

  sha256_hmac_final_vector (&sha256_hmac_ctx);

  tmpx->dgst[0] = sha256_hmac_ctx.opad.h[0];
  tmpx->dgst[1] = sha256_hmac_ctx.opad.h[1];
  tmpx->dgst[2] = sha256_hmac_ctx.opad.h[2];
  tmpx->dgst[3] = sha256_hmac_ctx.opad.h[3];
  tmpx->dgst[4] = sha256_hmac_ctx.opad.h[4];
  tmpx->dgst[5] = sha256_hmac_ctx.opad.h[5];
  tmpx->dgst[6] = sha256_hmac_ctx.opad.h[6];
  tmpx->dgst[7] = sha256_hmac_ctx.opad.h[7];

  tmpx->out[0] = tmpx->dgst[0];
  tmpx->out[1] = tmpx->dgst[1];
  tmpx->out[2] = tmpx->dgst[2];
  tmpx->out[3] = tmpx->dgst[3];
  tmpx->out[4] = tmpx->dgst[4];
  tmpx->out[5] = tmpx->dgst[5];
  tmpx->out[6] = tmpx->dgst[6];
  tmpx->out[7] = tmpx->dgst[7];

  /**
   * PBKDF2-SHA256-HMAC loop  
   */

  // convert tmpx to array sha256_tmps[VECT_SIZE]

  pbkdf2_sha256_tmp_t sha256_tmps[VECT_SIZE] = {0};
  convert_pbkdf2_sha256_from_V(tmpx, sha256_tmps);

  // main loop for PBKDF2-SHA256-HMAC

  u32x ipad[8];
  u32x opad[8];
  u32x dgst[8];
  u32x out[8];
  u32x last_dgst[8] = {0};

  // extract data from sha256_tmps: ipad, opad, dgst, out
  ipad[0] = packv (sha256_tmps, ipad, 0, 0);
  ipad[1] = packv (sha256_tmps, ipad, 0, 1);
  ipad[2] = packv (sha256_tmps, ipad, 0, 2);
  ipad[3] = packv (sha256_tmps, ipad, 0, 3);
  ipad[4] = packv (sha256_tmps, ipad, 0, 4);
  ipad[5] = packv (sha256_tmps, ipad, 0, 5);
  ipad[6] = packv (sha256_tmps, ipad, 0, 6);
  ipad[7] = packv (sha256_tmps, ipad, 0, 7);

  opad[0] = packv (sha256_tmps, opad, 0, 0);
  opad[1] = packv (sha256_tmps, opad, 0, 1);
  opad[2] = packv (sha256_tmps, opad, 0, 2);
  opad[3] = packv (sha256_tmps, opad, 0, 3);
  opad[4] = packv (sha256_tmps, opad, 0, 4);
  opad[5] = packv (sha256_tmps, opad, 0, 5);
  opad[6] = packv (sha256_tmps, opad, 0, 6);
  opad[7] = packv (sha256_tmps, opad, 0, 7);

  dgst[0] = packv (sha256_tmps, dgst, 0, 0);
  dgst[1] = packv (sha256_tmps, dgst, 0, 1);
  dgst[2] = packv (sha256_tmps, dgst, 0, 2);
  dgst[3] = packv (sha256_tmps, dgst, 0, 3);
  dgst[4] = packv (sha256_tmps, dgst, 0, 4);
  dgst[5] = packv (sha256_tmps, dgst, 0, 5);
  dgst[6] = packv (sha256_tmps, dgst, 0, 6);
  dgst[7] = packv (sha256_tmps, dgst, 0, 7);

  out[0] = packv (sha256_tmps, out, 0, 0);
  out[1] = packv (sha256_tmps, out, 0, 1);
  out[2] = packv (sha256_tmps, out, 0, 2);
  out[3] = packv (sha256_tmps, out, 0, 3);
  out[4] = packv (sha256_tmps, out, 0, 4);
  out[5] = packv (sha256_tmps, out, 0, 5);
  out[6] = packv (sha256_tmps, out, 0, 6);
  out[7] = packv (sha256_tmps, out, 0, 7);

  // PBKDF2-SHA256-HMAC iterations
  for (u32 i = 0; i < iteration - 1; i += 1)
  {
    // save digest of pre-last iteration
    if (i + 1 == iteration - 1) {
      last_dgst[0] = dgst[0];
      last_dgst[1] = dgst[1];
      last_dgst[2] = dgst[2];
      last_dgst[3] = dgst[3];
      last_dgst[4] = dgst[4];
      last_dgst[5] = dgst[5];
      last_dgst[6] = dgst[6];
      last_dgst[7] = dgst[7];
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = dgst[0];
    w0[1] = dgst[1];
    w0[2] = dgst[2];
    w0[3] = dgst[3];
    w1[0] = dgst[4];
    w1[1] = dgst[5];
    w1[2] = dgst[6];
    w1[3] = dgst[7];
    w2[0] = 0x80000000;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 32) * 8;

    hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

    out[0] ^= dgst[0];
    out[1] ^= dgst[1];
    out[2] ^= dgst[2];
    out[3] ^= dgst[3];
    out[4] ^= dgst[4];
    out[5] ^= dgst[5];
    out[6] ^= dgst[6];
    out[7] ^= dgst[7];
  }

  // save data (last_dgst, out) into sha256_tmps
  unpackv (sha256_tmps, dgst, 0, 0, last_dgst[0]);
  unpackv (sha256_tmps, dgst, 0, 1, last_dgst[1]);
  unpackv (sha256_tmps, dgst, 0, 2, last_dgst[2]);
  unpackv (sha256_tmps, dgst, 0, 3, last_dgst[3]);
  unpackv (sha256_tmps, dgst, 0, 4, last_dgst[4]);
  unpackv (sha256_tmps, dgst, 0, 5, last_dgst[5]);
  unpackv (sha256_tmps, dgst, 0, 6, last_dgst[6]);
  unpackv (sha256_tmps, dgst, 0, 7, last_dgst[7]);

  unpackv (sha256_tmps, out, 0, 0, out[0]);
  unpackv (sha256_tmps, out, 0, 1, out[1]);
  unpackv (sha256_tmps, out, 0, 2, out[2]);
  unpackv (sha256_tmps, out, 0, 3, out[3]);
  unpackv (sha256_tmps, out, 0, 4, out[4]);
  unpackv (sha256_tmps, out, 0, 5, out[5]);
  unpackv (sha256_tmps, out, 0, 6, out[6]);
  unpackv (sha256_tmps, out, 0, 7, out[7]);

  // convert sha256_tmps[VECT_SIZE] to tmpx
  convert_pbkdf2_sha256_to_V(sha256_tmps, tmpx);
}

KERNEL_FQ void m34000_loop (KERN_ATTR_TMPS_ESALT (racf_kdfaes_tmp_t, racf_kdfaes_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  /*
   * set key and salt 
   */
  
  u32x key[16] = {0};
  u32x salt[16] = {0};
  u32 salt_len = tmps[gid].salt_len;
  
  key[0] = packv (tmps, key, gid, 0);
  key[1] = packv (tmps, key, gid, 1);

  salt[0] = packv (tmps, salt_buf, gid, 0);
  salt[1] = packv (tmps, salt_buf, gid, 1);
  salt[2] = packv (tmps, salt_buf, gid, 2);
  salt[3] = packv (tmps, salt_buf, gid, 3);
  salt[4] = packv (tmps, salt_buf, gid, 4);
  salt[5] = packv (tmps, salt_buf, gid, 5);
  salt[6] = packv (tmps, salt_buf, gid, 6);
  salt[7] = packv (tmps, salt_buf, gid, 7);
  salt[8] = packv (tmps, salt_buf, gid, 8);
  salt[9] = packv (tmps, salt_buf, gid, 9);
  salt[10] = packv (tmps, salt_buf, gid, 10);
  salt[11] = packv (tmps, salt_buf, gid, 11);

  pbkdf2_sha256_tmpx_t pbkdf2_tmpx = {0};

  /*
   * internal loop with PBKDF2-SHA256-HMAC 
   */
  
  for (u32 i = 0; i < LOOP_CNT; i += 1)
  {
    racf_pbkdf_sha256_hmac_V(key, 8, salt, salt_len, esalt_bufs[DIGESTS_OFFSET_HOST].rep_fac * 100, &pbkdf2_tmpx);

    salt[0] = pbkdf2_tmpx.dgst[0];
    salt[1] = pbkdf2_tmpx.dgst[1];
    salt[2] = pbkdf2_tmpx.dgst[2];
    salt[3] = pbkdf2_tmpx.dgst[3];
    salt[4] = pbkdf2_tmpx.out[0];
    salt[5] = pbkdf2_tmpx.out[1];
    salt[6] = pbkdf2_tmpx.out[2];
    salt[7] = pbkdf2_tmpx.out[3];
    salt[8] = pbkdf2_tmpx.out[4];
    salt[9] = pbkdf2_tmpx.out[5];
    salt[10] = pbkdf2_tmpx.out[6];
    salt[11] = pbkdf2_tmpx.out[7];
    salt_len = 48;

    // fill mem_fact buffer (tmps->out)
    unpackv (tmps, out, gid, 8*LOOP_POS+8*i+0, pbkdf2_tmpx.out[0]);
    unpackv (tmps, out, gid, 8*LOOP_POS+8*i+1, pbkdf2_tmpx.out[1]);
    unpackv (tmps, out, gid, 8*LOOP_POS+8*i+2, pbkdf2_tmpx.out[2]);
    unpackv (tmps, out, gid, 8*LOOP_POS+8*i+3, pbkdf2_tmpx.out[3]);
    unpackv (tmps, out, gid, 8*LOOP_POS+8*i+4, pbkdf2_tmpx.out[4]);
    unpackv (tmps, out, gid, 8*LOOP_POS+8*i+5, pbkdf2_tmpx.out[5]);
    unpackv (tmps, out, gid, 8*LOOP_POS+8*i+6, pbkdf2_tmpx.out[6]);
    unpackv (tmps, out, gid, 8*LOOP_POS+8*i+7, pbkdf2_tmpx.out[7]);

  }

  /*
   * set salt_buf for the next mem_fact iteration 
   */

  unpackv (tmps, salt_buf, gid, 0, pbkdf2_tmpx.dgst[0]);
  unpackv (tmps, salt_buf, gid, 1, pbkdf2_tmpx.dgst[1]);
  unpackv (tmps, salt_buf, gid, 2, pbkdf2_tmpx.dgst[2]);
  unpackv (tmps, salt_buf, gid, 3, pbkdf2_tmpx.dgst[3]);

  unpackv (tmps, salt_buf, gid, 4, pbkdf2_tmpx.out[0]);
  unpackv (tmps, salt_buf, gid, 5, pbkdf2_tmpx.out[1]);
  unpackv (tmps, salt_buf, gid, 6, pbkdf2_tmpx.out[2]);
  unpackv (tmps, salt_buf, gid, 7, pbkdf2_tmpx.out[3]);
  unpackv (tmps, salt_buf, gid, 8, pbkdf2_tmpx.out[4]);
  unpackv (tmps, salt_buf, gid, 9, pbkdf2_tmpx.out[5]);
  unpackv (tmps, salt_buf, gid, 10, pbkdf2_tmpx.out[6]);
  unpackv (tmps, salt_buf, gid, 11, pbkdf2_tmpx.out[7]);
  
  u32x salt_len_x = 48;
  unpack (tmps, salt_len, gid, salt_len_x);
}


KERNEL_FQ void m34000_init2 (KERN_ATTR_TMPS_ESALT (racf_kdfaes_tmp_t, racf_kdfaes_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  /**
   * memory buffer preparation (transposition + PBKDF2-SHA256-HMAC with iter=1) 
   */
 
  // set key
  tmps[gid].key[0] = tmps[gid].salt_buf[4];
  tmps[gid].key[1] = tmps[gid].salt_buf[5];
  tmps[gid].key[2] = tmps[gid].salt_buf[6];
  tmps[gid].key[3] = tmps[gid].salt_buf[7];
  tmps[gid].key[4] = tmps[gid].salt_buf[8];
  tmps[gid].key[5] = tmps[gid].salt_buf[9];
  tmps[gid].key[6] = tmps[gid].salt_buf[10];
  tmps[gid].key[7] = tmps[gid].salt_buf[11];

  // zero filling salt_buf (only the first 8 bytes are needed)
  tmps[gid].salt_buf[8] = 0;
  tmps[gid].salt_buf[9] = 0;
  tmps[gid].salt_buf[10] = 0;
  tmps[gid].salt_buf[11] = 0;

  // PBKDF2-SHA256-HMAC with iter=1 for each 32-byte block in memory buffer
  for (u32 i = 0; i < esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac; i += 1)
  {
    u32 n_key = tmps[gid].key[7] & (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1);

    // set salt from memory buffer with offset n_key
    tmps[gid].salt_buf[0] = tmps[gid].out[n_key*8+0];
    tmps[gid].salt_buf[1] = tmps[gid].out[n_key*8+1];
    tmps[gid].salt_buf[2] = tmps[gid].out[n_key*8+2];
    tmps[gid].salt_buf[3] = tmps[gid].out[n_key*8+3];
    tmps[gid].salt_buf[4] = tmps[gid].out[n_key*8+4];
    tmps[gid].salt_buf[5] = tmps[gid].out[n_key*8+5];
    tmps[gid].salt_buf[6] = tmps[gid].out[n_key*8+6];
    tmps[gid].salt_buf[7] = tmps[gid].out[n_key*8+7];

    // do PBKDF2-SHA256-HMAC 
    sha256_hmac_ctx_t sha256_hmac_ctx;

    sha256_hmac_init_global (&sha256_hmac_ctx, tmps[gid].key, 32);

    sha256_hmac_update_global (&sha256_hmac_ctx, tmps[gid].salt_buf, 32);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = 1;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_update_64 (&sha256_hmac_ctx, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx);

    // save digest to out buf
    tmps[gid].out[i*8+0] = sha256_hmac_ctx.opad.h[0];
    tmps[gid].out[i*8+1] = sha256_hmac_ctx.opad.h[1];
    tmps[gid].out[i*8+2] = sha256_hmac_ctx.opad.h[2];
    tmps[gid].out[i*8+3] = sha256_hmac_ctx.opad.h[3];
    tmps[gid].out[i*8+4] = sha256_hmac_ctx.opad.h[4];
    tmps[gid].out[i*8+5] = sha256_hmac_ctx.opad.h[5];
    tmps[gid].out[i*8+6] = sha256_hmac_ctx.opad.h[6];
    tmps[gid].out[i*8+7] = sha256_hmac_ctx.opad.h[7];

    // set key for next iteration
    tmps[gid].key[0] = sha256_hmac_ctx.opad.h[0];
    tmps[gid].key[1] = sha256_hmac_ctx.opad.h[1];
    tmps[gid].key[2] = sha256_hmac_ctx.opad.h[2];
    tmps[gid].key[3] = sha256_hmac_ctx.opad.h[3];
    tmps[gid].key[4] = sha256_hmac_ctx.opad.h[4];
    tmps[gid].key[5] = sha256_hmac_ctx.opad.h[5];
    tmps[gid].key[6] = sha256_hmac_ctx.opad.h[6];
    tmps[gid].key[7] = sha256_hmac_ctx.opad.h[7];  
  }

  /**
   * PBKDF2-SHA256-HMAC init
   */

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global (&sha256_hmac_ctx, tmps[gid].key, 32);

  // set ipad and opad
  tmps[gid].pbkdf2_tmps.ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmps[gid].pbkdf2_tmps.ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmps[gid].pbkdf2_tmps.ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmps[gid].pbkdf2_tmps.ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmps[gid].pbkdf2_tmps.ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmps[gid].pbkdf2_tmps.ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmps[gid].pbkdf2_tmps.ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmps[gid].pbkdf2_tmps.ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmps[gid].pbkdf2_tmps.opad[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].pbkdf2_tmps.opad[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].pbkdf2_tmps.opad[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].pbkdf2_tmps.opad[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].pbkdf2_tmps.opad[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].pbkdf2_tmps.opad[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].pbkdf2_tmps.opad[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].pbkdf2_tmps.opad[7] = sha256_hmac_ctx.opad.h[7];

  // zero filling last 32-byte buf in tmps[gid].out. It's used as a key
  tmps[gid].out[8*(esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1)+0] = 0;
  tmps[gid].out[8*(esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1)+1] = 0;
  tmps[gid].out[8*(esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1)+2] = 0;
  tmps[gid].out[8*(esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1)+3] = 0;
  tmps[gid].out[8*(esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1)+4] = 0;
  tmps[gid].out[8*(esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1)+5] = 0;
  tmps[gid].out[8*(esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1)+6] = 0;
  tmps[gid].out[8*(esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1)+7] = 0;

  sha256_hmac_update_global (&sha256_hmac_ctx, tmps[gid].out, 32*(esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1));

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    tmps[gid].pbkdf2_tmps.dgst[i + 0] = sha256_hmac_ctx2.opad.h[0];
    tmps[gid].pbkdf2_tmps.dgst[i + 1] = sha256_hmac_ctx2.opad.h[1];
    tmps[gid].pbkdf2_tmps.dgst[i + 2] = sha256_hmac_ctx2.opad.h[2];
    tmps[gid].pbkdf2_tmps.dgst[i + 3] = sha256_hmac_ctx2.opad.h[3];
    tmps[gid].pbkdf2_tmps.dgst[i + 4] = sha256_hmac_ctx2.opad.h[4];
    tmps[gid].pbkdf2_tmps.dgst[i + 5] = sha256_hmac_ctx2.opad.h[5];
    tmps[gid].pbkdf2_tmps.dgst[i + 6] = sha256_hmac_ctx2.opad.h[6];
    tmps[gid].pbkdf2_tmps.dgst[i + 7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].pbkdf2_tmps.out[i + 0] = tmps[gid].pbkdf2_tmps.dgst[i + 0];
    tmps[gid].pbkdf2_tmps.out[i + 1] = tmps[gid].pbkdf2_tmps.dgst[i + 1];
    tmps[gid].pbkdf2_tmps.out[i + 2] = tmps[gid].pbkdf2_tmps.dgst[i + 2];
    tmps[gid].pbkdf2_tmps.out[i + 3] = tmps[gid].pbkdf2_tmps.dgst[i + 3];
    tmps[gid].pbkdf2_tmps.out[i + 4] = tmps[gid].pbkdf2_tmps.dgst[i + 4];
    tmps[gid].pbkdf2_tmps.out[i + 5] = tmps[gid].pbkdf2_tmps.dgst[i + 5];
    tmps[gid].pbkdf2_tmps.out[i + 6] = tmps[gid].pbkdf2_tmps.dgst[i + 6];
    tmps[gid].pbkdf2_tmps.out[i + 7] = tmps[gid].pbkdf2_tmps.dgst[i + 7];
  }
 
}


KERNEL_FQ void m34000_loop2 (KERN_ATTR_TMPS_ESALT (racf_kdfaes_tmp_t, racf_kdfaes_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  u32x ipad[8];
  u32x opad[8];

  ipad[0] = packv (tmps, pbkdf2_tmps.ipad, gid, 0);
  ipad[1] = packv (tmps, pbkdf2_tmps.ipad, gid, 1);
  ipad[2] = packv (tmps, pbkdf2_tmps.ipad, gid, 2);
  ipad[3] = packv (tmps, pbkdf2_tmps.ipad, gid, 3);
  ipad[4] = packv (tmps, pbkdf2_tmps.ipad, gid, 4);
  ipad[5] = packv (tmps, pbkdf2_tmps.ipad, gid, 5);
  ipad[6] = packv (tmps, pbkdf2_tmps.ipad, gid, 6);
  ipad[7] = packv (tmps, pbkdf2_tmps.ipad, gid, 7);

  opad[0] = packv (tmps, pbkdf2_tmps.opad, gid, 0);
  opad[1] = packv (tmps, pbkdf2_tmps.opad, gid, 1);
  opad[2] = packv (tmps, pbkdf2_tmps.opad, gid, 2);
  opad[3] = packv (tmps, pbkdf2_tmps.opad, gid, 3);
  opad[4] = packv (tmps, pbkdf2_tmps.opad, gid, 4);
  opad[5] = packv (tmps, pbkdf2_tmps.opad, gid, 5);
  opad[6] = packv (tmps, pbkdf2_tmps.opad, gid, 6);
  opad[7] = packv (tmps, pbkdf2_tmps.opad, gid, 7);
  
  for (u32 i = 0; i < 8; i += 8)
  {
    u32x dgst[8];
    u32x out[8];

    dgst[0] = packv (tmps, pbkdf2_tmps.dgst, gid, i + 0);
    dgst[1] = packv (tmps, pbkdf2_tmps.dgst, gid, i + 1);
    dgst[2] = packv (tmps, pbkdf2_tmps.dgst, gid, i + 2);
    dgst[3] = packv (tmps, pbkdf2_tmps.dgst, gid, i + 3);
    dgst[4] = packv (tmps, pbkdf2_tmps.dgst, gid, i + 4);
    dgst[5] = packv (tmps, pbkdf2_tmps.dgst, gid, i + 5);
    dgst[6] = packv (tmps, pbkdf2_tmps.dgst, gid, i + 6);
    dgst[7] = packv (tmps, pbkdf2_tmps.dgst, gid, i + 7);

    out[0] = packv (tmps, pbkdf2_tmps.out, gid, i + 0);
    out[1] = packv (tmps, pbkdf2_tmps.out, gid, i + 1);
    out[2] = packv (tmps, pbkdf2_tmps.out, gid, i + 2);
    out[3] = packv (tmps, pbkdf2_tmps.out, gid, i + 3);
    out[4] = packv (tmps, pbkdf2_tmps.out, gid, i + 4);
    out[5] = packv (tmps, pbkdf2_tmps.out, gid, i + 5);
    out[6] = packv (tmps, pbkdf2_tmps.out, gid, i + 6);
    out[7] = packv (tmps, pbkdf2_tmps.out, gid, i + 7);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 32) * 8;

      hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpackv (tmps, pbkdf2_tmps.dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, pbkdf2_tmps.dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, pbkdf2_tmps.dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, pbkdf2_tmps.dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, pbkdf2_tmps.dgst, gid, i + 4, dgst[4]);
    unpackv (tmps, pbkdf2_tmps.dgst, gid, i + 5, dgst[5]);
    unpackv (tmps, pbkdf2_tmps.dgst, gid, i + 6, dgst[6]);
    unpackv (tmps, pbkdf2_tmps.dgst, gid, i + 7, dgst[7]);

    unpackv (tmps, pbkdf2_tmps.out, gid, i + 0, out[0]);
    unpackv (tmps, pbkdf2_tmps.out, gid, i + 1, out[1]);
    unpackv (tmps, pbkdf2_tmps.out, gid, i + 2, out[2]);
    unpackv (tmps, pbkdf2_tmps.out, gid, i + 3, out[3]);
    unpackv (tmps, pbkdf2_tmps.out, gid, i + 4, out[4]);
    unpackv (tmps, pbkdf2_tmps.out, gid, i + 5, out[5]);
    unpackv (tmps, pbkdf2_tmps.out, gid, i + 6, out[6]);
    unpackv (tmps, pbkdf2_tmps.out, gid, i + 7, out[7]);
  }
  
}

KERNEL_FQ void m34000_comp (KERN_ATTR_TMPS_ESALT (racf_kdfaes_tmp_t, racf_kdfaes_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * AES shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  // prepare key and plain text
  u32 aes_key[8] = {0};

  // AES key is output from PBKDB2-SHA256-HMAC (loop2)
  aes_key[0] = tmps[gid].pbkdf2_tmps.out[0];
  aes_key[1] = tmps[gid].pbkdf2_tmps.out[1];
  aes_key[2] = tmps[gid].pbkdf2_tmps.out[2];
  aes_key[3] = tmps[gid].pbkdf2_tmps.out[3];
  aes_key[4] = tmps[gid].pbkdf2_tmps.out[4];
  aes_key[5] = tmps[gid].pbkdf2_tmps.out[5];
  aes_key[6] = tmps[gid].pbkdf2_tmps.out[6];
  aes_key[7] = tmps[gid].pbkdf2_tmps.out[7];

  // Plain text is encoded username
  u32 plain_text[4] = {0};
  plain_text[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  plain_text[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];
  plain_text[2] = salt_bufs[SALT_POS_HOST].salt_buf_pc[2];
  plain_text[3] = salt_bufs[SALT_POS_HOST].salt_buf_pc[3];

  u32 cipher_text[4] = {0};

  // AES 
  u32 aes_ks[60];

  AES256_set_encrypt_key (aes_ks, aes_key, s_te0, s_te1, s_te2, s_te3);
  aes256_encrypt (aes_ks, plain_text, cipher_text, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 r0 = cipher_text[DGST_R0];
  const u32 r1 = cipher_text[DGST_R1];
  const u32 r2 = cipher_text[DGST_R2];
  const u32 r3 = cipher_text[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}


