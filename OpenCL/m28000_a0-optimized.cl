/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible because of branches
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

typedef struct crc64
{
  u64 iv;

} crc64_t;

CONSTANT_VK u64a crc64jonestab[0x100] =
{
  0x0000000000000000, 0x7ad870c830358979,
  0xf5b0e190606b12f2, 0x8f689158505e9b8b,
  0xc038e5739841b68f, 0xbae095bba8743ff6,
  0x358804e3f82aa47d, 0x4f50742bc81f2d04,
  0xab28ecb46814fe75, 0xd1f09c7c5821770c,
  0x5e980d24087fec87, 0x24407dec384a65fe,
  0x6b1009c7f05548fa, 0x11c8790fc060c183,
  0x9ea0e857903e5a08, 0xe478989fa00bd371,
  0x7d08ff3b88be6f81, 0x07d08ff3b88be6f8,
  0x88b81eabe8d57d73, 0xf2606e63d8e0f40a,
  0xbd301a4810ffd90e, 0xc7e86a8020ca5077,
  0x4880fbd87094cbfc, 0x32588b1040a14285,
  0xd620138fe0aa91f4, 0xacf86347d09f188d,
  0x2390f21f80c18306, 0x594882d7b0f40a7f,
  0x1618f6fc78eb277b, 0x6cc0863448deae02,
  0xe3a8176c18803589, 0x997067a428b5bcf0,
  0xfa11fe77117cdf02, 0x80c98ebf2149567b,
  0x0fa11fe77117cdf0, 0x75796f2f41224489,
  0x3a291b04893d698d, 0x40f16bccb908e0f4,
  0xcf99fa94e9567b7f, 0xb5418a5cd963f206,
  0x513912c379682177, 0x2be1620b495da80e,
  0xa489f35319033385, 0xde51839b2936bafc,
  0x9101f7b0e12997f8, 0xebd98778d11c1e81,
  0x64b116208142850a, 0x1e6966e8b1770c73,
  0x8719014c99c2b083, 0xfdc17184a9f739fa,
  0x72a9e0dcf9a9a271, 0x08719014c99c2b08,
  0x4721e43f0183060c, 0x3df994f731b68f75,
  0xb29105af61e814fe, 0xc849756751dd9d87,
  0x2c31edf8f1d64ef6, 0x56e99d30c1e3c78f,
  0xd9810c6891bd5c04, 0xa3597ca0a188d57d,
  0xec09088b6997f879, 0x96d1784359a27100,
  0x19b9e91b09fcea8b, 0x636199d339c963f2,
  0xdf7adabd7a6e2d6f, 0xa5a2aa754a5ba416,
  0x2aca3b2d1a053f9d, 0x50124be52a30b6e4,
  0x1f423fcee22f9be0, 0x659a4f06d21a1299,
  0xeaf2de5e82448912, 0x902aae96b271006b,
  0x74523609127ad31a, 0x0e8a46c1224f5a63,
  0x81e2d7997211c1e8, 0xfb3aa75142244891,
  0xb46ad37a8a3b6595, 0xceb2a3b2ba0eecec,
  0x41da32eaea507767, 0x3b024222da65fe1e,
  0xa2722586f2d042ee, 0xd8aa554ec2e5cb97,
  0x57c2c41692bb501c, 0x2d1ab4dea28ed965,
  0x624ac0f56a91f461, 0x1892b03d5aa47d18,
  0x97fa21650afae693, 0xed2251ad3acf6fea,
  0x095ac9329ac4bc9b, 0x7382b9faaaf135e2,
  0xfcea28a2faafae69, 0x8632586aca9a2710,
  0xc9622c4102850a14, 0xb3ba5c8932b0836d,
  0x3cd2cdd162ee18e6, 0x460abd1952db919f,
  0x256b24ca6b12f26d, 0x5fb354025b277b14,
  0xd0dbc55a0b79e09f, 0xaa03b5923b4c69e6,
  0xe553c1b9f35344e2, 0x9f8bb171c366cd9b,
  0x10e3202993385610, 0x6a3b50e1a30ddf69,
  0x8e43c87e03060c18, 0xf49bb8b633338561,
  0x7bf329ee636d1eea, 0x012b592653589793,
  0x4e7b2d0d9b47ba97, 0x34a35dc5ab7233ee,
  0xbbcbcc9dfb2ca865, 0xc113bc55cb19211c,
  0x5863dbf1e3ac9dec, 0x22bbab39d3991495,
  0xadd33a6183c78f1e, 0xd70b4aa9b3f20667,
  0x985b3e827bed2b63, 0xe2834e4a4bd8a21a,
  0x6debdf121b863991, 0x1733afda2bb3b0e8,
  0xf34b37458bb86399, 0x8993478dbb8deae0,
  0x06fbd6d5ebd3716b, 0x7c23a61ddbe6f812,
  0x3373d23613f9d516, 0x49aba2fe23cc5c6f,
  0xc6c333a67392c7e4, 0xbc1b436e43a74e9d,
  0x95ac9329ac4bc9b5, 0xef74e3e19c7e40cc,
  0x601c72b9cc20db47, 0x1ac40271fc15523e,
  0x5594765a340a7f3a, 0x2f4c0692043ff643,
  0xa02497ca54616dc8, 0xdafce7026454e4b1,
  0x3e847f9dc45f37c0, 0x445c0f55f46abeb9,
  0xcb349e0da4342532, 0xb1eceec59401ac4b,
  0xfebc9aee5c1e814f, 0x8464ea266c2b0836,
  0x0b0c7b7e3c7593bd, 0x71d40bb60c401ac4,
  0xe8a46c1224f5a634, 0x927c1cda14c02f4d,
  0x1d148d82449eb4c6, 0x67ccfd4a74ab3dbf,
  0x289c8961bcb410bb, 0x5244f9a98c8199c2,
  0xdd2c68f1dcdf0249, 0xa7f41839ecea8b30,
  0x438c80a64ce15841, 0x3954f06e7cd4d138,
  0xb63c61362c8a4ab3, 0xcce411fe1cbfc3ca,
  0x83b465d5d4a0eece, 0xf96c151de49567b7,
  0x76048445b4cbfc3c, 0x0cdcf48d84fe7545,
  0x6fbd6d5ebd3716b7, 0x15651d968d029fce,
  0x9a0d8ccedd5c0445, 0xe0d5fc06ed698d3c,
  0xaf85882d2576a038, 0xd55df8e515432941,
  0x5a3569bd451db2ca, 0x20ed197575283bb3,
  0xc49581ead523e8c2, 0xbe4df122e51661bb,
  0x3125607ab548fa30, 0x4bfd10b2857d7349,
  0x04ad64994d625e4d, 0x7e7514517d57d734,
  0xf11d85092d094cbf, 0x8bc5f5c11d3cc5c6,
  0x12b5926535897936, 0x686de2ad05bcf04f,
  0xe70573f555e26bc4, 0x9ddd033d65d7e2bd,
  0xd28d7716adc8cfb9, 0xa85507de9dfd46c0,
  0x273d9686cda3dd4b, 0x5de5e64efd965432,
  0xb99d7ed15d9d8743, 0xc3450e196da80e3a,
  0x4c2d9f413df695b1, 0x36f5ef890dc31cc8,
  0x79a59ba2c5dc31cc, 0x037deb6af5e9b8b5,
  0x8c157a32a5b7233e, 0xf6cd0afa9582aa47,
  0x4ad64994d625e4da, 0x300e395ce6106da3,
  0xbf66a804b64ef628, 0xc5bed8cc867b7f51,
  0x8aeeace74e645255, 0xf036dc2f7e51db2c,
  0x7f5e4d772e0f40a7, 0x05863dbf1e3ac9de,
  0xe1fea520be311aaf, 0x9b26d5e88e0493d6,
  0x144e44b0de5a085d, 0x6e963478ee6f8124,
  0x21c640532670ac20, 0x5b1e309b16452559,
  0xd476a1c3461bbed2, 0xaeaed10b762e37ab,
  0x37deb6af5e9b8b5b, 0x4d06c6676eae0222,
  0xc26e573f3ef099a9, 0xb8b627f70ec510d0,
  0xf7e653dcc6da3dd4, 0x8d3e2314f6efb4ad,
  0x0256b24ca6b12f26, 0x788ec2849684a65f,
  0x9cf65a1b368f752e, 0xe62e2ad306bafc57,
  0x6946bb8b56e467dc, 0x139ecb4366d1eea5,
  0x5ccebf68aecec3a1, 0x2616cfa09efb4ad8,
  0xa97e5ef8cea5d153, 0xd3a62e30fe90582a,
  0xb0c7b7e3c7593bd8, 0xca1fc72bf76cb2a1,
  0x45775673a732292a, 0x3faf26bb9707a053,
  0x70ff52905f188d57, 0x0a2722586f2d042e,
  0x854fb3003f739fa5, 0xff97c3c80f4616dc,
  0x1bef5b57af4dc5ad, 0x61372b9f9f784cd4,
  0xee5fbac7cf26d75f, 0x9487ca0fff135e26,
  0xdbd7be24370c7322, 0xa10fceec0739fa5b,
  0x2e675fb4576761d0, 0x54bf2f7c6752e8a9,
  0xcdcf48d84fe75459, 0xb71738107fd2dd20,
  0x387fa9482f8c46ab, 0x42a7d9801fb9cfd2,
  0x0df7adabd7a6e2d6, 0x772fdd63e7936baf,
  0xf8474c3bb7cdf024, 0x829f3cf387f8795d,
  0x66e7a46c27f3aa2c, 0x1c3fd4a417c62355,
  0x935745fc4798b8de, 0xe98f353477ad31a7,
  0xa6df411fbfb21ca3, 0xdc0731d78f8795da,
  0x536fa08fdfd90e51, 0x29b7d047efec8728,
};

DECLSPEC u64 round_crc64jones (u64 a, const u64 v, SHM_TYPE u64 *s_crc64jonestab)
{
  const u64 k = (a ^ v) & 0xff;

  const u64 s = a >> 8;

  a = s_crc64jonestab[k];

  a ^= s;

  return a;
}

DECLSPEC u64 crc64jones (PRIVATE_AS const u32 *w, const u32 pw_len, const u64 iv, SHM_TYPE u64 *s_crc64jonestab)
{
  u64 a = iv;

  if (pw_len >=  1) a = round_crc64jones (a, w[0] >>  0, s_crc64jonestab);
  if (pw_len >=  2) a = round_crc64jones (a, w[0] >>  8, s_crc64jonestab);
  if (pw_len >=  3) a = round_crc64jones (a, w[0] >> 16, s_crc64jonestab);
  if (pw_len >=  4) a = round_crc64jones (a, w[0] >> 24, s_crc64jonestab);
  if (pw_len >=  5) a = round_crc64jones (a, w[1] >>  0, s_crc64jonestab);
  if (pw_len >=  6) a = round_crc64jones (a, w[1] >>  8, s_crc64jonestab);
  if (pw_len >=  7) a = round_crc64jones (a, w[1] >> 16, s_crc64jonestab);
  if (pw_len >=  8) a = round_crc64jones (a, w[1] >> 24, s_crc64jonestab);
  if (pw_len >=  9) a = round_crc64jones (a, w[2] >>  0, s_crc64jonestab);
  if (pw_len >= 10) a = round_crc64jones (a, w[2] >>  8, s_crc64jonestab);
  if (pw_len >= 11) a = round_crc64jones (a, w[2] >> 16, s_crc64jonestab);
  if (pw_len >= 12) a = round_crc64jones (a, w[2] >> 24, s_crc64jonestab);

  for (u32 i = 12, j = 3; i < pw_len; i += 4, j += 1)
  {
    if (pw_len >= (i + 1)) a = round_crc64jones (a, w[j] >>  0, s_crc64jonestab);
    if (pw_len >= (i + 2)) a = round_crc64jones (a, w[j] >>  8, s_crc64jonestab);
    if (pw_len >= (i + 3)) a = round_crc64jones (a, w[j] >> 16, s_crc64jonestab);
    if (pw_len >= (i + 4)) a = round_crc64jones (a, w[j] >> 24, s_crc64jonestab);
  }

  return a;
}

KERNEL_FQ void m28000_m04 (KERN_ATTR_RULES_ESALT (crc64_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * CRC64Jones shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_crc64jonestab[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_crc64jonestab[i] = crc64jonestab[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_crc64jonestab = crc64jonestab;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * Base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  const u64 iv = esalt_bufs[DIGESTS_OFFSET_HOST].iv;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32 w0[4] = { 0 };
    u32 w1[4] = { 0 };
    u32 w2[4] = { 0 };
    u32 w3[4] = { 0 };

    const u32 out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * crc32c
     */

    u32 w[16];

    w[ 0] = w0[0];
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = 0;

    u64 a = crc64jones (w, pw_len, iv, s_crc64jonestab);

    const u32 r0 = l32_from_64 (a);
    const u32 r1 = h32_from_64 (a);
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m28000_m08 (KERN_ATTR_RULES_ESALT (crc64_t))
{
}

KERNEL_FQ void m28000_m16 (KERN_ATTR_RULES_ESALT (crc64_t))
{
}

KERNEL_FQ void m28000_s04 (KERN_ATTR_RULES_ESALT (crc64_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * CRC64Jones shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_crc64jonestab[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_crc64jonestab[i] = crc64jonestab[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_crc64jonestab = crc64jonestab;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * Base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  const u64 iv = esalt_bufs[DIGESTS_OFFSET_HOST].iv;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32 w0[4] = { 0 };
    u32 w1[4] = { 0 };
    u32 w2[4] = { 0 };
    u32 w3[4] = { 0 };

    const u32 out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * crc32c
     */

    u32 w[16];

    w[ 0] = w0[0];
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = 0;

    u64 a = crc64jones (w, pw_len, iv, s_crc64jonestab);

    const u32 r0 = l32_from_64 (a);
    const u32 r1 = h32_from_64 (a);
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m28000_s08 (KERN_ATTR_RULES_ESALT (crc64_t))
{
}

KERNEL_FQ void m28000_s16 (KERN_ATTR_RULES_ESALT (crc64_t))
{
}
