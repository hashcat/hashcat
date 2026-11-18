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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

#ifdef MULTI_SALT_WINDOW

// Sweep: this launch tests every salt of the list at once, see module_salt_sweep (). The workgroup
// stages the window's precomputed md5 (salt) values in shared memory, then each candidate tests the
// whole window: one message block (the md5 (salt) hex and the md5 (pass) hex) plus the padding block.

DECLSPEC void m02810_sweep_md5 (LOCAL_AS const u32 *pc, PRIVATE_AS const u32x *ph, PRIVATE_AS u32x *dg)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w0[0] = pc[0];
  w0[1] = pc[1];
  w0[2] = pc[2];
  w0[3] = pc[3];
  w1[0] = pc[4];
  w1[1] = pc[5];
  w1[2] = pc[6];
  w1[3] = pc[7];

  w2[0] = ph[0];
  w2[1] = ph[1];
  w2[2] = ph[2];
  w2[3] = ph[3];
  w3[0] = ph[4];
  w3[1] = ph[5];
  w3[2] = ph[6];
  w3[3] = ph[7];

  u32x a;
  u32x b;
  u32x c;
  u32x d;

  u32x t;

  a = MD5M_A;
  b = MD5M_B;
  c = MD5M_C;
  d = MD5M_D;

  MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

  MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

  MD5_STEP (MD5_H1, a, b, c, d, w1[1], MD5C20, MD5S20);
  MD5_STEP (MD5_H2, d, a, b, c, w2[0], MD5C21, MD5S21);
  MD5_STEP (MD5_H1, c, d, a, b, w2[3], MD5C22, MD5S22);
  MD5_STEP (MD5_H2, b, c, d, a, w3[2], MD5C23, MD5S23);
  MD5_STEP (MD5_H1, a, b, c, d, w0[1], MD5C24, MD5S20);
  MD5_STEP (MD5_H2, d, a, b, c, w1[0], MD5C25, MD5S21);
  MD5_STEP (MD5_H1, c, d, a, b, w1[3], MD5C26, MD5S22);
  MD5_STEP (MD5_H2, b, c, d, a, w2[2], MD5C27, MD5S23);
  MD5_STEP (MD5_H1, a, b, c, d, w3[1], MD5C28, MD5S20);
  MD5_STEP (MD5_H2, d, a, b, c, w0[0], MD5C29, MD5S21);
  MD5_STEP (MD5_H1, c, d, a, b, w0[3], MD5C2a, MD5S22);
  MD5_STEP (MD5_H2, b, c, d, a, w1[2], MD5C2b, MD5S23);
  MD5_STEP (MD5_H1, a, b, c, d, w2[1], MD5C2c, MD5S20);
  MD5_STEP (MD5_H2, d, a, b, c, w3[0], MD5C2d, MD5S21);
  MD5_STEP (MD5_H1, c, d, a, b, w3[3], MD5C2e, MD5S22);
  MD5_STEP (MD5_H2, b, c, d, a, w0[2], MD5C2f, MD5S23);

  MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

  const u32x r_a = a + make_u32x (MD5M_A);
  const u32x r_b = b + make_u32x (MD5M_B);
  const u32x r_c = c + make_u32x (MD5M_C);
  const u32x r_d = d + make_u32x (MD5M_D);

  const u32x r_00 = 0x80;
  const u32x r_14 = 64 * 8;

  a = r_a;
  b = r_b;
  c = r_c;
  d = r_d;

  MD5_STEP (MD5_Fo, a, b, c, d, r_00, MD5C00, MD5S00);
  MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C01, MD5S01);
  MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C02, MD5S02);
  MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C03, MD5S03);
  MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C04, MD5S00);
  MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C05, MD5S01);
  MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C06, MD5S02);
  MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C07, MD5S03);
  MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C08, MD5S00);
  MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C09, MD5S01);
  MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C0a, MD5S02);
  MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C0b, MD5S03);
  MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C0c, MD5S00);
  MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C0d, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, r_14, MD5C0e, MD5S02);
  MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C0f, MD5S03);

  MD5_STEP0(MD5_Go, a, b, c, d,       MD5C10, MD5S10);
  MD5_STEP0(MD5_Go, d, a, b, c,       MD5C11, MD5S11);
  MD5_STEP0(MD5_Go, c, d, a, b,       MD5C12, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, r_00, MD5C13, MD5S13);
  MD5_STEP0(MD5_Go, a, b, c, d,       MD5C14, MD5S10);
  MD5_STEP0(MD5_Go, d, a, b, c,       MD5C15, MD5S11);
  MD5_STEP0(MD5_Go, c, d, a, b,       MD5C16, MD5S12);
  MD5_STEP0(MD5_Go, b, c, d, a,       MD5C17, MD5S13);
  MD5_STEP0(MD5_Go, a, b, c, d,       MD5C18, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, r_14, MD5C19, MD5S11);
  MD5_STEP0(MD5_Go, c, d, a, b,       MD5C1a, MD5S12);
  MD5_STEP0(MD5_Go, b, c, d, a,       MD5C1b, MD5S13);
  MD5_STEP0(MD5_Go, a, b, c, d,       MD5C1c, MD5S10);
  MD5_STEP0(MD5_Go, d, a, b, c,       MD5C1d, MD5S11);
  MD5_STEP0(MD5_Go, c, d, a, b,       MD5C1e, MD5S12);
  MD5_STEP0(MD5_Go, b, c, d, a,       MD5C1f, MD5S13);

  MD5_STEP0(MD5_H1, a, b, c, d,       MD5C20, MD5S20);
  MD5_STEP0(MD5_H2, d, a, b, c,       MD5C21, MD5S21);
  MD5_STEP0(MD5_H1, c, d, a, b,       MD5C22, MD5S22);
  MD5_STEP (MD5_H2, b, c, d, a, r_14, MD5C23, MD5S23);
  MD5_STEP0(MD5_H1, a, b, c, d,       MD5C24, MD5S20);
  MD5_STEP0(MD5_H2, d, a, b, c,       MD5C25, MD5S21);
  MD5_STEP0(MD5_H1, c, d, a, b,       MD5C26, MD5S22);
  MD5_STEP0(MD5_H2, b, c, d, a,       MD5C27, MD5S23);
  MD5_STEP0(MD5_H1, a, b, c, d,       MD5C28, MD5S20);
  MD5_STEP (MD5_H2, d, a, b, c, r_00, MD5C29, MD5S21);
  MD5_STEP0(MD5_H1, c, d, a, b,       MD5C2a, MD5S22);
  MD5_STEP0(MD5_H2, b, c, d, a,       MD5C2b, MD5S23);
  MD5_STEP0(MD5_H1, a, b, c, d,       MD5C2c, MD5S20);
  MD5_STEP0(MD5_H2, d, a, b, c,       MD5C2d, MD5S21);
  MD5_STEP0(MD5_H1, c, d, a, b,       MD5C2e, MD5S22);
  MD5_STEP0(MD5_H2, b, c, d, a,       MD5C2f, MD5S23);

  MD5_STEP (MD5_I , a, b, c, d, r_00, MD5C30, MD5S30);
  MD5_STEP0(MD5_I , d, a, b, c,       MD5C31, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, r_14, MD5C32, MD5S32);
  MD5_STEP0(MD5_I , b, c, d, a,       MD5C33, MD5S33);
  MD5_STEP0(MD5_I , a, b, c, d,       MD5C34, MD5S30);
  MD5_STEP0(MD5_I , d, a, b, c,       MD5C35, MD5S31);
  MD5_STEP0(MD5_I , c, d, a, b,       MD5C36, MD5S32);
  MD5_STEP0(MD5_I , b, c, d, a,       MD5C37, MD5S33);
  MD5_STEP0(MD5_I , a, b, c, d,       MD5C38, MD5S30);
  MD5_STEP0(MD5_I , d, a, b, c,       MD5C39, MD5S31);
  MD5_STEP0(MD5_I , c, d, a, b,       MD5C3a, MD5S32);
  MD5_STEP0(MD5_I , b, c, d, a,       MD5C3b, MD5S33);
  MD5_STEP0(MD5_I , a, b, c, d,       MD5C3c, MD5S30);
  MD5_STEP0(MD5_I , d, a, b, c,       MD5C3d, MD5S31);
  MD5_STEP0(MD5_I , c, d, a, b,       MD5C3e, MD5S32);
  MD5_STEP0(MD5_I , b, c, d, a,       MD5C3f, MD5S33);

  a += r_a;
  b += r_b;
  c += r_c;
  d += r_d;

  dg[0] = a;
  dg[1] = d;
  dg[2] = c;
  dg[3] = b;
}

// Per-lane compare and mark: lane n of the vector holds its own candidate

#define SWEEP_LANES_1(f)  f (0)
#define SWEEP_LANES_2(f)  SWEEP_LANES_1 (f) f (1)
#define SWEEP_LANES_4(f)  SWEEP_LANES_2 (f) f (2) f (3)
#define SWEEP_LANES_8(f)  SWEEP_LANES_4 (f) f (4) f (5) f (6) f (7)
#define SWEEP_LANES_16(f) SWEEP_LANES_8 (f) f (8) f (9) f (10) f (11) f (12) f (13) f (14) f (15)

#if VECT_SIZE == 1
#define SWEEP_LANES(f) SWEEP_LANES_1 (f)
#elif VECT_SIZE == 2
#define SWEEP_LANES(f) SWEEP_LANES_2 (f)
#elif VECT_SIZE == 4
#define SWEEP_LANES(f) SWEEP_LANES_4 (f)
#elif VECT_SIZE == 8
#define SWEEP_LANES(f) SWEEP_LANES_8 (f)
#elif VECT_SIZE == 16
#define SWEEP_LANES(f) SWEEP_LANES_16 (f)
#endif

#define SWEEP_CMP_LANE(n)                                                                             \
{                                                                                                     \
  if (vector_accessible (il_pos, IL_CNT, n))                                                          \
  {                                                                                                   \
    GLOBAL_AS const u32 *sweep_db = digests_buf[sweep_hp].digest_buf;                                 \
                                                                                                      \
    if ((VECTOR_ELEMENT (dg[0], n) == sweep_db[DGST_R0])                                              \
     && (VECTOR_ELEMENT (dg[1], n) == sweep_db[DGST_R1])                                              \
     && (VECTOR_ELEMENT (dg[2], n) == sweep_db[DGST_R2])                                              \
     && (VECTOR_ELEMENT (dg[3], n) == sweep_db[DGST_R3]))                                             \
    {                                                                                               \
      if (hc_atomic_inc (&hashes_shown[sweep_hp]) == 0)                                               \
      {                                                                                             \
        mark_hash (plains_buf, d_return_buf, sweep_gs, kernel_param->digests_cnt, sweep_dp, sweep_hp, gid, il_pos + n, 0, 0); \
      }                                                                                             \
    }                                                                                                 \
  }                                                                                                   \
}

// Shared sweep body of the m04/m08/m16 kernels: they differ only in how many words of the
// candidate block they load from pws, everything from the bfs merge on is identical.

DECLSPEC void m02810m_sweep (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC (), LOCAL_AS u32 *s_pc, LOCAL_AS u32 *s_idx, LOCAL_AS u32 *l_bin2asc)
{
  (void) pw_len; // the candidate block arrives pre-padded from the host

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 w_pos = 0; w_pos < SALTS_CNT; w_pos += MULTI_SALT_WINDOW)
  {
    const u32 sweep_len = ((SALTS_CNT - w_pos) < (u32) MULTI_SALT_WINDOW) ? (SALTS_CNT - w_pos) : (u32) MULTI_SALT_WINDOW;

    // the launch lists the live salts by position, see salt_sweep_launch (); the precomputed
    // md5 (salt) words come from salt_bufs through the list

    GLOBAL_AS const u32 *sweep_buf = (GLOBAL_AS const u32 *) d_extra0_buf;

    for (u32 i = lid; i < sweep_len; i += lsz)
    {
      s_idx[i] = sweep_buf[w_pos + i];
    }

    for (u32 i = lid; i < sweep_len * 8; i += lsz)
    {
      s_pc[i] = salt_bufs[sweep_buf[w_pos + (i >> 3)]].salt_buf_pc[i & 7];
    }

    SYNC_THREADS ();

    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = ix_create_bft (bfs_buf, il_pos);

      const u32x w0lr = w0l | w0r;

      u32x w0_t[4];
      u32x w1_t[4];
      u32x w2_t[4];
      u32x w3_t[4];

      w0_t[0] = w0lr;
      w0_t[1] = w0[1];
      w0_t[2] = w0[2];
      w0_t[3] = w0[3];
      w1_t[0] = w1[0];
      w1_t[1] = w1[1];
      w1_t[2] = w1[2];
      w1_t[3] = w1[3];
      w2_t[0] = w2[0];
      w2_t[1] = w2[1];
      w2_t[2] = w2[2];
      w2_t[3] = w2[3];
      w3_t[0] = w3[0];
      w3_t[1] = w3[1];
      w3_t[2] = w3[2];
      w3_t[3] = w3[3];

      /**
       * md5
       */

      u32x a = MD5M_A;
      u32x b = MD5M_B;
      u32x c = MD5M_C;
      u32x d = MD5M_D;

      MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

      MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

      u32x t;

      MD5_STEP (MD5_H1, a, b, c, d, w1_t[1], MD5C20, MD5S20);
      MD5_STEP (MD5_H2, d, a, b, c, w2_t[0], MD5C21, MD5S21);
      MD5_STEP (MD5_H1, c, d, a, b, w2_t[3], MD5C22, MD5S22);
      MD5_STEP (MD5_H2, b, c, d, a, w3_t[2], MD5C23, MD5S23);
      MD5_STEP (MD5_H1, a, b, c, d, w0_t[1], MD5C24, MD5S20);
      MD5_STEP (MD5_H2, d, a, b, c, w1_t[0], MD5C25, MD5S21);
      MD5_STEP (MD5_H1, c, d, a, b, w1_t[3], MD5C26, MD5S22);
      MD5_STEP (MD5_H2, b, c, d, a, w2_t[2], MD5C27, MD5S23);
      MD5_STEP (MD5_H1, a, b, c, d, w3_t[1], MD5C28, MD5S20);
      MD5_STEP (MD5_H2, d, a, b, c, w0_t[0], MD5C29, MD5S21);
      MD5_STEP (MD5_H1, c, d, a, b, w0_t[3], MD5C2a, MD5S22);
      MD5_STEP (MD5_H2, b, c, d, a, w1_t[2], MD5C2b, MD5S23);
      MD5_STEP (MD5_H1, a, b, c, d, w2_t[1], MD5C2c, MD5S20);
      MD5_STEP (MD5_H2, d, a, b, c, w3_t[0], MD5C2d, MD5S21);
      MD5_STEP (MD5_H1, c, d, a, b, w3_t[3], MD5C2e, MD5S22);
      MD5_STEP (MD5_H2, b, c, d, a, w0_t[2], MD5C2f, MD5S23);

      MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

      a += make_u32x (MD5M_A);
      b += make_u32x (MD5M_B);
      c += make_u32x (MD5M_C);
      d += make_u32x (MD5M_D);

      w2_t[0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
              | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
      w2_t[1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
              | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
      w2_t[2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
              | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
      w2_t[3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
              | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
      w3_t[0] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
              | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
      w3_t[1] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
              | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
      w3_t[2] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
              | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
      w3_t[3] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
              | uint_to_hex_lower8 ((d >> 24) & 255) << 16;

      u32x ph[8];

      ph[0] = w2_t[0];
      ph[1] = w2_t[1];
      ph[2] = w2_t[2];
      ph[3] = w2_t[3];
      ph[4] = w3_t[0];
      ph[5] = w3_t[1];
      ph[6] = w3_t[2];
      ph[7] = w3_t[3];

      for (u32 s = 0; s < sweep_len; s++)
      {
        const u32 sweep_gs = s_idx[s];

        u32x dg[4];

        m02810_sweep_md5 (s_pc + s * 8, ph, dg);

        // a self-test salt carries no digests_cnt, and its digest is the one at offset 0

        const u32 sweep_dcnt = (salt_bufs[sweep_gs].digests_cnt == 0) ? 1 : salt_bufs[sweep_gs].digests_cnt;
        const u32 sweep_doff = salt_bufs[sweep_gs].digests_offset;

        if (sweep_dcnt == 1)
        {
          const u32 sweep_hp = sweep_doff;
          const u32 sweep_dp = 0;

          if (MATCHES_NONE_VS (dg[0], digests_buf[sweep_hp].digest_buf[DGST_R0])) continue;

          SWEEP_LANES (SWEEP_CMP_LANE)
        }
        else
        {
          for (u32 sweep_dp = 0; sweep_dp < sweep_dcnt; sweep_dp++)
          {
            const u32 sweep_hp = sweep_doff + sweep_dp;

            SWEEP_LANES (SWEEP_CMP_LANE)
          }
        }
      }
    }

    SYNC_THREADS ();
  }
}

#endif

DECLSPEC void m02810m (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC (), LOCAL_AS u32 *l_bin2asc)
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];
  salt_buf0[2] = salt_bufs[SALT_POS_HOST].salt_buf_pc[2];
  salt_buf0[3] = salt_bufs[SALT_POS_HOST].salt_buf_pc[3];
  salt_buf1[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[4];
  salt_buf1[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[5];
  salt_buf1[2] = salt_bufs[SALT_POS_HOST].salt_buf_pc[6];
  salt_buf1[3] = salt_bufs[SALT_POS_HOST].salt_buf_pc[7];
  salt_buf2[0] = 0;
  salt_buf2[1] = 0;
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;
  salt_buf3[0] = 0;
  salt_buf3[1] = 0;
  salt_buf3[2] = 0;
  salt_buf3[3] = 0;

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];
    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = w3[2];
    w3_t[3] = w3[3];

    /**
     * md5
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    a += make_u32x (MD5M_A);
    b += make_u32x (MD5M_B);
    c += make_u32x (MD5M_C);
    d += make_u32x (MD5M_D);

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = salt_buf0[2];
    w0_t[3] = salt_buf0[3];
    w1_t[0] = salt_buf1[0];
    w1_t[1] = salt_buf1[1];
    w1_t[2] = salt_buf1[2];
    w1_t[3] = salt_buf1[3];

    w2_t[0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
    w2_t[1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
    w2_t[2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
    w2_t[3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
    w3_t[0] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
    w3_t[1] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
    w3_t[2] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
    w3_t[3] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((d >> 24) & 255) << 16;

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H1, a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    const u32x r_a = a + make_u32x (MD5M_A);
    const u32x r_b = b + make_u32x (MD5M_B);
    const u32x r_c = c + make_u32x (MD5M_C);
    const u32x r_d = d + make_u32x (MD5M_D);

    const u32x r_00 = 0x80;
    const u32x r_14 = 64 * 8;

    a = r_a;
    b = r_b;
    c = r_c;
    d = r_d;

    MD5_STEP (MD5_Fo, a, b, c, d, r_00, MD5C00, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C01, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C02, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C03, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C04, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C05, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C06, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C07, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C08, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C09, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C0a, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C0b, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C0c, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, r_14, MD5C0e, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C0f, MD5S03);

    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C10, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C11, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, r_00, MD5C13, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C14, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C15, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C16, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C17, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, r_14, MD5C19, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C1a, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C1b, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C1c, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C1d, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C1e, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C1f, MD5S13);

    MD5_STEP0(MD5_H1, a, b, c, d,       MD5C20, MD5S20);
    MD5_STEP0(MD5_H2, d, a, b, c,       MD5C21, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,       MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, r_14, MD5C23, MD5S23);
    MD5_STEP0(MD5_H1, a, b, c, d,       MD5C24, MD5S20);
    MD5_STEP0(MD5_H2, d, a, b, c,       MD5C25, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,       MD5C26, MD5S22);
    MD5_STEP0(MD5_H2, b, c, d, a,       MD5C27, MD5S23);
    MD5_STEP0(MD5_H1, a, b, c, d,       MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, r_00, MD5C29, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,       MD5C2a, MD5S22);
    MD5_STEP0(MD5_H2, b, c, d, a,       MD5C2b, MD5S23);
    MD5_STEP0(MD5_H1, a, b, c, d,       MD5C2c, MD5S20);
    MD5_STEP0(MD5_H2, d, a, b, c,       MD5C2d, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,       MD5C2e, MD5S22);
    MD5_STEP0(MD5_H2, b, c, d, a,       MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, r_00, MD5C30, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, r_14, MD5C32, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C33, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C34, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C35, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C36, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C37, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C38, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C39, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C3a, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C3b, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C3c, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C3d, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C3e, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C3f, MD5S33);

    a += r_a;
    b += r_b;
    c += r_c;
    d += r_d;

    COMPARE_M_SIMD (a, d, c, b);
  }
}

DECLSPEC void m02810s (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC (), LOCAL_AS u32 *l_bin2asc)
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];
  salt_buf0[2] = salt_bufs[SALT_POS_HOST].salt_buf_pc[2];
  salt_buf0[3] = salt_bufs[SALT_POS_HOST].salt_buf_pc[3];
  salt_buf1[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[4];
  salt_buf1[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[5];
  salt_buf1[2] = salt_bufs[SALT_POS_HOST].salt_buf_pc[6];
  salt_buf1[3] = salt_bufs[SALT_POS_HOST].salt_buf_pc[7];
  salt_buf2[0] = 0;
  salt_buf2[1] = 0;
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;
  salt_buf3[0] = 0;
  salt_buf3[1] = 0;
  salt_buf3[2] = 0;
  salt_buf3[3] = 0;

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

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];
    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = w3[2];
    w3_t[3] = w3[3];

    /**
     * md5
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    a += make_u32x (MD5M_A);
    b += make_u32x (MD5M_B);
    c += make_u32x (MD5M_C);
    d += make_u32x (MD5M_D);

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = salt_buf0[2];
    w0_t[3] = salt_buf0[3];
    w1_t[0] = salt_buf1[0];
    w1_t[1] = salt_buf1[1];
    w1_t[2] = salt_buf1[2];
    w1_t[3] = salt_buf1[3];

    w2_t[0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
    w2_t[1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
    w2_t[2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
    w2_t[3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
    w3_t[0] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
    w3_t[1] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
    w3_t[2] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
    w3_t[3] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((d >> 24) & 255) << 16;

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H1, a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    const u32x r_a = a + make_u32x (MD5M_A);
    const u32x r_b = b + make_u32x (MD5M_B);
    const u32x r_c = c + make_u32x (MD5M_C);
    const u32x r_d = d + make_u32x (MD5M_D);

    const u32x r_00 = 0x80;
    const u32x r_14 = 64 * 8;

    a = r_a;
    b = r_b;
    c = r_c;
    d = r_d;

    MD5_STEP (MD5_Fo, a, b, c, d, r_00, MD5C00, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C01, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C02, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C03, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C04, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C05, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C06, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C07, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C08, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C09, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C0a, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C0b, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C0c, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, r_14, MD5C0e, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C0f, MD5S03);

    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C10, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C11, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, r_00, MD5C13, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C14, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C15, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C16, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C17, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, r_14, MD5C19, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C1a, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C1b, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C1c, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C1d, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C1e, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C1f, MD5S13);

    MD5_STEP0(MD5_H1, a, b, c, d,       MD5C20, MD5S20);
    MD5_STEP0(MD5_H2, d, a, b, c,       MD5C21, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,       MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, r_14, MD5C23, MD5S23);
    MD5_STEP0(MD5_H1, a, b, c, d,       MD5C24, MD5S20);
    MD5_STEP0(MD5_H2, d, a, b, c,       MD5C25, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,       MD5C26, MD5S22);
    MD5_STEP0(MD5_H2, b, c, d, a,       MD5C27, MD5S23);
    MD5_STEP0(MD5_H1, a, b, c, d,       MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, r_00, MD5C29, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,       MD5C2a, MD5S22);
    MD5_STEP0(MD5_H2, b, c, d, a,       MD5C2b, MD5S23);
    MD5_STEP0(MD5_H1, a, b, c, d,       MD5C2c, MD5S20);
    MD5_STEP0(MD5_H2, d, a, b, c,       MD5C2d, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,       MD5C2e, MD5S22);
    MD5_STEP0(MD5_H2, b, c, d, a,       MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, r_00, MD5C30, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, r_14, MD5C32, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C33, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C34, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C35, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C36, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C37, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C38, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C39, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C3a, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C3b, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C3c, MD5S30);

    if (MATCHES_NONE_VS ((a + r_a), search[0])) continue;

    MD5_STEP0(MD5_I , d, a, b, c,       MD5C3d, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C3e, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C3f, MD5S33);

    a += r_a;
    b += r_b;
    c += r_c;
    d += r_d;

    COMPARE_S_SIMD (a, d, c, b);
  }
}

KERNEL_FQ KERNEL_FA void m02810_m04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

#ifdef MULTI_SALT_WINDOW

  // every thread stays alive for the window staging barriers; the extra lanes repeat the last
  // candidate, and the hashes_shown atomics deduplicate their hits

  const u64 gid = (get_global_id (0) < (u64) GID_CNT) ? get_global_id (0) : (u64) (GID_CNT - 1);

#else

  const u64 gid = get_global_id (0);

#endif

  /**
   * modifier
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * bin2asc table
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

#ifdef MULTI_SALT_WINDOW

  LOCAL_VK u32 s_pc[MULTI_SALT_WINDOW * 8];
  LOCAL_VK u32 s_idx[MULTI_SALT_WINDOW];

#endif

  SYNC_THREADS ();

#ifndef MULTI_SALT_WINDOW
  if (gid >= GID_CNT) return;
#endif

  /**
   * main
   */

#ifdef MULTI_SALT_WINDOW

  m02810m_sweep (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_pc, s_idx, l_bin2asc);
#else
  m02810m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, l_bin2asc);
#endif
}

KERNEL_FQ KERNEL_FA void m02810_m08 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

#ifdef MULTI_SALT_WINDOW

  // every thread stays alive for the window staging barriers; the extra lanes repeat the last
  // candidate, and the hashes_shown atomics deduplicate their hits

  const u64 gid = (get_global_id (0) < (u64) GID_CNT) ? get_global_id (0) : (u64) (GID_CNT - 1);

#else

  const u64 gid = get_global_id (0);

#endif

  /**
   * modifier
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * bin2asc table
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

#ifdef MULTI_SALT_WINDOW

  LOCAL_VK u32 s_pc[MULTI_SALT_WINDOW * 8];
  LOCAL_VK u32 s_idx[MULTI_SALT_WINDOW];

#endif

  SYNC_THREADS ();

#ifndef MULTI_SALT_WINDOW
  if (gid >= GID_CNT) return;
#endif

  /**
   * main
   */

#ifdef MULTI_SALT_WINDOW
  m02810m_sweep (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_pc, s_idx, l_bin2asc);
#else
  m02810m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, l_bin2asc);
#endif
}

KERNEL_FQ KERNEL_FA void m02810_m16 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

#ifdef MULTI_SALT_WINDOW

  // every thread stays alive for the window staging barriers; the extra lanes repeat the last
  // candidate, and the hashes_shown atomics deduplicate their hits

  const u64 gid = (get_global_id (0) < (u64) GID_CNT) ? get_global_id (0) : (u64) (GID_CNT - 1);

#else

  const u64 gid = get_global_id (0);

#endif

  /**
   * modifier
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * bin2asc table
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

#ifdef MULTI_SALT_WINDOW

  LOCAL_VK u32 s_pc[MULTI_SALT_WINDOW * 8];
  LOCAL_VK u32 s_idx[MULTI_SALT_WINDOW];

#endif

  SYNC_THREADS ();

#ifndef MULTI_SALT_WINDOW
  if (gid >= GID_CNT) return;
#endif

  /**
   * main
   */

#ifdef MULTI_SALT_WINDOW
  m02810m_sweep (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_pc, s_idx, l_bin2asc);
#else
  m02810m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, l_bin2asc);
#endif
}

KERNEL_FQ KERNEL_FA void m02810_s04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * modifier
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * bin2asc table
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * main
   */

  m02810s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, l_bin2asc);
}

KERNEL_FQ KERNEL_FA void m02810_s08 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * modifier
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * bin2asc table
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * main
   */

  m02810s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, l_bin2asc);
}

KERNEL_FQ KERNEL_FA void m02810_s16 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * modifier
   */

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * bin2asc table
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * main
   */

  m02810s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, l_bin2asc);
}
