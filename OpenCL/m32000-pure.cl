/**
 * Author......: hansvh
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct sha1_tmp
{
  u32 digest[5];
} sha1_tmp_t;

CONSTANT_AS uchar newdes_rotor[256] = {
  32, 137, 239, 188, 102, 125, 221, 72, 212, 68, 81, 37, 86, 237, 147, 149,
  70, 229, 17, 124, 115, 207, 33, 20, 122, 143, 25, 215, 51, 183, 138, 142,
  146, 211, 110, 173, 1, 228, 189, 14, 103, 78, 162, 36, 253, 167, 116, 255,
  158, 45, 185, 50, 98, 168, 250, 235, 54, 141, 195, 247, 240, 63, 148, 2,
  224, 169, 214, 180, 62, 22, 117, 108, 19, 172, 161, 159, 160, 47, 43, 171,
  194, 175, 178, 56, 196, 112, 23, 220, 89, 21, 164, 130, 157, 8, 85, 251,
  216, 44, 94, 179, 226, 38, 90, 119, 40, 202, 34, 206, 35, 69, 231, 246,
  29, 109, 74, 71, 176, 6, 60, 145, 65, 13, 77, 151, 12, 127, 95, 199,
  57, 101, 5, 232, 150, 210, 129, 24, 181, 10, 121, 187, 48, 193, 139, 252,
  219, 64, 88, 233, 96, 128, 80, 53, 191, 144, 218, 11, 106, 132, 155, 104,
  91, 136, 31, 42, 243, 66, 126, 135, 30, 26, 87, 186, 182, 154, 242, 123,
  82, 166, 208, 39, 152, 190, 113, 205, 114, 105, 225, 84, 73, 163, 99, 111,
  204, 61, 200, 217, 170, 15, 198, 28, 192, 254, 134, 234, 222, 7, 236, 248,
  201, 41, 177, 156, 92, 131, 67, 249, 245, 184, 203, 9, 241, 0, 27, 46,
  133, 174, 75, 18, 93, 209, 100, 120, 76, 213, 16, 83, 4, 107, 140, 52,
  58, 55, 3, 244, 97, 197, 238, 227, 118, 49, 79, 230, 223, 165, 153, 59
};

void new_des (uchar * block, uchar * newdes_key)
{
#define B0 (*block)
#define B1 (*(block+1))
#define B2 (*(block+2))
#define B3 (*(block+3))
#define B4 (*(block+4))
#define B5 (*(block+5))
#define B6 (*(block+6))
#define B7 (*(block+7))



  for (int count = 0; count < 8; count++)
  {
    B4 = B4 ^ newdes_rotor[B0 ^ *(newdes_key++)];
    B5 = B5 ^ newdes_rotor[B1 ^ *(newdes_key++)];
    B6 = B6 ^ newdes_rotor[B2 ^ *(newdes_key++)];
    B7 = B7 ^ newdes_rotor[B3 ^ *(newdes_key++)];

    B1 = B1 ^ newdes_rotor[B4 ^ *(newdes_key++)];
    B2 = B2 ^ newdes_rotor[B4 ^ B5];
    B3 = B3 ^ newdes_rotor[B6 ^ *(newdes_key++)];
    B0 = B0 ^ newdes_rotor[B7 ^ *(newdes_key++)];
  }

  B4 = B4 ^ newdes_rotor[B0 ^ *(newdes_key++)];
  B5 = B5 ^ newdes_rotor[B1 ^ *(newdes_key++)];
  B6 = B6 ^ newdes_rotor[B2 ^ *(newdes_key++)];
  B7 = B7 ^ newdes_rotor[B3 ^ *(newdes_key++)];
}

void key_expansion (uchar * sha1sum, uchar * result)
{
  uchar *shi = sha1sum;

  for (int count = 0; count < 15; count++)
  {
    *result = *shi;
    *(result + 1) = *shi ^ sha1sum[7];
    *(result + 2) = *shi ^ sha1sum[8];
    *(result + 3) = *shi++ ^ sha1sum[9];

    result += 4;
  }
}

KERNEL_FQ void m32000_init (KERN_ATTR_TMPS (sha1_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  // Initial "SHA-1" (with endianness bug)
  sha1_ctx_t ctx;

  sha1_init (&ctx);
  sha1_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
  sha1_final (&ctx);

  tmps[gid].digest[0] = hc_swap32 (ctx.h[0]);
  tmps[gid].digest[1] = hc_swap32 (ctx.h[1]);
  tmps[gid].digest[2] = hc_swap32 (ctx.h[2]);
  tmps[gid].digest[3] = hc_swap32 (ctx.h[3]);
  tmps[gid].digest[4] = hc_swap32 (ctx.h[4]);
}

KERNEL_FQ void m32000_loop (KERN_ATTR_TMPS (sha1_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  u32 digest[5];

  digest[0] = tmps[gid].digest[0];
  digest[1] = tmps[gid].digest[1];
  digest[2] = tmps[gid].digest[2];
  digest[3] = tmps[gid].digest[3];
  digest[4] = tmps[gid].digest[4];

  // Crate a NewDES key
  uchar newdes_key[60];

  key_expansion ((uchar *) digest, newdes_key);

  // Run NewDES on salt using the expanded key
  u32 salt[16] = { 0 };         // sha1_update_swap needs more space then our 8 byte salt; This seem to work!
  salt[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  // Run 1000 iterations of NewDES on the derived salt
  for (int i = 0; i < 1000; i++)
  {
    new_des ((uchar *) salt, newdes_key);
  }

  // Final "SHA-1" (with endianness bug)
  sha1_ctx_t ctx;

  sha1_init (&ctx);
  sha1_update_swap (&ctx, salt, 8);
  sha1_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
  sha1_final (&ctx);

  tmps[gid].digest[0] = ctx.h[0];
  tmps[gid].digest[1] = ctx.h[1];
  tmps[gid].digest[2] = ctx.h[2];
  tmps[gid].digest[3] = ctx.h[3];
  tmps[gid].digest[4] = ctx.h[4];
}

KERNEL_FQ void m32000_comp (KERN_ATTR_TMPS (sha1_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT)
    return;

  const u32 r0 = tmps[gid].digest[DGST_R0];
  const u32 r1 = tmps[gid].digest[DGST_R1];
  const u32 r2 = tmps[gid].digest[DGST_R2];
  const u32 r3 = tmps[gid].digest[DGST_R3];

#define il_pos 0

#ifdef KERNEL_STATIC
#include COMPARE_M
#endif
}
