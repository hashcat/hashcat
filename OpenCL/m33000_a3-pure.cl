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

/**
 * 破解逻辑:
 * 1. 输入的密文格式为 {enc8}BASE64STRING
 * 2. 去掉{enc8}前缀后进行base64解码
 * 3. 解码后的数据:
 *    - 前16字节为MD5哈希值
 *    - 后4字节为salt值
 * 4. 使用密码和salt组合: $pass.$salt
 * 5. 对组合后的字符串进行MD5哈希
 * 6. 比较计算结果与目标哈希值
 */

KERNEL_FQ void m33000_mxx (KERN_ATTR_VECTOR ())
{
  /**
   * 修饰符
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * 基础
   */

  const u32 pw_len = pws[gid].pw_len;

  // 存储密码
  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  // 获取salt
  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  // 打印第一个密码尝试的信息
  if (gid == 0 && lid == 0)
  {
    printf("[DEBUG-GPU] Salt length: %u\n", salt_len);
    printf("[DEBUG-GPU] Salt value: %08x\n", s[0]);
    printf("[DEBUG-GPU] Password length: %u\n", pw_len);
    printf("[DEBUG-GPU] First word: %08x\n", w[0]);
  }

  /**
   * 循环
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    // 初始化MD5上下文
    md5_ctx_vector_t ctx;

    md5_init_vector (&ctx);

    // 先更新密码
    md5_update_vector (&ctx, w, pw_len);

    // 再更新salt
    md5_update_vector (&ctx, s, salt_len);

    // 计算最终哈希值
    md5_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    // 打印第一个哈希计算的结果
    if (gid == 0 && il_pos == 0)
    {
      printf("[DEBUG-GPU] Password length: %u\n", pw_len);
      printf("[DEBUG-GPU] Salt length: %u\n", salt_len);
      printf("[DEBUG-GPU] First password bytes: %02x %02x %02x %02x\n",
             w[0] & 0xff, (w[0] >> 8) & 0xff, (w[0] >> 16) & 0xff, (w[0] >> 24) & 0xff);
      printf("[DEBUG-GPU] Salt bytes: %02x %02x %02x %02x\n",
             s[0] & 0xff, (s[0] >> 8) & 0xff, (s[0] >> 16) & 0xff, (s[0] >> 24) & 0xff);
      printf("[DEBUG-GPU] Computed hash: %08x %08x %08x %08x\n", r0, r1, r2, r3);
    }

    // 打印计算得到的哈希值(仅第一个线程)
    if (gid == 0 && il_pos == 0)
    {
      printf("[DEBUG-GPU] Computed hash: %08x %08x %08x %08x\n", r0, r1, r2, r3);
    }

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m33000_sxx (KERN_ATTR_VECTOR ())
{
  /**
   * 修饰符
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * 摘要
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * 基础
   */

  const u32 pw_len = pws[gid].pw_len;

  // 存储密码
  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  // 获取salt
  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  /**
   * 循环
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    // 初始化MD5上下文
    md5_ctx_vector_t ctx;

    md5_init_vector (&ctx);

    // 先更新密码
    md5_update_vector (&ctx, w, pw_len);

    // 再更新salt
    md5_update_vector (&ctx, s, salt_len);

    // 计算最终哈希值
    md5_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    // 打印计算得到的哈希值(仅第一个线程)
    if (gid == 0 && il_pos == 0)
    {
      printf("[DEBUG-GPU] Computed hash: %08x %08x %08x %08x\n", r0, r1, r2, r3);
    }

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}