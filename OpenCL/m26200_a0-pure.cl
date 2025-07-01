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
#include M2S(INCLUDE_PATH/inc_rp_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#endif

CONSTANT_VK u32a PE_CONST[256] =
{
      0, 49345, 49537,   320, 49921,   960,   640, 49729, 50689,  1728,  1920, 51009,  1280, 50625, 50305,  1088,
  52225,  3264,  3456, 52545,  3840, 53185, 52865,  3648,  2560, 51905, 52097,  2880, 51457,  2496,  2176, 51265,
  55297,  6336,  6528, 55617,  6912, 56257, 55937,  6720,  7680, 57025, 57217,  8000, 56577,  7616,  7296, 56385,
   5120, 54465, 54657,  5440, 55041,  6080,  5760, 54849, 53761,  4800,  4992, 54081,  4352, 53697, 53377,  4160,
  61441, 12480, 12672, 61761, 13056, 62401, 62081, 12864, 13824, 63169, 63361, 14144, 62721, 13760, 13440, 62529,
  15360, 64705, 64897, 15680, 65281, 16320, 16000, 65089, 64001, 15040, 15232, 64321, 14592, 63937, 63617, 14400,
  10240, 59585, 59777, 10560, 60161, 11200, 10880, 59969, 60929, 11968, 12160, 61249, 11520, 60865, 60545, 11328,
  58369,  9408,  9600, 58689,  9984, 59329, 59009,  9792,  8704, 58049, 58241,  9024, 57601,  8640,  8320, 57409,
  40961, 24768, 24960, 41281, 25344, 41921, 41601, 25152, 26112, 42689, 42881, 26432, 42241, 26048, 25728, 42049,
  27648, 44225, 44417, 27968, 44801, 28608, 28288, 44609, 43521, 27328, 27520, 43841, 26880, 43457, 43137, 26688,
  30720, 47297, 47489, 31040, 47873, 31680, 31360, 47681, 48641, 32448, 32640, 48961, 32000, 48577, 48257, 31808,
  46081, 29888, 30080, 46401, 30464, 47041, 46721, 30272, 29184, 45761, 45953, 29504, 45313, 29120, 28800, 45121,
  20480, 37057, 37249, 20800, 37633, 21440, 21120, 37441, 38401, 22208, 22400, 38721, 21760, 38337, 38017, 21568,
  39937, 23744, 23936, 40257, 24320, 40897, 40577, 24128, 23040, 39617, 39809, 23360, 39169, 22976, 22656, 38977,
  34817, 18624, 18816, 35137, 19200, 35777, 35457, 19008, 19968, 36545, 36737, 20288, 36097, 19904, 19584, 35905,
  17408, 33985, 34177, 17728, 34561, 18368, 18048, 34369, 33281, 17088, 17280, 33601, 16640, 33217, 32897, 16448
};

KERNEL_FQ KERNEL_FA void m26200_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 hash = 17;

    u8  scratch[16] = { 0 };

    PRIVATE_AS u8 *input = (PRIVATE_AS u8 *) tmp.i;

    for (u32 i = 0; i < 5; i++)
    {
      for (u32 j = 0; j < tmp.pw_len; j++)
      {
        int idx = 15 - (j & 15);

        scratch[idx] ^= input[j];
      }

      for (u32 j = 0; j < 16; j += 2)
      {
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[15]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[14]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[13]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[12]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[11]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[10]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 9]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 8]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 7]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 6]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 5]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 4]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 3]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 2]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 1]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 0]]);

        scratch[j]     = (unsigned char)( hash       & 0xff);
        scratch[j + 1] = (unsigned char)((hash >> 8) & 0xff);
      }
    }

    u8 target[16] = { 0 };

    for (u32 i = 0; i < 16; i++)
    {
      u8 lower = (scratch[i] & 0x7f);

      if ((lower >= 'A' && lower <= 'Z') || (lower >= 'a' && lower <= 'z'))
      {
        target[i] = lower;
      }
      else
      {
        target[i] = (u8)((scratch[i] >> 4) + 0x61);
      }
    }

    PRIVATE_AS u32 *digest = (PRIVATE_AS u32 *) target;

    const u32 r0 = digest[DGST_R0];
    const u32 r1 = digest[DGST_R1];
    const u32 r2 = digest[DGST_R2];
    const u32 r3 = digest[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m26200_sxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 hash = 17;

    u8  scratch[16] = { 0 };

    PRIVATE_AS u8 *input = (PRIVATE_AS u8 *) tmp.i;

    for (u32 i = 0; i < 5; i++)
    {
      for (u32 j = 0; j < tmp.pw_len; j++)
      {
        int idx = 15 - (j & 15);

        scratch[idx] ^= input[j];
      }

      for (u32 j = 0; j < 16; j += 2)
      {
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[15]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[14]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[13]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[12]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[11]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[10]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 9]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 8]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 7]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 6]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 5]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 4]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 3]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 2]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 1]]);
        hash = (hash >> 8 ^ PE_CONST[hash & 0xff] ^ PE_CONST[scratch[ 0]]);

        scratch[j]     = (unsigned char)( hash       & 0xff);
        scratch[j + 1] = (unsigned char)((hash >> 8) & 0xff);
      }
    }

    u8 target[16] = { 0 };

    for (u32 i = 0; i < 16; i++)
    {
      u8 lower = (scratch[i] & 0x7f);

      if ((lower >= 'A' && lower <= 'Z') || (lower >= 'a' && lower <= 'z'))
      {
        target[i] = lower;
      }
      else
      {
        target[i] = (u8)((scratch[i] >> 4) + 0x61);
      }
    }

    PRIVATE_AS u32 *digest = (PRIVATE_AS u32 *) target;

    const u32 r0 = digest[DGST_R0];
    const u32 r1 = digest[DGST_R1];
    const u32 r2 = digest[DGST_R2];
    const u32 r3 = digest[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
