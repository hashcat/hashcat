/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_truecrypt_keyfile.h"

DECLSPEC u32 u8add (const u32 a, const u32 b)
{
  const u32 a1 = (a >>  0) & 0xff;
  const u32 a2 = (a >>  8) & 0xff;
  const u32 a3 = (a >> 16) & 0xff;
  const u32 a4 = (a >> 24) & 0xff;

  const u32 b1 = (b >>  0) & 0xff;
  const u32 b2 = (b >>  8) & 0xff;
  const u32 b3 = (b >> 16) & 0xff;
  const u32 b4 = (b >> 24) & 0xff;

  const u32 r1 = (a1 + b1) & 0xff;
  const u32 r2 = (a2 + b2) & 0xff;
  const u32 r3 = (a3 + b3) & 0xff;
  const u32 r4 = (a4 + b4) & 0xff;

  const u32 r = r1 <<  0
              | r2 <<  8
              | r3 << 16
              | r4 << 24;

  return r;
}

DECLSPEC u32 hc_apply_keyfile_tc (PRIVATE_AS u32 *w, const int pw_len, const GLOBAL_AS tc_t *tc)
{
  if (tc->keyfile_enabled == 0) return pw_len;

  if (pw_len > 64)
  {
    w[ 0] = u8add (w[ 0], tc->keyfile_buf32[ 0]);
    w[ 1] = u8add (w[ 1], tc->keyfile_buf32[ 1]);
    w[ 2] = u8add (w[ 2], tc->keyfile_buf32[ 2]);
    w[ 3] = u8add (w[ 3], tc->keyfile_buf32[ 3]);
    w[ 4] = u8add (w[ 4], tc->keyfile_buf32[ 4]);
    w[ 5] = u8add (w[ 5], tc->keyfile_buf32[ 5]);
    w[ 6] = u8add (w[ 6], tc->keyfile_buf32[ 6]);
    w[ 7] = u8add (w[ 7], tc->keyfile_buf32[ 7]);
    w[ 8] = u8add (w[ 8], tc->keyfile_buf32[ 8]);
    w[ 9] = u8add (w[ 9], tc->keyfile_buf32[ 9]);
    w[10] = u8add (w[10], tc->keyfile_buf32[10]);
    w[11] = u8add (w[11], tc->keyfile_buf32[11]);
    w[12] = u8add (w[12], tc->keyfile_buf32[12]);
    w[13] = u8add (w[13], tc->keyfile_buf32[13]);
    w[14] = u8add (w[14], tc->keyfile_buf32[14]);
    w[15] = u8add (w[15], tc->keyfile_buf32[15]);
    w[16] = u8add (w[16], tc->keyfile_buf32[16]);
    w[17] = u8add (w[17], tc->keyfile_buf32[17]);
    w[18] = u8add (w[18], tc->keyfile_buf32[18]);
    w[19] = u8add (w[19], tc->keyfile_buf32[19]);
    w[20] = u8add (w[20], tc->keyfile_buf32[20]);
    w[21] = u8add (w[21], tc->keyfile_buf32[21]);
    w[22] = u8add (w[22], tc->keyfile_buf32[22]);
    w[23] = u8add (w[23], tc->keyfile_buf32[23]);
    w[24] = u8add (w[24], tc->keyfile_buf32[24]);
    w[25] = u8add (w[25], tc->keyfile_buf32[25]);
    w[26] = u8add (w[26], tc->keyfile_buf32[26]);
    w[27] = u8add (w[27], tc->keyfile_buf32[27]);
    w[28] = u8add (w[28], tc->keyfile_buf32[28]);
    w[29] = u8add (w[29], tc->keyfile_buf32[29]);
    w[30] = u8add (w[30], tc->keyfile_buf32[30]);
    w[31] = u8add (w[31], tc->keyfile_buf32[31]);

    return 128;
  }
  else
  {
    w[ 0] = u8add (w[ 0], tc->keyfile_buf16[ 0]);
    w[ 1] = u8add (w[ 1], tc->keyfile_buf16[ 1]);
    w[ 2] = u8add (w[ 2], tc->keyfile_buf16[ 2]);
    w[ 3] = u8add (w[ 3], tc->keyfile_buf16[ 3]);
    w[ 4] = u8add (w[ 4], tc->keyfile_buf16[ 4]);
    w[ 5] = u8add (w[ 5], tc->keyfile_buf16[ 5]);
    w[ 6] = u8add (w[ 6], tc->keyfile_buf16[ 6]);
    w[ 7] = u8add (w[ 7], tc->keyfile_buf16[ 7]);
    w[ 8] = u8add (w[ 8], tc->keyfile_buf16[ 8]);
    w[ 9] = u8add (w[ 9], tc->keyfile_buf16[ 9]);
    w[10] = u8add (w[10], tc->keyfile_buf16[10]);
    w[11] = u8add (w[11], tc->keyfile_buf16[11]);
    w[12] = u8add (w[12], tc->keyfile_buf16[12]);
    w[13] = u8add (w[13], tc->keyfile_buf16[13]);
    w[14] = u8add (w[14], tc->keyfile_buf16[14]);
    w[15] = u8add (w[15], tc->keyfile_buf16[15]);

    return 64;
  }
}
