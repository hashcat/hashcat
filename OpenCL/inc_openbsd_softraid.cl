/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_sha1.h"
#include "inc_cipher_aes.h"
#include "inc_openbsd_softraid.h"

// The mask key is 32 bytes in little endian words, the order the AES key schedule reads. The 32
// sector keys are decrypted 16 bytes at a time in ECB and go into an HMAC-SHA1 keyed with the SHA1
// of the mask key, as sr_crypto_calculate_check_hmac_sha1 () does. There is no early exit: the
// HMAC covers all 2048 bytes, so every candidate decrypts all of them. chk gets the five words in
// the order SHA-1 leaves them.

DECLSPEC void openbsd_softraid_check (PRIVATE_AS const u32 *mask_key, GLOBAL_AS const u32 *masked_keys, PRIVATE_AS u32 *chk, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 mk[16] = { 0 };

  for (u32 i = 0; i < 8; i++) mk[i] = mask_key[i];

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  sha1_update_swap (&ctx, mk, 32);

  sha1_final (&ctx);

  u32 hk[16] = { 0 };

  for (u32 i = 0; i < 5; i++) hk[i] = ctx.h[i];

  sha1_hmac_ctx_t hmac_ctx;

  sha1_hmac_init (&hmac_ctx, hk, 20);

  u32 ks[60];

  aes256_set_decrypt_key (ks, mask_key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  for (u32 off = 0; off < SR_CRYPTO_KEYSLEN / 4; off += 16)
  {
    u32 pt[16];

    for (u32 b = 0; b < 16; b += 4)
    {
      u32 ct[4];

      ct[0] = masked_keys[off + b + 0];
      ct[1] = masked_keys[off + b + 1];
      ct[2] = masked_keys[off + b + 2];
      ct[3] = masked_keys[off + b + 3];

      aes256_decrypt (ks, ct, &pt[b], s_td0, s_td1, s_td2, s_td3, s_td4);
    }

    for (u32 i = 0; i < 16; i++) pt[i] = hc_swap32_S (pt[i]);

    sha1_hmac_update (&hmac_ctx, pt, 64);
  }

  sha1_hmac_final (&hmac_ctx);

  for (u32 i = 0; i < 5; i++) chk[i] = hmac_ctx.opad.h[i];
}
