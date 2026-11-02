/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_OPENBSD_SOFTRAID_H
#define INC_OPENBSD_SOFTRAID_H

// The check that sr_crypto_decrypt_key () of OpenBSD sys/dev/softraid_crypto.c runs once the mask
// key is derived, which 38800 and 38810 share: they differ only in the KDF in front of it.

#define SR_CRYPTO_KEYSLEN 2048

typedef struct openbsd_softraid
{
  u32 masked_keys[SR_CRYPTO_KEYSLEN / 4];

} openbsd_softraid_t;

DECLSPEC void openbsd_softraid_check (PRIVATE_AS const u32 *mask_key, GLOBAL_AS const u32 *masked_keys, PRIVATE_AS u32 *chk, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4);

#endif // INC_OPENBSD_SOFTRAID_H
