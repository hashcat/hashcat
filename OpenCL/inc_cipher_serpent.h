/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

DECLSPEC void serpent128_set_key (u32 *ks, const u32 *ukey);
DECLSPEC void serpent128_encrypt (const u32 *ks, const u32 *in, u32 *out);
DECLSPEC void serpent128_decrypt (const u32 *ks, const u32 *in, u32 *out);
DECLSPEC void serpent256_set_key (u32 *ks, const u32 *ukey);
DECLSPEC void serpent256_encrypt (const u32 *ks, const u32 *in, u32 *out);
DECLSPEC void serpent256_decrypt (const u32 *ks, const u32 *in, u32 *out);
