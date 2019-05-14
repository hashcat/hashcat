/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_aes.h"
#include "inc_cipher_serpent.h"
#include "inc_cipher_twofish.h"
#include "inc_diskcryptor_xts.h"

DECLSPEC void dcrp_xts_mul2 (u32 *in, u32 *out)
{
  const u32 c = in[3] >> 31;

  out[3] = (in[3] << 1) | (in[2] >> 31);
  out[2] = (in[2] << 1) | (in[1] >> 31);
  out[1] = (in[1] << 1) | (in[0] >> 31);
  out[0] = (in[0] << 1);

  out[0] ^= c * 0x87;
}

DECLSPEC void dcrp_aes256_decrypt_xts (const u32 *ukey1, const u32 *ukey2, const u32 *in, u32 *out, u32 *S, u32 *T, u32 *ks, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];

  aes256_set_encrypt_key (ks, ukey2, s_te0, s_te1, s_te2, s_te3);
  aes256_encrypt (ks, S, T, s_te0, s_te1, s_te2, s_te3, s_te4);

  // skip four blocks (the starting position + 64 raw salt bytes that were replaced after encryption):

  dcrp_xts_mul2 (T, T);
  dcrp_xts_mul2 (T, T);
  dcrp_xts_mul2 (T, T);
  dcrp_xts_mul2 (T, T);

  out[0] ^= T[0];
  out[1] ^= T[1];
  out[2] ^= T[2];
  out[3] ^= T[3];

  aes256_set_decrypt_key (ks, ukey1, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);
  aes256_decrypt (ks, out, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] ^= T[0];
  out[1] ^= T[1];
  out[2] ^= T[2];
  out[3] ^= T[3];
}

DECLSPEC void dcrp_serpent256_decrypt_xts (const u32 *ukey1, const u32 *ukey2, const u32 *in, u32 *out, u32 *S, u32 *T, u32 *ks)
{
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];

  serpent256_set_key (ks, ukey2);
  serpent256_encrypt (ks, S, T);

  // skip four blocks (the starting position + 64 raw salt bytes that were replaced after encryption):

  dcrp_xts_mul2 (T, T);
  dcrp_xts_mul2 (T, T);
  dcrp_xts_mul2 (T, T);
  dcrp_xts_mul2 (T, T);

  out[0] ^= T[0];
  out[1] ^= T[1];
  out[2] ^= T[2];
  out[3] ^= T[3];

  serpent256_set_key (ks, ukey1);
  serpent256_decrypt (ks, out, out);

  out[0] ^= T[0];
  out[1] ^= T[1];
  out[2] ^= T[2];
  out[3] ^= T[3];
}

DECLSPEC void dcrp_twofish256_decrypt_xts (const u32 *ukey1, const u32 *ukey2, const u32 *in, u32 *out, u32 *S, u32 *T, u32 *sk, u32 *lk)
{
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];

  twofish256_set_key (sk, lk, ukey2);
  twofish256_encrypt (sk, lk, S, T);

  // skip four blocks (the starting position + 64 raw salt bytes that were replaced after encryption):

  dcrp_xts_mul2 (T, T);
  dcrp_xts_mul2 (T, T);
  dcrp_xts_mul2 (T, T);
  dcrp_xts_mul2 (T, T);

  out[0] ^= T[0];
  out[1] ^= T[1];
  out[2] ^= T[2];
  out[3] ^= T[3];

  twofish256_set_key (sk, lk, ukey1);
  twofish256_decrypt (sk, lk, out, out);

  out[0] ^= T[0];
  out[1] ^= T[1];
  out[2] ^= T[2];
  out[3] ^= T[3];
}

// 512 bit

DECLSPEC int dcrp_verify_header_aes (GLOBAL_AS const u32 *data_buf, const u32 *ukey1, const u32 *ukey2, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ks_aes[60];

  u32 S[4] = { 1, 0, 0, 0 }; // this weird offset / sector ID

  u32 T_aes[4] = { 0 };

  u32 data[4];

  data[0] = data_buf[0];
  data[1] = data_buf[1];
  data[2] = data_buf[2];
  data[3] = data_buf[3];

  u32 tmp[4];

  dcrp_aes256_decrypt_xts (ukey1, ukey2, data, tmp, S, T_aes, ks_aes, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  if (tmp[0] != 0x50524344) return 0; // signature / magic: "DCRP"

  if ((tmp[2] != 0x00040002) && (tmp[2] != 0x00050002) && (tmp[2] != 0x00080002)) return 0; // header version 0x0002 and flags either 0x04, 0x05 or 0x08

  if ((tmp[3] & 0xffff) != 0) return 0; // remaining 2 bytes of 0x00000004 / 0x00000005 / 0x00000008 => must be 0x0000

  return 1;
}

DECLSPEC int dcrp_verify_header_serpent (GLOBAL_AS const u32 *data_buf, const u32 *ukey1, const u32 *ukey2)
{
  u32 ks_serpent[140];

  u32 S[4] = { 1, 0, 0, 0 }; // this weird offset / sector ID. found by lot of research by philsmd

  u32 T_serpent[4] = { 0 };

  u32 data[4];

  data[0] = data_buf[0];
  data[1] = data_buf[1];
  data[2] = data_buf[2];
  data[3] = data_buf[3];

  u32 tmp[4];

  dcrp_serpent256_decrypt_xts (ukey1, ukey2, data, tmp, S, T_serpent, ks_serpent);

  if (tmp[0] != 0x50524344) return 0; // signature / magic: "DCRP"

  if ((tmp[2] != 0x00040002) && (tmp[2] != 0x00050002) && (tmp[2] != 0x00080002)) return 0; // header version 0x0002 and flags either 0x04, 0x05 or 0x08

  if ((tmp[3] & 0xffff) != 0) return 0; // remaining 2 bytes of 0x00000004 / 0x00000005 / 0x00000008 => must be 0x0000

  return 1;
}

DECLSPEC int dcrp_verify_header_twofish (GLOBAL_AS const u32 *data_buf, const u32 *ukey1, const u32 *ukey2)
{
  u32 sk_twofish[4];
  u32 lk_twofish[40];

  u32 S[4] = { 1, 0, 0, 0 }; // this weird offset / sector ID. found by lot of research by philsmd

  u32 T_twofish[4] = { 0 };

  u32 data[4];

  data[0] = data_buf[0];
  data[1] = data_buf[1];
  data[2] = data_buf[2];
  data[3] = data_buf[3];

  u32 tmp[4];

  dcrp_twofish256_decrypt_xts (ukey1, ukey2, data, tmp, S, T_twofish, sk_twofish, lk_twofish);

  if (tmp[0] != 0x50524344) return 0; // signature / magic: "DCRP"

  if ((tmp[2] != 0x00040002) && (tmp[2] != 0x00050002) && (tmp[2] != 0x00080002)) return 0; // header version 0x0002 and flags either 0x04, 0x05 or 0x08

  if ((tmp[3] & 0xffff) != 0) return 0; // remaining 2 bytes of 0x00000004 / 0x00000005 / 0x00000008 => must be 0x0000

  return 1;
}

// 1024 bit

DECLSPEC int dcrp_verify_header_aes_twofish (GLOBAL_AS const u32 *data_buf, const u32 *ukey1, const u32 *ukey2, const u32 *ukey3, const u32 *ukey4, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ks_aes[60];

  u32 sk_twofish[4];
  u32 lk_twofish[40];

  u32 S[4] = { 1, 0, 0, 0 }; // this weird offset / sector ID. found by lot of research by philsmd

  u32 T_aes[4]     = { 0 };
  u32 T_twofish[4] = { 0 };

  u32 data[4];

  data[0] = data_buf[0];
  data[1] = data_buf[1];
  data[2] = data_buf[2];
  data[3] = data_buf[3];

  u32 tmp[4];

  dcrp_aes256_decrypt_xts     (ukey2, ukey4, data, tmp, S, T_aes,     ks_aes, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);
  dcrp_twofish256_decrypt_xts (ukey1, ukey3, tmp,  tmp, S, T_twofish, sk_twofish, lk_twofish);

  if (tmp[0] != 0x50524344) return 0; // signature / magic: "DCRP"

  if ((tmp[2] != 0x00040002) && (tmp[2] != 0x00050002) && (tmp[2] != 0x00080002)) return 0; // header version 0x0002 and flags either 0x04, 0x05 or 0x08

  if ((tmp[3] & 0xffff) != 0) return 0; // remaining 2 bytes of 0x00000004 / 0x00000005 / 0x00000008 => must be 0x0000

  return 1;
}

DECLSPEC int dcrp_verify_header_serpent_aes (GLOBAL_AS const u32 *data_buf, const u32 *ukey1, const u32 *ukey2, const u32 *ukey3, const u32 *ukey4, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ks_serpent[140];
  u32 ks_aes[60];

  u32 S[4] = { 1, 0, 0, 0 }; // this weird offset / sector ID. found by lot of research by philsmd

  u32 T_serpent[4] = { 0 };
  u32 T_aes[4]     = { 0 };

  u32 data[4];

  data[0] = data_buf[0];
  data[1] = data_buf[1];
  data[2] = data_buf[2];
  data[3] = data_buf[3];

  u32 tmp[4];

  dcrp_serpent256_decrypt_xts (ukey2, ukey4, data, tmp, S, T_serpent, ks_serpent);
  dcrp_aes256_decrypt_xts     (ukey1, ukey3, tmp,  tmp, S, T_aes,     ks_aes, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  if (tmp[0] != 0x50524344) return 0; // signature / magic: "DCRP"

  if ((tmp[2] != 0x00040002) && (tmp[2] != 0x00050002) && (tmp[2] != 0x00080002)) return 0; // header version 0x0002 and flags either 0x04, 0x05 or 0x08

  if ((tmp[3] & 0xffff) != 0) return 0; // remaining 2 bytes of 0x00000004 / 0x00000005 / 0x00000008 => must be 0x0000

  return 1;
}

DECLSPEC int dcrp_verify_header_twofish_serpent (GLOBAL_AS const u32 *data_buf, const u32 *ukey1, const u32 *ukey2, const u32 *ukey3, const u32 *ukey4)
{
  u32 sk_twofish[4];
  u32 lk_twofish[40];

  u32 ks_serpent[140];

  u32 S[4] = { 1, 0, 0, 0 }; // this weird offset / sector ID. found by lot of research by philsmd

  u32 T_twofish[4] = { 0 };
  u32 T_serpent[4] = { 0 };

  u32 data[4];

  data[0] = data_buf[0];
  data[1] = data_buf[1];
  data[2] = data_buf[2];
  data[3] = data_buf[3];

  u32 tmp[4];

  dcrp_twofish256_decrypt_xts (ukey2, ukey4, data, tmp, S, T_twofish, sk_twofish, lk_twofish);
  dcrp_serpent256_decrypt_xts (ukey1, ukey3, tmp,  tmp, S, T_serpent, ks_serpent);

  if (tmp[0] != 0x50524344) return 0; // signature / magic: "DCRP"

  if ((tmp[2] != 0x00040002) && (tmp[2] != 0x00050002) && (tmp[2] != 0x00080002)) return 0; // header version 0x0002 and flags either 0x04, 0x05 or 0x08

  if ((tmp[3] & 0xffff) != 0) return 0; // remaining 2 bytes of 0x00000004 / 0x00000005 / 0x00000008 => must be 0x0000

  return 1;
}

// 1536 bit

DECLSPEC int dcrp_verify_header_aes_twofish_serpent (GLOBAL_AS const u32 *data_buf, const u32 *ukey1, const u32 *ukey2, const u32 *ukey3, const u32 *ukey4, const u32 *ukey5, const u32 *ukey6, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ks_aes[60];

  u32 sk_twofish[4];
  u32 lk_twofish[40];

  u32 ks_serpent[140];

  u32 S[4] = { 1, 0, 0, 0 }; // this weird offset / sector ID. found by lot of research by philsmd

  u32 T_aes[4]     = { 0 };
  u32 T_twofish[4] = { 0 };
  u32 T_serpent[4] = { 0 };

  u32 data[4];

  data[0] = data_buf[0];
  data[1] = data_buf[1];
  data[2] = data_buf[2];
  data[3] = data_buf[3];

  u32 tmp[4];

  dcrp_aes256_decrypt_xts     (ukey3, ukey6, data, tmp, S, T_aes,     ks_aes, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);
  dcrp_twofish256_decrypt_xts (ukey2, ukey5, tmp,  tmp, S, T_twofish, sk_twofish, lk_twofish);
  dcrp_serpent256_decrypt_xts (ukey1, ukey4, tmp,  tmp, S, T_serpent, ks_serpent);

  if (tmp[0] != 0x50524344) return 0; // signature / magic: "DCRP"

  if ((tmp[2] != 0x00040002) && (tmp[2] != 0x00050002) && (tmp[2] != 0x00080002)) return 0; // header version 0x0002 and flags either 0x04, 0x05 or 0x08

  if ((tmp[3] & 0xffff) != 0) return 0; // remaining 2 bytes of 0x00000004 / 0x00000005 / 0x00000008 => must be 0x0000

  return 1;
}

DECLSPEC int dcrp_verify_header_serpent_twofish_aes (GLOBAL_AS const u32 *data_buf, const u32 *ukey1, const u32 *ukey2, const u32 *ukey3, const u32 *ukey4, const u32 *ukey5, const u32 *ukey6, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ks_serpent[140];

  u32 sk_twofish[4];
  u32 lk_twofish[40];

  u32 ks_aes[60];

  u32 S[4] = { 1, 0, 0, 0 }; // this weird offset / sector ID. found by lot of research by philsmd

  u32 T_serpent[4] = { 0 };
  u32 T_twofish[4] = { 0 };
  u32 T_aes[4]     = { 0 };

  u32 data[4];

  data[0] = data_buf[0];
  data[1] = data_buf[1];
  data[2] = data_buf[2];
  data[3] = data_buf[3];

  u32 tmp[4];

  dcrp_serpent256_decrypt_xts (ukey3, ukey6, data, tmp, S, T_serpent, ks_serpent);
  dcrp_twofish256_decrypt_xts (ukey2, ukey5, tmp,  tmp, S, T_twofish, sk_twofish, lk_twofish);
  dcrp_aes256_decrypt_xts     (ukey1, ukey4, tmp,  tmp, S, T_aes,     ks_aes, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  if (tmp[0] != 0x50524344) return 0; // signature / magic: "DCRP"

  if ((tmp[2] != 0x00040002) && (tmp[2] != 0x00050002) && (tmp[2] != 0x00080002)) return 0; // header version 0x0002 and flags either 0x04, 0x05 or 0x08

  if ((tmp[3] & 0xffff) != 0) return 0; // remaining 2 bytes of 0x00000004 / 0x00000005 / 0x00000008 => must be 0x0000

  return 1;
}
