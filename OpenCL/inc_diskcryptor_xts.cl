DECLSPEC void xts_mul2 (u32 *in, u32 *out)
{
  const u32 c = in[3] >> 31;

  out[3] = (in[3] << 1) | (in[2] >> 31);
  out[2] = (in[2] << 1) | (in[1] >> 31);
  out[1] = (in[1] << 1) | (in[0] >> 31);
  out[0] = (in[0] << 1);

  out[0] ^= c * 0x87;
}

DECLSPEC void aes256_decrypt_xts (const u32 *ukey1, const u32 *ukey2, const u32 *in, u32 *out, u32 *S, u32 *T, u32 *ks, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];

  aes256_set_encrypt_key (ks, ukey2, s_te0, s_te1, s_te2, s_te3);
  aes256_encrypt (ks, S, T, s_te0, s_te1, s_te2, s_te3, s_te4);

  // skip four blocks (the starting position + 64 raw salt bytes that were replaced after encryption):

  xts_mul2 (T, T);
  xts_mul2 (T, T);
  xts_mul2 (T, T);
  xts_mul2 (T, T);

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

DECLSPEC int decrypt_and_check (GLOBAL_AS const u32 *encrypted_data, const u32 *ukey1, const u32 *ukey2, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ks_aes[60];

  u32 S[4] = { 1, 0, 0, 0 }; // this weird offset / sector ID. found by lot of research by philsmd

  u32 T_aes[4] = { 0 };

  u32 data[4];

  data[0] = encrypted_data[0];
  data[1] = encrypted_data[1];
  data[2] = encrypted_data[2];
  data[3] = encrypted_data[3];

  u32 out[4];

  aes256_decrypt_xts (ukey1, ukey2, data, out, S, T_aes, ks_aes, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  if (out[0] != 0x50524344) return 0; // signature / magic: "DCRP"

  if ((out[2] != 0x00040002) && (out[2] != 0x00050002)) return 0; // header version 0x0002 and flags either 0x04 or 0x05

  if ((out[3] & 0xffff) != 0) return 0; // remaining 2 bytes of 0x00000004 / 0x00000005 => must be 0x0000

  return 1;
}
