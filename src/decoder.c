/**
* decoder
*/

static void AES128_decrypt_cbc(const u32 key[4], const u32 iv[4], const u32 in[16], u32 out[16])
{
  AES_KEY skey;

  AES_set_decrypt_key((const u8 *)key, 128, &skey);

  u32 _iv[4] = { 0 };

  _iv[0] = iv[0];
  _iv[1] = iv[1];
  _iv[2] = iv[2];
  _iv[3] = iv[3];

  for (int i = 0; i < 16; i += 4)
  {
    u32 _in[4] = { 0 };
    u32 _out[4] = { 0 };

    _in[0] = in[i + 0];
    _in[1] = in[i + 1];
    _in[2] = in[i + 2];
    _in[3] = in[i + 3];

    AES_decrypt(&skey, (const u8 *)_in, (u8 *)_out);

    _out[0] ^= _iv[0];
    _out[1] ^= _iv[1];
    _out[2] ^= _iv[2];
    _out[3] ^= _iv[3];

    out[i + 0] = _out[0];
    out[i + 1] = _out[1];
    out[i + 2] = _out[2];
    out[i + 3] = _out[3];

    _iv[0] = _in[0];
    _iv[1] = _in[1];
    _iv[2] = _in[2];
    _iv[3] = _in[3];
  }
}

static void juniper_decrypt_hash(char *in, char *out)
{
  // base64 decode

  u8 base64_buf[100] = { 0 };

  base64_decode(base64_to_int, (const u8 *)in, DISPLAY_LEN_MIN_501, base64_buf);

  // iv stuff

  u32 juniper_iv[4] = { 0 };

  memcpy(juniper_iv, base64_buf, 12);

  memcpy(out, juniper_iv, 12);

  // reversed key

  u32 juniper_key[4] = { 0 };

  juniper_key[0] = byte_swap_32(0xa6707a7e);
  juniper_key[1] = byte_swap_32(0x8df91059);
  juniper_key[2] = byte_swap_32(0xdea70ae5);
  juniper_key[3] = byte_swap_32(0x2f9c2442);

  // AES decrypt

  u32 *in_ptr = (u32 *)(base64_buf + 12);
  u32 *out_ptr = (u32 *)(out + 12);

  AES128_decrypt_cbc(juniper_key, juniper_iv, in_ptr, out_ptr);
}

void phpass_decode(u8 digest[16], u8 buf[22])
{
  int l;

  l = itoa64_to_int(buf[0]) << 0;
  l |= itoa64_to_int(buf[1]) << 6;
  l |= itoa64_to_int(buf[2]) << 12;
  l |= itoa64_to_int(buf[3]) << 18;

  digest[0] = (l >> 0) & 0xff;
  digest[1] = (l >> 8) & 0xff;
  digest[2] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[4]) << 0;
  l |= itoa64_to_int(buf[5]) << 6;
  l |= itoa64_to_int(buf[6]) << 12;
  l |= itoa64_to_int(buf[7]) << 18;

  digest[3] = (l >> 0) & 0xff;
  digest[4] = (l >> 8) & 0xff;
  digest[5] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[8]) << 0;
  l |= itoa64_to_int(buf[9]) << 6;
  l |= itoa64_to_int(buf[10]) << 12;
  l |= itoa64_to_int(buf[11]) << 18;

  digest[6] = (l >> 0) & 0xff;
  digest[7] = (l >> 8) & 0xff;
  digest[8] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[12]) << 0;
  l |= itoa64_to_int(buf[13]) << 6;
  l |= itoa64_to_int(buf[14]) << 12;
  l |= itoa64_to_int(buf[15]) << 18;

  digest[9] = (l >> 0) & 0xff;
  digest[10] = (l >> 8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[16]) << 0;
  l |= itoa64_to_int(buf[17]) << 6;
  l |= itoa64_to_int(buf[18]) << 12;
  l |= itoa64_to_int(buf[19]) << 18;

  digest[12] = (l >> 0) & 0xff;
  digest[13] = (l >> 8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[20]) << 0;
  l |= itoa64_to_int(buf[21]) << 6;

  digest[15] = (l >> 0) & 0xff;
}

void phpass_encode(u8 digest[16], u8 buf[22])
{
  int l;

  l = (digest[0] << 0) | (digest[1] << 8) | (digest[2] << 16);

  buf[0] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[1] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[2] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[3] = int_to_itoa64(l & 0x3f);

  l = (digest[3] << 0) | (digest[4] << 8) | (digest[5] << 16);

  buf[4] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[5] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[6] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[7] = int_to_itoa64(l & 0x3f);

  l = (digest[6] << 0) | (digest[7] << 8) | (digest[8] << 16);

  buf[8] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[9] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64(l & 0x3f);

  l = (digest[9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64(l & 0x3f);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64(l & 0x3f);

  l = (digest[15] << 0);

  buf[20] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64(l & 0x3f);
}

void md5crypt_decode(u8 digest[16], u8 buf[22])
{
  int l;

  l = itoa64_to_int(buf[0]) << 0;
  l |= itoa64_to_int(buf[1]) << 6;
  l |= itoa64_to_int(buf[2]) << 12;
  l |= itoa64_to_int(buf[3]) << 18;

  digest[0] = (l >> 16) & 0xff;
  digest[6] = (l >> 8) & 0xff;
  digest[12] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[4]) << 0;
  l |= itoa64_to_int(buf[5]) << 6;
  l |= itoa64_to_int(buf[6]) << 12;
  l |= itoa64_to_int(buf[7]) << 18;

  digest[1] = (l >> 16) & 0xff;
  digest[7] = (l >> 8) & 0xff;
  digest[13] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[8]) << 0;
  l |= itoa64_to_int(buf[9]) << 6;
  l |= itoa64_to_int(buf[10]) << 12;
  l |= itoa64_to_int(buf[11]) << 18;

  digest[2] = (l >> 16) & 0xff;
  digest[8] = (l >> 8) & 0xff;
  digest[14] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[12]) << 0;
  l |= itoa64_to_int(buf[13]) << 6;
  l |= itoa64_to_int(buf[14]) << 12;
  l |= itoa64_to_int(buf[15]) << 18;

  digest[3] = (l >> 16) & 0xff;
  digest[9] = (l >> 8) & 0xff;
  digest[15] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[16]) << 0;
  l |= itoa64_to_int(buf[17]) << 6;
  l |= itoa64_to_int(buf[18]) << 12;
  l |= itoa64_to_int(buf[19]) << 18;

  digest[4] = (l >> 16) & 0xff;
  digest[10] = (l >> 8) & 0xff;
  digest[5] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[20]) << 0;
  l |= itoa64_to_int(buf[21]) << 6;

  digest[11] = (l >> 0) & 0xff;
}

void md5crypt_encode(u8 digest[16], u8 buf[22])
{
  int l;

  l = (digest[0] << 16) | (digest[6] << 8) | (digest[12] << 0);

  buf[0] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[1] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[2] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[3] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[1] << 16) | (digest[7] << 8) | (digest[13] << 0);

  buf[4] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[5] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[6] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[7] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[2] << 16) | (digest[8] << 8) | (digest[14] << 0);

  buf[8] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[9] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[3] << 16) | (digest[9] << 8) | (digest[15] << 0);

  buf[12] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[4] << 16) | (digest[10] << 8) | (digest[5] << 0);

  buf[16] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[11] << 0);

  buf[20] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64(l & 0x3f); l >>= 6;
}

void sha512crypt_decode(u8 digest[64], u8 buf[86])
{
  int l;

  l = itoa64_to_int(buf[0]) << 0;
  l |= itoa64_to_int(buf[1]) << 6;
  l |= itoa64_to_int(buf[2]) << 12;
  l |= itoa64_to_int(buf[3]) << 18;

  digest[0] = (l >> 16) & 0xff;
  digest[21] = (l >> 8) & 0xff;
  digest[42] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[4]) << 0;
  l |= itoa64_to_int(buf[5]) << 6;
  l |= itoa64_to_int(buf[6]) << 12;
  l |= itoa64_to_int(buf[7]) << 18;

  digest[22] = (l >> 16) & 0xff;
  digest[43] = (l >> 8) & 0xff;
  digest[1] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[8]) << 0;
  l |= itoa64_to_int(buf[9]) << 6;
  l |= itoa64_to_int(buf[10]) << 12;
  l |= itoa64_to_int(buf[11]) << 18;

  digest[44] = (l >> 16) & 0xff;
  digest[2] = (l >> 8) & 0xff;
  digest[23] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[12]) << 0;
  l |= itoa64_to_int(buf[13]) << 6;
  l |= itoa64_to_int(buf[14]) << 12;
  l |= itoa64_to_int(buf[15]) << 18;

  digest[3] = (l >> 16) & 0xff;
  digest[24] = (l >> 8) & 0xff;
  digest[45] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[16]) << 0;
  l |= itoa64_to_int(buf[17]) << 6;
  l |= itoa64_to_int(buf[18]) << 12;
  l |= itoa64_to_int(buf[19]) << 18;

  digest[25] = (l >> 16) & 0xff;
  digest[46] = (l >> 8) & 0xff;
  digest[4] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[20]) << 0;
  l |= itoa64_to_int(buf[21]) << 6;
  l |= itoa64_to_int(buf[22]) << 12;
  l |= itoa64_to_int(buf[23]) << 18;

  digest[47] = (l >> 16) & 0xff;
  digest[5] = (l >> 8) & 0xff;
  digest[26] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[24]) << 0;
  l |= itoa64_to_int(buf[25]) << 6;
  l |= itoa64_to_int(buf[26]) << 12;
  l |= itoa64_to_int(buf[27]) << 18;

  digest[6] = (l >> 16) & 0xff;
  digest[27] = (l >> 8) & 0xff;
  digest[48] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[28]) << 0;
  l |= itoa64_to_int(buf[29]) << 6;
  l |= itoa64_to_int(buf[30]) << 12;
  l |= itoa64_to_int(buf[31]) << 18;

  digest[28] = (l >> 16) & 0xff;
  digest[49] = (l >> 8) & 0xff;
  digest[7] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[32]) << 0;
  l |= itoa64_to_int(buf[33]) << 6;
  l |= itoa64_to_int(buf[34]) << 12;
  l |= itoa64_to_int(buf[35]) << 18;

  digest[50] = (l >> 16) & 0xff;
  digest[8] = (l >> 8) & 0xff;
  digest[29] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[36]) << 0;
  l |= itoa64_to_int(buf[37]) << 6;
  l |= itoa64_to_int(buf[38]) << 12;
  l |= itoa64_to_int(buf[39]) << 18;

  digest[9] = (l >> 16) & 0xff;
  digest[30] = (l >> 8) & 0xff;
  digest[51] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[40]) << 0;
  l |= itoa64_to_int(buf[41]) << 6;
  l |= itoa64_to_int(buf[42]) << 12;
  l |= itoa64_to_int(buf[43]) << 18;

  digest[31] = (l >> 16) & 0xff;
  digest[52] = (l >> 8) & 0xff;
  digest[10] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[44]) << 0;
  l |= itoa64_to_int(buf[45]) << 6;
  l |= itoa64_to_int(buf[46]) << 12;
  l |= itoa64_to_int(buf[47]) << 18;

  digest[53] = (l >> 16) & 0xff;
  digest[11] = (l >> 8) & 0xff;
  digest[32] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[48]) << 0;
  l |= itoa64_to_int(buf[49]) << 6;
  l |= itoa64_to_int(buf[50]) << 12;
  l |= itoa64_to_int(buf[51]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[33] = (l >> 8) & 0xff;
  digest[54] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[52]) << 0;
  l |= itoa64_to_int(buf[53]) << 6;
  l |= itoa64_to_int(buf[54]) << 12;
  l |= itoa64_to_int(buf[55]) << 18;

  digest[34] = (l >> 16) & 0xff;
  digest[55] = (l >> 8) & 0xff;
  digest[13] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[56]) << 0;
  l |= itoa64_to_int(buf[57]) << 6;
  l |= itoa64_to_int(buf[58]) << 12;
  l |= itoa64_to_int(buf[59]) << 18;

  digest[56] = (l >> 16) & 0xff;
  digest[14] = (l >> 8) & 0xff;
  digest[35] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[60]) << 0;
  l |= itoa64_to_int(buf[61]) << 6;
  l |= itoa64_to_int(buf[62]) << 12;
  l |= itoa64_to_int(buf[63]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[36] = (l >> 8) & 0xff;
  digest[57] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[64]) << 0;
  l |= itoa64_to_int(buf[65]) << 6;
  l |= itoa64_to_int(buf[66]) << 12;
  l |= itoa64_to_int(buf[67]) << 18;

  digest[37] = (l >> 16) & 0xff;
  digest[58] = (l >> 8) & 0xff;
  digest[16] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[68]) << 0;
  l |= itoa64_to_int(buf[69]) << 6;
  l |= itoa64_to_int(buf[70]) << 12;
  l |= itoa64_to_int(buf[71]) << 18;

  digest[59] = (l >> 16) & 0xff;
  digest[17] = (l >> 8) & 0xff;
  digest[38] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[72]) << 0;
  l |= itoa64_to_int(buf[73]) << 6;
  l |= itoa64_to_int(buf[74]) << 12;
  l |= itoa64_to_int(buf[75]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[39] = (l >> 8) & 0xff;
  digest[60] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[76]) << 0;
  l |= itoa64_to_int(buf[77]) << 6;
  l |= itoa64_to_int(buf[78]) << 12;
  l |= itoa64_to_int(buf[79]) << 18;

  digest[40] = (l >> 16) & 0xff;
  digest[61] = (l >> 8) & 0xff;
  digest[19] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[80]) << 0;
  l |= itoa64_to_int(buf[81]) << 6;
  l |= itoa64_to_int(buf[82]) << 12;
  l |= itoa64_to_int(buf[83]) << 18;

  digest[62] = (l >> 16) & 0xff;
  digest[20] = (l >> 8) & 0xff;
  digest[41] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[84]) << 0;
  l |= itoa64_to_int(buf[85]) << 6;

  digest[63] = (l >> 0) & 0xff;
}

void sha512crypt_encode(u8 digest[64], u8 buf[86])
{
  int l;

  l = (digest[0] << 16) | (digest[21] << 8) | (digest[42] << 0);

  buf[0] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[1] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[2] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[3] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[22] << 16) | (digest[43] << 8) | (digest[1] << 0);

  buf[4] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[5] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[6] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[7] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[44] << 16) | (digest[2] << 8) | (digest[23] << 0);

  buf[8] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[9] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[3] << 16) | (digest[24] << 8) | (digest[45] << 0);

  buf[12] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[25] << 16) | (digest[46] << 8) | (digest[4] << 0);

  buf[16] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[47] << 16) | (digest[5] << 8) | (digest[26] << 0);

  buf[20] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[6] << 16) | (digest[27] << 8) | (digest[48] << 0);

  buf[24] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[28] << 16) | (digest[49] << 8) | (digest[7] << 0);

  buf[28] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[50] << 16) | (digest[8] << 8) | (digest[29] << 0);

  buf[32] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[9] << 16) | (digest[30] << 8) | (digest[51] << 0);

  buf[36] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[31] << 16) | (digest[52] << 8) | (digest[10] << 0);

  buf[40] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[43] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[53] << 16) | (digest[11] << 8) | (digest[32] << 0);

  buf[44] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[45] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[46] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[47] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[12] << 16) | (digest[33] << 8) | (digest[54] << 0);

  buf[48] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[49] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[50] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[51] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[34] << 16) | (digest[55] << 8) | (digest[13] << 0);

  buf[52] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[53] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[54] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[55] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[56] << 16) | (digest[14] << 8) | (digest[35] << 0);

  buf[56] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[57] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[58] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[59] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[15] << 16) | (digest[36] << 8) | (digest[57] << 0);

  buf[60] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[61] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[62] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[63] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[37] << 16) | (digest[58] << 8) | (digest[16] << 0);

  buf[64] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[65] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[66] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[67] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[59] << 16) | (digest[17] << 8) | (digest[38] << 0);

  buf[68] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[69] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[70] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[71] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[18] << 16) | (digest[39] << 8) | (digest[60] << 0);

  buf[72] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[73] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[74] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[75] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[40] << 16) | (digest[61] << 8) | (digest[19] << 0);

  buf[76] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[77] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[78] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[79] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[62] << 16) | (digest[20] << 8) | (digest[41] << 0);

  buf[80] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[81] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[82] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[83] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = 0 | 0 | (digest[63] << 0);

  buf[84] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[85] = int_to_itoa64(l & 0x3f); l >>= 6;
}

void sha1aix_decode(u8 digest[20], u8 buf[27])
{
  int l;

  l = itoa64_to_int(buf[0]) << 0;
  l |= itoa64_to_int(buf[1]) << 6;
  l |= itoa64_to_int(buf[2]) << 12;
  l |= itoa64_to_int(buf[3]) << 18;

  digest[2] = (l >> 0) & 0xff;
  digest[1] = (l >> 8) & 0xff;
  digest[0] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[4]) << 0;
  l |= itoa64_to_int(buf[5]) << 6;
  l |= itoa64_to_int(buf[6]) << 12;
  l |= itoa64_to_int(buf[7]) << 18;

  digest[5] = (l >> 0) & 0xff;
  digest[4] = (l >> 8) & 0xff;
  digest[3] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[8]) << 0;
  l |= itoa64_to_int(buf[9]) << 6;
  l |= itoa64_to_int(buf[10]) << 12;
  l |= itoa64_to_int(buf[11]) << 18;

  digest[8] = (l >> 0) & 0xff;
  digest[7] = (l >> 8) & 0xff;
  digest[6] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[12]) << 0;
  l |= itoa64_to_int(buf[13]) << 6;
  l |= itoa64_to_int(buf[14]) << 12;
  l |= itoa64_to_int(buf[15]) << 18;

  digest[11] = (l >> 0) & 0xff;
  digest[10] = (l >> 8) & 0xff;
  digest[9] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[16]) << 0;
  l |= itoa64_to_int(buf[17]) << 6;
  l |= itoa64_to_int(buf[18]) << 12;
  l |= itoa64_to_int(buf[19]) << 18;

  digest[14] = (l >> 0) & 0xff;
  digest[13] = (l >> 8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[20]) << 0;
  l |= itoa64_to_int(buf[21]) << 6;
  l |= itoa64_to_int(buf[22]) << 12;
  l |= itoa64_to_int(buf[23]) << 18;

  digest[17] = (l >> 0) & 0xff;
  digest[16] = (l >> 8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[24]) << 0;
  l |= itoa64_to_int(buf[25]) << 6;
  l |= itoa64_to_int(buf[26]) << 12;

  digest[19] = (l >> 8) & 0xff;
  digest[18] = (l >> 16) & 0xff;
}

void sha1aix_encode(u8 digest[20], u8 buf[27])
{
  int l;

  l = (digest[2] << 0) | (digest[1] << 8) | (digest[0] << 16);

  buf[0] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[1] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[2] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[3] = int_to_itoa64(l & 0x3f);

  l = (digest[5] << 0) | (digest[4] << 8) | (digest[3] << 16);

  buf[4] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[5] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[6] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[7] = int_to_itoa64(l & 0x3f);

  l = (digest[8] << 0) | (digest[7] << 8) | (digest[6] << 16);

  buf[8] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[9] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64(l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[9] << 16);

  buf[12] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64(l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64(l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64(l & 0x3f);

  l = 0 | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64(l & 0x3f);
}

void sha256aix_decode(u8 digest[32], u8 buf[43])
{
  int l;

  l = itoa64_to_int(buf[0]) << 0;
  l |= itoa64_to_int(buf[1]) << 6;
  l |= itoa64_to_int(buf[2]) << 12;
  l |= itoa64_to_int(buf[3]) << 18;

  digest[2] = (l >> 0) & 0xff;
  digest[1] = (l >> 8) & 0xff;
  digest[0] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[4]) << 0;
  l |= itoa64_to_int(buf[5]) << 6;
  l |= itoa64_to_int(buf[6]) << 12;
  l |= itoa64_to_int(buf[7]) << 18;

  digest[5] = (l >> 0) & 0xff;
  digest[4] = (l >> 8) & 0xff;
  digest[3] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[8]) << 0;
  l |= itoa64_to_int(buf[9]) << 6;
  l |= itoa64_to_int(buf[10]) << 12;
  l |= itoa64_to_int(buf[11]) << 18;

  digest[8] = (l >> 0) & 0xff;
  digest[7] = (l >> 8) & 0xff;
  digest[6] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[12]) << 0;
  l |= itoa64_to_int(buf[13]) << 6;
  l |= itoa64_to_int(buf[14]) << 12;
  l |= itoa64_to_int(buf[15]) << 18;

  digest[11] = (l >> 0) & 0xff;
  digest[10] = (l >> 8) & 0xff;
  digest[9] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[16]) << 0;
  l |= itoa64_to_int(buf[17]) << 6;
  l |= itoa64_to_int(buf[18]) << 12;
  l |= itoa64_to_int(buf[19]) << 18;

  digest[14] = (l >> 0) & 0xff;
  digest[13] = (l >> 8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[20]) << 0;
  l |= itoa64_to_int(buf[21]) << 6;
  l |= itoa64_to_int(buf[22]) << 12;
  l |= itoa64_to_int(buf[23]) << 18;

  digest[17] = (l >> 0) & 0xff;
  digest[16] = (l >> 8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[24]) << 0;
  l |= itoa64_to_int(buf[25]) << 6;
  l |= itoa64_to_int(buf[26]) << 12;
  l |= itoa64_to_int(buf[27]) << 18;

  digest[20] = (l >> 0) & 0xff;
  digest[19] = (l >> 8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[28]) << 0;
  l |= itoa64_to_int(buf[29]) << 6;
  l |= itoa64_to_int(buf[30]) << 12;
  l |= itoa64_to_int(buf[31]) << 18;

  digest[23] = (l >> 0) & 0xff;
  digest[22] = (l >> 8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[32]) << 0;
  l |= itoa64_to_int(buf[33]) << 6;
  l |= itoa64_to_int(buf[34]) << 12;
  l |= itoa64_to_int(buf[35]) << 18;

  digest[26] = (l >> 0) & 0xff;
  digest[25] = (l >> 8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[36]) << 0;
  l |= itoa64_to_int(buf[37]) << 6;
  l |= itoa64_to_int(buf[38]) << 12;
  l |= itoa64_to_int(buf[39]) << 18;

  digest[29] = (l >> 0) & 0xff;
  digest[28] = (l >> 8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[40]) << 0;
  l |= itoa64_to_int(buf[41]) << 6;
  l |= itoa64_to_int(buf[42]) << 12;

  //digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >> 8) & 0xff;
  digest[30] = (l >> 16) & 0xff;
}

void sha256aix_encode(u8 digest[32], u8 buf[43])
{
  int l;

  l = (digest[2] << 0) | (digest[1] << 8) | (digest[0] << 16);

  buf[0] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[1] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[2] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[3] = int_to_itoa64(l & 0x3f);

  l = (digest[5] << 0) | (digest[4] << 8) | (digest[3] << 16);

  buf[4] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[5] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[6] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[7] = int_to_itoa64(l & 0x3f);

  l = (digest[8] << 0) | (digest[7] << 8) | (digest[6] << 16);

  buf[8] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[9] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64(l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[9] << 16);

  buf[12] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64(l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64(l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64(l & 0x3f);

  l = (digest[20] << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64(l & 0x3f);

  l = (digest[23] << 0) | (digest[22] << 8) | (digest[21] << 16);

  buf[28] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64(l & 0x3f);

  l = (digest[26] << 0) | (digest[25] << 8) | (digest[24] << 16);

  buf[32] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64(l & 0x3f);

  l = (digest[29] << 0) | (digest[28] << 8) | (digest[27] << 16);

  buf[36] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64(l & 0x3f);

  l = 0 | (digest[31] << 8) | (digest[30] << 16);

  buf[40] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64(l & 0x3f);
}

void sha512aix_decode(u8 digest[64], u8 buf[86])
{
  int l;

  l = itoa64_to_int(buf[0]) << 0;
  l |= itoa64_to_int(buf[1]) << 6;
  l |= itoa64_to_int(buf[2]) << 12;
  l |= itoa64_to_int(buf[3]) << 18;

  digest[2] = (l >> 0) & 0xff;
  digest[1] = (l >> 8) & 0xff;
  digest[0] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[4]) << 0;
  l |= itoa64_to_int(buf[5]) << 6;
  l |= itoa64_to_int(buf[6]) << 12;
  l |= itoa64_to_int(buf[7]) << 18;

  digest[5] = (l >> 0) & 0xff;
  digest[4] = (l >> 8) & 0xff;
  digest[3] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[8]) << 0;
  l |= itoa64_to_int(buf[9]) << 6;
  l |= itoa64_to_int(buf[10]) << 12;
  l |= itoa64_to_int(buf[11]) << 18;

  digest[8] = (l >> 0) & 0xff;
  digest[7] = (l >> 8) & 0xff;
  digest[6] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[12]) << 0;
  l |= itoa64_to_int(buf[13]) << 6;
  l |= itoa64_to_int(buf[14]) << 12;
  l |= itoa64_to_int(buf[15]) << 18;

  digest[11] = (l >> 0) & 0xff;
  digest[10] = (l >> 8) & 0xff;
  digest[9] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[16]) << 0;
  l |= itoa64_to_int(buf[17]) << 6;
  l |= itoa64_to_int(buf[18]) << 12;
  l |= itoa64_to_int(buf[19]) << 18;

  digest[14] = (l >> 0) & 0xff;
  digest[13] = (l >> 8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[20]) << 0;
  l |= itoa64_to_int(buf[21]) << 6;
  l |= itoa64_to_int(buf[22]) << 12;
  l |= itoa64_to_int(buf[23]) << 18;

  digest[17] = (l >> 0) & 0xff;
  digest[16] = (l >> 8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[24]) << 0;
  l |= itoa64_to_int(buf[25]) << 6;
  l |= itoa64_to_int(buf[26]) << 12;
  l |= itoa64_to_int(buf[27]) << 18;

  digest[20] = (l >> 0) & 0xff;
  digest[19] = (l >> 8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[28]) << 0;
  l |= itoa64_to_int(buf[29]) << 6;
  l |= itoa64_to_int(buf[30]) << 12;
  l |= itoa64_to_int(buf[31]) << 18;

  digest[23] = (l >> 0) & 0xff;
  digest[22] = (l >> 8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[32]) << 0;
  l |= itoa64_to_int(buf[33]) << 6;
  l |= itoa64_to_int(buf[34]) << 12;
  l |= itoa64_to_int(buf[35]) << 18;

  digest[26] = (l >> 0) & 0xff;
  digest[25] = (l >> 8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[36]) << 0;
  l |= itoa64_to_int(buf[37]) << 6;
  l |= itoa64_to_int(buf[38]) << 12;
  l |= itoa64_to_int(buf[39]) << 18;

  digest[29] = (l >> 0) & 0xff;
  digest[28] = (l >> 8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[40]) << 0;
  l |= itoa64_to_int(buf[41]) << 6;
  l |= itoa64_to_int(buf[42]) << 12;
  l |= itoa64_to_int(buf[43]) << 18;

  digest[32] = (l >> 0) & 0xff;
  digest[31] = (l >> 8) & 0xff;
  digest[30] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[44]) << 0;
  l |= itoa64_to_int(buf[45]) << 6;
  l |= itoa64_to_int(buf[46]) << 12;
  l |= itoa64_to_int(buf[47]) << 18;

  digest[35] = (l >> 0) & 0xff;
  digest[34] = (l >> 8) & 0xff;
  digest[33] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[48]) << 0;
  l |= itoa64_to_int(buf[49]) << 6;
  l |= itoa64_to_int(buf[50]) << 12;
  l |= itoa64_to_int(buf[51]) << 18;

  digest[38] = (l >> 0) & 0xff;
  digest[37] = (l >> 8) & 0xff;
  digest[36] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[52]) << 0;
  l |= itoa64_to_int(buf[53]) << 6;
  l |= itoa64_to_int(buf[54]) << 12;
  l |= itoa64_to_int(buf[55]) << 18;

  digest[41] = (l >> 0) & 0xff;
  digest[40] = (l >> 8) & 0xff;
  digest[39] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[56]) << 0;
  l |= itoa64_to_int(buf[57]) << 6;
  l |= itoa64_to_int(buf[58]) << 12;
  l |= itoa64_to_int(buf[59]) << 18;

  digest[44] = (l >> 0) & 0xff;
  digest[43] = (l >> 8) & 0xff;
  digest[42] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[60]) << 0;
  l |= itoa64_to_int(buf[61]) << 6;
  l |= itoa64_to_int(buf[62]) << 12;
  l |= itoa64_to_int(buf[63]) << 18;

  digest[47] = (l >> 0) & 0xff;
  digest[46] = (l >> 8) & 0xff;
  digest[45] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[64]) << 0;
  l |= itoa64_to_int(buf[65]) << 6;
  l |= itoa64_to_int(buf[66]) << 12;
  l |= itoa64_to_int(buf[67]) << 18;

  digest[50] = (l >> 0) & 0xff;
  digest[49] = (l >> 8) & 0xff;
  digest[48] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[68]) << 0;
  l |= itoa64_to_int(buf[69]) << 6;
  l |= itoa64_to_int(buf[70]) << 12;
  l |= itoa64_to_int(buf[71]) << 18;

  digest[53] = (l >> 0) & 0xff;
  digest[52] = (l >> 8) & 0xff;
  digest[51] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[72]) << 0;
  l |= itoa64_to_int(buf[73]) << 6;
  l |= itoa64_to_int(buf[74]) << 12;
  l |= itoa64_to_int(buf[75]) << 18;

  digest[56] = (l >> 0) & 0xff;
  digest[55] = (l >> 8) & 0xff;
  digest[54] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[76]) << 0;
  l |= itoa64_to_int(buf[77]) << 6;
  l |= itoa64_to_int(buf[78]) << 12;
  l |= itoa64_to_int(buf[79]) << 18;

  digest[59] = (l >> 0) & 0xff;
  digest[58] = (l >> 8) & 0xff;
  digest[57] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[80]) << 0;
  l |= itoa64_to_int(buf[81]) << 6;
  l |= itoa64_to_int(buf[82]) << 12;
  l |= itoa64_to_int(buf[83]) << 18;

  digest[62] = (l >> 0) & 0xff;
  digest[61] = (l >> 8) & 0xff;
  digest[60] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[84]) << 0;
  l |= itoa64_to_int(buf[85]) << 6;

  digest[63] = (l >> 16) & 0xff;
}

void sha512aix_encode(u8 digest[64], u8 buf[86])
{
  int l;

  l = (digest[2] << 0) | (digest[1] << 8) | (digest[0] << 16);

  buf[0] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[1] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[2] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[3] = int_to_itoa64(l & 0x3f);

  l = (digest[5] << 0) | (digest[4] << 8) | (digest[3] << 16);

  buf[4] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[5] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[6] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[7] = int_to_itoa64(l & 0x3f);

  l = (digest[8] << 0) | (digest[7] << 8) | (digest[6] << 16);

  buf[8] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[9] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64(l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[9] << 16);

  buf[12] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64(l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64(l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64(l & 0x3f);

  l = (digest[20] << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64(l & 0x3f);

  l = (digest[23] << 0) | (digest[22] << 8) | (digest[21] << 16);

  buf[28] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64(l & 0x3f);

  l = (digest[26] << 0) | (digest[25] << 8) | (digest[24] << 16);

  buf[32] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64(l & 0x3f);

  l = (digest[29] << 0) | (digest[28] << 8) | (digest[27] << 16);

  buf[36] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64(l & 0x3f);

  l = (digest[32] << 0) | (digest[31] << 8) | (digest[30] << 16);

  buf[40] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[43] = int_to_itoa64(l & 0x3f);

  l = (digest[35] << 0) | (digest[34] << 8) | (digest[33] << 16);

  buf[44] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[45] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[46] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[47] = int_to_itoa64(l & 0x3f);

  l = (digest[38] << 0) | (digest[37] << 8) | (digest[36] << 16);

  buf[48] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[49] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[50] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[51] = int_to_itoa64(l & 0x3f);

  l = (digest[41] << 0) | (digest[40] << 8) | (digest[39] << 16);

  buf[52] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[53] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[54] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[55] = int_to_itoa64(l & 0x3f);

  l = (digest[44] << 0) | (digest[43] << 8) | (digest[42] << 16);

  buf[56] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[57] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[58] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[59] = int_to_itoa64(l & 0x3f);

  l = (digest[47] << 0) | (digest[46] << 8) | (digest[45] << 16);

  buf[60] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[61] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[62] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[63] = int_to_itoa64(l & 0x3f);

  l = (digest[50] << 0) | (digest[49] << 8) | (digest[48] << 16);

  buf[64] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[65] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[66] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[67] = int_to_itoa64(l & 0x3f);

  l = (digest[53] << 0) | (digest[52] << 8) | (digest[51] << 16);

  buf[68] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[69] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[70] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[71] = int_to_itoa64(l & 0x3f);

  l = (digest[56] << 0) | (digest[55] << 8) | (digest[54] << 16);

  buf[72] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[73] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[74] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[75] = int_to_itoa64(l & 0x3f);

  l = (digest[59] << 0) | (digest[58] << 8) | (digest[57] << 16);

  buf[76] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[77] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[78] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[79] = int_to_itoa64(l & 0x3f);

  l = (digest[62] << 0) | (digest[61] << 8) | (digest[60] << 16);

  buf[80] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[81] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[82] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[83] = int_to_itoa64(l & 0x3f);

  l = 0 | 0 | (digest[63] << 16);

  buf[84] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[85] = int_to_itoa64(l & 0x3f); l >>= 6;
}

void sha256crypt_decode(u8 digest[32], u8 buf[43])
{
  int l;

  l = itoa64_to_int(buf[0]) << 0;
  l |= itoa64_to_int(buf[1]) << 6;
  l |= itoa64_to_int(buf[2]) << 12;
  l |= itoa64_to_int(buf[3]) << 18;

  digest[0] = (l >> 16) & 0xff;
  digest[10] = (l >> 8) & 0xff;
  digest[20] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[4]) << 0;
  l |= itoa64_to_int(buf[5]) << 6;
  l |= itoa64_to_int(buf[6]) << 12;
  l |= itoa64_to_int(buf[7]) << 18;

  digest[21] = (l >> 16) & 0xff;
  digest[1] = (l >> 8) & 0xff;
  digest[11] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[8]) << 0;
  l |= itoa64_to_int(buf[9]) << 6;
  l |= itoa64_to_int(buf[10]) << 12;
  l |= itoa64_to_int(buf[11]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[22] = (l >> 8) & 0xff;
  digest[2] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[12]) << 0;
  l |= itoa64_to_int(buf[13]) << 6;
  l |= itoa64_to_int(buf[14]) << 12;
  l |= itoa64_to_int(buf[15]) << 18;

  digest[3] = (l >> 16) & 0xff;
  digest[13] = (l >> 8) & 0xff;
  digest[23] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[16]) << 0;
  l |= itoa64_to_int(buf[17]) << 6;
  l |= itoa64_to_int(buf[18]) << 12;
  l |= itoa64_to_int(buf[19]) << 18;

  digest[24] = (l >> 16) & 0xff;
  digest[4] = (l >> 8) & 0xff;
  digest[14] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[20]) << 0;
  l |= itoa64_to_int(buf[21]) << 6;
  l |= itoa64_to_int(buf[22]) << 12;
  l |= itoa64_to_int(buf[23]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[25] = (l >> 8) & 0xff;
  digest[5] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[24]) << 0;
  l |= itoa64_to_int(buf[25]) << 6;
  l |= itoa64_to_int(buf[26]) << 12;
  l |= itoa64_to_int(buf[27]) << 18;

  digest[6] = (l >> 16) & 0xff;
  digest[16] = (l >> 8) & 0xff;
  digest[26] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[28]) << 0;
  l |= itoa64_to_int(buf[29]) << 6;
  l |= itoa64_to_int(buf[30]) << 12;
  l |= itoa64_to_int(buf[31]) << 18;

  digest[27] = (l >> 16) & 0xff;
  digest[7] = (l >> 8) & 0xff;
  digest[17] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[32]) << 0;
  l |= itoa64_to_int(buf[33]) << 6;
  l |= itoa64_to_int(buf[34]) << 12;
  l |= itoa64_to_int(buf[35]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[28] = (l >> 8) & 0xff;
  digest[8] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[36]) << 0;
  l |= itoa64_to_int(buf[37]) << 6;
  l |= itoa64_to_int(buf[38]) << 12;
  l |= itoa64_to_int(buf[39]) << 18;

  digest[9] = (l >> 16) & 0xff;
  digest[19] = (l >> 8) & 0xff;
  digest[29] = (l >> 0) & 0xff;

  l = itoa64_to_int(buf[40]) << 0;
  l |= itoa64_to_int(buf[41]) << 6;
  l |= itoa64_to_int(buf[42]) << 12;

  digest[31] = (l >> 8) & 0xff;
  digest[30] = (l >> 0) & 0xff;
}

void sha256crypt_encode(u8 digest[32], u8 buf[43])
{
  int l;

  l = (digest[0] << 16) | (digest[10] << 8) | (digest[20] << 0);

  buf[0] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[1] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[2] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[3] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[21] << 16) | (digest[1] << 8) | (digest[11] << 0);

  buf[4] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[5] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[6] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[7] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[12] << 16) | (digest[22] << 8) | (digest[2] << 0);

  buf[8] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[9] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[3] << 16) | (digest[13] << 8) | (digest[23] << 0);

  buf[12] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[24] << 16) | (digest[4] << 8) | (digest[14] << 0);

  buf[16] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[15] << 16) | (digest[25] << 8) | (digest[5] << 0);

  buf[20] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[6] << 16) | (digest[16] << 8) | (digest[26] << 0);

  buf[24] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[27] << 16) | (digest[7] << 8) | (digest[17] << 0);

  buf[28] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[18] << 16) | (digest[28] << 8) | (digest[8] << 0);

  buf[32] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = (digest[9] << 16) | (digest[19] << 8) | (digest[29] << 0);

  buf[36] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64(l & 0x3f); l >>= 6;

  l = 0 | (digest[31] << 8) | (digest[30] << 0);

  buf[40] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64(l & 0x3f);
}

void drupal7_decode(u8 digest[64], u8 buf[44])
{
  int l;

  l = itoa64_to_int(buf[0]) << 0;
  l |= itoa64_to_int(buf[1]) << 6;
  l |= itoa64_to_int(buf[2]) << 12;
  l |= itoa64_to_int(buf[3]) << 18;

  digest[0] = (l >> 0) & 0xff;
  digest[1] = (l >> 8) & 0xff;
  digest[2] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[4]) << 0;
  l |= itoa64_to_int(buf[5]) << 6;
  l |= itoa64_to_int(buf[6]) << 12;
  l |= itoa64_to_int(buf[7]) << 18;

  digest[3] = (l >> 0) & 0xff;
  digest[4] = (l >> 8) & 0xff;
  digest[5] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[8]) << 0;
  l |= itoa64_to_int(buf[9]) << 6;
  l |= itoa64_to_int(buf[10]) << 12;
  l |= itoa64_to_int(buf[11]) << 18;

  digest[6] = (l >> 0) & 0xff;
  digest[7] = (l >> 8) & 0xff;
  digest[8] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[12]) << 0;
  l |= itoa64_to_int(buf[13]) << 6;
  l |= itoa64_to_int(buf[14]) << 12;
  l |= itoa64_to_int(buf[15]) << 18;

  digest[9] = (l >> 0) & 0xff;
  digest[10] = (l >> 8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[16]) << 0;
  l |= itoa64_to_int(buf[17]) << 6;
  l |= itoa64_to_int(buf[18]) << 12;
  l |= itoa64_to_int(buf[19]) << 18;

  digest[12] = (l >> 0) & 0xff;
  digest[13] = (l >> 8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[20]) << 0;
  l |= itoa64_to_int(buf[21]) << 6;
  l |= itoa64_to_int(buf[22]) << 12;
  l |= itoa64_to_int(buf[23]) << 18;

  digest[15] = (l >> 0) & 0xff;
  digest[16] = (l >> 8) & 0xff;
  digest[17] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[24]) << 0;
  l |= itoa64_to_int(buf[25]) << 6;
  l |= itoa64_to_int(buf[26]) << 12;
  l |= itoa64_to_int(buf[27]) << 18;

  digest[18] = (l >> 0) & 0xff;
  digest[19] = (l >> 8) & 0xff;
  digest[20] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[28]) << 0;
  l |= itoa64_to_int(buf[29]) << 6;
  l |= itoa64_to_int(buf[30]) << 12;
  l |= itoa64_to_int(buf[31]) << 18;

  digest[21] = (l >> 0) & 0xff;
  digest[22] = (l >> 8) & 0xff;
  digest[23] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[32]) << 0;
  l |= itoa64_to_int(buf[33]) << 6;
  l |= itoa64_to_int(buf[34]) << 12;
  l |= itoa64_to_int(buf[35]) << 18;

  digest[24] = (l >> 0) & 0xff;
  digest[25] = (l >> 8) & 0xff;
  digest[26] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[36]) << 0;
  l |= itoa64_to_int(buf[37]) << 6;
  l |= itoa64_to_int(buf[38]) << 12;
  l |= itoa64_to_int(buf[39]) << 18;

  digest[27] = (l >> 0) & 0xff;
  digest[28] = (l >> 8) & 0xff;
  digest[29] = (l >> 16) & 0xff;

  l = itoa64_to_int(buf[40]) << 0;
  l |= itoa64_to_int(buf[41]) << 6;
  l |= itoa64_to_int(buf[42]) << 12;
  l |= itoa64_to_int(buf[43]) << 18;

  digest[30] = (l >> 0) & 0xff;
  digest[31] = (l >> 8) & 0xff;
  digest[32] = (l >> 16) & 0xff;

  digest[33] = 0;
  digest[34] = 0;
  digest[35] = 0;
  digest[36] = 0;
  digest[37] = 0;
  digest[38] = 0;
  digest[39] = 0;
  digest[40] = 0;
  digest[41] = 0;
  digest[42] = 0;
  digest[43] = 0;
  digest[44] = 0;
  digest[45] = 0;
  digest[46] = 0;
  digest[47] = 0;
  digest[48] = 0;
  digest[49] = 0;
  digest[50] = 0;
  digest[51] = 0;
  digest[52] = 0;
  digest[53] = 0;
  digest[54] = 0;
  digest[55] = 0;
  digest[56] = 0;
  digest[57] = 0;
  digest[58] = 0;
  digest[59] = 0;
  digest[60] = 0;
  digest[61] = 0;
  digest[62] = 0;
  digest[63] = 0;
}

void drupal7_encode(u8 digest[64], u8 buf[43])
{
  int l;

  l = (digest[0] << 0) | (digest[1] << 8) | (digest[2] << 16);

  buf[0] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[1] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[2] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[3] = int_to_itoa64(l & 0x3f);

  l = (digest[3] << 0) | (digest[4] << 8) | (digest[5] << 16);

  buf[4] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[5] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[6] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[7] = int_to_itoa64(l & 0x3f);

  l = (digest[6] << 0) | (digest[7] << 8) | (digest[8] << 16);

  buf[8] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[9] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64(l & 0x3f);

  l = (digest[9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64(l & 0x3f);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64(l & 0x3f);

  l = (digest[15] << 0) | (digest[16] << 8) | (digest[17] << 16);

  buf[20] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64(l & 0x3f);

  l = (digest[18] << 0) | (digest[19] << 8) | (digest[20] << 16);

  buf[24] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64(l & 0x3f);

  l = (digest[21] << 0) | (digest[22] << 8) | (digest[23] << 16);

  buf[28] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64(l & 0x3f);

  l = (digest[24] << 0) | (digest[25] << 8) | (digest[26] << 16);

  buf[32] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64(l & 0x3f);

  l = (digest[27] << 0) | (digest[28] << 8) | (digest[29] << 16);

  buf[36] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64(l & 0x3f);

  l = (digest[30] << 0) | (digest[31] << 8) | (digest[32] << 16);

  buf[40] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64(l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64(l & 0x3f); l >>= 6;
  //buf[43] = int_to_itoa64 (l & 0x3f);
}
