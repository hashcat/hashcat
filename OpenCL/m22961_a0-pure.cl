/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_blowfish.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#ifndef FIXED_LOCAL_SIZE
#define FIXED_LOCAL_SIZE 1
#endif

typedef struct sshng_openssh
{
  u32 data_buf[16384];
  int data_len;

  u32 salt_buf[4];
  u32 ct_buf[4];

  u32 rounds;
  u32 cipher_offset;

  int cipher;

} sshng_openssh_t;

DECLSPEC u32 sshng_stream2word (PRIVATE_AS const u8 *data, const int len, PRIVATE_AS int *off)
{
  u32 word = 0;

  for (int i = 0; i < 4; i++)
  {
    word = (word << 8) | data[*off];

    *off += 1;

    if (*off >= len) *off = 0;
  }

  return word;
}

DECLSPEC u32 sshng_read_u32_be (PRIVATE_AS const u8 *buf)
{
  return ((u32) buf[0] << 24)
       | ((u32) buf[1] << 16)
       | ((u32) buf[2] <<  8)
       | ((u32) buf[3] <<  0);
}

DECLSPEC void sshng_blowfish_init (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  for (u32 i = 0; i < 18; i++)
  {
    P[i] = c_pbox[i];
  }

  for (u32 i = 0; i < 256; i++)
  {
    SET_KEY32 (S0, i, c_sbox0[i]);
    SET_KEY32 (S1, i, c_sbox1[i]);
    SET_KEY32 (S2, i, c_sbox2[i]);
    SET_KEY32 (S3, i, c_sbox3[i]);
  }
}

DECLSPEC void sshng_blowfish_expand0state (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u8 *data, const int data_len)
{
  int data_off = 0;

  for (u32 i = 0; i < 18; i++)
  {
    P[i] ^= sshng_stream2word (data, data_len, &data_off);
  }

  u32 L0 = 0;
  u32 R0 = 0;

  for (u32 i = 0; i < 18; i += 2)
  {
    BF_ENCRYPT (L0, R0);

    P[i + 0] = L0;
    P[i + 1] = R0;
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S0, i + 0, L0);
    SET_KEY32 (S0, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S1, i + 0, L0);
    SET_KEY32 (S1, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S2, i + 0, L0);
    SET_KEY32 (S2, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S3, i + 0, L0);
    SET_KEY32 (S3, i + 1, R0);
  }
}

DECLSPEC void sshng_blowfish_expandstate (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u8 *data, const int data_len, PRIVATE_AS const u8 *key, const int key_len)
{
  int key_off = 0;
  int data_off = 0;

  for (u32 i = 0; i < 18; i++)
  {
    P[i] ^= sshng_stream2word (key, key_len, &key_off);
  }

  u32 L0 = 0;
  u32 R0 = 0;

  for (u32 i = 0; i < 18; i += 2)
  {
    L0 ^= sshng_stream2word (data, data_len, &data_off);
    R0 ^= sshng_stream2word (data, data_len, &data_off);

    BF_ENCRYPT (L0, R0);

    P[i + 0] = L0;
    P[i + 1] = R0;
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= sshng_stream2word (data, data_len, &data_off);
    R0 ^= sshng_stream2word (data, data_len, &data_off);

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S0, i + 0, L0);
    SET_KEY32 (S0, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= sshng_stream2word (data, data_len, &data_off);
    R0 ^= sshng_stream2word (data, data_len, &data_off);

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S1, i + 0, L0);
    SET_KEY32 (S1, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= sshng_stream2word (data, data_len, &data_off);
    R0 ^= sshng_stream2word (data, data_len, &data_off);

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S2, i + 0, L0);
    SET_KEY32 (S2, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= sshng_stream2word (data, data_len, &data_off);
    R0 ^= sshng_stream2word (data, data_len, &data_off);

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S3, i + 0, L0);
    SET_KEY32 (S3, i + 1, R0);
  }
}

DECLSPEC void sshng_sha512_to_bytes (PRIVATE_AS const sha512_ctx_t *ctx, PRIVATE_AS u8 *out)
{
  for (int i = 0; i < 8; i++)
  {
    const u64 v = ctx->h[i];

    out[(i * 8) + 0] = (u8) (v >> 56);
    out[(i * 8) + 1] = (u8) (v >> 48);
    out[(i * 8) + 2] = (u8) (v >> 40);
    out[(i * 8) + 3] = (u8) (v >> 32);
    out[(i * 8) + 4] = (u8) (v >> 24);
    out[(i * 8) + 5] = (u8) (v >> 16);
    out[(i * 8) + 6] = (u8) (v >>  8);
    out[(i * 8) + 7] = (u8) (v >>  0);
  }
}

DECLSPEC void sshng_sha512_bytes (PRIVATE_AS const u8 *in, const int len, PRIVATE_AS u8 *out)
{
  u32 w[32] = { 0 };
  u64 h[8];

  h[0] = SHA512M_A;
  h[1] = SHA512M_B;
  h[2] = SHA512M_C;
  h[3] = SHA512M_D;
  h[4] = SHA512M_E;
  h[5] = SHA512M_F;
  h[6] = SHA512M_G;
  h[7] = SHA512M_H;

  for (int i = 0; i < len; i++)
  {
    const int word_pos = i >> 2;
    const int shift    = 24 - ((i & 3) * 8);

    w[word_pos] |= (u32) in[i] << shift;
  }

  {
    const int word_pos = len >> 2;
    const int shift    = 24 - ((len & 3) * 8);

    w[word_pos] |= (u32) 0x80 << shift;
  }

  w[30] = 0;
  w[31] = (u32) (len * 8);

  sha512_transform (w +  0, w +  4, w +  8, w + 12, w + 16, w + 20, w + 24, w + 28, h);

  for (int i = 0; i < 8; i++)
  {
    const u64 v = h[i];

    out[(i * 8) + 0] = (u8) (v >> 56);
    out[(i * 8) + 1] = (u8) (v >> 48);
    out[(i * 8) + 2] = (u8) (v >> 40);
    out[(i * 8) + 3] = (u8) (v >> 32);
    out[(i * 8) + 4] = (u8) (v >> 24);
    out[(i * 8) + 5] = (u8) (v >> 16);
    out[(i * 8) + 6] = (u8) (v >>  8);
    out[(i * 8) + 7] = (u8) (v >>  0);
  }
}

DECLSPEC void sshng_bcrypt_hash (PRIVATE_AS const u8 *sha2pass, PRIVATE_AS const u8 *sha2salt, PRIVATE_AS u8 *out, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  PRIVATE_AS const u8 ciphertext[32] =
  {
    'O', 'x', 'y', 'c', 'h', 'r', 'o', 'm',
    'a', 't', 'i', 'c', 'B', 'l', 'o', 'w',
    'f', 'i', 's', 'h', 'S', 'w', 'a', 't',
    'D', 'y', 'n', 'a', 'm', 'i', 't', 'e'
  };

  u32 P[18];

  sshng_blowfish_init (P, S0, S1, S2, S3);
  sshng_blowfish_expandstate (P, S0, S1, S2, S3, sha2salt, 64, sha2pass, 64);

  for (int i = 0; i < 64; i++)
  {
    sshng_blowfish_expand0state (P, S0, S1, S2, S3, sha2salt, 64);
    sshng_blowfish_expand0state (P, S0, S1, S2, S3, sha2pass, 64);
  }

  u32 cdata[8];

  for (int i = 0; i < 8; i++)
  {
    const int j = i * 4;

    cdata[i] = ((u32) ciphertext[j + 0] << 24)
             | ((u32) ciphertext[j + 1] << 16)
             | ((u32) ciphertext[j + 2] <<  8)
             | ((u32) ciphertext[j + 3] <<  0);
  }

  for (int i = 0; i < 64; i++)
  {
    for (int j = 0; j < 8; j += 2)
    {
      u32 L0 = cdata[j + 0];
      u32 R0 = cdata[j + 1];

      BF_ENCRYPT (L0, R0);

      cdata[j + 0] = L0;
      cdata[j + 1] = R0;
    }
  }

  for (int i = 0; i < 8; i++)
  {
    const u32 v = cdata[i];

    out[(i * 4) + 0] = (u8) (v >>  0);
    out[(i * 4) + 1] = (u8) (v >>  8);
    out[(i * 4) + 2] = (u8) (v >> 16);
    out[(i * 4) + 3] = (u8) (v >> 24);
  }
}

KERNEL_FQ KERNEL_FA void m22961_mxx (KERN_ATTR_RULES_ESALT (sshng_openssh_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3]
  };

  COPY_PW (pws[gid]);

  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE][256];

  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];

  const u32 rounds = esalt_bufs[DIGESTS_OFFSET_HOST].rounds;

  const u32 ct[4] =
  {
    esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[0],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[1],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[2],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[3]
  };

  u8 salt_bytes[16];

  for (int i = 0; i < 4; i++)
  {
    const u32 v = esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[i];

    salt_bytes[(i * 4) + 0] = (u8) (v >>  0);
    salt_bytes[(i * 4) + 1] = (u8) (v >>  8);
    salt_bytes[(i * 4) + 2] = (u8) (v >> 16);
    salt_bytes[(i * 4) + 3] = (u8) (v >> 24);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha512_ctx_t ctx;

    sha512_init (&ctx);
    sha512_update_swap (&ctx, tmp.i, tmp.pw_len);
    sha512_final (&ctx);

    u8 sha2pass[64];

    sshng_sha512_to_bytes (&ctx, sha2pass);

    u8 keymaterial[48];

    for (int i = 0; i < 48; i++) keymaterial[i] = 0;

    const int keylen = 48;
    const int stride = (keylen + 31) / 32;
    const int amt    = (keylen + stride - 1) / stride;

    for (u32 count = 1; count <= 2; count++)
    {
      u8 countsalt[20];

      u8 sha2salt[64];
      u8 tmpout[32];
      u8 out[32];

      for (int i = 0; i < 16; i++) countsalt[i] = salt_bytes[i];

      countsalt[16] = (u8) (count >> 24);
      countsalt[17] = (u8) (count >> 16);
      countsalt[18] = (u8) (count >>  8);
      countsalt[19] = (u8) (count >>  0);

      sshng_sha512_bytes (countsalt, 20, sha2salt);

      sshng_bcrypt_hash (sha2pass, sha2salt, out, S0, S1, S2, S3);

      for (int i = 0; i < 32; i++) tmpout[i] = out[i];

      for (u32 r = 1; r < rounds; r++)
      {
        sshng_sha512_bytes (tmpout, 32, sha2salt);
        sshng_bcrypt_hash (sha2pass, sha2salt, tmpout, S0, S1, S2, S3);

        for (int i = 0; i < 32; i++) out[i] ^= tmpout[i];
      }

      for (int i = 0; i < amt; i++)
      {
        const int dest = i * stride + (int) count - 1;

        if (dest >= keylen) break;

        keymaterial[dest] = out[i];
      }
    }

    u32 ukey[8];
    u32 ks[60];
    u32 in[4];
    u32 out[4];

    for (int i = 0; i < 8; i++)
    {
      ukey[i] = sshng_read_u32_be (keymaterial + (i * 4));
    }

    AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    in[0] = sshng_read_u32_be (keymaterial + 32);
    in[1] = sshng_read_u32_be (keymaterial + 36);
    in[2] = sshng_read_u32_be (keymaterial + 40);
    in[3] = sshng_read_u32_be (keymaterial + 44);

    AES256_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0] ^= ct[0];
    out[1] ^= ct[1];
    out[2] ^= ct[2];
    out[3] ^= ct[3];

    if (out[0] != out[1]) continue;

    const u32 keytype_len = out[2];

    if ((keytype_len < 7) || (keytype_len > 32)) continue;
    if (out[3] != 0x7373682d) continue;

    const u32 rr0 = search[0];
    const u32 rr1 = search[1];
    const u32 rr2 = search[2];
    const u32 rr3 = search[3];

    COMPARE_M_SCALAR (rr0, rr1, rr2, rr3);
  }
}

KERNEL_FQ KERNEL_FA void m22961_sxx (KERN_ATTR_RULES_ESALT (sshng_openssh_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3]
  };

  COPY_PW (pws[gid]);

  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE][256];

  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];

  const u32 rounds = esalt_bufs[DIGESTS_OFFSET_HOST].rounds;

  const u32 ct[4] =
  {
    esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[0],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[1],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[2],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[3]
  };

  u8 salt_bytes[16];

  for (int i = 0; i < 4; i++)
  {
    const u32 v = esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[i];

    salt_bytes[(i * 4) + 0] = (u8) (v >>  0);
    salt_bytes[(i * 4) + 1] = (u8) (v >>  8);
    salt_bytes[(i * 4) + 2] = (u8) (v >> 16);
    salt_bytes[(i * 4) + 3] = (u8) (v >> 24);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha512_ctx_t ctx;

    sha512_init (&ctx);
    sha512_update_swap (&ctx, tmp.i, tmp.pw_len);
    sha512_final (&ctx);

    u8 sha2pass[64];

    sshng_sha512_to_bytes (&ctx, sha2pass);

    u8 keymaterial[48];

    for (int i = 0; i < 48; i++) keymaterial[i] = 0;

    const int keylen = 48;
    const int stride = (keylen + 31) / 32;
    const int amt    = (keylen + stride - 1) / stride;

    for (u32 count = 1; count <= 2; count++)
    {
      u8 countsalt[20];

      u8 sha2salt[64];
      u8 tmpout[32];
      u8 out[32];

      for (int i = 0; i < 16; i++) countsalt[i] = salt_bytes[i];

      countsalt[16] = (u8) (count >> 24);
      countsalt[17] = (u8) (count >> 16);
      countsalt[18] = (u8) (count >>  8);
      countsalt[19] = (u8) (count >>  0);

      sshng_sha512_bytes (countsalt, 20, sha2salt);

      sshng_bcrypt_hash (sha2pass, sha2salt, out, S0, S1, S2, S3);

      for (int i = 0; i < 32; i++) tmpout[i] = out[i];

      for (u32 r = 1; r < rounds; r++)
      {
        sshng_sha512_bytes (tmpout, 32, sha2salt);
        sshng_bcrypt_hash (sha2pass, sha2salt, tmpout, S0, S1, S2, S3);

        for (int i = 0; i < 32; i++) out[i] ^= tmpout[i];
      }

      for (int i = 0; i < amt; i++)
      {
        const int dest = i * stride + (int) count - 1;

        if (dest >= keylen) break;

        keymaterial[dest] = out[i];
      }
    }

    u32 ukey[8];
    u32 ks[60];
    u32 in[4];
    u32 out[4];

    for (int i = 0; i < 8; i++)
    {
      ukey[i] = sshng_read_u32_be (keymaterial + (i * 4));
    }

    AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    in[0] = sshng_read_u32_be (keymaterial + 32);
    in[1] = sshng_read_u32_be (keymaterial + 36);
    in[2] = sshng_read_u32_be (keymaterial + 40);
    in[3] = sshng_read_u32_be (keymaterial + 44);

    AES256_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0] ^= ct[0];
    out[1] ^= ct[1];
    out[2] ^= ct[2];
    out[3] ^= ct[3];

    if (out[0] != out[1]) continue;

    const u32 keytype_len = out[2];

    if ((keytype_len < 7) || (keytype_len > 32)) continue;
    if (out[3] != 0x7373682d) continue;

    const u32 rr0 = search[0];
    const u32 rr1 = search[1];
    const u32 rr2 = search[2];
    const u32 rr3 = search[3];

    COMPARE_S_SCALAR (rr0, rr1, rr2, rr3);
  }
}
