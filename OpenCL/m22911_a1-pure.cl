/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define BLOCK_SIZE 8
#define KEY_LENGTH 24

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_cipher_des.cl"
#include "inc_pem_common.cl"
#endif  // KERNEL_STATIC

KERNEL_FQ void m22911_sxx (KERN_ATTR_ESALT (pem_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= gid_max) return;

  #ifdef REAL_SHM

  LOCAL_VK u32 data_len;
  data_len = esalt_bufs[digests_offset].data_len;

  LOCAL_VK u32 data[HC_PEM_MAX_DATA_LENGTH / 4];

  for (u32 i = lid; i <= data_len / 4; i += lsz)
  {
    data[i] = esalt_bufs[digests_offset].data[i];
  }

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  const size_t data_len = esalt_bufs[digests_offset].data_len;
  u32 data[HC_PEM_MAX_DATA_LENGTH / 4];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < data_len / 4; i++)
  {
    data[i] = esalt_bufs[digests_offset].data[i];
  }

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif  // REAL_SHM

  u32 salt_buf[16] = { 0 };
  u32 salt_iv[BLOCK_SIZE / 4], first_block[BLOCK_SIZE / 4];

  prep_buffers(salt_buf, salt_iv, first_block, data, &esalt_bufs[digests_offset]);

  const u32 pw_len = pws[gid].pw_len;

  u32 w[16] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 comb_len = combs_buf[il_pos].pw_len;
    u32 c[64];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 16; i++)
    {
      c[i] = combs_buf[il_pos].i[i];
    }

    switch_buffer_by_offset_1x64_be_S (c, pw_len);

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 16; i++)
    {
      c[i] |= w[i];
    }

    u32 key[HC_PEM_MAX_KEY_LENGTH / 4];

    generate_key (salt_buf, c, pw_len + comb_len, key);

    u32 asn1_ok = 0, padding_ok = 0, plaintext_length, plaintext[BLOCK_SIZE / 4];
    u32 ciphertext[BLOCK_SIZE / 4], iv[BLOCK_SIZE / 4];
    u32 K0[16], K1[16], K2[16], K3[16], K4[16], K5[16];

    _des_crypt_keysetup (key[0], key[1], K0, K1, s_skb);
    _des_crypt_keysetup (key[2], key[3], K2, K3, s_skb);
    _des_crypt_keysetup (key[4], key[5], K4, K5, s_skb);

    u32 p1[BLOCK_SIZE / 4], p2[BLOCK_SIZE / 4];

    _des_crypt_decrypt (p1, first_block, K4, K5, s_SPtrans);
    _des_crypt_encrypt (p2, p1, K2, K3, s_SPtrans);
    _des_crypt_decrypt (plaintext, p2, K0, K1, s_SPtrans);


    #ifdef _unroll
    #pragma unroll
    #endif
    for (u32 i = 0; i < BLOCK_SIZE / 4; i++)
    {
      plaintext[i] ^= salt_iv[i];
    }

    #ifdef DEBUG
    printf("First plaintext block:");
    for (u32 i = 0; i < BLOCK_SIZE / 4; i++) printf(" 0x%08x", plaintext[i]);
    printf("\n");
    #endif    // DEBUG

    if (data_len < 128)
    {
      asn1_ok = (plaintext[0] & 0x00ff80ff) == 0x00020030;
      plaintext_length = ((plaintext[0] & 0x00007f00) >> 8) + 2;
    }
    else if (data_len < 256)
    {
      asn1_ok = (plaintext[0] & 0xff00ffff) == 0x02008130;
      plaintext_length = ((plaintext[0] & 0x00ff0000) >> 16) + 3;
    }
    else if (data_len < 65536)
    {
      asn1_ok = ((plaintext[0] & 0x0000ffff) == 0x00008230) && ((plaintext[1] & 0x000000ff) == 0x00000002);
      plaintext_length = ((plaintext[0] & 0xff000000) >> 24) + ((plaintext[0] & 0x00ff0000) >> 8) + 4;
    }

    #ifdef DEBUG
    if (asn1_ok == 1) printf("Passed ASN.1 sanity check\n");
    #endif    // DEBUG

    if (asn1_ok == 0)
    {
      continue;
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (u32 i = 0; i < BLOCK_SIZE / 4; i++)
    {
      iv[i] = first_block[i];
    }

    for (u32 i = BLOCK_SIZE / 4; i < data_len / 4; i += BLOCK_SIZE / 4)
    {
      #ifdef _unroll
      #pragma unroll
      #endif
      for (u32 j = 0; j < BLOCK_SIZE / 4; j++)
      {
        ciphertext[j] = data[i + j];
      }

      _des_crypt_decrypt (p1, ciphertext, K4, K5, s_SPtrans);
      _des_crypt_encrypt (p2, p1, K2, K3, s_SPtrans);
      _des_crypt_decrypt (plaintext, p2, K0, K1, s_SPtrans);

      #ifdef _unroll
      #pragma unroll
      #endif
      for (u32 j = 0; j < BLOCK_SIZE / 4; j++)
      {
        plaintext[j] ^= iv[j];
        iv[j] = ciphertext[j];
      }

      #ifdef DEBUG
      printf("Plaintext block %u:", i / (BLOCK_SIZE / 4));
      for (u32 j = 0; j < BLOCK_SIZE / 4; j++) printf(" 0x%08x", plaintext[j]);
      printf("\n");
      #endif
    }

    u32 padding_count = (plaintext[BLOCK_SIZE / 4 - 1] & 0xff000000) >> 24;
    u8 *pt_bytes = (u8 *) plaintext;

    #ifdef DEBUG
    printf("Padding byte: 0x%02x\n", padding_count);
    #endif

    if (padding_count > BLOCK_SIZE || padding_count == 0)
    {
      // That *can't* be right
      padding_ok = 0;
    } else {
      padding_ok = 1;
    }

    for (u32 i = 0; i < padding_count; i++)
    {
      if (pt_bytes[BLOCK_SIZE - 1 - i] != padding_count)
      {
        padding_ok = 0;
        break;
      }
      plaintext_length++;
    }

    #ifdef DEBUG
    if (padding_ok == 1) printf("Padding checks out\n");
    if (plaintext_length == data_len) printf("ASN.1 sequence length checks out\n");
    #endif

    if (asn1_ok == 1 && padding_ok == 1 && plaintext_length == data_len)
    {
      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos, 0, 0);
      }
    }
  }
}
