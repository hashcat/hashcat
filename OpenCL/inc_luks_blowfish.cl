/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha512.h"
#include "inc_hash_ripemd160.h"
#include "inc_cipher_blowfish.h"
#include "inc_luks_af.h"
#include "inc_luks_essiv.h"
#include "inc_luks_blowfish.h"

// LUKS with Blowfish. Two things make this unlike the AES, Serpent and Twofish includes beside it.
//
// Blowfish has an eight byte block, so a 512 byte sector holds 64 of them rather than 32, and XTS
// does not arise at all because that mode is defined over a sixteen byte block. A container here
// carries cbc-plain, cbc-plain64 or cbc-essiv:sha256.
//
// Its S boxes are key dependent and live in local memory, 4 KB per work item, so two keys cannot be
// scheduled at the same time without halving the work items a group holds. The ESSIV initialisation
// vectors are therefore computed while the ESSIV key is the one in the S boxes, and kept in a
// private buffer while the data key is scheduled over the top. That is also why the sector
// functions take the vector rather than deriving it: one of them serves every cipher mode.

DECLSPEC void blowfish_decrypt_block (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *iv)
{
  // the key material arrives from the hash line as it sits on disk, so the words are in host order
  // and Blowfish reads them big endian. iv holds the previous block in that big endian form.

  u32 L = hc_swap32_S (in[0]);
  u32 R = hc_swap32_S (in[1]);

  const u32 c0 = L;
  const u32 c1 = R;

  BF_DECRYPT (L, R);

  out[0] = hc_swap32_S (L ^ iv[0]);
  out[1] = hc_swap32_S (R ^ iv[1]);

  iv[0] = c0;
  iv[1] = c1;
}

DECLSPEC void blowfish_encrypt_block (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS u32 *L, PRIVATE_AS u32 *R)
{
  u32 l = *L;
  u32 r = *R;

  BF_ENCRYPT (l, r);

  *L = l;
  *R = r;
}

DECLSPEC void luks_blowfish_iv_plain (PRIVATE_AS u32 *iv, const u32 sector)
{
  // cbc-plain and cbc-plain64 both put the sector number little endian in the cipher block, which
  // fills all eight bytes here. The two differ only above sector 2 ** 32, which key material and a
  // first payload sector never reach.

  iv[0] = hc_swap32_S (sector);
  iv[1] = 0;
}

DECLSPEC void luks_blowfish_iv_essiv (PRIVATE_AS u32 *iv_buf, const int sector_cnt, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  // cbc-essiv:sha256 encrypts the same block under a key the ESSIV hash gives, and the S boxes hold
  // that key for as long as this runs

  for (int sector = 0; sector < sector_cnt; sector++)
  {
    u32 L = hc_swap32_S ((u32) sector);
    u32 R = 0;

    blowfish_encrypt_block (P, S0, S1, S2, S3, &L, &R);

    iv_buf[(sector * 2) + 0] = L;
    iv_buf[(sector * 2) + 1] = R;
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc128 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in  = 0;
  int idx_out = 0;

  for (int block = 0; block < 64; block++)
  {
    u32 data_in[2];

    data_in[0] = in[idx_in++];
    data_in[1] = in[idx_in++];

    u32 data_out[2];

    blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

    out[idx_out++] = data_out[0];
    out[idx_out++] = data_out[1];
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha1 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 32; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 2; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha1_diffuse16 (mk);
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha1_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 31; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 2; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha1_diffuse16 (mk);
  }
  // the last stripe of the key material is merged without a diffusion

  int idx_mk = 0;

  for (int block = 0; block < 2; block++)
  {
    u32 data_in[2];

    data_in[0] = in[idx_in++];
    data_in[1] = in[idx_in++];

    u32 data_out[2];

    blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

    mk[idx_mk++] ^= data_out[0];
    mk[idx_mk++] ^= data_out[1];
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha256 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 32; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 2; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha256_diffuse16 (mk);
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha256_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 31; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 2; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha256_diffuse16 (mk);
  }
  // the last stripe of the key material is merged without a diffusion

  int idx_mk = 0;

  for (int block = 0; block < 2; block++)
  {
    u32 data_in[2];

    data_in[0] = in[idx_in++];
    data_in[1] = in[idx_in++];

    u32 data_out[2];

    blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

    mk[idx_mk++] ^= data_out[0];
    mk[idx_mk++] ^= data_out[1];
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha512 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 32; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 2; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha512_diffuse16 (mk);
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha512_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 31; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 2; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha512_diffuse16 (mk);
  }
  // the last stripe of the key material is merged without a diffusion

  int idx_mk = 0;

  for (int block = 0; block < 2; block++)
  {
    u32 data_in[2];

    data_in[0] = in[idx_in++];
    data_in[1] = in[idx_in++];

    u32 data_out[2];

    blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

    mk[idx_mk++] ^= data_out[0];
    mk[idx_mk++] ^= data_out[1];
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_ripemd160 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 32; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 2; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_ripemd160_diffuse16 (mk);
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_ripemd160_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 31; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 2; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_ripemd160_diffuse16 (mk);
  }
  // the last stripe of the key material is merged without a diffusion

  int idx_mk = 0;

  for (int block = 0; block < 2; block++)
  {
    u32 data_in[2];

    data_in[0] = in[idx_in++];
    data_in[1] = in[idx_in++];

    u32 data_out[2];

    blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

    mk[idx_mk++] ^= data_out[0];
    mk[idx_mk++] ^= data_out[1];
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc256 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in  = 0;
  int idx_out = 0;

  for (int block = 0; block < 64; block++)
  {
    u32 data_in[2];

    data_in[0] = in[idx_in++];
    data_in[1] = in[idx_in++];

    u32 data_out[2];

    blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

    out[idx_out++] = data_out[0];
    out[idx_out++] = data_out[1];
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha1 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 16; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 4; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha1_diffuse32 (mk);
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha1_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 15; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 4; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha1_diffuse32 (mk);
  }
  // the last stripe of the key material is merged without a diffusion

  int idx_mk = 0;

  for (int block = 0; block < 4; block++)
  {
    u32 data_in[2];

    data_in[0] = in[idx_in++];
    data_in[1] = in[idx_in++];

    u32 data_out[2];

    blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

    mk[idx_mk++] ^= data_out[0];
    mk[idx_mk++] ^= data_out[1];
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha256 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 16; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 4; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha256_diffuse32 (mk);
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha256_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 15; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 4; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha256_diffuse32 (mk);
  }
  // the last stripe of the key material is merged without a diffusion

  int idx_mk = 0;

  for (int block = 0; block < 4; block++)
  {
    u32 data_in[2];

    data_in[0] = in[idx_in++];
    data_in[1] = in[idx_in++];

    u32 data_out[2];

    blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

    mk[idx_mk++] ^= data_out[0];
    mk[idx_mk++] ^= data_out[1];
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha512 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 16; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 4; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha512_diffuse32 (mk);
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha512_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 15; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 4; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_sha512_diffuse32 (mk);
  }
  // the last stripe of the key material is merged without a diffusion

  int idx_mk = 0;

  for (int block = 0; block < 4; block++)
  {
    u32 data_in[2];

    data_in[0] = in[idx_in++];
    data_in[1] = in[idx_in++];

    u32 data_out[2];

    blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

    mk[idx_mk++] ^= data_out[0];
    mk[idx_mk++] ^= data_out[1];
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_ripemd160 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 16; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 4; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_ripemd160_diffuse32 (mk);
  }
}

DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_ripemd160_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in)
{
  u32 iv[2] = { iv_in[0], iv_in[1] };

  int idx_in = 0;

  for (int i = 0; i < 15; i++)
  {
    int idx_mk = 0;

    for (int block = 0; block < 4; block++)
    {
      u32 data_in[2];

      data_in[0] = in[idx_in++];
      data_in[1] = in[idx_in++];

      u32 data_out[2];

      blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

      mk[idx_mk++] ^= data_out[0];
      mk[idx_mk++] ^= data_out[1];
    }

    AF_ripemd160_diffuse32 (mk);
  }
  // the last stripe of the key material is merged without a diffusion

  int idx_mk = 0;

  for (int block = 0; block < 4; block++)
  {
    u32 data_in[2];

    data_in[0] = in[idx_in++];
    data_in[1] = in[idx_in++];

    u32 data_out[2];

    blowfish_decrypt_block (P, S0, S1, S2, S3, data_in, data_out, iv);

    mk[idx_mk++] ^= data_out[0];
    mk[idx_mk++] ^= data_out[1];
  }
}

DECLSPEC void luks_blowfish_essiv_key_and_ivs (PRIVATE_AS const u32 *ukey, const int key_words, PRIVATE_AS u32 *iv_buf, const int sector_cnt, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  // The ESSIV key is the SHA-256 of the data key, and every sector's vector is that sector number
  // encrypted under it. Both keys cannot sit in the S boxes at once, so the vectors are taken now
  // and the caller schedules the data key over the top afterwards.
  //
  // ESSIV_sha256_init takes its key in host order and answers in host order, while Blowfish reads
  // big endian, so the key turns around on the way in and the hash turns around on the way out.

  u32 key_host[8];

  for (int i = 0; i < key_words; i++) key_host[i] = hc_swap32_S (ukey[i]);

  u32 essivhash[8];

  if (key_words == 4) ESSIV_sha256_init128 (key_host, essivhash);
  else                ESSIV_sha256_init256 (key_host, essivhash);

  u32 ekey[8];

  for (int i = 0; i < 8; i++) ekey[i] = hc_swap32_S (essivhash[i]);

  blowfish_set_key (ekey, 8, P, S0, S1, S2, S3);

  luks_blowfish_iv_essiv (iv_buf, sector_cnt, P, S0, S1, S2, S3);
}

DECLSPEC void luks_af_sha1_then_blowfish_decrypt (GLOBAL_AS const luks_t *luks_bufs, GLOBAL_AS luks_tmp_t *tmps, PRIVATE_AS u32 *pt_buf, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  const u32 key_size    = luks_bufs->key_size;
  const u32 cipher_mode = luks_bufs->cipher_mode;

  const int key_words = key_size / 32;

  const int sector_cnt = (key_size * LUKS_STRIPES) / (512 * 8);

  // the derivation leaves its result in big endian words, which is the order Blowfish reads, so
  // unlike the cipher includes beside this one the key goes in as it stands

  u32 ukey[8];

  for (int i = 0; i < key_words; i++) ukey[i] = tmps->out32[i];

  u32 mk[16] = { 0 };

  if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_ESSIV_SHA256)
  {
    u32 iv_buf[LUKS_BF_SECTOR_MAX * 2];

    luks_blowfish_essiv_key_and_ivs (ukey, key_words, iv_buf, sector_cnt, P, S0, S1, S2, S3);

    blowfish_set_key (ukey, key_words, P, S0, S1, S2, S3);

    int offset = 0;
    int sector = 0;

    for (sector = 0; sector < sector_cnt - 1; sector++, offset += (512 / 4))
    {
      if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha1 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
      else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha1 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
    }

    if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha1_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
    else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha1_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
  }
  else if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_PLAIN || cipher_mode == HC_LUKS_CIPHER_MODE_CBC_PLAIN64)
  {
    blowfish_set_key (ukey, key_words, P, S0, S1, S2, S3);

    int offset = 0;
    int sector = 0;

    for (sector = 0; sector < sector_cnt - 1; sector++, offset += (512 / 4))
    {
      u32 iv[2];

      luks_blowfish_iv_plain (iv, (u32) sector);

      if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha1 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
      else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha1 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
    }

    u32 iv[2];

    luks_blowfish_iv_plain (iv, (u32) sector);

    if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha1_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
    else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha1_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
  }
  else
  {
    return;
  }

  // the merge leaves the master key in host order, so this one does turn around

  u32 mkey[8];

  for (int i = 0; i < key_words; i++) mkey[i] = hc_swap32_S (mk[i]);

  u32 iv[2];

  if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_ESSIV_SHA256)
  {
    u32 iv_one[2];

    luks_blowfish_essiv_key_and_ivs (mkey, key_words, iv_one, 1, P, S0, S1, S2, S3);

    iv[0] = iv_one[0];
    iv[1] = iv_one[1];
  }
  else
  {
    luks_blowfish_iv_plain (iv, 0);
  }

  blowfish_set_key (mkey, key_words, P, S0, S1, S2, S3);

  if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128 (luks_bufs->ct_buf, pt_buf, P, S0, S1, S2, S3, iv);
  else                                  luks_decrypt_sector_blowfish_cbc256 (luks_bufs->ct_buf, pt_buf, P, S0, S1, S2, S3, iv);
}

DECLSPEC void luks_af_sha256_then_blowfish_decrypt (GLOBAL_AS const luks_t *luks_bufs, GLOBAL_AS luks_tmp_t *tmps, PRIVATE_AS u32 *pt_buf, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  const u32 key_size    = luks_bufs->key_size;
  const u32 cipher_mode = luks_bufs->cipher_mode;

  const int key_words = key_size / 32;

  const int sector_cnt = (key_size * LUKS_STRIPES) / (512 * 8);

  // the derivation leaves its result in big endian words, which is the order Blowfish reads, so
  // unlike the cipher includes beside this one the key goes in as it stands

  u32 ukey[8];

  for (int i = 0; i < key_words; i++) ukey[i] = tmps->out32[i];

  u32 mk[16] = { 0 };

  if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_ESSIV_SHA256)
  {
    u32 iv_buf[LUKS_BF_SECTOR_MAX * 2];

    luks_blowfish_essiv_key_and_ivs (ukey, key_words, iv_buf, sector_cnt, P, S0, S1, S2, S3);

    blowfish_set_key (ukey, key_words, P, S0, S1, S2, S3);

    int offset = 0;
    int sector = 0;

    for (sector = 0; sector < sector_cnt - 1; sector++, offset += (512 / 4))
    {
      if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha256 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
      else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha256 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
    }

    if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha256_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
    else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha256_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
  }
  else if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_PLAIN || cipher_mode == HC_LUKS_CIPHER_MODE_CBC_PLAIN64)
  {
    blowfish_set_key (ukey, key_words, P, S0, S1, S2, S3);

    int offset = 0;
    int sector = 0;

    for (sector = 0; sector < sector_cnt - 1; sector++, offset += (512 / 4))
    {
      u32 iv[2];

      luks_blowfish_iv_plain (iv, (u32) sector);

      if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha256 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
      else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha256 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
    }

    u32 iv[2];

    luks_blowfish_iv_plain (iv, (u32) sector);

    if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha256_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
    else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha256_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
  }
  else
  {
    return;
  }

  // the merge leaves the master key in host order, so this one does turn around

  u32 mkey[8];

  for (int i = 0; i < key_words; i++) mkey[i] = hc_swap32_S (mk[i]);

  u32 iv[2];

  if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_ESSIV_SHA256)
  {
    u32 iv_one[2];

    luks_blowfish_essiv_key_and_ivs (mkey, key_words, iv_one, 1, P, S0, S1, S2, S3);

    iv[0] = iv_one[0];
    iv[1] = iv_one[1];
  }
  else
  {
    luks_blowfish_iv_plain (iv, 0);
  }

  blowfish_set_key (mkey, key_words, P, S0, S1, S2, S3);

  if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128 (luks_bufs->ct_buf, pt_buf, P, S0, S1, S2, S3, iv);
  else                                  luks_decrypt_sector_blowfish_cbc256 (luks_bufs->ct_buf, pt_buf, P, S0, S1, S2, S3, iv);
}

DECLSPEC void luks_af_sha512_then_blowfish_decrypt (GLOBAL_AS const luks_t *luks_bufs, GLOBAL_AS luks_tmp_t *tmps, PRIVATE_AS u32 *pt_buf, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  const u32 key_size    = luks_bufs->key_size;
  const u32 cipher_mode = luks_bufs->cipher_mode;

  const int key_words = key_size / 32;

  const int sector_cnt = (key_size * LUKS_STRIPES) / (512 * 8);

  // a SHA-512 derivation leaves its result in out64 rather than out32, and Blowfish reads big
  // endian words, so each u64 gives its high half and then its low half

  u32 ukey[8];

  for (int i = 0; i < key_words; i += 2)
  {
    ukey[i + 0] = h32_from_64_S (tmps->out64[i / 2]);
    ukey[i + 1] = l32_from_64_S (tmps->out64[i / 2]);
  }

  u32 mk[16] = { 0 };

  if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_ESSIV_SHA256)
  {
    u32 iv_buf[LUKS_BF_SECTOR_MAX * 2];

    luks_blowfish_essiv_key_and_ivs (ukey, key_words, iv_buf, sector_cnt, P, S0, S1, S2, S3);

    blowfish_set_key (ukey, key_words, P, S0, S1, S2, S3);

    int offset = 0;
    int sector = 0;

    for (sector = 0; sector < sector_cnt - 1; sector++, offset += (512 / 4))
    {
      if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha512 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
      else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha512 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
    }

    if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha512_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
    else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha512_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
  }
  else if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_PLAIN || cipher_mode == HC_LUKS_CIPHER_MODE_CBC_PLAIN64)
  {
    blowfish_set_key (ukey, key_words, P, S0, S1, S2, S3);

    int offset = 0;
    int sector = 0;

    for (sector = 0; sector < sector_cnt - 1; sector++, offset += (512 / 4))
    {
      u32 iv[2];

      luks_blowfish_iv_plain (iv, (u32) sector);

      if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha512 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
      else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha512 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
    }

    u32 iv[2];

    luks_blowfish_iv_plain (iv, (u32) sector);

    if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_sha512_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
    else                                  luks_decrypt_sector_blowfish_cbc256_mk_sha512_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
  }
  else
  {
    return;
  }

  // the merge leaves the master key in host order, so this one does turn around

  u32 mkey[8];

  for (int i = 0; i < key_words; i++) mkey[i] = hc_swap32_S (mk[i]);

  u32 iv[2];

  if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_ESSIV_SHA256)
  {
    u32 iv_one[2];

    luks_blowfish_essiv_key_and_ivs (mkey, key_words, iv_one, 1, P, S0, S1, S2, S3);

    iv[0] = iv_one[0];
    iv[1] = iv_one[1];
  }
  else
  {
    luks_blowfish_iv_plain (iv, 0);
  }

  blowfish_set_key (mkey, key_words, P, S0, S1, S2, S3);

  if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128 (luks_bufs->ct_buf, pt_buf, P, S0, S1, S2, S3, iv);
  else                                  luks_decrypt_sector_blowfish_cbc256 (luks_bufs->ct_buf, pt_buf, P, S0, S1, S2, S3, iv);
}

DECLSPEC void luks_af_ripemd160_then_blowfish_decrypt (GLOBAL_AS const luks_t *luks_bufs, GLOBAL_AS luks_tmp_t *tmps, PRIVATE_AS u32 *pt_buf, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  const u32 key_size    = luks_bufs->key_size;
  const u32 cipher_mode = luks_bufs->cipher_mode;

  const int key_words = key_size / 32;

  const int sector_cnt = (key_size * LUKS_STRIPES) / (512 * 8);

  // RIPEMD-160 leaves its result in host order, where SHA-1 and SHA-256 leave big endian words, so
  // this one turns the key around and those two do not

  u32 ukey[8];

  for (int i = 0; i < key_words; i++) ukey[i] = hc_swap32_S (tmps->out32[i]);

  u32 mk[16] = { 0 };

  if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_ESSIV_SHA256)
  {
    u32 iv_buf[LUKS_BF_SECTOR_MAX * 2];

    luks_blowfish_essiv_key_and_ivs (ukey, key_words, iv_buf, sector_cnt, P, S0, S1, S2, S3);

    blowfish_set_key (ukey, key_words, P, S0, S1, S2, S3);

    int offset = 0;
    int sector = 0;

    for (sector = 0; sector < sector_cnt - 1; sector++, offset += (512 / 4))
    {
      if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_ripemd160 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
      else                                  luks_decrypt_sector_blowfish_cbc256_mk_ripemd160 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
    }

    if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_ripemd160_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
    else                                  luks_decrypt_sector_blowfish_cbc256_mk_ripemd160_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv_buf + (sector * 2));
  }
  else if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_PLAIN || cipher_mode == HC_LUKS_CIPHER_MODE_CBC_PLAIN64)
  {
    blowfish_set_key (ukey, key_words, P, S0, S1, S2, S3);

    int offset = 0;
    int sector = 0;

    for (sector = 0; sector < sector_cnt - 1; sector++, offset += (512 / 4))
    {
      u32 iv[2];

      luks_blowfish_iv_plain (iv, (u32) sector);

      if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_ripemd160 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
      else                                  luks_decrypt_sector_blowfish_cbc256_mk_ripemd160 (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
    }

    u32 iv[2];

    luks_blowfish_iv_plain (iv, (u32) sector);

    if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128_mk_ripemd160_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
    else                                  luks_decrypt_sector_blowfish_cbc256_mk_ripemd160_final (luks_bufs->af_buf + offset, mk, P, S0, S1, S2, S3, iv);
  }
  else
  {
    return;
  }

  // the merge leaves the master key in host order, so this one does turn around

  u32 mkey[8];

  for (int i = 0; i < key_words; i++) mkey[i] = hc_swap32_S (mk[i]);

  u32 iv[2];

  if (cipher_mode == HC_LUKS_CIPHER_MODE_CBC_ESSIV_SHA256)
  {
    u32 iv_one[2];

    luks_blowfish_essiv_key_and_ivs (mkey, key_words, iv_one, 1, P, S0, S1, S2, S3);

    iv[0] = iv_one[0];
    iv[1] = iv_one[1];
  }
  else
  {
    luks_blowfish_iv_plain (iv, 0);
  }

  blowfish_set_key (mkey, key_words, P, S0, S1, S2, S3);

  if (key_size == HC_LUKS_KEY_SIZE_128) luks_decrypt_sector_blowfish_cbc128 (luks_bufs->ct_buf, pt_buf, P, S0, S1, S2, S3, iv);
  else                                  luks_decrypt_sector_blowfish_cbc256 (luks_bufs->ct_buf, pt_buf, P, S0, S1, S2, S3, iv);
}
