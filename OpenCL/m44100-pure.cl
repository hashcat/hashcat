/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#include M2S(INCLUDE_PATH/inc_bignum_2048.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// The RSA key the keymaster blob held, recovered by the user and carried on the hash line. n0 and
// mont_one are derived from n once per hash on the host, because bn2048_mont_ctx_init gets R mod n
// by doubling 1 mod n 2048 times and that does not belong in a per candidate kernel. to_sign_off is
// where the module decided the signed bytes go, so this kernel needs none of the footer's words.

typedef struct androidfde_km
{
  u32 n[64];
  u32 d[64];
  u32 mont_one[64];

  u32 n0;

  u32 kdf_type;
  u32 to_sign_off;

} androidfde_km_t;

// Each scrypt pass ends with a PBKDF2 over that pass's own password, and the kernel that produced
// the password has exited by then, so both have to survive in the tmps. sig is the 256 byte
// signature, which is the second pass's password, and ikey is the 16 bytes cryptfs.c calls the
// intermediate key, which is the third pass's.

typedef struct androidfde_km_tmp
{
  u32 sig[64];
  u32 ikey[4];

  u32 in[SCRYPT_CNT4];
  u32 out[SCRYPT_CNT4];

} androidfde_km_tmp_t;

// Three scrypt passes, three loop kernels, and each transition in its own init kernel. So no kernel
// needs to ask which pass it is in, and the shape on the page is the shape of the algorithm.

KERNEL_FQ KERNEL_FA void m44100_init (KERN_ATTR_TMPS_ESALT (androidfde_km_tmp_t, androidfde_km_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_pbkdf2_ggg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m44100_loop_prepare (KERN_ATTR_TMPS (androidfde_km_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_init (P, X, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m44100_loop (KERN_ATTR_TMPS (androidfde_km_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];
  u32 T[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_loop (P, X, T, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

// The boundary between the first and second pass, so this kernel holds the RSA operation and
// nothing else.

KERNEL_FQ KERNEL_FA void m44100_init2 (KERN_ATTR_TMPS_ESALT (androidfde_km_tmp_t, androidfde_km_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  // finish the first pass, whose password was the candidate

  u32 ikey[8];

  scrypt_pbkdf2_ggp (pws[gid].i, pws[gid].pw_len, tmps[gid].in, SCRYPT_SZ, ikey, 32);

  // keymaster_sign_object () zeroes a 256 byte buffer and copies the 32 bytes into it, and where
  // they land is the whole difference between the two keymaster variants. KDF_SCRYPT_KEYMASTER puts
  // them one byte in, which keeps the most significant byte zero and the number below the modulus.
  // KDF_SCRYPT_KEYMASTER_BADLY_PADDED puts them at the front, so the number is 256 times larger and
  // exceeds the modulus a quarter of the time, which bn2048_powm () answers canonically anyway.
  // Writing them at an offset the module chose keeps that a difference in data, not a second path.

  const u32 to_sign_off = esalt_bufs[DIGESTS_OFFSET_HOST].to_sign_off;

  u32 msg[64];

  for (u32 i = 0; i < 64; i++) msg[i] = 0;

  for (u32 i = 0; i < 32; i++)
  {
    const u32 b = (ikey[i / 4] >> ((i % 4) * 8)) & 0xff;
    const u32 p = to_sign_off + i;

    msg[p / 4] |= b << ((p % 4) * 8);
  }

  // bn2048_from_be reverses the word order and swaps each word, so it is safe in place

  bn2048_from_be (msg, msg);

  u32 rsa_n[64];
  u32 rsa_d[64];
  u32 rsa_one[64];

  for (u32 i = 0; i < 64; i++)
  {
    rsa_n[i]   = esalt_bufs[DIGESTS_OFFSET_HOST].n[i];
    rsa_d[i]   = esalt_bufs[DIGESTS_OFFSET_HOST].d[i];
    rsa_one[i] = esalt_bufs[DIGESTS_OFFSET_HOST].mont_one[i];
  }

  u32 sig[64];

  bn2048_powm (sig, msg, rsa_d, rsa_n, esalt_bufs[DIGESTS_OFFSET_HOST].n0, rsa_one);

  bn2048_to_be (sig, sig);

  for (u32 i = 0; i < 64; i++) tmps[gid].sig[i] = sig[i];

  // the second pass takes all 256 bytes of the signature as its password

  scrypt_pbkdf2_ggg (tmps[gid].sig, 256, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m44100_loop2_prepare (KERN_ATTR_TMPS (androidfde_km_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_init (P, X, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m44100_loop2 (KERN_ATTR_TMPS (androidfde_km_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];
  u32 T[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_loop (P, X, T, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

// The boundary between the second and third pass. No RSA here, just the rechain.

KERNEL_FQ KERNEL_FA void m44100_init3 (KERN_ATTR_TMPS (androidfde_km_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  // finish the second pass, whose password was the signature

  u32 ikey[8];

  scrypt_pbkdf2_ggp (tmps[gid].sig, 256, tmps[gid].in, SCRYPT_SZ, ikey, 32);

  // cryptfs.c copies KEY_LEN_BYTES into intermediate_key, so the third pass runs over the first
  // 16 bytes of this and not over all 32

  tmps[gid].ikey[0] = ikey[0];
  tmps[gid].ikey[1] = ikey[1];
  tmps[gid].ikey[2] = ikey[2];
  tmps[gid].ikey[3] = ikey[3];

  scrypt_pbkdf2_ggg (tmps[gid].ikey, 16, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m44100_loop3_prepare (KERN_ATTR_TMPS (androidfde_km_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_init (P, X, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m44100_loop3 (KERN_ATTR_TMPS (androidfde_km_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];
  u32 T[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_loop (P, X, T, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m44100_comp (KERN_ATTR_TMPS (androidfde_km_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  u32 out[8];

  scrypt_pbkdf2_ggp (tmps[gid].ikey, 16, tmps[gid].in, SCRYPT_SZ, out, 32);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
