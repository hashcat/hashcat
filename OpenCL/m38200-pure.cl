/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define md5crypt_magic 0x00243124u

// byte p into word-packed array a, little-endian within each u32, the same convention pws[].i uses

#define PUTCHAR_LE(a,p,c) ((a)[(p) / 4] = (((a)[(p) / 4] & ~(0xffu << (((p) & 3) * 8))) | ((u32) (c) << (((p) & 3) * 8))))

CONSTANT_VK u8 CISCO38200_ITOA64[64] =
{
  '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

DECLSPEC u8 cisco38200_itoa64 (const u32 v)
{
  return CISCO38200_ITOA64[v & 0x3f];
}

typedef struct cisco38200_tmp
{
  u32 digest_buf[4]; // md5crypt (Type 5) running / final digest
  u32 pw_buf[8];     // assembled "$1$<salt>$<hash>" string fed to scrypt as its password

  #ifndef SCRYPT_TMP_ELEM
  #define SCRYPT_TMP_ELEM 1
  #endif

  u32 in[SCRYPT_TMP_ELEM / 2];
  u32 out[SCRYPT_TMP_ELEM / 2];

} cisco38200_tmp_t;

KERNEL_FQ KERNEL_FA void m38200_init (KERN_ATTR_TMPS (cisco38200_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len_pc;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf_pc[idx];
  }

  md5_ctx_t md5_ctx1;

  md5_init (&md5_ctx1);

  md5_update (&md5_ctx1, w, pw_len);
  md5_update (&md5_ctx1, s, salt_len);
  md5_update (&md5_ctx1, w, pw_len);

  md5_final (&md5_ctx1);

  u32 final[16] = { 0 };

  final[0] = md5_ctx1.h[0];
  final[1] = md5_ctx1.h[1];
  final[2] = md5_ctx1.h[2];
  final[3] = md5_ctx1.h[3];

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update (&md5_ctx, w, pw_len);

  u32 m[16] = { 0 };

  m[0] = md5crypt_magic;

  md5_update (&md5_ctx, m, 3);
  md5_update (&md5_ctx, s, salt_len);

  int pl;

  for (pl = pw_len; pl > 16; pl -= 16)
  {
    md5_update (&md5_ctx, final, 16);
  }

  truncate_block_4x4_le_S (final, pl);

  md5_update (&md5_ctx, final, pl);

  for (int i = pw_len; i != 0; i >>= 1)
  {
    u32 t[16] = { 0 };

    if (i & 1)
    {
      t[0] = 0;
    }
    else
    {
      t[0] = w[0] & 0xff;
    }

    md5_update (&md5_ctx, t, 1);
  }

  md5_final (&md5_ctx);

  tmps[gid].digest_buf[0] = md5_ctx.h[0];
  tmps[gid].digest_buf[1] = md5_ctx.h[1];
  tmps[gid].digest_buf[2] = md5_ctx.h[2];
  tmps[gid].digest_buf[3] = md5_ctx.h[3];
}

KERNEL_FQ KERNEL_FA void m38200_loop (KERN_ATTR_TMPS (cisco38200_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len_pc;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf_pc[idx];
  }

  u32 digest[16] = { 0 };

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    md5_ctx_t md5_ctx;

    md5_init (&md5_ctx);

    if (j & 1)
    {
      md5_update (&md5_ctx, w, pw_len);
    }
    else
    {
      md5_update (&md5_ctx, digest, 16);
    }

    if (j % 3)
    {
      md5_update (&md5_ctx, s, salt_len);
    }

    if (j % 7)
    {
      md5_update (&md5_ctx, w, pw_len);
    }

    if (j & 1)
    {
      md5_update (&md5_ctx, digest, 16);
    }
    else
    {
      md5_update (&md5_ctx, w, pw_len);
    }

    md5_final (&md5_ctx);

    digest[0] = md5_ctx.h[0];
    digest[1] = md5_ctx.h[1];
    digest[2] = md5_ctx.h[2];
    digest[3] = md5_ctx.h[3];
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

KERNEL_FQ KERNEL_FA void m38200_init2 (KERN_ATTR_TMPS (cisco38200_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // unpack the 16-byte md5crypt digest to individual bytes

  u8 d[16];

  d[ 0] = (tmps[gid].digest_buf[0] >>  0) & 0xff;
  d[ 1] = (tmps[gid].digest_buf[0] >>  8) & 0xff;
  d[ 2] = (tmps[gid].digest_buf[0] >> 16) & 0xff;
  d[ 3] = (tmps[gid].digest_buf[0] >> 24) & 0xff;
  d[ 4] = (tmps[gid].digest_buf[1] >>  0) & 0xff;
  d[ 5] = (tmps[gid].digest_buf[1] >>  8) & 0xff;
  d[ 6] = (tmps[gid].digest_buf[1] >> 16) & 0xff;
  d[ 7] = (tmps[gid].digest_buf[1] >> 24) & 0xff;
  d[ 8] = (tmps[gid].digest_buf[2] >>  0) & 0xff;
  d[ 9] = (tmps[gid].digest_buf[2] >>  8) & 0xff;
  d[10] = (tmps[gid].digest_buf[2] >> 16) & 0xff;
  d[11] = (tmps[gid].digest_buf[2] >> 24) & 0xff;
  d[12] = (tmps[gid].digest_buf[3] >>  0) & 0xff;
  d[13] = (tmps[gid].digest_buf[3] >>  8) & 0xff;
  d[14] = (tmps[gid].digest_buf[3] >> 16) & 0xff;
  d[15] = (tmps[gid].digest_buf[3] >> 24) & 0xff;

  // crypt(3)/md5crypt's byte regrouping: groups of (i, i+6, i+12) plus a final lone byte

  u8 enc[22];

  int l;

  l = (d[0] << 16) | (d[6] << 8) | d[12];
  enc[0] = cisco38200_itoa64 (l); l >>= 6; enc[1] = cisco38200_itoa64 (l); l >>= 6; enc[2] = cisco38200_itoa64 (l); l >>= 6; enc[3] = cisco38200_itoa64 (l);

  l = (d[1] << 16) | (d[7] << 8) | d[13];
  enc[4] = cisco38200_itoa64 (l); l >>= 6; enc[5] = cisco38200_itoa64 (l); l >>= 6; enc[6] = cisco38200_itoa64 (l); l >>= 6; enc[7] = cisco38200_itoa64 (l);

  l = (d[2] << 16) | (d[8] << 8) | d[14];
  enc[8] = cisco38200_itoa64 (l); l >>= 6; enc[9] = cisco38200_itoa64 (l); l >>= 6; enc[10] = cisco38200_itoa64 (l); l >>= 6; enc[11] = cisco38200_itoa64 (l);

  l = (d[3] << 16) | (d[9] << 8) | d[15];
  enc[12] = cisco38200_itoa64 (l); l >>= 6; enc[13] = cisco38200_itoa64 (l); l >>= 6; enc[14] = cisco38200_itoa64 (l); l >>= 6; enc[15] = cisco38200_itoa64 (l);

  l = (d[4] << 16) | (d[10] << 8) | d[5];
  enc[16] = cisco38200_itoa64 (l); l >>= 6; enc[17] = cisco38200_itoa64 (l); l >>= 6; enc[18] = cisco38200_itoa64 (l); l >>= 6; enc[19] = cisco38200_itoa64 (l);

  l = d[11];
  enc[20] = cisco38200_itoa64 (l); l >>= 6; enc[21] = cisco38200_itoa64 (l);

  // assemble "$1$<type5 salt>$<enc>", zero padded, into tmps[gid].pw_buf

  tmps[gid].pw_buf[0] = 0;
  tmps[gid].pw_buf[1] = 0;
  tmps[gid].pw_buf[2] = 0;
  tmps[gid].pw_buf[3] = 0;
  tmps[gid].pw_buf[4] = 0;
  tmps[gid].pw_buf[5] = 0;
  tmps[gid].pw_buf[6] = 0;
  tmps[gid].pw_buf[7] = 0;

  const u32 salt_len_pc = salt_bufs[SALT_POS_HOST].salt_len_pc;

  u32 pos = 0;

  PUTCHAR_LE (tmps[gid].pw_buf, pos, '$'); pos++;
  PUTCHAR_LE (tmps[gid].pw_buf, pos, '1'); pos++;
  PUTCHAR_LE (tmps[gid].pw_buf, pos, '$'); pos++;

  for (u32 i = 0; i < salt_len_pc; i++)
  {
    const u32 w_idx = i / 4;
    const u32 b_idx = i % 4;

    const u8 c = (salt_bufs[SALT_POS_HOST].salt_buf_pc[w_idx] >> (b_idx * 8)) & 0xff;

    PUTCHAR_LE (tmps[gid].pw_buf, pos, c); pos++;
  }

  PUTCHAR_LE (tmps[gid].pw_buf, pos, '$'); pos++;

  for (u32 i = 0; i < 22; i++)
  {
    PUTCHAR_LE (tmps[gid].pw_buf, pos, enc[i]); pos++;
  }

  // stage 2: scrypt (N=16384, r=1, p=1) over the assembled string, salted with the type9 salt

  scrypt_pbkdf2_ggg (tmps[gid].pw_buf, pos, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m38200_loop2_prepare (KERN_ATTR_TMPS (cisco38200_tmp_t))
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

KERNEL_FQ KERNEL_FA void m38200_loop2 (KERN_ATTR_TMPS (cisco38200_tmp_t))
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

KERNEL_FQ KERNEL_FA void m38200_comp (KERN_ATTR_TMPS (cisco38200_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  // the assembled password's length depends only on the salt, not the candidate, so recompute it
  // here rather than storing it: 3 ("$1$") + type5 salt + 1 ("$") + 22 (encoded md5crypt hash)

  const u32 pw_len = 3 + salt_bufs[SALT_POS_HOST].salt_len_pc + 1 + 22;

  u32 out[4];

  scrypt_pbkdf2_ggp (tmps[gid].pw_buf, pw_len, tmps[gid].in, SCRYPT_SZ, out, 16);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
