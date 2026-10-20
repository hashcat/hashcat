/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_PBKDF2_H
#define INC_PBKDF2_H

// PBKDF2 split along a slow hash's kernels: _init in the init kernel, _loop for each run of the
// loop kernel, _comp in the comp kernel. The state carries the HMAC pad states and, for each output
// block, the last U and the XOR of all U so far. It holds up to 64 bytes of derived key.

#define PBKDF2_MD5_BLOCKS    4
#define PBKDF2_SHA1_BLOCKS   4
#define PBKDF2_SHA256_BLOCKS 2
#define PBKDF2_SHA512_BLOCKS 1

typedef struct pbkdf2_md5_state
{
  u32 ipad[4];
  u32 opad[4];

  u32 dgst[PBKDF2_MD5_BLOCKS * 4];
  u32 out[PBKDF2_MD5_BLOCKS * 4];

} pbkdf2_md5_state_t;

typedef struct pbkdf2_sha1_state
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[PBKDF2_SHA1_BLOCKS * 5];
  u32 out[PBKDF2_SHA1_BLOCKS * 5];

} pbkdf2_sha1_state_t;

typedef struct pbkdf2_sha256_state
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[PBKDF2_SHA256_BLOCKS * 8];
  u32 out[PBKDF2_SHA256_BLOCKS * 8];

} pbkdf2_sha256_state_t;

typedef struct pbkdf2_sha512_state
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[PBKDF2_SHA512_BLOCKS * 8];
  u64 out[PBKDF2_SHA512_BLOCKS * 8];

} pbkdf2_sha512_state_t;

DECLSPEC void pbkdf2_md5_run    (PRIVATE_AS const u32 *ipad, PRIVATE_AS const u32 *opad, PRIVATE_AS u32 *dgst);
DECLSPEC void pbkdf2_sha1_run   (PRIVATE_AS const u32 *ipad, PRIVATE_AS const u32 *opad, PRIVATE_AS u32 *dgst);
DECLSPEC void pbkdf2_sha256_run (PRIVATE_AS const u32 *ipad, PRIVATE_AS const u32 *opad, PRIVATE_AS u32 *dgst);
DECLSPEC void pbkdf2_sha512_run (PRIVATE_AS const u64 *ipad, PRIVATE_AS const u64 *opad, PRIVATE_AS u64 *dgst);

DECLSPEC void pbkdf2_md5_run_V    (PRIVATE_AS const u32x *ipad, PRIVATE_AS const u32x *opad, PRIVATE_AS u32x *dgst);
DECLSPEC void pbkdf2_sha1_run_V   (PRIVATE_AS const u32x *ipad, PRIVATE_AS const u32x *opad, PRIVATE_AS u32x *dgst);
DECLSPEC void pbkdf2_sha256_run_V (PRIVATE_AS const u32x *ipad, PRIVATE_AS const u32x *opad, PRIVATE_AS u32x *dgst);
DECLSPEC void pbkdf2_sha512_run_V (PRIVATE_AS const u64x *ipad, PRIVATE_AS const u64x *opad, PRIVATE_AS u64x *dgst);

DECLSPEC void pbkdf2_md5_init    (PRIVATE_AS pbkdf2_md5_state_t    *st, PRIVATE_AS const u32 *key, const int key_len, PRIVATE_AS const u32 *salt, const int salt_len, const u32 first, const u32 blocks);
DECLSPEC void pbkdf2_sha1_init   (PRIVATE_AS pbkdf2_sha1_state_t   *st, PRIVATE_AS const u32 *key, const int key_len, PRIVATE_AS const u32 *salt, const int salt_len, const u32 first, const u32 blocks);
DECLSPEC void pbkdf2_sha256_init (PRIVATE_AS pbkdf2_sha256_state_t *st, PRIVATE_AS const u32 *key, const int key_len, PRIVATE_AS const u32 *salt, const int salt_len, const u32 first, const u32 blocks);
DECLSPEC void pbkdf2_sha512_init (PRIVATE_AS pbkdf2_sha512_state_t *st, PRIVATE_AS const u32 *key, const int key_len, PRIVATE_AS const u32 *salt, const int salt_len, const u32 first, const u32 blocks);

DECLSPEC void pbkdf2_md5_loop    (PRIVATE_AS pbkdf2_md5_state_t    *st, const u32 blocks, const u32 loops);
DECLSPEC void pbkdf2_sha1_loop   (PRIVATE_AS pbkdf2_sha1_state_t   *st, const u32 blocks, const u32 loops);
DECLSPEC void pbkdf2_sha256_loop (PRIVATE_AS pbkdf2_sha256_state_t *st, const u32 blocks, const u32 loops);
DECLSPEC void pbkdf2_sha512_loop (PRIVATE_AS pbkdf2_sha512_state_t *st, const u32 blocks, const u32 loops);

DECLSPEC void pbkdf2_dk_tail     (PRIVATE_AS u32 *dk, const u32 dk_len);

DECLSPEC void pbkdf2_md5_comp    (PRIVATE_AS const pbkdf2_md5_state_t    *st, PRIVATE_AS u32 *dk, const u32 dk_len);
DECLSPEC void pbkdf2_sha1_comp   (PRIVATE_AS const pbkdf2_sha1_state_t   *st, PRIVATE_AS u32 *dk, const u32 dk_len);
DECLSPEC void pbkdf2_sha256_comp (PRIVATE_AS const pbkdf2_sha256_state_t *st, PRIVATE_AS u32 *dk, const u32 dk_len);
DECLSPEC void pbkdf2_sha512_comp (PRIVATE_AS const pbkdf2_sha512_state_t *st, PRIVATE_AS u32 *dk, const u32 dk_len);

#endif // INC_PBKDF2_H
