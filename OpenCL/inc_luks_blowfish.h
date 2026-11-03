/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_LUKS_BLOWFISH_H
#define INC_LUKS_BLOWFISH_H

// The most sectors of key material any supported key size reaches, which is a 256 bit key: its
// 4000 stripes of 32 bytes are 250 sectors. A 128 bit key reaches 125. The ESSIV vectors for a
// whole run are held in a buffer of this size, so it has to be a compile time bound.

#define LUKS_BF_SECTOR_MAX 250

DECLSPEC void blowfish_decrypt_block (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *iv);
DECLSPEC void blowfish_encrypt_block (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS u32 *L, PRIVATE_AS u32 *R);
DECLSPEC void luks_blowfish_iv_plain (PRIVATE_AS u32 *iv, const u32 sector);
DECLSPEC void luks_blowfish_iv_essiv (PRIVATE_AS u32 *iv_buf, const int sector_cnt, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3);
DECLSPEC void luks_decrypt_sector_blowfish_cbc128 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha1 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha1_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha256 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha256_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha512 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_sha512_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_ripemd160 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc128_mk_ripemd160_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc256 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha1 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha1_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha256 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha256_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha512 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_sha512_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_ripemd160 (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_decrypt_sector_blowfish_cbc256_mk_ripemd160_final (GLOBAL_AS const u32 *in, PRIVATE_AS u32 *mk, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *iv_in);
DECLSPEC void luks_blowfish_essiv_key_and_ivs (PRIVATE_AS const u32 *ukey, const int key_words, PRIVATE_AS u32 *iv_buf, const int sector_cnt, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3);
DECLSPEC void luks_af_sha1_then_blowfish_decrypt (GLOBAL_AS const luks_t *luks_bufs, GLOBAL_AS luks_tmp_t *tmps, PRIVATE_AS u32 *pt_buf, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3);
DECLSPEC void luks_af_sha256_then_blowfish_decrypt (GLOBAL_AS const luks_t *luks_bufs, GLOBAL_AS luks_tmp_t *tmps, PRIVATE_AS u32 *pt_buf, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3);
DECLSPEC void luks_af_sha512_then_blowfish_decrypt (GLOBAL_AS const luks_t *luks_bufs, GLOBAL_AS luks_tmp_t *tmps, PRIVATE_AS u32 *pt_buf, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3);
DECLSPEC void luks_af_ripemd160_then_blowfish_decrypt (GLOBAL_AS const luks_t *luks_bufs, GLOBAL_AS luks_tmp_t *tmps, PRIVATE_AS u32 *pt_buf, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3);

#endif // INC_LUKS_BLOWFISH_H
