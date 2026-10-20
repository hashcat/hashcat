/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_KRB5_DES_H
#define INC_KRB5_DES_H

DECLSPEC u32 krb5_des_rev7 (const u32 x);
DECLSPEC u32 krb5_des_odd_parity (const u32 x);
DECLSPEC void krb5_des_key_correction (PRIVATE_AS u32 *k);
DECLSPEC void krb5_des_build_buf (PRIVATE_AS const u32 *pw, const u32 pw_len, GLOBAL_AS const u32 *salt_buf, const u32 salt_len, PRIVATE_AS u32 *w);
DECLSPEC void krb5_des_string_to_key (PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64]);

#endif // INC_KRB5_DES_H
