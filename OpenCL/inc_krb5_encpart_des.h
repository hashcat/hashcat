/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_KRB5_ENCPART_DES_H
#define INC_KRB5_ENCPART_DES_H

DECLSPEC bool krb5_des_encpart_asn1 (const u32 w0, const u32 w1, const bool is_rep);
DECLSPEC bool krb5_des_encpart_check (PRIVATE_AS const u32 *key, GLOBAL_AS const u32 *checksum, GLOBAL_AS const u32 *edata2, const u32 edata2_len, const bool is_rep, SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64]);

#endif // INC_KRB5_ENCPART_DES_H
