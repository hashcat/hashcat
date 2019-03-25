/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EMU_M02501_PURE_H
#define _EMU_M02501_PURE_H

typedef struct wpa_pmk_tmp
{
  u32 out[8];

} wpa_pmk_tmp_t;

typedef struct wpa_eapol
{
  u32  pke[32];
  u32  eapol[64 + 16];
  u16  eapol_len;
  u8   message_pair;
  int  message_pair_chgd;
  u8   keyver;
  u8   orig_mac_ap[6];
  u8   orig_mac_sta[6];
  u8   orig_nonce_ap[32];
  u8   orig_nonce_sta[32];
  u8   essid_len;
  u8   essid[32];
  u32  keymic[4];
  u32  hash[4];
  int  nonce_compare;
  int  nonce_error_corrections;
  int  detected_le;
  int  detected_be;

} wpa_eapol_t;

KERNEL_FQ void m02501_init (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t));
KERNEL_FQ void m02501_loop (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t));
KERNEL_FQ void m02501_comp (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t));
KERNEL_FQ void m02501_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t));
KERNEL_FQ void m02501_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t));
KERNEL_FQ void m02501_aux3 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t));

#endif // _EMU_M02501_PURE_H
