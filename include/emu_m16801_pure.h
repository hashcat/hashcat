/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EMU_M16801_PURE_H
#define _EMU_M16801_PURE_H

#define DGST_ELEM 4
#define DGST_POS0 0
#define DGST_POS1 1
#define DGST_POS2 2
#define DGST_POS3 3

typedef struct digest
{
  u32 digest_buf[DGST_ELEM];

} digest_t;

typedef struct wpa_pmk_tmp
{
  u32 out[8];

} wpa_pmk_tmp_t;

typedef struct wpa_pmkid
{
  u32  pmkid[4];
  u32  pmkid_data[16];
  u8   orig_mac_ap[6];
  u8   orig_mac_sta[6];
  u8   essid_len;
  u32  essid_buf[16];

} wpa_pmkid_t;

KERNEL_FQ void m16801_init (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t));
KERNEL_FQ void m16801_loop (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t));
KERNEL_FQ void m16801_comp (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t));
KERNEL_FQ void m16801_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t));
KERNEL_FQ void m16801_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t));
KERNEL_FQ void m16801_aux3 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t));

#endif // _EMU_M16801_PURE_H
