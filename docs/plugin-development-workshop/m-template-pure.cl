/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

KERNEL_FQ void m<number>_init (KERN_ATTR_TMPS_ESALT (workshop_temp_t, workshop_t))
{
}

KERNEL_FQ void m<number>_loop (KERN_ATTR_TMPS_ESALT (workshop_temp_t, workshop_t))
{
}

KERNEL_FQ void m<number>_comp (KERN_ATTR_TMPS_ESALT (workshop_temp_t, workshop_t))
{
}
