/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define XSTR(x) #x
#define STR(x) XSTR(x)

#ifdef KERNEL_STATIC
#include STR(INCLUDE_PATH/inc_vendor.h)
#include STR(INCLUDE_PATH/inc_types.h)
#include STR(INCLUDE_PATH/inc_platform.cl)
#include STR(INCLUDE_PATH/inc_common.cl)
#endif

KERNEL_FQ void m02000_mxx (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m02000_sxx (KERN_ATTR_RULES ())
{
}
