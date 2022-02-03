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

KERNEL_FQ void m02000_m04 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m02000_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m02000_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m02000_s04 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m02000_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m02000_s16 (KERN_ATTR_RULES ())
{
}
