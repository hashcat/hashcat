/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_SYSFS_H
#define _EXT_SYSFS_H

static const char SYS_BUS_PCI_DEVICES[] = "/sys/bus/pci/devices";

typedef int HM_ADAPTER_SYSFS;

typedef void *SYSFS_LIB;

typedef struct hm_sysfs_lib
{
  // currently not using libudev, because it can only read values, not set them, so using /sys instead

  SYSFS_LIB lib;

} hm_sysfs_lib_t;

typedef hm_sysfs_lib_t SYSFS_PTR;

#endif // _EXT_SYSFS_H
