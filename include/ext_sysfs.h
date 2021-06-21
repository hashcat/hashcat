/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_SYSFS_H
#define _EXT_SYSFS_H

#include <stdbool.h>

static const char SYS_BUS_PCI_DEVICES[] = "/sys/bus/pci/devices";

typedef int HM_ADAPTER_SYSFS;

typedef void *SYSFS_LIB;

typedef struct hm_sysfs_lib
{
  // currently not using libudev, because it can only read values, not set them, so using /sys instead

  SYSFS_LIB lib;

} hm_sysfs_lib_t;

typedef hm_sysfs_lib_t SYSFS_PTR;

bool sysfs_init (void *hashcat_ctx);
void sysfs_close (void *hashcat_ctx);
char *hm_SYSFS_get_syspath_device (void *hashcat_ctx, const int backend_device_idx);
char *hm_SYSFS_get_syspath_hwmon (void *hashcat_ctx, const int backend_device_idx);
int hm_SYSFS_get_fan_speed_current (void *hashcat_ctx, const int backend_device_idx, int *val);
int hm_SYSFS_get_temperature_current (void *hashcat_ctx, const int backend_device_idx, int *val);
int hm_SYSFS_get_pp_dpm_sclk (void *hashcat_ctx, const int backend_device_idx, int *val);
int hm_SYSFS_get_pp_dpm_mclk (void *hashcat_ctx, const int backend_device_idx, int *val);
int hm_SYSFS_get_pp_dpm_pcie (void *hashcat_ctx, const int backend_device_idx, int *val);
int hm_SYSFS_get_gpu_busy_percent (void *hashcat_ctx, const int backend_device_idx, int *val);

#endif // _EXT_SYSFS_H
