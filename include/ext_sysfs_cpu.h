/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_SYSFS_CPU_H
#define _EXT_SYSFS_CPU_H

#include <stdbool.h>

static const char SYSFS_HWMON[] = "/sys/class/hwmon";

static const char SENSOR_CORETEMP[] = "coretemp";
static const char SENSOR_K10TEMP[]  = "k10temp";
static const char SENSOR_K8TEMP[]   = "k8temp";
static const char SENSOR_ACPITZ[]   = "acpitz";

static const char PROC_STAT[] = "/proc/stat";

typedef int HM_ADAPTER_SYSFS_CPU;

typedef void *SYSFS_CPU_LIB;

typedef struct hm_sysfs_cpu_lib
{
  // currently not using libudev, because it can only read values, not set them, so using /sys instead

  SYSFS_CPU_LIB lib;

} hm_sysfs_cpu_lib_t;

typedef struct
{
  unsigned long user;
  unsigned long nice;
  unsigned long system;
  unsigned long idle;
  unsigned long iowait;
  unsigned long irq;
  unsigned long softirq;
  unsigned long steal;
  unsigned long guest;
  unsigned long guest_nice;

} proc_stat_t;

typedef hm_sysfs_cpu_lib_t SYSFS_CPU_PTR;

bool sysfs_cpu_init (void *hashcat_ctx);
void sysfs_cpu_close (void *hashcat_ctx);
char *hm_SYSFS_CPU_get_syspath_hwmon ();
int hm_SYSFS_CPU_get_temperature_current (void *hashcat_ctx, int *val);

bool read_proc_stat (void *hashcat_ctx, proc_stat_t *proc_stat);
int hm_SYSFS_CPU_get_utilization_current (void *hashcat_ctx, int *val);

#endif // _EXT_SYSFS_CPU_H
