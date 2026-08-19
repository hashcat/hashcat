/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "filehandling.h"
#include "path.h"
#include "event.h"
#include "folder.h"
#include "ext_sysfs_intelgpu.h"

bool sysfs_intelgpu_init (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  SYSFS_INTELGPU_PTR *sysfs_intelgpu = (SYSFS_INTELGPU_PTR *) hwmon_ctx->hm_sysfs_intelgpu;

  memset (sysfs_intelgpu, 0, sizeof (SYSFS_INTELGPU_PTR));

  char *path;

  hc_asprintf (&path, "%s", SYS_BUS_PCI_DEVICES);

  const bool r = hc_path_read (path);

  hcfree (path);

  return r;
}

void sysfs_intelgpu_close (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  SYSFS_INTELGPU_PTR *sysfs_intelgpu = (SYSFS_INTELGPU_PTR *) hwmon_ctx->hm_sysfs_intelgpu;

  if (sysfs_intelgpu)
  {
    hcfree (sysfs_intelgpu);
  }
}

char *hm_SYSFS_INTELGPU_get_syspath_device (void *hashcat_ctx, const int backend_device_idx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_device_idx];

  char *syspath;

  hc_asprintf (&syspath, "%s/0000:%02x:%02x.%01x", SYS_BUS_PCI_DEVICES, device_param->pcie_bus, device_param->pcie_device, device_param->pcie_function);

  return syspath;
}

char *hm_SYSFS_INTELGPU_get_syspath_hwmon (void *hashcat_ctx, const int backend_device_idx)
{
  char *syspath = hm_SYSFS_INTELGPU_get_syspath_device (hashcat_ctx, backend_device_idx);

  if (syspath == NULL)
  {
    event_log_error (hashcat_ctx, "hm_SYSFS_INTELGPU_get_syspath_device() failed.");

    return NULL;
  }

  char *hwmon = (char *) hcmalloc (HCBUFSIZ_TINY);

  snprintf (hwmon, HCBUFSIZ_TINY, "%s/hwmon", syspath);

  char *hwmonN = first_file_in_directory (hwmon);

  if (hwmonN == NULL)
  {
    event_log_error (hashcat_ctx, "First_file_in_directory() failed.");

    hcfree (syspath);

    hcfree (hwmon);
    hcfree (hwmonN);

    return NULL;
  }

  snprintf (hwmon, HCBUFSIZ_TINY, "%s/hwmon/%s", syspath, hwmonN);

  hcfree (syspath);

  hcfree (hwmonN);

  return hwmon;
}

int hm_SYSFS_INTELGPU_get_fan_speed_current (void *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_INTELGPU_get_syspath_hwmon (hashcat_ctx, backend_device_idx);

  if (syspath == NULL) return -1;

  char *path_cur;

  hc_asprintf (&path_cur, "%s/fan1_input", syspath);

  hcfree (syspath);

  HCFILE fp_cur;

  if (hc_fopen_raw (&fp_cur, path_cur, "r") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", path_cur, strerror (errno));

    hcfree (path_cur);

    return -1;
  }

  int pwm1_cur = 0;

  if (hc_fscanf (&fp_cur, "%d", &pwm1_cur) != 1)
  {
    hc_fclose (&fp_cur);

    event_log_error (hashcat_ctx, "%s: unexpected data.", path_cur);

    hcfree (path_cur);

    return -1;
  }

  hc_fclose (&fp_cur);

  // 10 is probably wrong here, but the interface lacks a way to query a reference value
  // so we must assume the value reflects an absolute value
  const float pwm1_percent = (float) pwm1_cur / 10;

  *val = (int) pwm1_percent;

  hcfree (path_cur);

  return 0;
}

int hm_SYSFS_INTELGPU_get_temperature_current (void *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_INTELGPU_get_syspath_hwmon (hashcat_ctx, backend_device_idx);

  if (syspath == NULL) return -1;

  char *path;

  hc_asprintf (&path, "%s/temp1_input", syspath);

  hcfree (syspath);

  HCFILE fp;

  if (hc_fopen_raw (&fp, path, "r") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  int temperature = 0;

  if (hc_fscanf (&fp, "%d", &temperature) != 1)
  {
    hc_fclose (&fp);

    event_log_error (hashcat_ctx, "%s: unexpected data.", path);

    hcfree (path);

    return -1;
  }

  hc_fclose (&fp);

  *val = temperature / 1000;

  hcfree (path);

  return 0;
}
