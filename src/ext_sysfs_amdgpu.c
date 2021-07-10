/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "event.h"
#include "folder.h"
#include "ext_sysfs_amdgpu.h"

bool sysfs_amdgpu_init (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  SYSFS_AMDGPU_PTR *sysfs_amdgpu = (SYSFS_AMDGPU_PTR *) hwmon_ctx->hm_sysfs_amdgpu;

  memset (sysfs_amdgpu, 0, sizeof (SYSFS_AMDGPU_PTR));

  char *path;

  hc_asprintf (&path, "%s", SYS_BUS_PCI_DEVICES);

  const bool r = hc_path_read (path);

  hcfree (path);

  return r;
}

void sysfs_amdgpu_close (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  SYSFS_AMDGPU_PTR *sysfs_amdgpu = (SYSFS_AMDGPU_PTR *) hwmon_ctx->hm_sysfs_amdgpu;

  if (sysfs_amdgpu)
  {
    hcfree (sysfs_amdgpu);
  }
}

char *hm_SYSFS_AMDGPU_get_syspath_device (void *hashcat_ctx, const int backend_device_idx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_device_idx];

  char *syspath;

  hc_asprintf (&syspath, "%s/0000:%02x:%02x.%01x", SYS_BUS_PCI_DEVICES, device_param->pcie_bus, device_param->pcie_device, device_param->pcie_function);

  return syspath;
}

char *hm_SYSFS_AMDGPU_get_syspath_hwmon (void *hashcat_ctx, const int backend_device_idx)
{
  char *syspath = hm_SYSFS_AMDGPU_get_syspath_device (hashcat_ctx, backend_device_idx);

  if (syspath == NULL)
  {
    event_log_error (hashcat_ctx, "hm_SYSFS_AMDGPU_get_syspath_device() failed.");

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

int hm_SYSFS_AMDGPU_get_fan_speed_current (void *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_AMDGPU_get_syspath_hwmon (hashcat_ctx, backend_device_idx);

  if (syspath == NULL) return -1;

  char *path_cur;
  char *path_max;

  hc_asprintf (&path_cur, "%s/pwm1",     syspath);
  hc_asprintf (&path_max, "%s/pwm1_max", syspath);

  hcfree (syspath);

  HCFILE fp_cur;

  if (hc_fopen (&fp_cur, path_cur, "r") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", path_cur, strerror (errno));

    hcfree (path_cur);
    hcfree (path_max);

    return -1;
  }

  int pwm1_cur = 0;

  if (hc_fscanf (&fp_cur, "%d", &pwm1_cur) != 1)
  {
    hc_fclose (&fp_cur);

    event_log_error (hashcat_ctx, "%s: unexpected data.", path_cur);

    hcfree (path_cur);
    hcfree (path_max);

    return -1;
  }

  hc_fclose (&fp_cur);

  HCFILE fp_max;

  if (hc_fopen (&fp_max, path_max, "r") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", path_max, strerror (errno));

    hcfree (path_cur);
    hcfree (path_max);

    return -1;
  }

  int pwm1_max = 0;

  if (hc_fscanf (&fp_max, "%d", &pwm1_max) != 1)
  {
    hc_fclose (&fp_max);

    event_log_error (hashcat_ctx, "%s: unexpected data.", path_max);

    hcfree (path_cur);
    hcfree (path_max);

    return -1;
  }

  hc_fclose (&fp_max);

  if (pwm1_max == 0)
  {
    event_log_error (hashcat_ctx, "%s: pwm1_max cannot be 0.", path_max);

    hcfree (path_cur);
    hcfree (path_max);

    return -1;
  }

  const float p1 = (float) pwm1_max / 100.0F;

  const float pwm1_percent = (float) pwm1_cur / p1;

  *val = (int) pwm1_percent;

  hcfree (path_cur);
  hcfree (path_max);

  return 0;
}

int hm_SYSFS_AMDGPU_get_temperature_current (void *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_AMDGPU_get_syspath_hwmon (hashcat_ctx, backend_device_idx);

  if (syspath == NULL) return -1;

  char *path;

  hc_asprintf (&path, "%s/temp1_input", syspath);

  hcfree (syspath);

  HCFILE fp;

  if (hc_fopen (&fp, path, "r") == false)
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

int hm_SYSFS_AMDGPU_get_pp_dpm_sclk (void *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_AMDGPU_get_syspath_device (hashcat_ctx, backend_device_idx);

  if (syspath == NULL) return -1;

  char *path;

  hc_asprintf (&path, "%s/pp_dpm_sclk", syspath);

  hcfree (syspath);

  HCFILE fp;

  if (hc_fopen (&fp, path, "r") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  int clockfreq = 0;

  while (!hc_feof (&fp))
  {
    char buf[HCBUFSIZ_TINY] = { 0 };

    char *ptr = hc_fgets (buf, sizeof (buf), &fp);

    if (ptr == NULL) continue;

    size_t len = strlen (ptr);

    if (len < 2) continue;

    if (ptr[len - 2] != '*') continue;

    int profile = 0;

    int rc = sscanf (ptr, "%d: %dMHz", &profile, &clockfreq);

    if (rc == 2) break;
  }

  hc_fclose (&fp);

  *val = clockfreq;

  hcfree (path);

  return 0;
}

int hm_SYSFS_AMDGPU_get_pp_dpm_mclk (void *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_AMDGPU_get_syspath_device (hashcat_ctx, backend_device_idx);

  if (syspath == NULL) return -1;

  char *path;

  hc_asprintf (&path, "%s/pp_dpm_mclk", syspath);

  hcfree (syspath);

  HCFILE fp;

  if (hc_fopen (&fp, path, "r") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  int clockfreq = 0;

  while (!hc_feof (&fp))
  {
    char buf[HCBUFSIZ_TINY];

    char *ptr = hc_fgets (buf, sizeof (buf), &fp);

    if (ptr == NULL) continue;

    size_t len = strlen (ptr);

    if (len < 2) continue;

    if (ptr[len - 2] != '*') continue;

    int profile = 0;

    int rc = sscanf (ptr, "%d: %dMHz", &profile, &clockfreq);

    if (rc == 2) break;
  }

  hc_fclose (&fp);

  *val = clockfreq;

  hcfree (path);

  return 0;
}

int hm_SYSFS_AMDGPU_get_pp_dpm_pcie (void *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_AMDGPU_get_syspath_device (hashcat_ctx, backend_device_idx);

  if (syspath == NULL) return -1;

  char *path;

  hc_asprintf (&path, "%s/current_link_width", syspath);

  hcfree (syspath);

  HCFILE fp;

  if (hc_fopen (&fp, path, "r") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  int lanes = 0;

  while (!hc_feof (&fp))
  {
    char buf[HCBUFSIZ_TINY];

    char *ptr = hc_fgets (buf, sizeof (buf), &fp);

    if (ptr == NULL) continue;

    size_t len = strlen (ptr);

    if (len < 2) continue;

    int rc = sscanf (ptr, "%d", &lanes);

    if (rc == 1) break;
  }

  hc_fclose (&fp);

  *val = lanes;

  hcfree (path);

  return 0;
}

int hm_SYSFS_AMDGPU_get_gpu_busy_percent (void *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_AMDGPU_get_syspath_device (hashcat_ctx, backend_device_idx);

  if (syspath == NULL) return -1;

  char *path;

  hc_asprintf (&path, "%s/gpu_busy_percent", syspath);

  hcfree (syspath);

  HCFILE fp;

  if (hc_fopen (&fp, path, "r") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  int util = 0;

  while (!hc_feof (&fp))
  {
    char buf[HCBUFSIZ_TINY];

    char *ptr = hc_fgets (buf, sizeof (buf), &fp);

    if (ptr == NULL) continue;

    size_t len = strlen (ptr);

    if (len < 1) continue;

    int rc = sscanf (ptr, "%d", &util);

    if (rc == 1) break;
  }

  hc_fclose (&fp);

  *val = util;

  hcfree (path);

  return 0;
}
