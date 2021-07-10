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
#include "ext_sysfs_cpu.h"

bool sysfs_cpu_init (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  SYSFS_CPU_PTR *sysfs_cpu = (SYSFS_CPU_PTR *) hwmon_ctx->hm_sysfs_cpu;

  memset (sysfs_cpu, 0, sizeof (SYSFS_CPU_PTR));

  char *path;

  hc_asprintf (&path, "%s/hwmon0", SYSFS_HWMON);

  const bool r = hc_path_read (path);

  hcfree (path);

  return r;
}

void sysfs_cpu_close (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  SYSFS_CPU_PTR *sysfs_cpu = (SYSFS_CPU_PTR *) hwmon_ctx->hm_sysfs_cpu;

  if (sysfs_cpu)
  {
    hcfree (sysfs_cpu);
  }
}

char *hm_SYSFS_CPU_get_syspath_hwmon ()
{
  char *found[4];

  found[0] = NULL;
  found[1] = NULL;
  found[2] = NULL;
  found[3] = NULL;

  // 16 ok?

  for (int i = 0; i < 16; i++)
  {
    char *path = NULL;

    hc_asprintf (&path, "%s/hwmon%d/name", SYSFS_HWMON, i);

    HCFILE fp;

    if (hc_fopen_raw (&fp, path, "rb") == false) continue;

    char buf[16];

    const size_t line_len = fgetl (&fp, buf, sizeof (buf));

    if (line_len)
    {
      if (strcmp (buf, SENSOR_CORETEMP) == 0) hc_asprintf (&found[0], "%s/hwmon%d", SYSFS_HWMON, i);
      if (strcmp (buf, SENSOR_K10TEMP)  == 0) hc_asprintf (&found[1], "%s/hwmon%d", SYSFS_HWMON, i);
      if (strcmp (buf, SENSOR_K8TEMP)   == 0) hc_asprintf (&found[2], "%s/hwmon%d", SYSFS_HWMON, i);
      if (strcmp (buf, SENSOR_ACPITZ)   == 0) hc_asprintf (&found[3], "%s/hwmon%d", SYSFS_HWMON, i);
    }

    hc_fclose (&fp);

    hcfree (path);
  }

  if (found[0]) return found[0];
  if (found[1]) return found[1];
  if (found[2]) return found[2];
  if (found[3]) return found[3];

  return NULL;
}

int hm_SYSFS_CPU_get_temperature_current (void *hashcat_ctx, int *val)
{
  char *syspath = hm_SYSFS_CPU_get_syspath_hwmon ();

  if (syspath == NULL) return -1;

  char *path = NULL;

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
