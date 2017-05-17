/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "dynloader.h"
#include "shared.h"
#include "folder.h"
#include "hwmon.h"

// sysfs functions

static bool sysfs_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  SYSFS_PTR *sysfs = hwmon_ctx->hm_sysfs;

  memset (sysfs, 0, sizeof (SYSFS_PTR));

  char *path = hcmalloc (HCBUFSIZ_TINY);

  snprintf (path, HCBUFSIZ_TINY - 1, "%s", SYS_BUS_PCI_DEVICES);

  const bool r = hc_path_read (path);

  hcfree (path);

  return r;
}

static void sysfs_close (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  SYSFS_PTR *sysfs = hwmon_ctx->hm_sysfs;

  if (sysfs)
  {
    hcfree (sysfs);
  }

  return;
}

static char *hm_SYSFS_get_syspath_device (hashcat_ctx_t *hashcat_ctx, const int device_id)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

  char *syspath;

  hc_asprintf (&syspath, "%s/0000:%02x:%02x.%01x", SYS_BUS_PCI_DEVICES, device_param->pcie_bus, device_param->pcie_device, device_param->pcie_function);

  return syspath;
}

static char *hm_SYSFS_get_syspath_hwmon (hashcat_ctx_t *hashcat_ctx, const int device_id)
{
  char *syspath = hm_SYSFS_get_syspath_device (hashcat_ctx, device_id);

  if (syspath == NULL)
  {
    event_log_error (hashcat_ctx, "hm_SYSFS_get_syspath_device() failed.");

    return NULL;
  }

  char *hwmon = hcmalloc (HCBUFSIZ_TINY);

  snprintf (hwmon, HCBUFSIZ_TINY - 1, "%s/hwmon", syspath);

  char *hwmonN = first_file_in_directory (hwmon);

  if (hwmonN == NULL)
  {
    event_log_error (hashcat_ctx, "First_file_in_directory() failed.");

    hcfree (syspath);

    hcfree (hwmon);
    hcfree (hwmonN);

    return NULL;
  }

  snprintf (hwmon, HCBUFSIZ_TINY - 1, "%s/hwmon/%s", syspath, hwmonN);

  hcfree (syspath);

  hcfree (hwmonN);

  return hwmon;
}

static int hm_SYSFS_get_fan_speed_current (hashcat_ctx_t *hashcat_ctx, const int device_id, int *val)
{
  char *syspath = hm_SYSFS_get_syspath_hwmon (hashcat_ctx, device_id);

  if (syspath == NULL) return -1;

  char *path_cur = hcmalloc (HCBUFSIZ_TINY);
  char *path_max = hcmalloc (HCBUFSIZ_TINY);

  snprintf (path_cur, HCBUFSIZ_TINY - 1, "%s/pwm1",     syspath);
  snprintf (path_max, HCBUFSIZ_TINY - 1, "%s/pwm1_max", syspath);

  hcfree (syspath);

  FILE *fd_cur = fopen (path_cur, "r");

  if (fd_cur == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", path_cur, strerror (errno));

    hcfree (path_cur);
    hcfree (path_max);

    return -1;
  }

  int pwm1_cur = 0;

  if (fscanf (fd_cur, "%d", &pwm1_cur) != 1)
  {
    fclose (fd_cur);

    event_log_error (hashcat_ctx, "%s: unexpected data.", path_cur);

    hcfree (path_cur);
    hcfree (path_max);

    return -1;
  }

  fclose (fd_cur);

  FILE *fd_max = fopen (path_max, "r");

  if (fd_max == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", path_max, strerror (errno));

    hcfree (path_cur);
    hcfree (path_max);

    return -1;
  }

  int pwm1_max = 0;

  if (fscanf (fd_max, "%d", &pwm1_max) != 1)
  {
    fclose (fd_max);

    event_log_error (hashcat_ctx, "%s: unexpected data.", path_max);

    hcfree (path_cur);
    hcfree (path_max);

    return -1;
  }

  fclose (fd_max);

  if (pwm1_max == 0)
  {
    event_log_error (hashcat_ctx, "%s: pwm1_max cannot be 0.", path_max);

    hcfree (path_cur);
    hcfree (path_max);

    return -1;
  }

  const float p1 = (float) pwm1_max / 100.0f;

  const float pwm1_percent = (float) pwm1_cur / p1;

  *val = (int) pwm1_percent;

  hcfree (path_cur);
  hcfree (path_max);

  return 0;
}

static int hm_SYSFS_set_fan_control (hashcat_ctx_t *hashcat_ctx, const int device_id, int val)
{
  char *syspath = hm_SYSFS_get_syspath_hwmon (hashcat_ctx, device_id);

  if (syspath == NULL) return -1;

  char *path = hcmalloc (HCBUFSIZ_TINY);

  snprintf (path, HCBUFSIZ_TINY - 1, "%s/pwm1_enable", syspath);

  hcfree (syspath);

  FILE *fd = fopen (path, "w");

  if (fd == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  fprintf (fd, "%d", val);

  fclose (fd);

  hcfree (path);

  return 0;
}

static int hm_SYSFS_set_fan_speed_target (hashcat_ctx_t *hashcat_ctx, const int device_id, int val)
{
  char *syspath = hm_SYSFS_get_syspath_hwmon (hashcat_ctx, device_id);

  if (syspath == NULL) return -1;

  char *path     = hcmalloc (HCBUFSIZ_TINY);
  char *path_max = hcmalloc (HCBUFSIZ_TINY);

  snprintf (path,     HCBUFSIZ_TINY - 1, "%s/pwm1",     syspath);
  snprintf (path_max, HCBUFSIZ_TINY - 1, "%s/pwm1_max", syspath);

  hcfree (syspath);

  FILE *fd_max = fopen (path_max, "r");

  if (fd_max == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", path_max, strerror (errno));

    hcfree (path);
    hcfree (path_max);

    return -1;
  }

  int pwm1_max = 0;

  if (fscanf (fd_max, "%d", &pwm1_max) != 1)
  {
    fclose (fd_max);

    event_log_error (hashcat_ctx, "%s: unexpected data.", path_max);

    hcfree (path);
    hcfree (path_max);

    return -1;
  }

  fclose (fd_max);

  if (pwm1_max == 0)
  {
    event_log_error (hashcat_ctx, "%s: pwm1_max cannot be 0.", path_max);

    hcfree (path);
    hcfree (path_max);

    return -1;
  }

  const float p1 = (float) pwm1_max / 100.0f;

  FILE *fd = fopen (path, "w");

  if (fd == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);
    hcfree (path_max);

    return -1;
  }

  fprintf (fd, "%d", (int) ((float) val * p1));

  fclose (fd);

  hcfree (path);
  hcfree (path_max);

  return 0;
}

static int hm_SYSFS_get_temperature_current (hashcat_ctx_t *hashcat_ctx, const int device_id, int *val)
{
  char *syspath = hm_SYSFS_get_syspath_hwmon (hashcat_ctx, device_id);

  if (syspath == NULL) return -1;

  char *path = hcmalloc (HCBUFSIZ_TINY);

  snprintf (path, HCBUFSIZ_TINY - 1, "%s/temp1_input", syspath);

  hcfree (syspath);

  FILE *fd = fopen (path, "r");

  if (fd == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  int temperature = 0;

  if (fscanf (fd, "%d", &temperature) != 1)
  {
    fclose (fd);

    event_log_error (hashcat_ctx, "%s: unexpected data.", path);

    hcfree (path);

    return -1;
  }

  fclose (fd);

  *val = temperature / 1000;

  hcfree (path);

  return 0;
}

static int hm_SYSFS_get_pp_dpm_sclk (hashcat_ctx_t *hashcat_ctx, const int device_id, int *val)
{
  char *syspath = hm_SYSFS_get_syspath_device (hashcat_ctx, device_id);

  if (syspath == NULL) return -1;

  char *path = hcmalloc (HCBUFSIZ_TINY);

  snprintf (path, HCBUFSIZ_TINY - 1, "%s/pp_dpm_sclk", syspath);

  hcfree (syspath);

  FILE *fd = fopen (path, "r");

  if (fd == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  int clockfreq = 0;

  while (!feof (fd))
  {
    char buf[HCBUFSIZ_TINY];

    char *ptr = fgets (buf, sizeof (buf), fd);

    if (ptr == NULL) continue;

    size_t len = strlen (ptr);

    if (len < 2) continue;

    if (ptr[len - 2] != '*') continue;

    int profile = 0;

    int rc = sscanf (ptr, "%d: %dMHz", &profile, &clockfreq);

    if (rc == 2) break;
  }

  fclose (fd);

  *val = clockfreq;

  hcfree (path);

  return 0;
}

static int hm_SYSFS_get_pp_dpm_mclk (hashcat_ctx_t *hashcat_ctx, const int device_id, int *val)
{
  char *syspath = hm_SYSFS_get_syspath_device (hashcat_ctx, device_id);

  if (syspath == NULL) return -1;

  char *path = hcmalloc (HCBUFSIZ_TINY);

  snprintf (path, HCBUFSIZ_TINY - 1, "%s/pp_dpm_mclk", syspath);

  hcfree (syspath);

  FILE *fd = fopen (path, "r");

  if (fd == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  int clockfreq = 0;

  while (!feof (fd))
  {
    char buf[HCBUFSIZ_TINY];

    char *ptr = fgets (buf, sizeof (buf), fd);

    if (ptr == NULL) continue;

    size_t len = strlen (ptr);

    if (len < 2) continue;

    if (ptr[len - 2] != '*') continue;

    int profile = 0;

    int rc = sscanf (ptr, "%d: %dMHz", &profile, &clockfreq);

    if (rc == 2) break;
  }

  fclose (fd);

  *val = clockfreq;

  hcfree (path);

  return 0;
}

static int hm_SYSFS_get_pp_dpm_pcie (hashcat_ctx_t *hashcat_ctx, const int device_id, int *val)
{
  char *syspath = hm_SYSFS_get_syspath_device (hashcat_ctx, device_id);

  if (syspath == NULL) return -1;

  char *path = hcmalloc (HCBUFSIZ_TINY);

  snprintf (path, HCBUFSIZ_TINY - 1, "%s/pp_dpm_pcie", syspath);

  hcfree (syspath);

  FILE *fd = fopen (path, "r");

  if (fd == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  int lanes = 0;

  while (!feof (fd))
  {
    char buf[HCBUFSIZ_TINY];

    char *ptr = fgets (buf, sizeof (buf), fd);

    if (ptr == NULL) continue;

    size_t len = strlen (ptr);

    if (len < 2) continue;

    if (ptr[len - 2] != '*') continue;

    int   profile = 0;
    float speed = 0;

    int rc = sscanf (ptr, "%d: %fGB, x%d *", &profile, &speed, &lanes);

    if (rc == 3) break;
  }

  fclose (fd);

  *val = lanes;

  hcfree (path);

  return 0;
}

static int hm_SYSFS_set_power_dpm_force_performance_level (hashcat_ctx_t *hashcat_ctx, const int device_id, const char *val)
{
  char *syspath = hm_SYSFS_get_syspath_device (hashcat_ctx, device_id);

  if (syspath == NULL) return -1;

  char *path = hcmalloc (HCBUFSIZ_TINY);

  snprintf (path, HCBUFSIZ_TINY - 1, "%s/power_dpm_force_performance_level", syspath);

  hcfree (syspath);

  FILE *fd = fopen (path, "w");

  if (fd == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", path, strerror (errno));

    hcfree (path);

    return -1;
  }

  fprintf (fd, "%s", val);

  fclose (fd);

  hcfree (path);

  return 0;
}

// nvml functions

static int nvml_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  memset (nvml, 0, sizeof (NVML_PTR));

  #if defined (_WIN)

  nvml->lib = hc_dlopen ("nvml.dll");

  if (!nvml->lib)
  {
    DWORD BufferSize = 1024;

    DWORD Type = REG_SZ;

    char *Buffer = (char *) hcmalloc (BufferSize + 1);

    HKEY hKey = 0;

    if (RegOpenKeyExA (HKEY_LOCAL_MACHINE, "SOFTWARE\\NVIDIA Corporation\\Global\\NVSMI", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
      if (RegQueryValueExA (hKey, "NVSMIPATH", NULL, &Type, (LPBYTE)Buffer, &BufferSize) == ERROR_SUCCESS)
      {
        Buffer[BufferSize] = 0;
      }
      else
      {
        //if (user_options->quiet == false)
        //  event_log_error (hashcat_ctx, "NVML library load failed. Proceeding without NVML HWMon enabled.");

        return -1;
      }

      RegCloseKey (hKey);
    }
    else
    {
      //if (user_options->quiet == false)
      //  event_log_error (hashcat_ctx, "NVML library load failed. Proceeding without NVML HWMon enabled.");

      return -1;
    }

    strcat (Buffer, "\\nvml.dll");

    nvml->lib = hc_dlopen (Buffer);

    hcfree (Buffer);
  }

  #elif defined (__CYGWIN__)

  nvml->lib = hc_dlopen("nvml.dll", RTLD_NOW);

  if (!nvml->lib)
  {
    FILE *nvml_lib = fopen ("/proc/registry/HKEY_LOCAL_MACHINE/SOFTWARE/NVIDIA Corporation/Global/NVSMI/NVSMIPATH", "rb");

    if (nvml_lib == NULL)
    {
      //if (user_options->quiet == false)
      //  event_log_error (hashcat_ctx, "NVML library load failed: %m. Proceeding without NVML HWMon enabled.");

      return -1;
    }

    char *nvml_winpath, *nvml_cygpath;

    nvml_winpath = (char *) hcmalloc (100);

    fread (nvml_winpath, 100, 1, nvml_lib);

    fclose (nvml_lib);

    ssize_t size = cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_PROC_CYGDRIVE, nvml_winpath, NULL, 0);

    if (size > 0)
    {
      nvml_cygpath = (char *) hcmalloc (size + 9);

      cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_PROC_CYGDRIVE, nvml_winpath, nvml_cygpath, size);
    }
    else
    {
      //if (user_options->quiet == false)
      //  event_log_error (hashcat_ctx, "Could not find NVML on this system. Proceeding without NVML HWMon enabled.");

      return -1;
    }

    strcat (nvml_cygpath, "/nvml.dll");

    nvml->lib = hc_dlopen (nvml_cygpath, RTLD_NOW);
  }

  #elif defined (_POSIX)

  nvml->lib = hc_dlopen ("libnvidia-ml.so", RTLD_NOW);

  if (!nvml->lib)
  {
    nvml->lib = hc_dlopen ("libnvidia-ml.so.1", RTLD_NOW);
  }

  #endif

  if (!nvml->lib)
  {
    //if (user_options->quiet == false)
    //  event_log_error (hashcat_ctx, "NVML library load failed. Proceeding without NVML HWMon enabled.");

    return -1;
  }

  HC_LOAD_FUNC(nvml, nvmlErrorString, NVML_ERROR_STRING, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlInit, NVML_INIT, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlShutdown, NVML_SHUTDOWN, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetCount, NVML_DEVICE_GET_COUNT, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetName, NVML_DEVICE_GET_NAME, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetHandleByIndex, NVML_DEVICE_GET_HANDLE_BY_INDEX, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetTemperature, NVML_DEVICE_GET_TEMPERATURE, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetFanSpeed, NVML_DEVICE_GET_FAN_SPEED, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetPowerUsage, NVML_DEVICE_GET_POWER_USAGE, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetUtilizationRates, NVML_DEVICE_GET_UTILIZATION_RATES, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetClockInfo, NVML_DEVICE_GET_CLOCKINFO, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetTemperatureThreshold, NVML_DEVICE_GET_THRESHOLD, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetCurrPcieLinkGeneration, NVML_DEVICE_GET_CURRPCIELINKGENERATION, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetCurrPcieLinkWidth, NVML_DEVICE_GET_CURRPCIELINKWIDTH, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetCurrentClocksThrottleReasons, NVML_DEVICE_GET_CURRENTCLOCKSTHROTTLEREASONS, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetSupportedClocksThrottleReasons, NVML_DEVICE_GET_SUPPORTEDCLOCKSTHROTTLEREASONS, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceSetComputeMode, NVML_DEVICE_SET_COMPUTEMODE, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceSetGpuOperationMode, NVML_DEVICE_SET_OPERATIONMODE, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetPowerManagementLimitConstraints, NVML_DEVICE_GET_POWERMANAGEMENTLIMITCONSTRAINTS, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceSetPowerManagementLimit, NVML_DEVICE_SET_POWERMANAGEMENTLIMIT, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetPowerManagementLimit, NVML_DEVICE_GET_POWERMANAGEMENTLIMIT, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetPciInfo, NVML_DEVICE_GET_PCIINFO, NVML, 0)

  return 0;
}

static void nvml_close (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  if (nvml)
  {
    if (nvml->lib)
      hc_dlclose (nvml->lib);

    hcfree (nvml);
  }
}

static const char *hm_NVML_nvmlErrorString (NVML_PTR *nvml, const nvmlReturn_t nvml_rc)
{
  return nvml->nvmlErrorString (nvml_rc);
}

static int hm_NVML_nvmlInit (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlInit ();

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlInit(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NVML_nvmlShutdown (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlShutdown ();

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlShutdown(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NVML_nvmlDeviceGetCount (hashcat_ctx_t *hashcat_ctx, unsigned int *deviceCount)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetCount (deviceCount);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetCount(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NVML_nvmlDeviceGetHandleByIndex (hashcat_ctx_t *hashcat_ctx, unsigned int device_index, nvmlDevice_t *device)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetHandleByIndex (device_index, device);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetHandleByIndex(): %s", string);

    return -1;
  }

  return 0;
}

/*
static int hm_NVML_nvmlDeviceGetName (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, char *name, unsigned int length)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetName (device, name, length);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetName(): %s", string);

    return -1;
  }

  return 0;
}
*/

static int hm_NVML_nvmlDeviceGetTemperature (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetTemperature (device, sensorType, temp);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetTemperature(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NVML_nvmlDeviceGetFanSpeed (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *speed)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetFanSpeed (device, speed);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetFanSpeed(): %s", string);

    return -1;
  }

  return 0;
}

/*
static int hm_NVML_nvmlDeviceGetPowerUsage (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *power)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPowerUsage (device, power);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetPowerUsage(): %s", string);

    return -1;
  }

  return 0;
}
*/

static int hm_NVML_nvmlDeviceGetUtilizationRates (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlUtilization_t *utilization)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetUtilizationRates (device, utilization);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetUtilizationRates(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlClockType_t type, unsigned int *clockfreq)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetClockInfo (device, type, clockfreq);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetClockInfo(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlTemperatureThresholds_t thresholdType, unsigned int *temp)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetTemperatureThreshold (device, thresholdType, temp);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetTemperatureThreshold(): %s", string);

    return -1;
  }

  return 0;
}

/*
static int hm_NVML_nvmlDeviceGetCurrPcieLinkGeneration (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *currLinkGen)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetCurrPcieLinkGeneration (device, currLinkGen);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetCurrPcieLinkGeneration(): %s", string);

    return -1;
  }

  return 0;
}
*/

static int hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *currLinkWidth)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetCurrPcieLinkWidth (device, currLinkWidth);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetCurrPcieLinkWidth(): %s", string);

    return -1;
  }

  return 0;
}

/*
static int hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned long long *clocksThrottleReasons)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetCurrentClocksThrottleReasons (device, clocksThrottleReasons);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetCurrentClocksThrottleReasons(): %s", string);

    return -1;
  }

  return 0;
}
*/

/*
static int hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned long long *supportedClocksThrottleReasons)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetSupportedClocksThrottleReasons (device, supportedClocksThrottleReasons);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetSupportedClocksThrottleReasons(): %s", string);

    return -1;
  }

  return 0;
}
*/

/*
static int hm_NVML_nvmlDeviceSetComputeMode (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlComputeMode_t mode)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceSetComputeMode (device, mode);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceSetComputeMode(): %s", string);

    return -1;
  }

  return 0;
}
*/

/*
static int hm_NVML_nvmlDeviceSetGpuOperationMode (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlGpuOperationMode_t mode)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceSetGpuOperationMode (device, mode);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceSetGpuOperationMode(): %s", string);

    return -1;
  }

  return 0;
}
*/

static int hm_NVML_nvmlDeviceGetPowerManagementLimitConstraints (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *minLimit, unsigned int *maxLimit)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPowerManagementLimitConstraints (device, minLimit, maxLimit);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetPowerManagementLimitConstraints(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NVML_nvmlDeviceSetPowerManagementLimit (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int limit)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceSetPowerManagementLimit (device, limit);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceSetPowerManagementLimit(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NVML_nvmlDeviceGetPowerManagementLimit (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *limit)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPowerManagementLimit (device, limit);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetPowerManagementLimit(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NVML_nvmlDeviceGetPciInfo (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlPciInfo_t *pci)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPciInfo (device, pci);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "nvmlDeviceGetPciInfo(): %s", string);

    return -1;
  }

  return 0;
}

// nvapi functions

static int nvapi_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  memset (nvapi, 0, sizeof (NVAPI_PTR));

  #if defined (_WIN)

  #if defined (_WIN64)
  nvapi->lib = hc_dlopen ("nvapi64.dll");
  #else
  nvapi->lib = hc_dlopen ("nvapi.dll");
  #endif

  #else

  #if defined (__CYGWIN__)

  #if defined (__x86_x64__)
  nvapi->lib = hc_dlopen ("nvapi64.dll", RTLD_NOW);
  #else
  nvapi->lib = hc_dlopen ("nvapi.dll", RTLD_NOW);
  #endif

  #else
  nvapi->lib = hc_dlopen ("nvapi.so", RTLD_NOW); // uhm yes, but .. yeah
  #endif

  #endif

  if (!nvapi->lib)
  {
    //if (user_options->quiet == false)
    //  event_log_error (hashcat_ctx, "Load of NVAPI library failed. Proceeding without NVAPI HWMon enabled.");

    return -1;
  }

  HC_LOAD_FUNC(nvapi, nvapi_QueryInterface,             NVAPI_QUERYINTERFACE,             NVAPI,                0)
  HC_LOAD_ADDR(nvapi, NvAPI_Initialize,                 NVAPI_INITIALIZE,                 nvapi_QueryInterface, 0x0150E828u, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_Unload,                     NVAPI_UNLOAD,                     nvapi_QueryInterface, 0xD22BDD7Eu, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GetErrorMessage,            NVAPI_GETERRORMESSAGE,            nvapi_QueryInterface, 0x6C2D048Cu, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_EnumPhysicalGPUs,           NVAPI_ENUMPHYSICALGPUS,           nvapi_QueryInterface, 0xE5AC921Fu, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetPerfPoliciesInfo,    NVAPI_GPU_GETPERFPOLICIESINFO,    nvapi_QueryInterface, 0x409D9841u, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetPerfPoliciesStatus,  NVAPI_GPU_GETPERFPOLICIESSTATUS,  nvapi_QueryInterface, 0x3D358A0Cu, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_SetCoolerLevels,        NVAPI_GPU_SETCOOLERLEVELS,        nvapi_QueryInterface, 0x891FA0AEu, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetBusId,               NVAPI_GPU_GETBUSID,               nvapi_QueryInterface, 0x1BE0B8E5u, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetBusSlotId,           NVAPI_GPU_GETBUSSLOTID,           nvapi_QueryInterface, 0x2A0A350Fu, NVAPI, 0)

  return 0;
}

static void nvapi_close (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  if (nvapi)
  {
    if (nvapi->lib)
      hc_dlclose (nvapi->lib);

    hcfree (nvapi);
  }
}

static void hm_NvAPI_GetErrorMessage (NVAPI_PTR *nvapi, const NvAPI_Status NvAPI_rc, NvAPI_ShortString string)
{
  nvapi->NvAPI_GetErrorMessage (NvAPI_rc, string);
}

static int hm_NvAPI_Initialize (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_Initialize ();

  if (NvAPI_rc == NVAPI_LIBRARY_NOT_FOUND) return -1;

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_Initialize(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NvAPI_Unload (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_Unload ();

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_Unload(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NvAPI_EnumPhysicalGPUs (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle nvGPUHandle[NVAPI_MAX_PHYSICAL_GPUS], NvU32 *pGpuCount)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_EnumPhysicalGPUs (nvGPUHandle, pGpuCount);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_EnumPhysicalGPUs(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NvAPI_GPU_GetPerfPoliciesInfo (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_POLICIES_INFO_PARAMS_V1 *perfPolicies_info)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetPerfPoliciesInfo (hPhysicalGpu, perfPolicies_info);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_GPU_GetPerfPoliciesInfo(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NvAPI_GPU_GetPerfPoliciesStatus (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1 *perfPolicies_status)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetPerfPoliciesStatus (hPhysicalGpu, perfPolicies_status);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_GPU_GetPerfPoliciesStatus(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NvAPI_GPU_SetCoolerLevels (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NvU32 coolerIndex, NV_GPU_COOLER_LEVELS *pCoolerLevels)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_SetCoolerLevels (hPhysicalGpu, coolerIndex, pCoolerLevels);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_GPU_SetCoolerLevels(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NvAPI_GPU_GetBusId (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pBusId)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetBusId (hPhysicalGpu, pBusId);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_GPU_GetBusId(): %s", string);

    return -1;
  }

  return 0;
}

static int hm_NvAPI_GPU_GetBusSlotId (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pBusSlotId)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetBusSlotId (hPhysicalGpu, pBusSlotId);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_GPU_GetBusSlotId(): %s", string);

    return -1;
  }

  return 0;
}

/*
#if defined (__MINGW64__)

void __security_check_cookie (uintptr_t _StackCookie);

void __security_check_cookie (uintptr_t _StackCookie)
{
  (void) _StackCookie;
}

void __GSHandlerCheck ();

void __GSHandlerCheck ()
{
}

#endif
*/

// xnvctrl functions

static int xnvctrl_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  memset (xnvctrl, 0, sizeof (XNVCTRL_PTR));

  #if defined (_WIN)

  // unsupport platform?
  return -1;

  #else

  xnvctrl->lib_x11 = dlopen ("libX11.so", RTLD_LAZY);

  if (xnvctrl->lib_x11 == NULL)
  {
    //event_log_error (hashcat_ctx, "Failed to load the X11 library: %s", dlerror());
    //event_log_error (hashcat_ctx, "Please install the libx11-dev package.");

    return -1;
  }

  xnvctrl->lib_xnvctrl = dlopen ("libXNVCtrl.so", RTLD_LAZY);

  if (xnvctrl->lib_xnvctrl == NULL)
  {
    //event_log_error (hashcat_ctx, "Failed to load the XNVCTRL library: %s", dlerror());
    //event_log_error (hashcat_ctx, "Please install the libxnvctrl-dev package.");

    return -1;
  }

  HC_LOAD_FUNC2 (xnvctrl, XOpenDisplay,  XOPENDISPLAY,  lib_x11, X11, 0);
  HC_LOAD_FUNC2 (xnvctrl, XCloseDisplay, XCLOSEDISPLAY, lib_x11, X11, 0);

  HC_LOAD_FUNC2 (xnvctrl, XNVCTRLQueryTargetCount,     XNVCTRLQUERYTARGETCOUNT,     lib_xnvctrl, XNVCTRL, 0);
  HC_LOAD_FUNC2 (xnvctrl, XNVCTRLQueryTargetAttribute, XNVCTRLQUERYTARGETATTRIBUTE, lib_xnvctrl, XNVCTRL, 0);
  HC_LOAD_FUNC2 (xnvctrl, XNVCTRLSetTargetAttribute,   XNVCTRLSETTARGETATTRIBUTE,   lib_xnvctrl, XNVCTRL, 0);

  return 0;

  #endif
}

static void xnvctrl_close (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl)
  {
    #if defined (_POSIX)

    if (xnvctrl->lib_x11)
    {
      dlclose (xnvctrl->lib_x11);
    }

    if (xnvctrl->lib_xnvctrl)
    {
      dlclose (xnvctrl->lib_xnvctrl);
    }

    #endif

    hcfree (xnvctrl);
  }
}

static int hm_XNVCTRL_XOpenDisplay (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XOpenDisplay == NULL) return -1;

  void *dpy = xnvctrl->XOpenDisplay (NULL);

  if (dpy == NULL)
  {
    event_log_error (hashcat_ctx, "XOpenDisplay() failed.");

    return -1;
  }

  xnvctrl->dpy = dpy;

  return 0;
}

static void hm_XNVCTRL_XCloseDisplay (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XCloseDisplay == NULL) return;

  if (xnvctrl->dpy == NULL) return;

  xnvctrl->XCloseDisplay (xnvctrl->dpy);
}

static int hm_XNVCTRL_query_target_count (hashcat_ctx_t *hashcat_ctx, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetCount == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const int rc = xnvctrl->XNVCTRLQueryTargetCount (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "%s", "XNVCTRLQueryTargetCount() failed.");

    return -1;
  }

  return 0;
}

static int hm_XNVCTRL_get_fan_control (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const bool rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_COOLER_MANUAL_CONTROL, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "XNVCTRLQueryTargetAttribute() failed.");

    // help the user to fix the problem

    event_log_warning (hashcat_ctx, "This error typically occurs when you did not set up NVidia Coolbits.");
    event_log_warning (hashcat_ctx, "To fix, run this command:");
    event_log_warning (hashcat_ctx, "    sudo nvidia-xconfig --cool-bits=12");
    event_log_warning (hashcat_ctx, "Do not forget to restart X afterwards.");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  return 0;
}

static int hm_XNVCTRL_set_fan_control (hashcat_ctx_t *hashcat_ctx, const int gpu, int val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLSetTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  int cur;

  int rc = hm_XNVCTRL_get_fan_control (hashcat_ctx, gpu, &cur);

  if (rc == -1) return -1;

  xnvctrl->XNVCTRLSetTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_COOLER_MANUAL_CONTROL, val);

  rc = hm_XNVCTRL_get_fan_control (hashcat_ctx, gpu, &cur);

  if (rc == -1) return -1;

  if (cur != val) return -1;

  return 0;
}

/*
static int hm_XNVCTRL_get_core_threshold (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const bool rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_CORE_THRESHOLD, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "XNVCTRLQueryTargetAttribute(NV_CTRL_GPU_CORE_THRESHOLD) failed.");

    return -1;
  }

  return 0;
}
*/

/*
static int hm_XNVCTRL_get_fan_speed_current (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const bool rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_CURRENT_LEVEL, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "XNVCTRLQueryTargetAttribute(NV_CTRL_THERMAL_COOLER_CURRENT_LEVEL) failed.");

    return -1;
  }

  return 0;
}
*/

static int hm_XNVCTRL_get_fan_speed_target (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_LEVEL, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "%s", "XNVCTRLQueryTargetAttribute(NV_CTRL_THERMAL_COOLER_LEVEL) failed.");

    return -1;
  }

  return 0;
}

static int hm_XNVCTRL_set_fan_speed_target (hashcat_ctx_t *hashcat_ctx, const int gpu, int val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLSetTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  int cur;

  int rc = hm_XNVCTRL_get_fan_speed_target (hashcat_ctx, gpu, &cur);

  if (rc == -1) return -1;

  xnvctrl->XNVCTRLSetTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_LEVEL, val);

  rc = hm_XNVCTRL_get_fan_speed_target (hashcat_ctx, gpu, &cur);

  if (rc == -1) return -1;

  if (cur != val) return -1;

  return 0;
}

static int hm_XNVCTRL_get_pci_bus (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_PCI_BUS, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "%s", "XNVCTRLQueryTargetAttribute(NV_CTRL_PCI_BUS) failed.");

    return -1;
  }

  return 0;
}

static int hm_XNVCTRL_get_pci_device (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_PCI_DEVICE, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "%s", "XNVCTRLQueryTargetAttribute(NV_CTRL_PCI_DEVICE) failed.");

    return -1;
  }

  return 0;
}

static int hm_XNVCTRL_get_pci_function (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_PCI_FUNCTION, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "%s", "XNVCTRLQueryTargetAttribute(NV_CTRL_PCI_FUNCTION) failed.");

    return -1;
  }

  return 0;
}

// ADL functions

static int adl_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  memset (adl, 0, sizeof (ADL_PTR));

  #if defined (_WIN)
  adl->lib = hc_dlopen ("atiadlxx.dll");

  if (!adl->lib)
  {
    adl->lib = hc_dlopen ("atiadlxy.dll");
  }
  #elif defined (__CYGWIN__)
  adl->lib = hc_dlopen ("atiadlxx.dll", RTLD_NOW);

  if (!adl->lib)
  {
    adl->lib = hc_dlopen ("atiadlxy.dll", RTLD_NOW);
  }
  #elif defined (_POSIX)
  adl->lib = hc_dlopen ("libatiadlxx.so", RTLD_NOW);
  #endif

  if (!adl->lib)
  {
    //if (user_options->quiet == false)
    //  event_log_error (hashcat_ctx, "Load of ADL library failed. Proceeding without ADL HWMon enabled.");

    return -1;
  }

  HC_LOAD_FUNC(adl, ADL_Main_Control_Destroy, ADL_MAIN_CONTROL_DESTROY, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Main_Control_Create, ADL_MAIN_CONTROL_CREATE, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Adapter_NumberOfAdapters_Get, ADL_ADAPTER_NUMBEROFADAPTERS_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Adapter_AdapterInfo_Get, ADL_ADAPTER_ADAPTERINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Display_DisplayInfo_Get, ADL_DISPLAY_DISPLAYINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Adapter_ID_Get, ADL_ADAPTER_ID_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Adapter_VideoBiosInfo_Get, ADL_ADAPTER_VIDEOBIOSINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_ThermalDevices_Enum, ADL_OVERDRIVE5_THERMALDEVICES_ENUM, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_Temperature_Get, ADL_OVERDRIVE5_TEMPERATURE_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_Temperature_Get, ADL_OVERDRIVE6_TEMPERATURE_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_CurrentActivity_Get, ADL_OVERDRIVE5_CURRENTACTIVITY_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_FanSpeedInfo_Get, ADL_OVERDRIVE5_FANSPEEDINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_FanSpeed_Get, ADL_OVERDRIVE5_FANSPEED_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_FanSpeed_Get, ADL_OVERDRIVE6_FANSPEED_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_FanSpeed_Set, ADL_OVERDRIVE5_FANSPEED_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_FanSpeed_Set, ADL_OVERDRIVE6_FANSPEED_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_FanSpeedToDefault_Set, ADL_OVERDRIVE5_FANSPEEDTODEFAULT_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_ODParameters_Get, ADL_OVERDRIVE5_ODPARAMETERS_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_ODPerformanceLevels_Get, ADL_OVERDRIVE5_ODPERFORMANCELEVELS_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_ODPerformanceLevels_Set, ADL_OVERDRIVE5_ODPERFORMANCELEVELS_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_PowerControlInfo_Get, ADL_OVERDRIVE6_POWERCONTROLINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_PowerControl_Get, ADL_OVERDRIVE6_POWERCONTROL_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_PowerControl_Set, ADL_OVERDRIVE6_POWERCONTROL_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Adapter_Active_Get, ADL_ADAPTER_ACTIVE_GET, ADL, 0)
  //HC_LOAD_FUNC(adl, ADL_DisplayEnable_Set, ADL_DISPLAYENABLE_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive_Caps, ADL_OVERDRIVE_CAPS, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_PowerControl_Caps, ADL_OVERDRIVE6_POWERCONTROL_CAPS, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_Capabilities_Get, ADL_OVERDRIVE6_CAPABILITIES_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_StateInfo_Get, ADL_OVERDRIVE6_STATEINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_CurrentStatus_Get, ADL_OVERDRIVE6_CURRENTSTATUS_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_State_Set, ADL_OVERDRIVE6_STATE_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_TargetTemperatureData_Get, ADL_OVERDRIVE6_TARGETTEMPERATUREDATA_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_TargetTemperatureRangeInfo_Get, ADL_OVERDRIVE6_TARGETTEMPERATURERANGEINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_FanSpeed_Reset, ADL_OVERDRIVE6_FANSPEED_RESET, ADL, 0)

  return 0;
}

static void adl_close (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  if (adl)
  {
    if (adl->lib)
      hc_dlclose (adl->lib);

    hcfree (adl);
  }
}

static int hm_ADL_Main_Control_Destroy (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Main_Control_Destroy ();

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Main_Control_Destroy(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Main_Control_Create (hashcat_ctx_t *hashcat_ctx, ADL_MAIN_MALLOC_CALLBACK callback, int iEnumConnectedAdapters)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Main_Control_Create (callback, iEnumConnectedAdapters);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Main_Control_Create(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Adapter_NumberOfAdapters_Get (hashcat_ctx_t *hashcat_ctx, int *lpNumAdapters)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Adapter_NumberOfAdapters_Get (lpNumAdapters);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Adapter_NumberOfAdapters_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Adapter_AdapterInfo_Get (hashcat_ctx_t *hashcat_ctx, LPAdapterInfo lpInfo, int iInputSize)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Adapter_AdapterInfo_Get (lpInfo, iInputSize);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Adapter_AdapterInfo_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive5_Temperature_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_Temperature_Get (iAdapterIndex, iThermalControllerIndex, lpTemperature);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive5_Temperature_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive6_Temperature_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *iTemperature)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_Temperature_Get (iAdapterIndex, iTemperature);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_Temperature_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLPMActivity *lpActivity)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_CurrentActivity_Get (iAdapterIndex, lpActivity);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive5_CurrentActivity_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_FanSpeed_Get (iAdapterIndex, iThermalControllerIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive5_FanSpeed_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive6_FanSpeed_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6FanSpeedInfo *lpFanSpeedInfo)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_FanSpeed_Get (iAdapterIndex, lpFanSpeedInfo);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_FanSpeed_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive5_FanSpeed_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_FanSpeed_Set (iAdapterIndex, iThermalControllerIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive5_FanSpeed_Set(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive6_FanSpeed_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6FanSpeedValue *lpFanSpeedValue)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_FanSpeed_Set (iAdapterIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_FanSpeed_Set(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive5_FanSpeedToDefault_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_FanSpeedToDefault_Set (iAdapterIndex, iThermalControllerIndex);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive5_FanSpeedToDefault_Set(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive_PowerControlInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6PowerControlInfo *powertune)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_PowerControlInfo_Get (iAdapterIndex, powertune);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_PowerControlInfo_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive_PowerControl_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *iCurrentValue)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  int default_value = 0;

  const int ADL_rc = adl->ADL_Overdrive6_PowerControl_Get (iAdapterIndex, iCurrentValue, &default_value);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_PowerControl_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive_PowerControl_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int level)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

  const int hm_rc = hm_ADL_Overdrive_PowerControlInfo_Get (hashcat_ctx, iAdapterIndex, &powertune);

  if (hm_rc == -1) return -1;

  int min  = powertune.iMinValue;
  int max  = powertune.iMaxValue;
  int step = powertune.iStepValue;

  if (level < min || level > max)
  {
    event_log_error (hashcat_ctx, "ADL PowerControl level invalid.");

    return -1;
  }

  if (step == 0)
  {
    event_log_error (hashcat_ctx, "ADL PowerControl step invalid.");

    return -1;
  }

  if (level % step != 0)
  {
    event_log_error (hashcat_ctx, "ADL PowerControl step invalid.");

    return -1;
  }

  const int ADL_rc = adl->ADL_Overdrive6_PowerControl_Set (iAdapterIndex, level);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_PowerControl_Set(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive_Caps (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *od_supported, int *od_enabled, int *od_version)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive_Caps (iAdapterIndex, od_supported, od_enabled, od_version);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive_Caps(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive6_PowerControl_Caps (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *lpSupported)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_PowerControl_Caps (iAdapterIndex, lpSupported);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_PowerControl_Caps(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive_Capabilities_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6Capabilities *caps)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_Capabilities_Get (iAdapterIndex, caps);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_Capabilities_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive_StateInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int type, ADLOD6MemClockState *state)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_StateInfo_Get (iAdapterIndex, type, state);

  if (ADL_rc == ADL_OK)
  {
    // check if clocks are okay with step sizes
    // if not run a little hack: adjust the clocks to nearest clock size (clock down just a little bit)

    ADLOD6Capabilities caps;

    const int hm_rc = hm_ADL_Overdrive_Capabilities_Get (hashcat_ctx, iAdapterIndex, &caps);

    if (hm_rc == -1) return -1;

    if (state->state.aLevels[0].iEngineClock % caps.sEngineClockRange.iStep != 0)
    {
      event_log_error (hashcat_ctx, "ADL engine step size invalid for performance level 1.");

      //state->state.aLevels[0].iEngineClock -= state->state.aLevels[0].iEngineClock % caps.sEngineClockRange.iStep;

      return -1;
    }

    if (state->state.aLevels[1].iEngineClock % caps.sEngineClockRange.iStep != 0)
    {
      event_log_error (hashcat_ctx, "ADL engine step size invalid for performance level 2.");

      //state->state.aLevels[1].iEngineClock -= state->state.aLevels[1].iEngineClock % caps.sEngineClockRange.iStep;

      return -1;
    }

    if (state->state.aLevels[0].iMemoryClock % caps.sMemoryClockRange.iStep != 0)
    {
      event_log_error (hashcat_ctx, "ADL memory step size invalid for performance level 1.");

      //state->state.aLevels[0].iMemoryClock -= state->state.aLevels[0].iMemoryClock % caps.sMemoryClockRange.iStep;

      return -1;
    }

    if (state->state.aLevels[1].iMemoryClock % caps.sMemoryClockRange.iStep != 0)
    {
      event_log_error (hashcat_ctx, "ADL memory step size invalid for performance level 2.");

      //state->state.aLevels[1].iMemoryClock -= state->state.aLevels[1].iMemoryClock % caps.sMemoryClockRange.iStep;

      return -1;
    }
  }
  else
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_StateInfo_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive_State_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int type, ADLOD6StateInfo *state)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  // sanity checks

  ADLOD6Capabilities caps;

  const int hm_rc = hm_ADL_Overdrive_Capabilities_Get (hashcat_ctx, iAdapterIndex, &caps);

  if (hm_rc == -1) return -1;

  if (state->aLevels[0].iEngineClock < caps.sEngineClockRange.iMin || state->aLevels[1].iEngineClock > caps.sEngineClockRange.iMax)
  {
    event_log_error (hashcat_ctx, "ADL engine clock outside valid range.");

    return -1;
  }

  if (state->aLevels[1].iEngineClock % caps.sEngineClockRange.iStep != 0)
  {
    event_log_error (hashcat_ctx, "ADL engine step size invalid.");

    return -1;
  }

  if (state->aLevels[0].iMemoryClock < caps.sMemoryClockRange.iMin || state->aLevels[1].iMemoryClock > caps.sMemoryClockRange.iMax)
  {
    event_log_error (hashcat_ctx, "ADL memory clock outside valid range.");

    return -1;
  }

  if (state->aLevels[1].iMemoryClock % caps.sMemoryClockRange.iStep != 0)
  {
    event_log_error (hashcat_ctx, "ADL memory step size invalid.");

    return -1;
  }

  const int ADL_rc = adl->ADL_Overdrive6_State_Set (iAdapterIndex, type, state);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_State_Set(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive6_TargetTemperatureData_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *cur_temp, int *default_temp)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_TargetTemperatureData_Get (iAdapterIndex, cur_temp, default_temp);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_TargetTemperatureData_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

static int hm_ADL_Overdrive6_FanSpeed_Reset (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_FanSpeed_Reset (iAdapterIndex);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_FanSpeed_Reset(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

// general functions

static int get_adapters_num_adl (hashcat_ctx_t *hashcat_ctx, int *iNumberAdapters)
{
  const int hm_rc = hm_ADL_Adapter_NumberOfAdapters_Get (hashcat_ctx, iNumberAdapters);

  if (hm_rc == -1) return -1;

  if (iNumberAdapters == NULL)
  {
    event_log_error (hashcat_ctx, "No ADL adapters found.");

    return -1;
  }

  return 0;
}

static int hm_get_adapter_index_nvapi (hashcat_ctx_t *hashcat_ctx, HM_ADAPTER_NVAPI *nvapiGPUHandle)
{
  NvU32 pGpuCount;

  if (hm_NvAPI_EnumPhysicalGPUs (hashcat_ctx, nvapiGPUHandle, &pGpuCount) == -1) return 0;

  if (pGpuCount == 0)
  {
    event_log_error (hashcat_ctx, "No NvAPI adapters found.");

    return 0;
  }

  return (pGpuCount);
}

static int hm_get_adapter_index_nvml (hashcat_ctx_t *hashcat_ctx, HM_ADAPTER_NVML *nvmlGPUHandle)
{
  unsigned int deviceCount = 0;

  hm_NVML_nvmlDeviceGetCount (hashcat_ctx, &deviceCount);

  if (deviceCount == 0)
  {
    event_log_error (hashcat_ctx, "No NVML adapters found.");

    return 0;
  }

  for (u32 i = 0; i < deviceCount; i++)
  {
    if (hm_NVML_nvmlDeviceGetHandleByIndex (hashcat_ctx, i, &nvmlGPUHandle[i]) == -1) break;

    // can be used to determine if the device by index matches the cuda device by index
    // char name[100]; memset (name, 0, sizeof (name));
    // hm_NVML_nvmlDeviceGetName (hashcat_ctx, nvGPUHandle[i], name, sizeof (name) - 1);
  }

  return (deviceCount);
}

int hm_get_threshold_slowdown_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].threshold_slowdown_get_supported == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {

      }
      else if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {
        int CurrentValue = 0;
        int DefaultValue = 0;

        if (hm_ADL_Overdrive6_TargetTemperatureData_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &CurrentValue, &DefaultValue) == -1)
        {
          hwmon_ctx->hm_device[device_id].threshold_slowdown_get_supported = false;

          return -1;
        }

        // the return value has never been tested since hm_ADL_Overdrive6_TargetTemperatureData_Get() never worked on any system. expect problems.

        return DefaultValue;
      }
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int target = 0;

      if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, (unsigned int *) &target) == -1)
      {
        hwmon_ctx->hm_device[device_id].threshold_slowdown_get_supported = false;

        return -1;
      }

      return target;
    }
  }

  hwmon_ctx->hm_device[device_id].threshold_slowdown_get_supported = false;

  return -1;
}

int hm_get_threshold_shutdown_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].threshold_shutdown_get_supported == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {

      }
      else if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {

      }
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int target = 0;

      if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, NVML_TEMPERATURE_THRESHOLD_SHUTDOWN, (unsigned int *) &target) == -1)
      {
        hwmon_ctx->hm_device[device_id].threshold_shutdown_get_supported = false;

        return -1;
      }

      return target;
    }
  }

  hwmon_ctx->hm_device[device_id].threshold_shutdown_get_supported = false;

  return -1;
}

int hm_get_temperature_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].temperature_get_supported == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {
        ADLTemperature Temperature;

        Temperature.iSize = sizeof (ADLTemperature);

        if (hm_ADL_Overdrive5_Temperature_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, 0, &Temperature) == -1)
        {
          hwmon_ctx->hm_device[device_id].temperature_get_supported = false;

          return -1;
        }

        return Temperature.iTemperature / 1000;
      }
      else if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {
        int Temperature = 0;

        if (hm_ADL_Overdrive6_Temperature_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &Temperature) == -1)
        {
          hwmon_ctx->hm_device[device_id].temperature_get_supported = false;

          return -1;
        }

        return Temperature / 1000;
      }
    }

    if (hwmon_ctx->hm_sysfs)
    {
      int temperature = 0;

      if (hm_SYSFS_get_temperature_current (hashcat_ctx, device_id, &temperature) == -1)
      {
        hwmon_ctx->hm_device[device_id].temperature_get_supported = false;

        return -1;
      }

      return temperature;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int temperature = 0;

      if (hm_NVML_nvmlDeviceGetTemperature (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, NVML_TEMPERATURE_GPU, (u32 *) &temperature) == -1)
      {
        hwmon_ctx->hm_device[device_id].temperature_get_supported = false;

        return -1;
      }

      return temperature;
    }
  }

  hwmon_ctx->hm_device[device_id].temperature_get_supported = false;

  return -1;
}

int hm_get_fanpolicy_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fanpolicy_get_supported == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {
        ADLFanSpeedValue lpFanSpeedValue;

        memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

        lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
        lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;

        if (hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, 0, &lpFanSpeedValue) == -1)
        {
          hwmon_ctx->hm_device[device_id].fanpolicy_get_supported = false;
          hwmon_ctx->hm_device[device_id].fanspeed_get_supported  = false;

          return -1;
        }

        return (lpFanSpeedValue.iFanSpeed & ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED) ? 0 : 1;
      }
      else // od_version == 6
      {
        return 1;
      }
    }

    if (hwmon_ctx->hm_sysfs)
    {
      return 1;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    return 1;
  }

  hwmon_ctx->hm_device[device_id].fanpolicy_get_supported = false;
  hwmon_ctx->hm_device[device_id].fanspeed_get_supported  = false;

  return -1;
}

int hm_get_fanspeed_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fanspeed_get_supported == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {
        ADLFanSpeedValue lpFanSpeedValue;

        memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

        lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
        lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
        lpFanSpeedValue.iFlags     = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;

        if (hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, 0, &lpFanSpeedValue) == -1)
        {
          hwmon_ctx->hm_device[device_id].fanspeed_get_supported = false;

          return -1;
        }

        return lpFanSpeedValue.iFanSpeed;
      }
      else // od_version == 6
      {
        ADLOD6FanSpeedInfo faninfo;

        memset (&faninfo, 0, sizeof (faninfo));

        if (hm_ADL_Overdrive6_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &faninfo) == -1)
        {
          hwmon_ctx->hm_device[device_id].fanspeed_get_supported = false;

          return -1;
        }

        return faninfo.iFanSpeedPercent;
      }
    }

    if (hwmon_ctx->hm_sysfs)
    {
      int speed = 0;

      if (hm_SYSFS_get_fan_speed_current (hashcat_ctx, device_id, &speed) == -1)
      {
        hwmon_ctx->hm_device[device_id].fanspeed_get_supported = false;

        return -1;
      }

      return speed;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int speed = 0;

      if (hm_NVML_nvmlDeviceGetFanSpeed (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, (u32 *) &speed) == -1)
      {
        hwmon_ctx->hm_device[device_id].fanspeed_get_supported = false;

        return -1;
      }

      return speed;
    }
  }

  hwmon_ctx->hm_device[device_id].fanspeed_get_supported = false;

  return -1;
}

int hm_get_buslanes_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].buslanes_get_supported == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &PMActivity) == -1)
      {
        hwmon_ctx->hm_device[device_id].buslanes_get_supported = false;

        return -1;
      }

      return PMActivity.iCurrentBusLanes;
    }

    if (hwmon_ctx->hm_sysfs)
    {
      int lanes;

      if (hm_SYSFS_get_pp_dpm_pcie (hashcat_ctx, device_id, &lanes) == -1)
      {
        hwmon_ctx->hm_device[device_id].buslanes_get_supported = false;

        return -1;
      }

      return lanes;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int currLinkWidth;

      if (hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &currLinkWidth) == -1)
      {
        hwmon_ctx->hm_device[device_id].buslanes_get_supported = false;

        return -1;
      }

      return currLinkWidth;
    }
  }

  hwmon_ctx->hm_device[device_id].buslanes_get_supported = false;

  return -1;
}

int hm_get_utilization_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].utilization_get_supported == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &PMActivity) == -1)
      {
        hwmon_ctx->hm_device[device_id].utilization_get_supported = false;

        return -1;
      }

      return PMActivity.iActivityPercent;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    if (hwmon_ctx->hm_nvml)
    {
      nvmlUtilization_t utilization;

      if (hm_NVML_nvmlDeviceGetUtilizationRates (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &utilization) == -1)
      {
        hwmon_ctx->hm_device[device_id].utilization_get_supported = false;

        return -1;
      }

      return utilization.gpu;
    }
  }

  hwmon_ctx->hm_device[device_id].utilization_get_supported = false;

  return -1;
}

int hm_get_memoryspeed_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].memoryspeed_get_supported == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &PMActivity) == -1)
      {
        hwmon_ctx->hm_device[device_id].memoryspeed_get_supported = false;

        return -1;
      }

      return PMActivity.iMemoryClock / 100;
    }

    if (hwmon_ctx->hm_sysfs)
    {
      int clockfreq;

      if (hm_SYSFS_get_pp_dpm_mclk (hashcat_ctx, device_id, &clockfreq) == -1)
      {
        hwmon_ctx->hm_device[device_id].memoryspeed_get_supported = false;

        return -1;
      }

      return clockfreq;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int clockfreq;

      if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, NVML_CLOCK_MEM, &clockfreq) == -1)
      {
        hwmon_ctx->hm_device[device_id].memoryspeed_get_supported = false;

        return -1;
      }

      return clockfreq;
    }
  }

  hwmon_ctx->hm_device[device_id].memoryspeed_get_supported = false;

  return -1;
}

int hm_get_corespeed_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].corespeed_get_supported == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &PMActivity) == -1)
      {
        hwmon_ctx->hm_device[device_id].corespeed_get_supported = false;

        return -1;
      }

      return PMActivity.iEngineClock / 100;
    }

    if (hwmon_ctx->hm_sysfs)
    {
      int clockfreq;

      if (hm_SYSFS_get_pp_dpm_sclk (hashcat_ctx, device_id, &clockfreq) == -1)
      {
        hwmon_ctx->hm_device[device_id].corespeed_get_supported = false;

        return -1;
      }

      return clockfreq;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int clockfreq;

      if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, NVML_CLOCK_SM, &clockfreq) == -1)
      {
        hwmon_ctx->hm_device[device_id].corespeed_get_supported = false;

        return -1;
      }

      return clockfreq;
    }
  }

  hwmon_ctx->hm_device[device_id].corespeed_get_supported = false;

  return -1;
}

int hm_get_throttle_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].throttle_get_supported == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    if (hwmon_ctx->hm_nvml)
    {
      /* this is triggered by mask generator, too. therefore useless
      unsigned long long clocksThrottleReasons = 0;
      unsigned long long supportedThrottleReasons = 0;

      if (hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons   (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &clocksThrottleReasons)    == -1) return -1;
      if (hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &supportedThrottleReasons) == -1) return -1;

      clocksThrottleReasons &=  supportedThrottleReasons;
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonGpuIdle;
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonApplicationsClocksSetting;
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonUnknown;

      if (opencl_ctx->kernel_power_final)
      {
        clocksThrottleReasons &= ~nvmlClocksThrottleReasonHwSlowdown;
      }

      return (clocksThrottleReasons != nvmlClocksThrottleReasonNone);
      */
    }

    if (hwmon_ctx->hm_nvapi)
    {
      NV_GPU_PERF_POLICIES_INFO_PARAMS_V1   perfPolicies_info;
      NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1 perfPolicies_status;

      memset (&perfPolicies_info,   0, sizeof (NV_GPU_PERF_POLICIES_INFO_PARAMS_V1));
      memset (&perfPolicies_status, 0, sizeof (NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1));

      perfPolicies_info.version   = MAKE_NVAPI_VERSION (NV_GPU_PERF_POLICIES_INFO_PARAMS_V1, 1);
      perfPolicies_status.version = MAKE_NVAPI_VERSION (NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1, 1);

      hm_NvAPI_GPU_GetPerfPoliciesInfo (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvapi, &perfPolicies_info);

      perfPolicies_status.info_value = perfPolicies_info.info_value;

      hm_NvAPI_GPU_GetPerfPoliciesStatus (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvapi, &perfPolicies_status);

      return perfPolicies_status.throttle & 2;
    }
  }

  hwmon_ctx->hm_device[device_id].throttle_get_supported = false;

  return -1;
}

int hm_set_fanspeed_with_device_id_adl (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed, const int fanpolicy)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fanspeed_set_supported == false) return -1;

  if (hwmon_ctx->hm_adl)
  {
    if (fanpolicy == 1)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {
        ADLFanSpeedValue lpFanSpeedValue;

        memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

        lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
        lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
        lpFanSpeedValue.iFlags     = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;
        lpFanSpeedValue.iFanSpeed  = fanspeed;

        if (hm_ADL_Overdrive5_FanSpeed_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, 0, &lpFanSpeedValue) == -1)
        {
          hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

          return -1;
        }

        return 0;
      }
      else // od_version == 6
      {
        ADLOD6FanSpeedValue fan_speed_value;

        memset (&fan_speed_value, 0, sizeof (fan_speed_value));

        fan_speed_value.iSpeedType = ADL_OD6_FANSPEED_TYPE_PERCENT;
        fan_speed_value.iFanSpeed  = fanspeed;

        if (hm_ADL_Overdrive6_FanSpeed_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &fan_speed_value) == -1)
        {
          hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

          return -1;
        }

        return 0;
      }
    }
    else
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {
        if (hm_ADL_Overdrive5_FanSpeedToDefault_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, 0) == -1)
        {
          hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

          return -1;
        }

        return 0;
      }
      else // od_version == 6
      {
        if (hm_ADL_Overdrive6_FanSpeed_Reset (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl) == -1)
        {
          hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

          return -1;
        }

        return 0;
      }
    }
  }

  hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

  return -1;
}

int hm_set_fanspeed_with_device_id_nvapi (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed, const int fanpolicy)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fanspeed_set_supported == false) return -1;

  if (hwmon_ctx->hm_nvapi)
  {
    if (fanpolicy == 1)
    {
      NV_GPU_COOLER_LEVELS CoolerLevels;

      memset (&CoolerLevels, 0, sizeof (NV_GPU_COOLER_LEVELS));

      CoolerLevels.Version = GPU_COOLER_LEVELS_VER | sizeof (NV_GPU_COOLER_LEVELS);

      CoolerLevels.Levels[0].Level  = fanspeed;
      CoolerLevels.Levels[0].Policy = 1;

      if (hm_NvAPI_GPU_SetCoolerLevels (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvapi, 0, &CoolerLevels) == -1)
      {
        hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

        return -1;
      }

      return 0;
    }
    else
    {
      NV_GPU_COOLER_LEVELS CoolerLevels;

      memset (&CoolerLevels, 0, sizeof (NV_GPU_COOLER_LEVELS));

      CoolerLevels.Version = GPU_COOLER_LEVELS_VER | sizeof (NV_GPU_COOLER_LEVELS);

      CoolerLevels.Levels[0].Level  = 100;
      CoolerLevels.Levels[0].Policy = 0x20;

      if (hm_NvAPI_GPU_SetCoolerLevels (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvapi, 0, &CoolerLevels) == -1)
      {
        hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

        return -1;
      }

      return 0;
    }
  }

  hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

  return -1;
}

int hm_set_fanspeed_with_device_id_xnvctrl (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fanspeed_set_supported  == false) return -1;

  if (hwmon_ctx->hm_xnvctrl)
  {
    if (hm_XNVCTRL_set_fan_speed_target (hashcat_ctx, hwmon_ctx->hm_device[device_id].xnvctrl, fanspeed) == -1)
    {
      hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

      return -1;
    }

    return 0;
  }

  hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

  return -1;
}

int hm_set_fanspeed_with_device_id_sysfs (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fanspeed_set_supported == false) return -1;

  if (hwmon_ctx->hm_sysfs)
  {
    if (hm_SYSFS_set_fan_speed_target (hashcat_ctx, device_id, fanspeed) == -1)
    {
      hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

      return -1;
    }

    return 0;
  }

  hwmon_ctx->hm_device[device_id].fanspeed_set_supported = false;

  return -1;
}

static int hm_set_fanctrl_with_device_id_xnvctrl (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fanpolicy_set_supported == false) return -1;

  if (hwmon_ctx->hm_xnvctrl)
  {
    if (hm_XNVCTRL_set_fan_control (hashcat_ctx, hwmon_ctx->hm_device[device_id].xnvctrl, val) == -1)
    {
      hwmon_ctx->hm_device[device_id].fanpolicy_set_supported = false;
      hwmon_ctx->hm_device[device_id].fanspeed_set_supported  = false;

      return -1;
    }

    return 0;
  }

  hwmon_ctx->hm_device[device_id].fanpolicy_set_supported = false;
  hwmon_ctx->hm_device[device_id].fanspeed_set_supported  = false;

  return -1;
}

static int hm_set_fanctrl_with_device_id_sysfs (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fanpolicy_set_supported == false) return -1;

  if (hwmon_ctx->hm_sysfs)
  {
    if (hm_SYSFS_set_fan_control (hashcat_ctx, device_id, val) == -1)
    {
      hwmon_ctx->hm_device[device_id].fanpolicy_set_supported = false;
      hwmon_ctx->hm_device[device_id].fanspeed_set_supported  = false;

      return -1;
    }

    return 0;
  }

  hwmon_ctx->hm_device[device_id].fanpolicy_set_supported = false;
  hwmon_ctx->hm_device[device_id].fanspeed_set_supported  = false;

  return -1;
}

int hwmon_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t    *hwmon_ctx    = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t   *opencl_ctx   = hashcat_ctx->opencl_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  hwmon_ctx->enabled = false;

  if (user_options->keyspace          == true) return 0;
  if (user_options->left              == true) return 0;
  if (user_options->opencl_info       == true) return 0;
  if (user_options->show              == true) return 0;
  if (user_options->stdout_flag       == true) return 0;
  if (user_options->usage             == true) return 0;
  if (user_options->version           == true) return 0;
  if (user_options->gpu_temp_disable  == true) return 0;

  hwmon_ctx->hm_device = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));

  /**
   * Initialize shared libraries
   */

  hm_attrs_t *hm_adapters_adl     = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_nvapi   = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_nvml    = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_xnvctrl = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_sysfs   = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));

  #define FREE_ADAPTERS           \
  {                               \
    hcfree (hm_adapters_adl);     \
    hcfree (hm_adapters_nvapi);   \
    hcfree (hm_adapters_nvml);    \
    hcfree (hm_adapters_xnvctrl); \
    hcfree (hm_adapters_sysfs);   \
  }

  if (opencl_ctx->need_nvml == true)
  {
    hwmon_ctx->hm_nvml = (NVML_PTR *) hcmalloc (sizeof (NVML_PTR));

    if (nvml_init (hashcat_ctx) == -1)
    {
      hcfree (hwmon_ctx->hm_nvml);

      hwmon_ctx->hm_nvml = NULL;
    }
  }

  if ((opencl_ctx->need_nvapi == true) && (hwmon_ctx->hm_nvml)) // nvapi can't work alone, we need nvml, too
  {
    hwmon_ctx->hm_nvapi = (NVAPI_PTR *) hcmalloc (sizeof (NVAPI_PTR));

    if (nvapi_init (hashcat_ctx) == -1)
    {
      hcfree (hwmon_ctx->hm_nvapi);

      hwmon_ctx->hm_nvapi = NULL;
    }
  }

  if ((opencl_ctx->need_xnvctrl == true) && (hwmon_ctx->hm_nvml)) // xnvctrl can't work alone, we need nvml, too
  {
    hwmon_ctx->hm_xnvctrl = (XNVCTRL_PTR *) hcmalloc (sizeof (XNVCTRL_PTR));

    if (xnvctrl_init (hashcat_ctx) == -1)
    {
      hcfree (hwmon_ctx->hm_xnvctrl);

      hwmon_ctx->hm_xnvctrl = NULL;
    }
  }

  if (opencl_ctx->need_adl == true)
  {
    hwmon_ctx->hm_adl = (ADL_PTR *) hcmalloc (sizeof (ADL_PTR));

    if (adl_init (hashcat_ctx) == -1)
    {
      hcfree (hwmon_ctx->hm_adl);

      hwmon_ctx->hm_adl = NULL;
    }
  }

  if (opencl_ctx->need_sysfs == true)
  {
    hwmon_ctx->hm_sysfs = (SYSFS_PTR *) hcmalloc (sizeof (SYSFS_PTR));

    if (sysfs_init (hashcat_ctx) == false)
    {
      hcfree (hwmon_ctx->hm_sysfs);

      hwmon_ctx->hm_sysfs = NULL;
    }

    // also if there's ADL, we don't need sysfs

    if (hwmon_ctx->hm_adl)
    {
      hcfree (hwmon_ctx->hm_sysfs);

      hwmon_ctx->hm_sysfs = NULL;
    }
  }

  if (hwmon_ctx->hm_nvml)
  {
    if (hm_NVML_nvmlInit (hashcat_ctx) == 0)
    {
      HM_ADAPTER_NVML *nvmlGPUHandle = (HM_ADAPTER_NVML *) hccalloc (DEVICES_MAX, sizeof (HM_ADAPTER_NVML));

      int tmp_in = hm_get_adapter_index_nvml (hashcat_ctx, nvmlGPUHandle);

      for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if (device_param->skipped == true) continue;

        if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        if (device_param->device_vendor_id != VENDOR_ID_NV) continue;

        for (int i = 0; i < tmp_in; i++)
        {
          nvmlPciInfo_t pci;

          int rc = hm_NVML_nvmlDeviceGetPciInfo (hashcat_ctx, nvmlGPUHandle[i], &pci);

          if (rc == -1) continue;

          if ((device_param->pcie_bus      == pci.bus)
           && (device_param->pcie_device   == (pci.device >> 3))
           && (device_param->pcie_function == (pci.device & 7)))
          {
            const u32 platform_devices_id = device_param->platform_devices_id;

            hm_adapters_nvml[platform_devices_id].nvml = nvmlGPUHandle[i];

            hm_adapters_nvml[platform_devices_id].buslanes_get_supported            = true;
            hm_adapters_nvml[platform_devices_id].corespeed_get_supported           = true;
            hm_adapters_nvml[platform_devices_id].fanspeed_get_supported            = true;
            hm_adapters_nvml[platform_devices_id].memoryspeed_get_supported         = true;
            hm_adapters_nvml[platform_devices_id].temperature_get_supported         = true;
            hm_adapters_nvml[platform_devices_id].threshold_shutdown_get_supported  = true;
            hm_adapters_nvml[platform_devices_id].threshold_slowdown_get_supported  = true;
            hm_adapters_nvml[platform_devices_id].utilization_get_supported         = true;
          }
        }
      }

      hcfree (nvmlGPUHandle);
    }
  }

  if (hwmon_ctx->hm_nvapi)
  {
    if (hm_NvAPI_Initialize (hashcat_ctx) == 0)
    {
      HM_ADAPTER_NVAPI *nvGPUHandle = (HM_ADAPTER_NVAPI *) hccalloc (NVAPI_MAX_PHYSICAL_GPUS, sizeof (HM_ADAPTER_NVAPI));

      int tmp_in = hm_get_adapter_index_nvapi (hashcat_ctx, nvGPUHandle);

      for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if (device_param->skipped == true) continue;

        if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        if (device_param->device_vendor_id != VENDOR_ID_NV) continue;

        for (int i = 0; i < tmp_in; i++)
        {
          NvU32 BusId     = 0;
          NvU32 BusSlotId = 0;

          int rc1 = hm_NvAPI_GPU_GetBusId (hashcat_ctx, nvGPUHandle[i], &BusId);

          if (rc1 == -1) continue;

          int rc2 = hm_NvAPI_GPU_GetBusSlotId (hashcat_ctx, nvGPUHandle[i], &BusSlotId);

          if (rc2 == -1) continue;

          if ((device_param->pcie_bus      == BusId)
           && (device_param->pcie_device   == (BusSlotId >> 3))
           && (device_param->pcie_function == (BusSlotId & 7)))
          {
            const u32 platform_devices_id = device_param->platform_devices_id;

            hm_adapters_nvapi[platform_devices_id].nvapi = nvGPUHandle[i];

            hm_adapters_nvapi[platform_devices_id].fanspeed_set_supported   = true;
            hm_adapters_nvapi[platform_devices_id].fanpolicy_get_supported  = true;
            hm_adapters_nvapi[platform_devices_id].fanpolicy_set_supported  = true;
            hm_adapters_nvapi[platform_devices_id].throttle_get_supported   = true;
          }
        }
      }

      hcfree (nvGPUHandle);
    }
  }

  if (hwmon_ctx->hm_xnvctrl)
  {
    if (hm_XNVCTRL_XOpenDisplay (hashcat_ctx) == 0)
    {
      int tmp_in = 0;

      hm_XNVCTRL_query_target_count (hashcat_ctx, &tmp_in);

      for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        if (device_param->device_vendor_id != VENDOR_ID_NV) continue;

        for (int i = 0; i < tmp_in; i++)
        {
          int pci_bus = 0;
          int pci_device = 0;
          int pci_function = 0;

          const int rc1 = hm_XNVCTRL_get_pci_bus (hashcat_ctx, i, &pci_bus);

          if (rc1 == -1) continue;

          const int rc2 = hm_XNVCTRL_get_pci_device (hashcat_ctx, i, &pci_device);

          if (rc2 == -1) continue;

          const int rc3 = hm_XNVCTRL_get_pci_function (hashcat_ctx, i, &pci_function);

          if (rc3 == -1) continue;

          if ((device_param->pcie_bus      == pci_bus)
           && (device_param->pcie_device   == pci_device)
           && (device_param->pcie_function == pci_function))
          {
            const u32 platform_devices_id = device_param->platform_devices_id;

            hm_adapters_xnvctrl[platform_devices_id].xnvctrl = i;

            hm_adapters_xnvctrl[platform_devices_id].fanspeed_get_supported  = true;
            hm_adapters_xnvctrl[platform_devices_id].fanspeed_set_supported  = true;
            hm_adapters_xnvctrl[platform_devices_id].fanpolicy_get_supported = true;
            hm_adapters_xnvctrl[platform_devices_id].fanpolicy_set_supported = true;
          }
        }
      }
    }
  }

  if (hwmon_ctx->hm_adl)
  {
    if (hm_ADL_Main_Control_Create (hashcat_ctx, ADL_Main_Memory_Alloc, 0) == 0)
    {
      // total number of adapters

      int tmp_in;

      if (get_adapters_num_adl (hashcat_ctx, &tmp_in) == -1)
      {
        FREE_ADAPTERS;

        return -1;
      }

      // adapter info

      LPAdapterInfo lpAdapterInfo = (LPAdapterInfo) hccalloc (tmp_in, sizeof (AdapterInfo));

      const int rc_adapter_info_adl = hm_ADL_Adapter_AdapterInfo_Get (hashcat_ctx, lpAdapterInfo, tmp_in * sizeof (AdapterInfo));

      if (rc_adapter_info_adl == -1)
      {
        FREE_ADAPTERS;

        return -1;
      }

      for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if (device_param->skipped == true) continue;

        if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        if (device_param->device_vendor_id != VENDOR_ID_AMD) continue;

        for (int i = 0; i < tmp_in; i++)
        {
          if ((device_param->pcie_bus      == lpAdapterInfo[i].iBusNumber)
           && (device_param->pcie_device   == (lpAdapterInfo[i].iDeviceNumber >> 3))
           && (device_param->pcie_function == (lpAdapterInfo[i].iDeviceNumber & 7)))
          {
            const u32 platform_devices_id = device_param->platform_devices_id;

            int od_supported = 0;
            int od_enabled   = 0;
            int od_version   = 0;

            hm_ADL_Overdrive_Caps (hashcat_ctx, lpAdapterInfo[i].iAdapterIndex, &od_supported, &od_enabled, &od_version);

            hm_adapters_adl[platform_devices_id].od_version = od_version;

            hm_adapters_adl[platform_devices_id].adl = lpAdapterInfo[i].iAdapterIndex;

            hm_adapters_adl[platform_devices_id].buslanes_get_supported            = true;
            hm_adapters_adl[platform_devices_id].corespeed_get_supported           = true;
            hm_adapters_adl[platform_devices_id].fanspeed_get_supported            = true;
            hm_adapters_adl[platform_devices_id].fanspeed_set_supported            = true;
            hm_adapters_adl[platform_devices_id].fanpolicy_get_supported           = true;
            hm_adapters_adl[platform_devices_id].fanpolicy_set_supported           = true;
            hm_adapters_adl[platform_devices_id].memoryspeed_get_supported         = true;
            hm_adapters_adl[platform_devices_id].temperature_get_supported         = true;
            hm_adapters_adl[platform_devices_id].threshold_slowdown_get_supported  = true;
            hm_adapters_adl[platform_devices_id].utilization_get_supported         = true;
          }
        }
      }

      hcfree (lpAdapterInfo);
    }
  }

  if (hwmon_ctx->hm_sysfs)
  {
    if (1)
    {
      int hm_adapters_id = 0;

      for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        hm_adapters_sysfs[hm_adapters_id].sysfs = device_id;

        hm_adapters_sysfs[hm_adapters_id].buslanes_get_supported    = true;
        hm_adapters_sysfs[hm_adapters_id].corespeed_get_supported   = true;
        hm_adapters_sysfs[hm_adapters_id].fanspeed_get_supported    = true;
        hm_adapters_sysfs[hm_adapters_id].fanspeed_set_supported    = true;
        hm_adapters_sysfs[hm_adapters_id].fanpolicy_get_supported   = true;
        hm_adapters_sysfs[hm_adapters_id].fanpolicy_set_supported   = true;
        hm_adapters_sysfs[hm_adapters_id].memoryspeed_get_supported = true;
        hm_adapters_sysfs[hm_adapters_id].temperature_get_supported = true;

        hm_adapters_id++;
      }
    }
  }

  if (hwmon_ctx->hm_adl == NULL && hwmon_ctx->hm_nvml == NULL && hwmon_ctx->hm_xnvctrl == NULL && hwmon_ctx->hm_sysfs == NULL)
  {
    FREE_ADAPTERS;

    return 0;
  }

  /**
   * looks like we have some manageable device
   */

  hwmon_ctx->enabled = true;

  /**
   * save buffer required for later restores
   */

  hwmon_ctx->od_clock_mem_status = (ADLOD6MemClockState *) hccalloc (opencl_ctx->devices_cnt, sizeof (ADLOD6MemClockState));

  hwmon_ctx->od_power_control_status = (int *) hccalloc (opencl_ctx->devices_cnt, sizeof (int));

  hwmon_ctx->nvml_power_limit = (unsigned int *) hccalloc (opencl_ctx->devices_cnt, sizeof (unsigned int));

  /**
   * HM devices: copy
   */

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped == true) continue;

    if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

    const u32 platform_devices_id = device_param->platform_devices_id;

    if (device_param->device_vendor_id == VENDOR_ID_AMD)
    {
      hwmon_ctx->hm_device[device_id].adl         = hm_adapters_adl[platform_devices_id].adl;
      hwmon_ctx->hm_device[device_id].sysfs       = hm_adapters_sysfs[platform_devices_id].sysfs;
      hwmon_ctx->hm_device[device_id].nvapi       = 0;
      hwmon_ctx->hm_device[device_id].nvml        = 0;
      hwmon_ctx->hm_device[device_id].xnvctrl     = 0;
      hwmon_ctx->hm_device[device_id].od_version  = 0;

      if (hwmon_ctx->hm_adl)
      {
        hwmon_ctx->hm_device[device_id].od_version = hm_adapters_adl[platform_devices_id].od_version;

        hwmon_ctx->hm_device[device_id].buslanes_get_supported            |= hm_adapters_adl[platform_devices_id].buslanes_get_supported;
        hwmon_ctx->hm_device[device_id].corespeed_get_supported           |= hm_adapters_adl[platform_devices_id].corespeed_get_supported;
        hwmon_ctx->hm_device[device_id].fanspeed_get_supported            |= hm_adapters_adl[platform_devices_id].fanspeed_get_supported;
        hwmon_ctx->hm_device[device_id].fanspeed_set_supported            |= hm_adapters_adl[platform_devices_id].fanspeed_set_supported;
        hwmon_ctx->hm_device[device_id].fanpolicy_get_supported           |= hm_adapters_adl[platform_devices_id].fanpolicy_get_supported;
        hwmon_ctx->hm_device[device_id].fanpolicy_set_supported           |= hm_adapters_adl[platform_devices_id].fanpolicy_set_supported;
        hwmon_ctx->hm_device[device_id].memoryspeed_get_supported         |= hm_adapters_adl[platform_devices_id].memoryspeed_get_supported;
        hwmon_ctx->hm_device[device_id].temperature_get_supported         |= hm_adapters_adl[platform_devices_id].temperature_get_supported;
        hwmon_ctx->hm_device[device_id].threshold_shutdown_get_supported  |= hm_adapters_adl[platform_devices_id].threshold_shutdown_get_supported;
        hwmon_ctx->hm_device[device_id].threshold_slowdown_get_supported  |= hm_adapters_adl[platform_devices_id].threshold_slowdown_get_supported;
        hwmon_ctx->hm_device[device_id].throttle_get_supported            |= hm_adapters_adl[platform_devices_id].throttle_get_supported;
        hwmon_ctx->hm_device[device_id].utilization_get_supported         |= hm_adapters_adl[platform_devices_id].utilization_get_supported;
      }

      if (hwmon_ctx->hm_sysfs)
      {
        hwmon_ctx->hm_device[device_id].buslanes_get_supported            |= hm_adapters_sysfs[platform_devices_id].buslanes_get_supported;
        hwmon_ctx->hm_device[device_id].corespeed_get_supported           |= hm_adapters_sysfs[platform_devices_id].corespeed_get_supported;
        hwmon_ctx->hm_device[device_id].fanspeed_get_supported            |= hm_adapters_sysfs[platform_devices_id].fanspeed_get_supported;
        hwmon_ctx->hm_device[device_id].fanspeed_set_supported            |= hm_adapters_sysfs[platform_devices_id].fanspeed_set_supported;
        hwmon_ctx->hm_device[device_id].fanpolicy_get_supported           |= hm_adapters_sysfs[platform_devices_id].fanpolicy_get_supported;
        hwmon_ctx->hm_device[device_id].fanpolicy_set_supported           |= hm_adapters_sysfs[platform_devices_id].fanpolicy_set_supported;
        hwmon_ctx->hm_device[device_id].memoryspeed_get_supported         |= hm_adapters_sysfs[platform_devices_id].memoryspeed_get_supported;
        hwmon_ctx->hm_device[device_id].temperature_get_supported         |= hm_adapters_sysfs[platform_devices_id].temperature_get_supported;
        hwmon_ctx->hm_device[device_id].threshold_shutdown_get_supported  |= hm_adapters_sysfs[platform_devices_id].threshold_shutdown_get_supported;
        hwmon_ctx->hm_device[device_id].threshold_slowdown_get_supported  |= hm_adapters_sysfs[platform_devices_id].threshold_slowdown_get_supported;
        hwmon_ctx->hm_device[device_id].throttle_get_supported            |= hm_adapters_sysfs[platform_devices_id].throttle_get_supported;
        hwmon_ctx->hm_device[device_id].utilization_get_supported         |= hm_adapters_sysfs[platform_devices_id].utilization_get_supported;
      }
    }

    if (device_param->device_vendor_id == VENDOR_ID_NV)
    {
      hwmon_ctx->hm_device[device_id].adl         = 0;
      hwmon_ctx->hm_device[device_id].sysfs       = 0;
      hwmon_ctx->hm_device[device_id].nvapi       = hm_adapters_nvapi[platform_devices_id].nvapi;
      hwmon_ctx->hm_device[device_id].nvml        = hm_adapters_nvml[platform_devices_id].nvml;
      hwmon_ctx->hm_device[device_id].xnvctrl     = hm_adapters_xnvctrl[platform_devices_id].xnvctrl;
      hwmon_ctx->hm_device[device_id].od_version  = 0;

      if (hwmon_ctx->hm_nvml)
      {
        hwmon_ctx->hm_device[device_id].buslanes_get_supported            |= hm_adapters_nvml[platform_devices_id].buslanes_get_supported;
        hwmon_ctx->hm_device[device_id].corespeed_get_supported           |= hm_adapters_nvml[platform_devices_id].corespeed_get_supported;
        hwmon_ctx->hm_device[device_id].fanspeed_get_supported            |= hm_adapters_nvml[platform_devices_id].fanspeed_get_supported;
        hwmon_ctx->hm_device[device_id].fanspeed_set_supported            |= hm_adapters_nvml[platform_devices_id].fanspeed_set_supported;
        hwmon_ctx->hm_device[device_id].fanpolicy_get_supported           |= hm_adapters_nvml[platform_devices_id].fanpolicy_get_supported;
        hwmon_ctx->hm_device[device_id].fanpolicy_set_supported           |= hm_adapters_nvml[platform_devices_id].fanpolicy_set_supported;
        hwmon_ctx->hm_device[device_id].memoryspeed_get_supported         |= hm_adapters_nvml[platform_devices_id].memoryspeed_get_supported;
        hwmon_ctx->hm_device[device_id].temperature_get_supported         |= hm_adapters_nvml[platform_devices_id].temperature_get_supported;
        hwmon_ctx->hm_device[device_id].threshold_shutdown_get_supported  |= hm_adapters_nvml[platform_devices_id].threshold_shutdown_get_supported;
        hwmon_ctx->hm_device[device_id].threshold_slowdown_get_supported  |= hm_adapters_nvml[platform_devices_id].threshold_slowdown_get_supported;
        hwmon_ctx->hm_device[device_id].throttle_get_supported            |= hm_adapters_nvml[platform_devices_id].throttle_get_supported;
        hwmon_ctx->hm_device[device_id].utilization_get_supported         |= hm_adapters_nvml[platform_devices_id].utilization_get_supported;
      }

      if (hwmon_ctx->hm_nvapi)
      {
        hwmon_ctx->hm_device[device_id].buslanes_get_supported            |= hm_adapters_nvapi[platform_devices_id].buslanes_get_supported;
        hwmon_ctx->hm_device[device_id].corespeed_get_supported           |= hm_adapters_nvapi[platform_devices_id].corespeed_get_supported;
        hwmon_ctx->hm_device[device_id].fanspeed_get_supported            |= hm_adapters_nvapi[platform_devices_id].fanspeed_get_supported;
        hwmon_ctx->hm_device[device_id].fanspeed_set_supported            |= hm_adapters_nvapi[platform_devices_id].fanspeed_set_supported;
        hwmon_ctx->hm_device[device_id].fanpolicy_get_supported           |= hm_adapters_nvapi[platform_devices_id].fanpolicy_get_supported;
        hwmon_ctx->hm_device[device_id].fanpolicy_set_supported           |= hm_adapters_nvapi[platform_devices_id].fanpolicy_set_supported;
        hwmon_ctx->hm_device[device_id].memoryspeed_get_supported         |= hm_adapters_nvapi[platform_devices_id].memoryspeed_get_supported;
        hwmon_ctx->hm_device[device_id].temperature_get_supported         |= hm_adapters_nvapi[platform_devices_id].temperature_get_supported;
        hwmon_ctx->hm_device[device_id].threshold_shutdown_get_supported  |= hm_adapters_nvapi[platform_devices_id].threshold_shutdown_get_supported;
        hwmon_ctx->hm_device[device_id].threshold_slowdown_get_supported  |= hm_adapters_nvapi[platform_devices_id].threshold_slowdown_get_supported;
        hwmon_ctx->hm_device[device_id].throttle_get_supported            |= hm_adapters_nvapi[platform_devices_id].throttle_get_supported;
        hwmon_ctx->hm_device[device_id].utilization_get_supported         |= hm_adapters_nvapi[platform_devices_id].utilization_get_supported;
      }

      if (hwmon_ctx->hm_xnvctrl)
      {
        hwmon_ctx->hm_device[device_id].buslanes_get_supported            |= hm_adapters_xnvctrl[platform_devices_id].buslanes_get_supported;
        hwmon_ctx->hm_device[device_id].corespeed_get_supported           |= hm_adapters_xnvctrl[platform_devices_id].corespeed_get_supported;
        hwmon_ctx->hm_device[device_id].fanspeed_get_supported            |= hm_adapters_xnvctrl[platform_devices_id].fanspeed_get_supported;
        hwmon_ctx->hm_device[device_id].fanspeed_set_supported            |= hm_adapters_xnvctrl[platform_devices_id].fanspeed_set_supported;
        hwmon_ctx->hm_device[device_id].fanpolicy_get_supported           |= hm_adapters_xnvctrl[platform_devices_id].fanpolicy_get_supported;
        hwmon_ctx->hm_device[device_id].fanpolicy_set_supported           |= hm_adapters_xnvctrl[platform_devices_id].fanpolicy_set_supported;
        hwmon_ctx->hm_device[device_id].memoryspeed_get_supported         |= hm_adapters_xnvctrl[platform_devices_id].memoryspeed_get_supported;
        hwmon_ctx->hm_device[device_id].temperature_get_supported         |= hm_adapters_xnvctrl[platform_devices_id].temperature_get_supported;
        hwmon_ctx->hm_device[device_id].threshold_shutdown_get_supported  |= hm_adapters_xnvctrl[platform_devices_id].threshold_shutdown_get_supported;
        hwmon_ctx->hm_device[device_id].threshold_slowdown_get_supported  |= hm_adapters_xnvctrl[platform_devices_id].threshold_slowdown_get_supported;
        hwmon_ctx->hm_device[device_id].throttle_get_supported            |= hm_adapters_xnvctrl[platform_devices_id].throttle_get_supported;
        hwmon_ctx->hm_device[device_id].utilization_get_supported         |= hm_adapters_xnvctrl[platform_devices_id].utilization_get_supported;
      }
    }

    // by calling the different functions here this will disable them in case they will error out
    // this will also reduce the error itself printed to the user to a single print on startup

    hm_get_buslanes_with_device_id            (hashcat_ctx, device_id);
    hm_get_corespeed_with_device_id           (hashcat_ctx, device_id);
    hm_get_fanpolicy_with_device_id           (hashcat_ctx, device_id);
    hm_get_fanspeed_with_device_id            (hashcat_ctx, device_id);
    hm_get_memoryspeed_with_device_id         (hashcat_ctx, device_id);
    hm_get_temperature_with_device_id         (hashcat_ctx, device_id);
    hm_get_threshold_shutdown_with_device_id  (hashcat_ctx, device_id);
    hm_get_threshold_slowdown_with_device_id  (hashcat_ctx, device_id);
    hm_get_throttle_with_device_id            (hashcat_ctx, device_id);
    hm_get_utilization_with_device_id         (hashcat_ctx, device_id);
  }

  FREE_ADAPTERS;

  /**
   * powertune on user request
   */

  if (user_options->powertune_enable == true)
  {
    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped == true) continue;

      if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

      if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
      {
        if (hwmon_ctx->hm_adl)
        {
          /**
           * Temporary fix:
           * with AMD r9 295x cards it seems that we need to set the powertune value just AFTER the ocl init stuff
           * otherwise after hc_clCreateContext () etc, powertune value was set back to "normal" and cards unfortunately
           * were not working @ full speed (setting hm_ADL_Overdrive_PowerControl_Set () here seems to fix the problem)
           * Driver / ADL bug?
           */

          if (hwmon_ctx->hm_device[device_id].od_version == 6)
          {
            int ADL_rc;

            // check powertune capabilities first, if not available then skip device

            int powertune_supported = 0;

            ADL_rc = hm_ADL_Overdrive6_PowerControl_Caps (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &powertune_supported);

            if (ADL_rc == ADL_ERR)
            {
              event_log_error (hashcat_ctx, "Failed to get ADL PowerControl capabilities.");

              return -1;
            }

            // first backup current value, we will restore it later

            if (powertune_supported != 0)
            {
              // powercontrol settings

              ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

              ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &powertune);

              if (ADL_rc == ADL_ERR)
              {
                event_log_error (hashcat_ctx, "Failed to get current ADL PowerControl values.");

                return -1;
              }

              ADL_rc = hm_ADL_Overdrive_PowerControl_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &hwmon_ctx->od_power_control_status[device_id]);

              if (ADL_rc == ADL_ERR)
              {
                event_log_error (hashcat_ctx, "Failed to get current ADL PowerControl values.");

                return -1;
              }

              ADL_rc = hm_ADL_Overdrive_PowerControl_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, powertune.iMaxValue);

              if (ADL_rc == ADL_ERR)
              {
                event_log_error (hashcat_ctx, "Failed to set new ADL PowerControl values.");

                return -1;
              }

              // clocks

              memset (&hwmon_ctx->od_clock_mem_status[device_id], 0, sizeof (ADLOD6MemClockState));

              hwmon_ctx->od_clock_mem_status[device_id].state.iNumberOfPerformanceLevels = 2;

              ADL_rc = hm_ADL_Overdrive_StateInfo_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, ADL_OD6_GETSTATEINFO_CUSTOM_PERFORMANCE, &hwmon_ctx->od_clock_mem_status[device_id]);

              if (ADL_rc == ADL_ERR)
              {
                event_log_error (hashcat_ctx, "Failed to get ADL memory and engine clock frequency.");

                return -1;
              }

              // Query capabilities only to see if profiles were not "damaged", if so output a warning but do accept the users profile settings

              ADLOD6Capabilities caps = {0, 0, 0, {0, 0, 0}, {0, 0, 0}, 0, 0};

              ADL_rc = hm_ADL_Overdrive_Capabilities_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &caps);

              if (ADL_rc == ADL_ERR)
              {
                event_log_error (hashcat_ctx, "Failed to get ADL device capabilities.");

                return -1;
              }

              int engine_clock_max =       (int) (0.6666f * caps.sEngineClockRange.iMax);
              int memory_clock_max =       (int) (0.6250f * caps.sMemoryClockRange.iMax);

              int warning_trigger_engine = (int) (0.25f   * engine_clock_max);
              int warning_trigger_memory = (int) (0.25f   * memory_clock_max);

              int engine_clock_profile_max = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iEngineClock;
              int memory_clock_profile_max = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iMemoryClock;

              // warning if profile has too low max values

              if ((engine_clock_max - engine_clock_profile_max) > warning_trigger_engine)
              {
                event_log_error (hashcat_ctx, "Custom profile has low maximum engine clock value. Expect reduced performance.");
              }

              if ((memory_clock_max - memory_clock_profile_max) > warning_trigger_memory)
              {
                event_log_error (hashcat_ctx, "Custom profile has low maximum memory clock value. Expect reduced performance.");
              }

              ADLOD6StateInfo *performance_state = (ADLOD6StateInfo*) hccalloc (1, sizeof (ADLOD6StateInfo) + sizeof (ADLOD6PerformanceLevel));

              performance_state->iNumberOfPerformanceLevels = 2;

              performance_state->aLevels[0].iEngineClock = engine_clock_profile_max;
              performance_state->aLevels[1].iEngineClock = engine_clock_profile_max;
              performance_state->aLevels[0].iMemoryClock = memory_clock_profile_max;
              performance_state->aLevels[1].iMemoryClock = memory_clock_profile_max;

              ADL_rc = hm_ADL_Overdrive_State_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, ADL_OD6_SETSTATE_PERFORMANCE, performance_state);

              if (ADL_rc == ADL_ERR)
              {
                event_log_error (hashcat_ctx, "Failed to set ADL performance state.");

                return -1;
              }

              hcfree (performance_state);
            }

            // set powertune value only

            if (powertune_supported != 0)
            {
              // powertune set
              ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

              ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &powertune);

              if (ADL_rc == ADL_ERR)
              {
                event_log_error (hashcat_ctx, "Failed to get current ADL PowerControl settings.");

                return -1;
              }

              ADL_rc = hm_ADL_Overdrive_PowerControl_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, powertune.iMaxValue);

              if (ADL_rc == ADL_ERR)
              {
                event_log_error (hashcat_ctx, "Failed to set new ADL PowerControl values.");

                return -1;
              }
            }
          }
        }

        if (hwmon_ctx->hm_sysfs)
        {
          hm_SYSFS_set_power_dpm_force_performance_level (hashcat_ctx, device_id, "high");
        }
      }

      if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
      {
        // first backup current value, we will restore it later

        unsigned int limit;

        bool powertune_supported = false;

        if (hm_NVML_nvmlDeviceGetPowerManagementLimit (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &limit) == NVML_SUCCESS)
        {
          powertune_supported = true;
        }

        // if backup worked, activate the maximum allowed

        if (powertune_supported == true)
        {
          unsigned int minLimit;
          unsigned int maxLimit;

          if (hm_NVML_nvmlDeviceGetPowerManagementLimitConstraints (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &minLimit, &maxLimit) == NVML_SUCCESS)
          {
            if (maxLimit > 0)
            {
              if (hm_NVML_nvmlDeviceSetPowerManagementLimit (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, maxLimit) == NVML_SUCCESS)
              {
                // now we can be sure we need to reset later

                hwmon_ctx->nvml_power_limit[device_id] = limit;
              }
            }
          }
        }
      }
    }
  }

  /**
   * Store initial fanspeed if gpu_temp_retain is enabled
   */

  if (user_options->gpu_temp_retain > 0)
  {
    bool one_success = false;

    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped == true) continue;

      if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

      if (hwmon_ctx->hm_device[device_id].fanspeed_get_supported == false) continue;
      if (hwmon_ctx->hm_device[device_id].fanspeed_set_supported == false) continue;

      const int fanspeed = hm_get_fanspeed_with_device_id (hashcat_ctx, device_id);

      if (fanspeed == -1) continue;

      if (device_param->device_vendor_id == VENDOR_ID_AMD)
      {
        if (hwmon_ctx->hm_adl)
        {
          hm_set_fanspeed_with_device_id_adl (hashcat_ctx, device_id, fanspeed, 1);
        }

        if (hwmon_ctx->hm_sysfs)
        {
          hm_set_fanctrl_with_device_id_sysfs (hashcat_ctx, device_id, 1);

          hm_set_fanspeed_with_device_id_sysfs (hashcat_ctx, device_id, fanspeed);
        }
      }
      else if (device_param->device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_xnvctrl)
        {
          hm_set_fanctrl_with_device_id_xnvctrl (hashcat_ctx, device_id, NV_CTRL_GPU_COOLER_MANUAL_CONTROL_TRUE);

          hm_set_fanspeed_with_device_id_xnvctrl (hashcat_ctx, device_id, fanspeed);
        }

        if (hwmon_ctx->hm_nvapi)
        {
          hm_set_fanspeed_with_device_id_nvapi (hashcat_ctx, device_id, fanspeed, 1);
        }
      }

      if ((hwmon_ctx->hm_device[device_id].fanpolicy_set_supported == true) && (hwmon_ctx->hm_device[device_id].fanspeed_set_supported == true)) one_success = true;
    }

    if (one_success == false) user_options->gpu_temp_retain = 0;
  }

  return 0;
}

void hwmon_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t    *hwmon_ctx    = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t   *opencl_ctx   = hashcat_ctx->opencl_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (hwmon_ctx->enabled == false) return;

  // reset default fan speed

  if (user_options->gpu_temp_retain > 0)
  {
    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped == true) continue;

      if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

      if (hwmon_ctx->hm_device[device_id].fanspeed_get_supported == false) continue;
      if (hwmon_ctx->hm_device[device_id].fanspeed_set_supported == false) continue;

      int rc = -1;

      if (device_param->device_vendor_id == VENDOR_ID_AMD)
      {
        if (hwmon_ctx->hm_adl)
        {
          rc = hm_set_fanspeed_with_device_id_adl (hashcat_ctx, device_id, 100, 0);
        }

        if (hwmon_ctx->hm_sysfs)
        {
          rc = hm_set_fanctrl_with_device_id_sysfs (hashcat_ctx, device_id, 2);
        }
      }
      else if (device_param->device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_xnvctrl)
        {
          rc = hm_set_fanctrl_with_device_id_xnvctrl (hashcat_ctx, device_id, NV_CTRL_GPU_COOLER_MANUAL_CONTROL_FALSE);
        }

        if (hwmon_ctx->hm_nvapi)
        {
          rc = hm_set_fanspeed_with_device_id_nvapi (hashcat_ctx, device_id, 100, 0);
        }
      }

      if (rc == -1) event_log_error (hashcat_ctx, "Failed to restore default fan speed and policy for device #%u", device_id + 1);
    }
  }

  // reset power tuning

  if (user_options->powertune_enable == true)
  {
    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped == true) continue;

      if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

      if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
      {
        if (hwmon_ctx->hm_adl)
        {
          if (hwmon_ctx->hm_device[device_id].od_version == 6)
          {
            // check powertune capabilities first, if not available then skip device

            int powertune_supported = 0;

            if ((hm_ADL_Overdrive6_PowerControl_Caps (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &powertune_supported)) == -1)
            {
              //event_log_error (hashcat_ctx, "Failed to get ADL PowerControl capabilities.");

              continue;
            }

            if (powertune_supported != 0)
            {
              // powercontrol settings

              if ((hm_ADL_Overdrive_PowerControl_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, hwmon_ctx->od_power_control_status[device_id])) == -1)
              {
                //event_log_error (hashcat_ctx, "Failed to restore the ADL PowerControl values.");

                continue;
              }

              // clocks

              ADLOD6StateInfo *performance_state = (ADLOD6StateInfo*) hccalloc (1, sizeof (ADLOD6StateInfo) + sizeof (ADLOD6PerformanceLevel));

              performance_state->iNumberOfPerformanceLevels = 2;

              performance_state->aLevels[0].iEngineClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[0].iEngineClock;
              performance_state->aLevels[1].iEngineClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iEngineClock;
              performance_state->aLevels[0].iMemoryClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[0].iMemoryClock;
              performance_state->aLevels[1].iMemoryClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iMemoryClock;

              if ((hm_ADL_Overdrive_State_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, ADL_OD6_SETSTATE_PERFORMANCE, performance_state)) == -1)
              {
                //event_log_error (hashcat_ctx, "Failed to restore ADL performance state.");

                continue;
              }

              hcfree (performance_state);
            }
          }
        }

        if (hwmon_ctx->hm_sysfs)
        {
          hm_SYSFS_set_power_dpm_force_performance_level (hashcat_ctx, device_id, "auto");
        }
      }

      if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
      {
        unsigned int power_limit = hwmon_ctx->nvml_power_limit[device_id];

        if (power_limit > 0)
        {
          hm_NVML_nvmlDeviceSetPowerManagementLimit (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, power_limit);
        }
      }
    }
  }

  // unload shared libraries

  if (hwmon_ctx->hm_nvml)
  {
    hm_NVML_nvmlShutdown (hashcat_ctx);

    nvml_close (hashcat_ctx);
  }

  if (hwmon_ctx->hm_nvapi)
  {
    hm_NvAPI_Unload (hashcat_ctx);

    nvapi_close (hashcat_ctx);
  }

  if (hwmon_ctx->hm_xnvctrl)
  {
    hm_XNVCTRL_XCloseDisplay (hashcat_ctx);

    xnvctrl_close (hashcat_ctx);
  }

  if (hwmon_ctx->hm_adl)
  {
    hm_ADL_Main_Control_Destroy (hashcat_ctx);

    adl_close (hashcat_ctx);
  }

  if (hwmon_ctx->hm_sysfs)
  {

    sysfs_close (hashcat_ctx);
  }

  // free memory

  hcfree (hwmon_ctx->nvml_power_limit);
  hcfree (hwmon_ctx->od_power_control_status);
  hcfree (hwmon_ctx->od_clock_mem_status);

  hcfree (hwmon_ctx->hm_device);

  memset (hwmon_ctx, 0, sizeof (hwmon_ctx_t));
}
