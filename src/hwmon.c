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

  char *path;

  hc_asprintf (&path, "%s", SYS_BUS_PCI_DEVICES);

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
}

static char *hm_SYSFS_get_syspath_device (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  hc_device_param_t *device_param = &backend_ctx->devices_param[backend_device_idx];

  char *syspath;

  hc_asprintf (&syspath, "%s/0000:%02x:%02x.%01x", SYS_BUS_PCI_DEVICES, device_param->pcie_bus, device_param->pcie_device, device_param->pcie_function);

  return syspath;
}

static char *hm_SYSFS_get_syspath_hwmon (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  char *syspath = hm_SYSFS_get_syspath_device (hashcat_ctx, backend_device_idx);

  if (syspath == NULL)
  {
    event_log_error (hashcat_ctx, "hm_SYSFS_get_syspath_device() failed.");

    return NULL;
  }

  char *hwmon = hcmalloc (HCBUFSIZ_TINY);

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

static int hm_SYSFS_get_fan_speed_current (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_get_syspath_hwmon (hashcat_ctx, backend_device_idx);

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

static int hm_SYSFS_get_temperature_current (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_get_syspath_hwmon (hashcat_ctx, backend_device_idx);

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

static int hm_SYSFS_get_pp_dpm_sclk (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_get_syspath_device (hashcat_ctx, backend_device_idx);

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

static int hm_SYSFS_get_pp_dpm_mclk (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_get_syspath_device (hashcat_ctx, backend_device_idx);

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

static int hm_SYSFS_get_pp_dpm_pcie (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, int *val)
{
  char *syspath = hm_SYSFS_get_syspath_device (hashcat_ctx, backend_device_idx);

  if (syspath == NULL) return -1;

  char *path;

  hc_asprintf (&path, "%s/pp_dpm_pcie", syspath);

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

    if (ptr[len - 2] != '*') continue;

    int   profile = 0;
    float speed = 0;

    int rc = sscanf (ptr, "%d: %fGB, x%d *", &profile, &speed, &lanes);

    if (rc == 3) break;
  }

  hc_fclose (&fp);

  *val = lanes;

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

  nvml->lib = hc_dlopen("nvml.dll");

  if (!nvml->lib)
  {
    HCFILE nvml_lib;

    if (hc_fopen (&nvml_lib, "/proc/registry/HKEY_LOCAL_MACHINE/SOFTWARE/NVIDIA Corporation/Global/NVSMI/NVSMIPATH", "rb") == false)
    {
      //if (user_options->quiet == false)
      //  event_log_error (hashcat_ctx, "NVML library load failed: %m. Proceeding without NVML HWMon enabled.");

      return -1;
    }

    char *nvml_winpath, *nvml_cygpath;

    nvml_winpath = (char *) hcmalloc (100);

    hc_fread (nvml_winpath, 100, 1, &nvml_lib);

    hc_fclose (&nvml_lib);

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

    nvml->lib = hc_dlopen (nvml_cygpath);
  }

  #elif defined (_POSIX)

  nvml->lib = hc_dlopen ("libnvidia-ml.so");

  if (!nvml->lib)
  {
    nvml->lib = hc_dlopen ("libnvidia-ml.so.1");
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
  HC_LOAD_FUNC(nvml, nvmlDeviceGetUtilizationRates, NVML_DEVICE_GET_UTILIZATION_RATES, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetClockInfo, NVML_DEVICE_GET_CLOCKINFO, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetTemperatureThreshold, NVML_DEVICE_GET_THRESHOLD, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetCurrPcieLinkGeneration, NVML_DEVICE_GET_CURRPCIELINKGENERATION, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetCurrPcieLinkWidth, NVML_DEVICE_GET_CURRPCIELINKWIDTH, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetCurrentClocksThrottleReasons, NVML_DEVICE_GET_CURRENTCLOCKSTHROTTLEREASONS, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlDeviceGetSupportedClocksThrottleReasons, NVML_DEVICE_GET_SUPPORTEDCLOCKSTHROTTLEREASONS, NVML, 0)
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
  nvapi->lib = hc_dlopen ("nvapi64.dll");
  #else
  nvapi->lib = hc_dlopen ("nvapi.dll");
  #endif

  #else
  nvapi->lib = hc_dlopen ("nvapi.so"); // uhm yes, but .. yeah
  #endif

  #endif

  if (!nvapi->lib)
  {
    //if (user_options->quiet == false)
    //  event_log_error (hashcat_ctx, "Load of NVAPI library failed. Proceeding without NVAPI HWMon enabled.");

    return -1;
  }

  HC_LOAD_FUNC(nvapi, nvapi_QueryInterface,             NVAPI_QUERYINTERFACE,             NVAPI,                0)
  HC_LOAD_ADDR(nvapi, NvAPI_Initialize,                 NVAPI_INITIALIZE,                 nvapi_QueryInterface, 0x0150E828U, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_Unload,                     NVAPI_UNLOAD,                     nvapi_QueryInterface, 0xD22BDD7EU, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GetErrorMessage,            NVAPI_GETERRORMESSAGE,            nvapi_QueryInterface, 0x6C2D048CU, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_EnumPhysicalGPUs,           NVAPI_ENUMPHYSICALGPUS,           nvapi_QueryInterface, 0xE5AC921FU, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetPerfPoliciesInfo,    NVAPI_GPU_GETPERFPOLICIESINFO,    nvapi_QueryInterface, 0x409D9841U, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetPerfPoliciesStatus,  NVAPI_GPU_GETPERFPOLICIESSTATUS,  nvapi_QueryInterface, 0x3D358A0CU, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetBusId,               NVAPI_GPU_GETBUSID,               nvapi_QueryInterface, 0x1BE0B8E5U, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetBusSlotId,           NVAPI_GPU_GETBUSSLOTID,           nvapi_QueryInterface, 0x2A0A350FU, NVAPI, 0)

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
  adl->lib = hc_dlopen ("atiadlxx.dll");

  if (!adl->lib)
  {
    adl->lib = hc_dlopen ("atiadlxy.dll");
  }
  #elif defined (_POSIX)
  adl->lib = hc_dlopen ("libatiadlxx.so");
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
  HC_LOAD_FUNC(adl, ADL_Adapter_Active_Get, ADL_ADAPTER_ACTIVE_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive_Caps, ADL_OVERDRIVE_CAPS, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_Capabilities_Get, ADL_OVERDRIVE6_CAPABILITIES_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_StateInfo_Get, ADL_OVERDRIVE6_STATEINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_CurrentStatus_Get, ADL_OVERDRIVE6_CURRENTSTATUS_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_TargetTemperatureData_Get, ADL_OVERDRIVE6_TARGETTEMPERATUREDATA_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_TargetTemperatureRangeInfo_Get, ADL_OVERDRIVE6_TARGETTEMPERATURERANGEINFO_GET, ADL, 0)

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

int hm_get_threshold_slowdown_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].threshold_slowdown_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int target = 0;

      if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, (unsigned int *) &target) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].threshold_slowdown_get_supported = false;

        return -1;
      }

      return target;
    }
  }

  if (backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if ((backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
        {

        }
        else if (hwmon_ctx->hm_device[backend_device_idx].od_version == 6)
        {
          int CurrentValue = 0;
          int DefaultValue = 0;

          if (hm_ADL_Overdrive6_TargetTemperatureData_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &CurrentValue, &DefaultValue) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].threshold_slowdown_get_supported = false;

            return -1;
          }

          // the return value has never been tested since hm_ADL_Overdrive6_TargetTemperatureData_Get() never worked on any system. expect problems.

          return DefaultValue;
        }
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (hwmon_ctx->hm_nvml)
      {
        int target = 0;

        if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, (unsigned int *) &target) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].threshold_slowdown_get_supported = false;

          return -1;
        }

        return target;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].threshold_slowdown_get_supported = false;

  return -1;
}

int hm_get_threshold_shutdown_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].threshold_shutdown_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int target = 0;

      if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_THRESHOLD_SHUTDOWN, (unsigned int *) &target) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].threshold_shutdown_get_supported = false;

        return -1;
      }

      return target;
    }
  }

  if (backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if ((backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
        {

        }
        else if (hwmon_ctx->hm_device[backend_device_idx].od_version == 6)
        {

        }
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (hwmon_ctx->hm_nvml)
      {
        int target = 0;

        if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_THRESHOLD_SHUTDOWN, (unsigned int *) &target) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].threshold_shutdown_get_supported = false;

          return -1;
        }

        return target;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].threshold_shutdown_get_supported = false;

  return -1;
}

int hm_get_temperature_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int temperature = 0;

      if (hm_NVML_nvmlDeviceGetTemperature (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_GPU, (u32 *) &temperature) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

        return -1;
      }

      return temperature;
    }
  }

  if (backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if ((backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
        {
          ADLTemperature Temperature;

          Temperature.iSize = sizeof (ADLTemperature);

          if (hm_ADL_Overdrive5_Temperature_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, 0, &Temperature) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

            return -1;
          }

          return Temperature.iTemperature / 1000;
        }

        if (hwmon_ctx->hm_device[backend_device_idx].od_version == 6)
        {
          int Temperature = 0;

          if (hm_ADL_Overdrive6_Temperature_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &Temperature) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

            return -1;
          }

          return Temperature / 1000;
        }
      }

      if (hwmon_ctx->hm_sysfs)
      {
        int temperature = 0;

        if (hm_SYSFS_get_temperature_current (hashcat_ctx, backend_device_idx, &temperature) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

          return -1;
        }

        return temperature;
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (hwmon_ctx->hm_nvml)
      {
        int temperature = 0;

        if (hm_NVML_nvmlDeviceGetTemperature (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_GPU, (u32 *) &temperature) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

          return -1;
        }

        return temperature;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

  return -1;
}

int hm_get_fanpolicy_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].fanpolicy_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    return 1;
  }

  if (backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if ((backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;

          if (hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, 0, &lpFanSpeedValue) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].fanpolicy_get_supported = false;
            hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported  = false;

            return -1;
          }

          return (lpFanSpeedValue.iFanSpeed & ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED) ? 0 : 1;
        }

        if (hwmon_ctx->hm_device[backend_device_idx].od_version == 6)
        {
          return 1;
        }
      }

      if (hwmon_ctx->hm_sysfs)
      {
        return 1;
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
    {
      return 1;
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].fanpolicy_get_supported = false;
  hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported  = false;

  return -1;
}

int hm_get_fanspeed_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int speed = 0;

      if (hm_NVML_nvmlDeviceGetFanSpeed (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, (u32 *) &speed) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

        return -1;
      }

      return speed;
    }
  }

  if (backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if ((backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
          lpFanSpeedValue.iFlags     = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;

          if (hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, 0, &lpFanSpeedValue) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

            return -1;
          }

          return lpFanSpeedValue.iFanSpeed;
        }

        if (hwmon_ctx->hm_device[backend_device_idx].od_version == 6)
        {
          ADLOD6FanSpeedInfo faninfo;

          memset (&faninfo, 0, sizeof (faninfo));

          if (hm_ADL_Overdrive6_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &faninfo) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

            return -1;
          }

          return faninfo.iFanSpeedPercent;
        }
      }

      if (hwmon_ctx->hm_sysfs)
      {
        int speed = 0;

        if (hm_SYSFS_get_fan_speed_current (hashcat_ctx, backend_device_idx, &speed) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

          return -1;
        }

        return speed;
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (hwmon_ctx->hm_nvml)
      {
        int speed = 0;

        if (hm_NVML_nvmlDeviceGetFanSpeed (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, (u32 *) &speed) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

          return -1;
        }

        return speed;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

  return -1;
}

int hm_get_buslanes_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int currLinkWidth;

      if (hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &currLinkWidth) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

        return -1;
      }

      return currLinkWidth;
    }
  }

  if (backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if ((backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        ADLPMActivity PMActivity;

        PMActivity.iSize = sizeof (ADLPMActivity);

        if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &PMActivity) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

          return -1;
        }

        return PMActivity.iCurrentBusLanes;
      }

      if (hwmon_ctx->hm_sysfs)
      {
        int lanes;

        if (hm_SYSFS_get_pp_dpm_pcie (hashcat_ctx, backend_device_idx, &lanes) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

          return -1;
        }

        return lanes;
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (hwmon_ctx->hm_nvml)
      {
        unsigned int currLinkWidth;

        if (hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &currLinkWidth) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

          return -1;
        }

        return currLinkWidth;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

  return -1;
}

int hm_get_utilization_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      nvmlUtilization_t utilization;

      if (hm_NVML_nvmlDeviceGetUtilizationRates (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &utilization) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

        return -1;
      }

      return utilization.gpu;
    }
  }

  if (backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if ((backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        ADLPMActivity PMActivity;

        PMActivity.iSize = sizeof (ADLPMActivity);

        if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &PMActivity) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

          return -1;
        }

        return PMActivity.iActivityPercent;
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (hwmon_ctx->hm_nvml)
      {
        nvmlUtilization_t utilization;

        if (hm_NVML_nvmlDeviceGetUtilizationRates (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &utilization) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

          return -1;
        }

        return utilization.gpu;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

  return -1;
}

int hm_get_memoryspeed_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int clockfreq;

      if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_CLOCK_MEM, &clockfreq) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

        return -1;
      }

      return clockfreq;
    }
  }

  if (backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if ((backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        ADLPMActivity PMActivity;

        PMActivity.iSize = sizeof (ADLPMActivity);

        if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &PMActivity) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

          return -1;
        }

        return PMActivity.iMemoryClock / 100;
      }

      if (hwmon_ctx->hm_sysfs)
      {
        int clockfreq;

        if (hm_SYSFS_get_pp_dpm_mclk (hashcat_ctx, backend_device_idx, &clockfreq) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

          return -1;
        }

        return clockfreq;
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (hwmon_ctx->hm_nvml)
      {
        unsigned int clockfreq;

        if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_CLOCK_MEM, &clockfreq) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

          return -1;
        }

        return clockfreq;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

  return -1;
}

int hm_get_corespeed_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int clockfreq;

      if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_CLOCK_SM, &clockfreq) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

        return -1;
      }

      return clockfreq;
    }
  }

  if (backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if ((backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        ADLPMActivity PMActivity;

        PMActivity.iSize = sizeof (ADLPMActivity);

        if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &PMActivity) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

          return -1;
        }

        return PMActivity.iEngineClock / 100;
      }

      if (hwmon_ctx->hm_sysfs)
      {
        int clockfreq;

        if (hm_SYSFS_get_pp_dpm_sclk (hashcat_ctx, backend_device_idx, &clockfreq) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

          return -1;
        }

        return clockfreq;
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (hwmon_ctx->hm_nvml)
      {
        unsigned int clockfreq;

        if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_CLOCK_SM, &clockfreq) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

          return -1;
        }

        return clockfreq;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

  return -1;
}

int hm_get_throttle_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].throttle_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      /* this is triggered by mask generator, too. therefore useless
      unsigned long long clocksThrottleReasons = 0;
      unsigned long long supportedThrottleReasons = 0;

      if (hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons   (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &clocksThrottleReasons)    == -1) return -1;
      if (hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &supportedThrottleReasons) == -1) return -1;

      clocksThrottleReasons &=  supportedThrottleReasons;
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonGpuIdle;
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonApplicationsClocksSetting;
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonUnknown;

      if (backend_ctx->kernel_power_final)
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

      hm_NvAPI_GPU_GetPerfPoliciesInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvapi, &perfPolicies_info);

      perfPolicies_status.info_value = perfPolicies_info.info_value;

      hm_NvAPI_GPU_GetPerfPoliciesStatus (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvapi, &perfPolicies_status);

      return perfPolicies_status.throttle & 2;
    }
  }

  if (backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if ((backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD)
    {
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (hwmon_ctx->hm_nvml)
      {
        /* this is triggered by mask generator, too. therefore useless
        unsigned long long clocksThrottleReasons = 0;
        unsigned long long supportedThrottleReasons = 0;

        if (hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons   (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &clocksThrottleReasons)    == -1) return -1;
        if (hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &supportedThrottleReasons) == -1) return -1;

        clocksThrottleReasons &=  supportedThrottleReasons;
        clocksThrottleReasons &= ~nvmlClocksThrottleReasonGpuIdle;
        clocksThrottleReasons &= ~nvmlClocksThrottleReasonApplicationsClocksSetting;
        clocksThrottleReasons &= ~nvmlClocksThrottleReasonUnknown;

        if (backend_ctx->kernel_power_final)
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

        hm_NvAPI_GPU_GetPerfPoliciesInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvapi, &perfPolicies_info);

        perfPolicies_status.info_value = perfPolicies_info.info_value;

        hm_NvAPI_GPU_GetPerfPoliciesStatus (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvapi, &perfPolicies_status);

        return perfPolicies_status.throttle & 2;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].throttle_get_supported = false;

  return -1;
}

int hwmon_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t    *hwmon_ctx    = hashcat_ctx->hwmon_ctx;
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  hwmon_ctx->enabled = false;

  #if !defined (WITH_HWMON)
  return 0;
  #endif // WITH_HWMON

  if (user_options->example_hashes  == true) return 0;
  if (user_options->keyspace        == true) return 0;
  if (user_options->left            == true) return 0;
  if (user_options->backend_info    == true) return 0;
  if (user_options->show            == true) return 0;
  if (user_options->stdout_flag     == true) return 0;
  if (user_options->usage           == true) return 0;
  if (user_options->version         == true) return 0;
  if (user_options->hwmon_disable   == true) return 0;

  hwmon_ctx->hm_device = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));

  /**
   * Initialize shared libraries
   */

  hm_attrs_t *hm_adapters_adl   = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_nvapi = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_nvml  = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_sysfs = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));

  #define FREE_ADAPTERS         \
  {                             \
    hcfree (hm_adapters_adl);   \
    hcfree (hm_adapters_nvapi); \
    hcfree (hm_adapters_nvml);  \
    hcfree (hm_adapters_sysfs); \
  }

  if (backend_ctx->need_nvml == true)
  {
    hwmon_ctx->hm_nvml = (NVML_PTR *) hcmalloc (sizeof (NVML_PTR));

    if (nvml_init (hashcat_ctx) == -1)
    {
      hcfree (hwmon_ctx->hm_nvml);

      hwmon_ctx->hm_nvml = NULL;
    }
  }

  if ((backend_ctx->need_nvapi == true) && (hwmon_ctx->hm_nvml)) // nvapi can't work alone, we need nvml, too
  {
    hwmon_ctx->hm_nvapi = (NVAPI_PTR *) hcmalloc (sizeof (NVAPI_PTR));

    if (nvapi_init (hashcat_ctx) == -1)
    {
      hcfree (hwmon_ctx->hm_nvapi);

      hwmon_ctx->hm_nvapi = NULL;
    }
  }

  if (backend_ctx->need_adl == true)
  {
    hwmon_ctx->hm_adl = (ADL_PTR *) hcmalloc (sizeof (ADL_PTR));

    if (adl_init (hashcat_ctx) == -1)
    {
      hcfree (hwmon_ctx->hm_adl);

      hwmon_ctx->hm_adl = NULL;
    }
  }

  if (backend_ctx->need_sysfs == true)
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

      for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == true) continue;

        if (device_param->is_cuda == true)
        {
          for (int i = 0; i < tmp_in; i++)
          {
            nvmlPciInfo_t pci;

            int rc = hm_NVML_nvmlDeviceGetPciInfo (hashcat_ctx, nvmlGPUHandle[i], &pci);

            if (rc == -1) continue;

            if ((device_param->pcie_bus      == pci.bus)
             && (device_param->pcie_device   == (pci.device >> 3))
             && (device_param->pcie_function == (pci.device & 7)))
            {
              const u32 device_id = device_param->device_id;

              hm_adapters_nvml[device_id].nvml = nvmlGPUHandle[i];

              hm_adapters_nvml[device_id].buslanes_get_supported            = true;
              hm_adapters_nvml[device_id].corespeed_get_supported           = true;
              hm_adapters_nvml[device_id].fanspeed_get_supported            = true;
              hm_adapters_nvml[device_id].memoryspeed_get_supported         = true;
              hm_adapters_nvml[device_id].temperature_get_supported         = true;
              hm_adapters_nvml[device_id].threshold_shutdown_get_supported  = true;
              hm_adapters_nvml[device_id].threshold_slowdown_get_supported  = true;
              hm_adapters_nvml[device_id].utilization_get_supported         = true;
            }
          }
        }

        if (device_param->is_opencl == true)
        {
          if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

          if (device_param->opencl_device_vendor_id != VENDOR_ID_NV) continue;

          for (int i = 0; i < tmp_in; i++)
          {
            nvmlPciInfo_t pci;

            int rc = hm_NVML_nvmlDeviceGetPciInfo (hashcat_ctx, nvmlGPUHandle[i], &pci);

            if (rc == -1) continue;

            if ((device_param->pcie_bus      == pci.bus)
             && (device_param->pcie_device   == (pci.device >> 3))
             && (device_param->pcie_function == (pci.device & 7)))
            {
              const u32 device_id = device_param->device_id;

              hm_adapters_nvml[device_id].nvml = nvmlGPUHandle[i];

              hm_adapters_nvml[device_id].buslanes_get_supported            = true;
              hm_adapters_nvml[device_id].corespeed_get_supported           = true;
              hm_adapters_nvml[device_id].fanspeed_get_supported            = true;
              hm_adapters_nvml[device_id].memoryspeed_get_supported         = true;
              hm_adapters_nvml[device_id].temperature_get_supported         = true;
              hm_adapters_nvml[device_id].threshold_shutdown_get_supported  = true;
              hm_adapters_nvml[device_id].threshold_slowdown_get_supported  = true;
              hm_adapters_nvml[device_id].utilization_get_supported         = true;
            }
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

      for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == true) continue;

        if (device_param->is_cuda == true)
        {
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
              const u32 device_id = device_param->device_id;

              hm_adapters_nvapi[device_id].nvapi = nvGPUHandle[i];

              hm_adapters_nvapi[device_id].fanpolicy_get_supported  = true;
              hm_adapters_nvapi[device_id].throttle_get_supported   = true;
            }
          }
        }

        if (device_param->is_opencl == true)
        {
          if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

          if (device_param->opencl_device_vendor_id != VENDOR_ID_NV) continue;

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
              const u32 device_id = device_param->device_id;

              hm_adapters_nvapi[device_id].nvapi = nvGPUHandle[i];

              hm_adapters_nvapi[device_id].fanpolicy_get_supported  = true;
              hm_adapters_nvapi[device_id].throttle_get_supported   = true;
            }
          }
        }
      }

      hcfree (nvGPUHandle);
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

      for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == true) continue;

        if (device_param->is_cuda == true)
        {
          // nothing to do
        }

        if (device_param->is_opencl == true)
        {
          if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

          if (device_param->opencl_device_vendor_id != VENDOR_ID_AMD) continue;

          for (int i = 0; i < tmp_in; i++)
          {
            if ((device_param->pcie_bus      == lpAdapterInfo[i].iBusNumber)
             && (device_param->pcie_device   == (lpAdapterInfo[i].iDeviceNumber >> 3))
             && (device_param->pcie_function == (lpAdapterInfo[i].iDeviceNumber & 7)))
            {
              const u32 device_id = device_param->device_id;

              int od_supported = 0;
              int od_enabled   = 0;
              int od_version   = 0;

              hm_ADL_Overdrive_Caps (hashcat_ctx, lpAdapterInfo[i].iAdapterIndex, &od_supported, &od_enabled, &od_version);

              hm_adapters_adl[device_id].od_version = od_version;

              hm_adapters_adl[device_id].adl = lpAdapterInfo[i].iAdapterIndex;

              hm_adapters_adl[device_id].buslanes_get_supported            = true;
              hm_adapters_adl[device_id].corespeed_get_supported           = true;
              hm_adapters_adl[device_id].fanspeed_get_supported            = true;
              hm_adapters_adl[device_id].fanpolicy_get_supported           = true;
              hm_adapters_adl[device_id].memoryspeed_get_supported         = true;
              hm_adapters_adl[device_id].temperature_get_supported         = true;
              hm_adapters_adl[device_id].threshold_slowdown_get_supported  = true;
              hm_adapters_adl[device_id].utilization_get_supported         = true;
            }
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

      for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->is_cuda == true)
        {
          // nothing to do
        }

        if (device_param->is_opencl == true)
        {
          if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

          hm_adapters_sysfs[hm_adapters_id].sysfs = backend_devices_idx; // ????

          hm_adapters_sysfs[hm_adapters_id].buslanes_get_supported    = true;
          hm_adapters_sysfs[hm_adapters_id].corespeed_get_supported   = true;
          hm_adapters_sysfs[hm_adapters_id].fanspeed_get_supported    = true;
          hm_adapters_sysfs[hm_adapters_id].fanpolicy_get_supported   = true;
          hm_adapters_sysfs[hm_adapters_id].memoryspeed_get_supported = true;
          hm_adapters_sysfs[hm_adapters_id].temperature_get_supported = true;

          hm_adapters_id++;
        }
      }
    }
  }

  if (hwmon_ctx->hm_adl == NULL && hwmon_ctx->hm_nvml == NULL && hwmon_ctx->hm_sysfs == NULL)
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

  hwmon_ctx->od_clock_mem_status = (ADLOD6MemClockState *) hccalloc (backend_ctx->backend_devices_cnt, sizeof (ADLOD6MemClockState));

  /**
   * HM devices: copy
   */

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;

    const u32 device_id = device_param->device_id;

    if (device_param->is_cuda == true)
    {
      hwmon_ctx->hm_device[backend_devices_idx].adl         = 0;
      hwmon_ctx->hm_device[backend_devices_idx].sysfs       = 0;
      hwmon_ctx->hm_device[backend_devices_idx].nvapi       = hm_adapters_nvapi[device_id].nvapi;
      hwmon_ctx->hm_device[backend_devices_idx].nvml        = hm_adapters_nvml[device_id].nvml;
      hwmon_ctx->hm_device[backend_devices_idx].od_version  = 0;

      if (hwmon_ctx->hm_nvml)
      {
        hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_nvml[device_id].buslanes_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_nvml[device_id].corespeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_nvml[device_id].fanspeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_nvml[device_id].fanpolicy_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_nvml[device_id].memoryspeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_nvml[device_id].temperature_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_nvml[device_id].threshold_shutdown_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_nvml[device_id].threshold_slowdown_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_nvml[device_id].throttle_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_nvml[device_id].utilization_get_supported;
      }

      if (hwmon_ctx->hm_nvapi)
      {
        hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_nvapi[device_id].buslanes_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_nvapi[device_id].corespeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_nvapi[device_id].fanspeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_nvapi[device_id].fanpolicy_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_nvapi[device_id].memoryspeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_nvapi[device_id].temperature_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_nvapi[device_id].threshold_shutdown_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_nvapi[device_id].threshold_slowdown_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_nvapi[device_id].throttle_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_nvapi[device_id].utilization_get_supported;
      }
    }

    if (device_param->is_opencl == true)
    {
      if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

      if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD)
      {
        hwmon_ctx->hm_device[backend_devices_idx].adl         = hm_adapters_adl[device_id].adl;
        hwmon_ctx->hm_device[backend_devices_idx].sysfs       = hm_adapters_sysfs[device_id].sysfs;
        hwmon_ctx->hm_device[backend_devices_idx].nvapi       = 0;
        hwmon_ctx->hm_device[backend_devices_idx].nvml        = 0;
        hwmon_ctx->hm_device[backend_devices_idx].od_version  = 0;

        if (hwmon_ctx->hm_adl)
        {
          hwmon_ctx->hm_device[backend_devices_idx].od_version = hm_adapters_adl[device_id].od_version;

          hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_adl[device_id].buslanes_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_adl[device_id].corespeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_adl[device_id].fanspeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_adl[device_id].fanpolicy_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_adl[device_id].memoryspeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_adl[device_id].temperature_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_adl[device_id].threshold_shutdown_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_adl[device_id].threshold_slowdown_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_adl[device_id].throttle_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_adl[device_id].utilization_get_supported;
        }

        if (hwmon_ctx->hm_sysfs)
        {
          hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_sysfs[device_id].buslanes_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_sysfs[device_id].corespeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_sysfs[device_id].fanspeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_sysfs[device_id].fanpolicy_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_sysfs[device_id].memoryspeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_sysfs[device_id].temperature_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_sysfs[device_id].threshold_shutdown_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_sysfs[device_id].threshold_slowdown_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_sysfs[device_id].throttle_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_sysfs[device_id].utilization_get_supported;
        }
      }

      if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
      {
        hwmon_ctx->hm_device[backend_devices_idx].adl         = 0;
        hwmon_ctx->hm_device[backend_devices_idx].sysfs       = 0;
        hwmon_ctx->hm_device[backend_devices_idx].nvapi       = hm_adapters_nvapi[device_id].nvapi;
        hwmon_ctx->hm_device[backend_devices_idx].nvml        = hm_adapters_nvml[device_id].nvml;
        hwmon_ctx->hm_device[backend_devices_idx].od_version  = 0;

        if (hwmon_ctx->hm_nvml)
        {
          hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_nvml[device_id].buslanes_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_nvml[device_id].corespeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_nvml[device_id].fanspeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_nvml[device_id].fanpolicy_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_nvml[device_id].memoryspeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_nvml[device_id].temperature_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_nvml[device_id].threshold_shutdown_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_nvml[device_id].threshold_slowdown_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_nvml[device_id].throttle_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_nvml[device_id].utilization_get_supported;
        }

        if (hwmon_ctx->hm_nvapi)
        {
          hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_nvapi[device_id].buslanes_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_nvapi[device_id].corespeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_nvapi[device_id].fanspeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_nvapi[device_id].fanpolicy_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_nvapi[device_id].memoryspeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_nvapi[device_id].temperature_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_nvapi[device_id].threshold_shutdown_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_nvapi[device_id].threshold_slowdown_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_nvapi[device_id].throttle_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_nvapi[device_id].utilization_get_supported;
        }
      }
    }

    // by calling the different functions here this will disable them in case they will error out
    // this will also reduce the error itself printed to the user to a single print on startup

    hm_get_buslanes_with_devices_idx           (hashcat_ctx, backend_devices_idx);
    hm_get_corespeed_with_devices_idx          (hashcat_ctx, backend_devices_idx);
    hm_get_fanpolicy_with_devices_idx          (hashcat_ctx, backend_devices_idx);
    hm_get_fanspeed_with_devices_idx           (hashcat_ctx, backend_devices_idx);
    hm_get_memoryspeed_with_devices_idx        (hashcat_ctx, backend_devices_idx);
    hm_get_temperature_with_devices_idx        (hashcat_ctx, backend_devices_idx);
    hm_get_threshold_shutdown_with_devices_idx (hashcat_ctx, backend_devices_idx);
    hm_get_threshold_slowdown_with_devices_idx (hashcat_ctx, backend_devices_idx);
    hm_get_throttle_with_devices_idx           (hashcat_ctx, backend_devices_idx);
    hm_get_utilization_with_devices_idx        (hashcat_ctx, backend_devices_idx);
  }

  FREE_ADAPTERS;

  return 0;
}

void hwmon_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return;

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

  hcfree (hwmon_ctx->od_clock_mem_status);

  hcfree (hwmon_ctx->hm_device);

  memset (hwmon_ctx, 0, sizeof (hwmon_ctx_t));
}
