/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "filehandling.h"
#include "ext_nvml.h"

#include "dynloader.h"

#if defined (__CYGWIN__)
#include <sys/cygwin.h>
#endif

// nvml functions

int nvml_init (void *hashcat_ctx_0)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

    size_t r = hc_fread (nvml_winpath, 100, 1, &nvml_lib);

    hc_fclose (&nvml_lib);

    if (r != 1) return false;

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

void nvml_close (void *hashcat_ctx_0)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  if (nvml)
  {
    if (nvml->lib)
      hc_dlclose (nvml->lib);

    hcfree (nvml);
  }
}

const char *hm_NVML_nvmlErrorString (NVML_PTR *nvml, const nvmlReturn_t nvml_rc)
{
  return nvml->nvmlErrorString (nvml_rc);
}

int hm_NVML_nvmlInit (void *hashcat_ctx_0)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_NVML_nvmlShutdown (void *hashcat_ctx_0)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_NVML_nvmlDeviceGetCount (void *hashcat_ctx_0, unsigned int *deviceCount)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_NVML_nvmlDeviceGetHandleByIndex (void *hashcat_ctx_0, unsigned int device_index, nvmlDevice_t *device)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_NVML_nvmlDeviceGetTemperature (void *hashcat_ctx_0, nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_NVML_nvmlDeviceGetFanSpeed (void *hashcat_ctx_0, nvmlDevice_t device, unsigned int *speed)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_NVML_nvmlDeviceGetUtilizationRates (void *hashcat_ctx_0, nvmlDevice_t device, nvmlUtilization_t *utilization)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_NVML_nvmlDeviceGetClockInfo (void *hashcat_ctx_0, nvmlDevice_t device, nvmlClockType_t type, unsigned int *clockfreq)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_NVML_nvmlDeviceGetTemperatureThreshold (void *hashcat_ctx_0, nvmlDevice_t device, nvmlTemperatureThresholds_t thresholdType, unsigned int *temp)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (void *hashcat_ctx_0, nvmlDevice_t device, unsigned int *currLinkWidth)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_NVML_nvmlDeviceGetPciInfo (void *hashcat_ctx_0, nvmlDevice_t device, nvmlPciInfo_t *pci)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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

int hm_get_adapter_index_nvml (void *hashcat_ctx_0, HM_ADAPTER_NVML *nvmlGPUHandle)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) hashcat_ctx_0;

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
