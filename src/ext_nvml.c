/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#include <ext_nvml.h>

int nvml_init (NVML_PTR *nvml)
{
  if (!nvml) return -1;

  memset (nvml, 0, sizeof (NVML_PTR));

  #ifdef _WIN
  nvml->lib = hc_dlopen ("nvml.dll");

  if (!nvml->lib)
  {
    DWORD BufferSize = 1024;

    DWORD Type = REG_SZ;

    char *Buffer = (char *) mymalloc (BufferSize + 1);

    HKEY hKey = 0;

    if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\NVIDIA Corporation\\Global\\NVSMI"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
      if (RegQueryValueEx (hKey, TEXT("NVSMIPATH"), NULL, &Type, (PVOID) Buffer, &BufferSize) == ERROR_SUCCESS)
      {
        Buffer[BufferSize] = 0;
      }
      else
      {
        if (data.quiet == 0)
          log_info ("WARNING: NVML library load failed, proceed without NVML HWMon enabled.");

        return -1;
      }

      RegCloseKey (hKey);
    }
    else
    {
      if (data.quiet == 0)
        log_info ("WARNING: NVML library load failed, proceed without NVML HWMon enabled.");

      return -1;
    }

    strcat (Buffer, "\\nvml.dll");

    nvml->lib = hc_dlopen (Buffer);

    myfree (Buffer);
  }

  #elif _POSIX
  nvml->lib = hc_dlopen ("libnvidia-ml.so", RTLD_NOW);
  #endif

  if (!nvml->lib)
  {
    if (data.quiet == 0)
      log_info ("WARNING: NVML library load failed, proceed without NVML HWMon enabled.");

    return -1;
  }

  HC_LOAD_FUNC(nvml, nvmlErrorString, NVML_ERROR_STRING, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlInit, NVML_INIT, NVML, 0)
  HC_LOAD_FUNC(nvml, nvmlShutdown, NVML_SHUTDOWN, NVML, 0)
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

  return 0;
}

void nvml_close (NVML_PTR *nvml)
{
  if (nvml)
  {
    if (nvml->lib)
      hc_dlclose (nvml->lib);

    myfree (nvml);
  }
}

const char *hm_NVML_nvmlErrorString (NVML_PTR *nvml, nvmlReturn_t nvml_rc)
{
  if (!nvml) return NULL;

  return nvml->nvmlErrorString (nvml_rc);
}

nvmlReturn_t hm_NVML_nvmlInit (NVML_PTR *nvml)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlInit ();

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    log_info ("WARN: %s %d %s\n", "nvmlInit()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlShutdown (NVML_PTR *nvml)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlShutdown ();

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    log_info ("WARN: %s %d %s\n", "nvmlShutdown()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetName (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, char *name, unsigned int length)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetName (device, name, length);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetName()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetHandleByIndex (NVML_PTR *nvml, int skip_warnings, unsigned int index, nvmlDevice_t *device)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetHandleByIndex (index, device);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetHandleByIndex()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetTemperature (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetTemperature (device, sensorType, temp);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetTemperature()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetFanSpeed (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, unsigned int *speed)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetFanSpeed (device, speed);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetFanSpeed()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetPowerUsage (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, unsigned int *power)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPowerUsage (device, power);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetPowerUsage()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetUtilizationRates (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, nvmlUtilization_t *utilization)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetUtilizationRates (device, utilization);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetUtilizationRates()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetClockInfo (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, nvmlClockType_t type, unsigned int *clock)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetClockInfo (device, type, clock);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetClockInfo()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetTemperatureThreshold (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, nvmlTemperatureThresholds_t thresholdType, unsigned int *temp)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetTemperatureThreshold (device, thresholdType, temp);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetTemperatureThreshold()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetCurrPcieLinkGeneration (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, unsigned int *currLinkGen)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetCurrPcieLinkGeneration (device, currLinkGen);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetCurrPcieLinkGeneration()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, unsigned int *currLinkWidth)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetCurrPcieLinkWidth (device, currLinkWidth);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetCurrPcieLinkWidth()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, unsigned long long *clocksThrottleReasons)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetCurrentClocksThrottleReasons (device, clocksThrottleReasons);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetCurrentClocksThrottleReasons()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, unsigned long long *supportedClocksThrottleReasons)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetSupportedClocksThrottleReasons (device, supportedClocksThrottleReasons);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetSupportedClocksThrottleReasons()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceSetComputeMode (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, nvmlComputeMode_t mode)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceSetComputeMode (device, mode);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceSetComputeMode()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceSetGpuOperationMode (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, nvmlGpuOperationMode_t mode)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceSetGpuOperationMode (device, mode);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceSetGpuOperationMode()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetPowerManagementLimitConstraints (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, unsigned int *minLimit, unsigned int *maxLimit)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPowerManagementLimitConstraints (device, minLimit, maxLimit);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetPowerManagementLimitConstraints()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceSetPowerManagementLimit (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, unsigned int limit)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceSetPowerManagementLimit (device, limit);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceSetPowerManagementLimit()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetPowerManagementLimit (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, unsigned int *limit)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPowerManagementLimit (device, limit);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetPowerManagementLimit()", nvml_rc, string);
    }
  }

  return nvml_rc;
}
