/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#include <ext_nvml.h>

int nvml_init (NVML_PTR *nvml)
{
  if (!nvml) return (-1);

  memset (nvml, 0, sizeof (NVML_PTR));

  nvml->lib = hc_dlopen ("libnvidia-ml.so", RTLD_NOW);

  if (!nvml->lib)
  {
    //if (data.quiet == 0)
    //  log_info ("WARNING: load NVML library failed, proceed without NVML HWMon enabled.");

    return (-1);
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

nvmlReturn_t hm_NVML_nvmlDeviceGetName (NVML_PTR *nvml, nvmlDevice_t device, char *name, unsigned int length)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetName (device, name, length);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    log_info ("WARN: %s %d %s\n", "nvmlDeviceGetName()", nvml_rc, string);
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

nvmlReturn_t hm_NVML_nvmlDeviceGetTemperature (NVML_PTR *nvml, nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetTemperature (device, sensorType, temp);

  if (nvml_rc != NVML_SUCCESS)
  {
    *temp = -1;

    //const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    //log_info ("WARN: %s %d %s\n", "nvmlDeviceGetTemperature()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetFanSpeed (NVML_PTR *nvml, int skip_warnings, nvmlDevice_t device, unsigned int *speed)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetFanSpeed (device, speed);

  if (nvml_rc != NVML_SUCCESS)
  {
    *speed = -1;

    if (skip_warnings == 0)
    {
      const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetFanSpeed()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

/* only tesla following */

nvmlReturn_t hm_NVML_nvmlDeviceGetPowerUsage (NVML_PTR *nvml, nvmlDevice_t device, unsigned int *power)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPowerUsage (device, power);

  if (nvml_rc != NVML_SUCCESS)
  {
    *power = -1;

    //const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    //log_info ("WARN: %s %d %s\n", "nvmlDeviceGetPowerUsage()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hm_NVML_nvmlDeviceGetUtilizationRates (NVML_PTR *nvml, nvmlDevice_t device, nvmlUtilization_t *utilization)
{
  if (!nvml) return -1;

  nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetUtilizationRates (device, utilization);

  if (nvml_rc != NVML_SUCCESS)
  {
    utilization->gpu    = -1;
    utilization->memory = -1;

    //const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    //log_info ("WARN: %s %d %s\n", "nvmlDeviceGetUtilizationRates()", nvml_rc, string);
  }

  return nvml_rc;
}
