/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_nvml.h>

//#ifdef _POSIX // implied

void *GetLibFunction (void *pLibrary, const char *name)
{
  return dlsym (pLibrary, name);
}

const char * hc_NVML_nvmlErrorString (HM_LIB hDLL, nvmlReturn_t nvml_rc)
{
  NVML_ERROR_STRING nvmlErrorString = (NVML_ERROR_STRING) GetLibFunction (hDLL, "nvmlErrorString");

  if (nvmlErrorString == NULL)
  {
    log_error ("ERROR: %s\n", "nvmlErrorString() is missing");

    exit (-1);
  }

  return nvmlErrorString (nvml_rc);
}

nvmlReturn_t hc_NVML_nvmlInit (HM_LIB hDLL)
{
  NVML_INIT nvmlInit = (NVML_INIT) GetLibFunction (hDLL, "nvmlInit");

  if (nvmlInit == NULL)
  {
    log_error ("ERROR: %s\n", "nvmlInit() is missing");

    exit (-1);
  }

  nvmlReturn_t nvml_rc = nvmlInit ();

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hc_NVML_nvmlErrorString (hDLL, nvml_rc);

    log_info ("WARN: %s %d %s\n", "nvmlInit()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlShutdown (HM_LIB hDLL)
{
  NVML_SHUTDOWN nvmlShutdown = (NVML_SHUTDOWN) GetLibFunction (hDLL, "nvmlShutdown");

  if (nvmlShutdown == NULL)
  {
    log_error ("ERROR: %s\n", "nvmlShutdown() is missing");

    exit (-1);
  }

  nvmlReturn_t nvml_rc = nvmlShutdown ();

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hc_NVML_nvmlErrorString (hDLL, nvml_rc);

    log_info ("WARN: %s %d %s\n", "nvmlShutdown()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlDeviceGetName (HM_LIB hDLL, nvmlDevice_t device, char *name, unsigned int length)
{
  NVML_DEVICE_GET_NAME nvmlDeviceGetName = (NVML_DEVICE_GET_NAME) GetLibFunction (hDLL, "nvmlDeviceGetName");

  if (nvmlDeviceGetName == NULL)
  {
    log_error ("ERROR: %s\n", "nvmlDeviceGetName() is missing");

    exit (-1);
  }

  nvmlReturn_t nvml_rc = nvmlDeviceGetName (device, name, length);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hc_NVML_nvmlErrorString (hDLL, nvml_rc);

    log_info ("WARN: %s %d %s\n", "nvmlDeviceGetName()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlDeviceGetHandleByIndex (HM_LIB hDLL, int skip_warnings, unsigned int index, nvmlDevice_t *device)
{
  NVML_DEVICE_GET_HANDLE_BY_INDEX nvmlDeviceGetHandleByIndex = (NVML_DEVICE_GET_HANDLE_BY_INDEX) GetLibFunction (hDLL, "nvmlDeviceGetHandleByIndex");

  if (nvmlDeviceGetHandleByIndex == NULL)
  {
    log_error ("ERROR: %s\n", "nvmlDeviceGetHandleByIndex() is missing");

    exit (-1);
  }

  nvmlReturn_t nvml_rc = nvmlDeviceGetHandleByIndex (index, device);

  if (nvml_rc != NVML_SUCCESS)
  {
    if (skip_warnings == 0)
    {
      const char *string = hc_NVML_nvmlErrorString (hDLL, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetHandleByIndex()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlDeviceGetTemperature (HM_LIB hDLL, nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp)
{
  NVML_DEVICE_GET_TEMPERATURE nvmlDeviceGetTemperature = (NVML_DEVICE_GET_TEMPERATURE) GetLibFunction (hDLL, "nvmlDeviceGetTemperature");

  if (nvmlDeviceGetTemperature == NULL)
  {
    log_error ("ERROR: %s\n", "nvmlDeviceGetTemperature() is missing");

    exit (-1);
  }

  nvmlReturn_t nvml_rc = nvmlDeviceGetTemperature (device, sensorType, temp);

  if (nvml_rc != NVML_SUCCESS)
  {
    *temp = -1;

    //const char *string = hc_NVML_nvmlErrorString (hDLL, nvml_rc);

    //log_info ("WARN: %s %d %s\n", "nvmlDeviceGetTemperature()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlDeviceGetFanSpeed (HM_LIB hDLL, int skip_warnings, nvmlDevice_t device, unsigned int *speed)
{
  NVML_DEVICE_GET_FAN_SPEED nvmlDeviceGetFanSpeed = (NVML_DEVICE_GET_FAN_SPEED) GetLibFunction (hDLL, "nvmlDeviceGetFanSpeed");

  if (nvmlDeviceGetFanSpeed == NULL)
  {
    log_error ("ERROR: %s\n", "nvmlDeviceGetFanSpeed() is missing");

    exit (-1);
  }

  nvmlReturn_t nvml_rc = nvmlDeviceGetFanSpeed (device, speed);

  if (nvml_rc != NVML_SUCCESS)
  {
    *speed = -1;

    if (skip_warnings == 0)
    {
      const char *string = hc_NVML_nvmlErrorString (hDLL, nvml_rc);

      log_info ("WARN: %s %d %s\n", "nvmlDeviceGetFanSpeed()", nvml_rc, string);
    }
  }

  return nvml_rc;
}

/* only tesla following */

nvmlReturn_t hc_NVML_nvmlDeviceGetPowerUsage (HM_LIB hDLL, nvmlDevice_t device, unsigned int *power)
{
  NVML_DEVICE_GET_POWER_USAGE nvmlDeviceGetPowerUsage = (NVML_DEVICE_GET_POWER_USAGE) GetLibFunction (hDLL, "nvmlDeviceGetPowerUsage");

  if (nvmlDeviceGetPowerUsage == NULL)
  {
    log_error ("ERROR: %s\n", "nvmlDeviceGetPowerUsage() is missing");

    exit (-1);
  }

  nvmlReturn_t nvml_rc = nvmlDeviceGetPowerUsage (device, power);

  if (nvml_rc != NVML_SUCCESS)
  {
    *power = -1;

    //const char *string = hc_NVML_nvmlErrorString (hDLL, nvml_rc);

    //log_info ("WARN: %s %d %s\n", "nvmlDeviceGetPowerUsage()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlDeviceGetUtilizationRates (HM_LIB hDLL, nvmlDevice_t device, nvmlUtilization_t *utilization)
{
  NVML_DEVICE_GET_UTILIZATION_RATES nvmlDeviceGetUtilizationRates = (NVML_DEVICE_GET_UTILIZATION_RATES) GetLibFunction (hDLL, "nvmlDeviceGetUtilizationRates");

  if (nvmlDeviceGetUtilizationRates == NULL)
  {
    log_error ("ERROR: %s\n", "nvmlDeviceGetUtilizationRates() is missing");

    exit (-1);
  }

  nvmlReturn_t nvml_rc = nvmlDeviceGetUtilizationRates (device, utilization);

  if (nvml_rc != NVML_SUCCESS)
  {
    utilization->gpu    = -1;
    utilization->memory = -1;

    //const char *string = hc_NVML_nvmlErrorString (hDLL, nvml_rc);

    //log_info ("WARN: %s %d %s\n", "nvmlDeviceGetUtilizationRates()", nvml_rc, string);
  }

  return nvml_rc;
}

//#endif
