/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_nvml.h>

nvmlReturn_t hc_NVML_nvmlInit (void)
{
  nvmlReturn_t nvml_rc = nvmlInit ();

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = nvmlErrorString (nvml_rc);

    log_info ("WARN: %s %d %s\n", "nvmlInit()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlShutdown (void)
{
  nvmlReturn_t nvml_rc = nvmlShutdown ();

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = nvmlErrorString (nvml_rc);

    log_info ("WARN: %s %d %s\n", "nvmlShutdown()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlDeviceGetName (nvmlDevice_t device, char *name, unsigned int length)
{
  nvmlReturn_t nvml_rc = nvmlDeviceGetName (device, name, length);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = nvmlErrorString (nvml_rc);

    log_info ("WARN: %s %d %s\n", "nvmlDeviceGetName()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlDeviceGetHandleByIndex (unsigned int index, nvmlDevice_t *device)
{
  nvmlReturn_t nvml_rc = nvmlDeviceGetHandleByIndex (index, device);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = nvmlErrorString (nvml_rc);

    log_info ("WARN: %s %d %s\n", "nvmlDeviceGetHandleByIndex()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlDeviceGetTemperature (nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp)
{
  nvmlReturn_t nvml_rc = nvmlDeviceGetTemperature (device, sensorType, temp);

  if (nvml_rc != NVML_SUCCESS)
  {
    *temp = -1;

    //const char *string = nvmlErrorString (nvml_rc);

    //log_info ("WARN: %s %d %s\n", "nvmlDeviceGetTemperature()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlDeviceGetFanSpeed (nvmlDevice_t device, unsigned int *speed)
{
  nvmlReturn_t nvml_rc = nvmlDeviceGetFanSpeed (device, speed);

  if (nvml_rc != NVML_SUCCESS)
  {
    *speed = -1;

    //const char *string = nvmlErrorString (nvml_rc);

    //log_info ("WARN: %s %d %s\n", "nvmlDeviceGetFanSpeed()", nvml_rc, string);
  }

  return nvml_rc;
}

/* only tesla following */

nvmlReturn_t hc_NVML_nvmlDeviceGetPowerUsage (nvmlDevice_t device, unsigned int *power)
{
  nvmlReturn_t nvml_rc = nvmlDeviceGetPowerUsage (device, power);

  if (nvml_rc != NVML_SUCCESS)
  {
    *power = -1;

    //const char *string = nvmlErrorString (nvml_rc);

    //log_info ("WARN: %s %d %s\n", "nvmlDeviceGetPowerUsage()", nvml_rc, string);
  }

  return nvml_rc;
}

nvmlReturn_t hc_NVML_nvmlDeviceGetUtilizationRates (nvmlDevice_t device, nvmlUtilization_t *utilization)
{
  nvmlReturn_t nvml_rc = nvmlDeviceGetUtilizationRates (device, utilization);

  if (nvml_rc != NVML_SUCCESS)
  {
    utilization->gpu    = -1;
    utilization->memory = -1;

    //const char *string = nvmlErrorString (nvml_rc);

    //log_info ("WARN: %s %d %s\n", "nvmlDeviceGetUtilizationRates()", nvml_rc, string);
  }

  return nvml_rc;
}
