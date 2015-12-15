/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef EXT_NVML_H
#define EXT_NVML_H

#include <common.h>

#include <nvml.h>

typedef nvmlDevice_t HM_ADAPTER_NV;

typedef const char * (*NVML_ERROR_STRING) (nvmlReturn_t);
typedef int (*NVML_INIT) ();
typedef int (*NVML_SHUTDOWN) ();
typedef nvmlReturn_t (*NVML_DEVICE_GET_NAME) (nvmlDevice_t, char *, unsigned int);
typedef nvmlReturn_t (*NVML_DEVICE_GET_HANDLE_BY_INDEX) (unsigned int, nvmlDevice_t *);
typedef nvmlReturn_t (*NVML_DEVICE_GET_TEMPERATURE) (nvmlDevice_t, nvmlTemperatureSensors_t, unsigned int *);
typedef nvmlReturn_t (*NVML_DEVICE_GET_FAN_SPEED) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t (*NVML_DEVICE_GET_POWER_USAGE) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t (*NVML_DEVICE_GET_UTILIZATION_RATES) (nvmlDevice_t, nvmlUtilization_t *);

nvmlReturn_t hc_NVML_nvmlInit (HM_LIB hDLL);
nvmlReturn_t hc_NVML_nvmlShutdown (HM_LIB hDLL);
nvmlReturn_t hc_NVML_nvmlDeviceGetName (HM_LIB hDLL, nvmlDevice_t device, char *name, unsigned int length);
nvmlReturn_t hc_NVML_nvmlDeviceGetHandleByIndex (HM_LIB hDLL, int, unsigned int index, nvmlDevice_t *device);
nvmlReturn_t hc_NVML_nvmlDeviceGetTemperature (HM_LIB hDLL, nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp);
nvmlReturn_t hc_NVML_nvmlDeviceGetFanSpeed (HM_LIB hDLL, int, nvmlDevice_t device, unsigned int *speed);
nvmlReturn_t hc_NVML_nvmlDeviceGetPowerUsage (HM_LIB hDLL, nvmlDevice_t device, unsigned int *power);
nvmlReturn_t hc_NVML_nvmlDeviceGetUtilizationRates (HM_LIB hDLL, nvmlDevice_t device, nvmlUtilization_t *utilization);

#endif
