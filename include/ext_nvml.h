/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef EXT_NVML_H
#define EXT_NVML_H

#include <common.h>

#include <nvml.h>

//typedef nvmlDevice_t HM_ADAPTER;

nvmlReturn_t hc_NVML_nvmlInit (void);
nvmlReturn_t hc_NVML_nvmlShutdown (void);
nvmlReturn_t hc_NVML_nvmlDeviceGetName (nvmlDevice_t device, char *name, unsigned int length);
nvmlReturn_t hc_NVML_nvmlDeviceGetHandleByIndex (unsigned int index, nvmlDevice_t *device);
nvmlReturn_t hc_NVML_nvmlDeviceGetTemperature (nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp);
nvmlReturn_t hc_NVML_nvmlDeviceGetFanSpeed (nvmlDevice_t device, unsigned int *speed);
nvmlReturn_t hc_NVML_nvmlDeviceGetPowerUsage (nvmlDevice_t device, unsigned int *power);
nvmlReturn_t hc_NVML_nvmlDeviceGetUtilizationRates (nvmlDevice_t device, nvmlUtilization_t *utilization);

#endif
