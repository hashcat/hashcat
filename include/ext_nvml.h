/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#ifndef EXT_NVML_H
#define EXT_NVML_H

#if defined(HAVE_HWMON) && defined(HAVE_NVML)

#include <common.h>

/**
 * Declarations from nvml.h
 */

typedef struct nvmlDevice_st* nvmlDevice_t;

typedef struct nvmlPciInfo_st {
  char busId[16];
  unsigned int domain;
  unsigned int bus;
  unsigned int device;
  unsigned int pciDeviceId;
  unsigned int pciSubSystemId;
} nvmlPciInfo_t;

typedef struct nvmlUtilization_st {
  unsigned int gpu;    // GPU kernel execution last second, percent
  unsigned int memory; // GPU memory read/write last second, percent
} nvmlUtilization_t;

typedef enum nvmlTemperatureSensors_enum {
  NVML_TEMPERATURE_GPU = 0     // Temperature sensor for the GPU die
} nvmlTemperatureSensors_t;

typedef enum nvmlReturn_enum {
  NVML_SUCCESS = 0,                   // The operation was successful
  NVML_ERROR_UNINITIALIZED = 1,       // NVML was not first initialized with nvmlInit()
  NVML_ERROR_INVALID_ARGUMENT = 2,    // A supplied argument is invalid
  NVML_ERROR_NOT_SUPPORTED = 3,       // The requested operation is not available on target device
  NVML_ERROR_NO_PERMISSION = 4,       // The current user does not have permission for operation
  NVML_ERROR_ALREADY_INITIALIZED = 5, // Deprecated: Multiple initializations are now allowed through ref counting
  NVML_ERROR_NOT_FOUND = 6,           // A query to find an object was unsuccessful
  NVML_ERROR_INSUFFICIENT_SIZE = 7,   // An input argument is not large enough
  NVML_ERROR_INSUFFICIENT_POWER = 8,  // A device's external power cables are not properly attached
  NVML_ERROR_DRIVER_NOT_LOADED = 9,   // NVIDIA driver is not loaded
  NVML_ERROR_TIMEOUT = 10,            // User provided timeout passed
  NVML_ERROR_UNKNOWN = 999            // An internal driver error occurred
} nvmlReturn_t;

/*
 * End of declarations from nvml.h
 **/

typedef nvmlDevice_t HM_ADAPTER_NV;

#include <shared.h>

typedef const char * (*NVML_ERROR_STRING) (nvmlReturn_t);
typedef int (*NVML_INIT) (void);
typedef int (*NVML_SHUTDOWN) (void);
typedef nvmlReturn_t (*NVML_DEVICE_GET_NAME) (nvmlDevice_t, char *, unsigned int);
typedef nvmlReturn_t (*NVML_DEVICE_GET_HANDLE_BY_INDEX) (unsigned int, nvmlDevice_t *);
typedef nvmlReturn_t (*NVML_DEVICE_GET_TEMPERATURE) (nvmlDevice_t, nvmlTemperatureSensors_t, unsigned int *);
typedef nvmlReturn_t (*NVML_DEVICE_GET_FAN_SPEED) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t (*NVML_DEVICE_GET_POWER_USAGE) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t (*NVML_DEVICE_GET_UTILIZATION_RATES) (nvmlDevice_t, nvmlUtilization_t *);

typedef struct
{
  NV_LIB lib;

  NVML_ERROR_STRING nvmlErrorString;
  NVML_INIT nvmlInit;
  NVML_SHUTDOWN nvmlShutdown;
  NVML_DEVICE_GET_NAME nvmlDeviceGetName;
  NVML_DEVICE_GET_HANDLE_BY_INDEX nvmlDeviceGetHandleByIndex;
  NVML_DEVICE_GET_TEMPERATURE nvmlDeviceGetTemperature;
  NVML_DEVICE_GET_FAN_SPEED nvmlDeviceGetFanSpeed;
  NVML_DEVICE_GET_POWER_USAGE nvmlDeviceGetPowerUsage;
  NVML_DEVICE_GET_UTILIZATION_RATES nvmlDeviceGetUtilizationRates;

} hm_nvml_lib_t;

#define NVML_PTR hm_nvml_lib_t

int nvml_init (NVML_PTR *lib);
void nvml_close (NVML_PTR *lib);

const char * hm_NVML_nvmlErrorString (NVML_PTR *nvml, nvmlReturn_t nvml_rc);
nvmlReturn_t hm_NVML_nvmlInit (NVML_PTR *nvml);
nvmlReturn_t hm_NVML_nvmlShutdown (NVML_PTR *nvml);
nvmlReturn_t hm_NVML_nvmlDeviceGetName (NVML_PTR *nvml, nvmlDevice_t device, char *name, unsigned int length);
nvmlReturn_t hm_NVML_nvmlDeviceGetHandleByIndex (NVML_PTR *nvml, int, unsigned int index, nvmlDevice_t *device);
nvmlReturn_t hm_NVML_nvmlDeviceGetTemperature (NVML_PTR *nvml, nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp);
nvmlReturn_t hm_NVML_nvmlDeviceGetFanSpeed (NVML_PTR *nvml, int, nvmlDevice_t device, unsigned int *speed);
nvmlReturn_t hm_NVML_nvmlDeviceGetPowerUsage (NVML_PTR *nvml, nvmlDevice_t device, unsigned int *power);
nvmlReturn_t hm_NVML_nvmlDeviceGetUtilizationRates (NVML_PTR *nvml, nvmlDevice_t device, nvmlUtilization_t *utilization);

#endif // HAVE_HWMON && HAVE_NVML

#endif // EXT_NVML_H
