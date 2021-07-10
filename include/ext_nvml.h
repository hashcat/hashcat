/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _NVML_H
#define _NVML_H

/**
 * Declarations from nvml.h
 */

typedef struct nvmlDevice_st* nvmlDevice_t;

typedef struct nvmlPciInfo_st
{
    char busId[16];                  //!< The tuple domain:bus:device.function PCI identifier (&amp; NULL terminator)
    unsigned int domain;             //!< The PCI domain on which the device's bus resides, 0 to 0xffff
    unsigned int bus;                //!< The bus on which the device resides, 0 to 0xff
    unsigned int device;             //!< The device's id on the bus, 0 to 31
    unsigned int pciDeviceId;        //!< The combined 16-bit device id and 16-bit vendor id

    // Added in NVML 2.285 API
    unsigned int pciSubSystemId;     //!< The 32-bit Sub System Device ID

    // NVIDIA reserved for internal use only
    unsigned int reserved0;
    unsigned int reserved1;
    unsigned int reserved2;
    unsigned int reserved3;
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

typedef enum nvmlClockType_enum {
  NVML_CLOCK_GRAPHICS = 0,
  NVML_CLOCK_SM = 1,
  NVML_CLOCK_MEM = 2
} nvmlClockType_t;

typedef enum nvmlTemperatureThresholds_enum
{
    NVML_TEMPERATURE_THRESHOLD_SHUTDOWN = 0,    // Temperature at which the GPU will shut down
                                                // for HW protection
    NVML_TEMPERATURE_THRESHOLD_SLOWDOWN = 1,    // Temperature at which the GPU will begin slowdown
    // Keep this last
    NVML_TEMPERATURE_THRESHOLD_COUNT
} nvmlTemperatureThresholds_t;

/**
 * Compute mode.
 *
 * NVML_COMPUTEMODE_EXCLUSIVE_PROCESS was added in CUDA 4.0.
 * Earlier CUDA versions supported a single exclusive mode,
 * which is equivalent to NVML_COMPUTEMODE_EXCLUSIVE_THREAD in CUDA 4.0 and beyond.
 */
typedef enum nvmlComputeMode_enum
{
    NVML_COMPUTEMODE_DEFAULT           = 0,  //!< Default compute mode -- multiple contexts per device
    NVML_COMPUTEMODE_EXCLUSIVE_THREAD  = 1,  //!< Compute-exclusive-thread mode -- only one context per device, usable from one thread at a time
    NVML_COMPUTEMODE_PROHIBITED        = 2,  //!< Compute-prohibited mode -- no contexts per device
    NVML_COMPUTEMODE_EXCLUSIVE_PROCESS = 3,  //!< Compute-exclusive-process mode -- only one context per device, usable from multiple threads at a time

    // Keep this last
    NVML_COMPUTEMODE_COUNT
} nvmlComputeMode_t;

/**
 * GPU Operation Mode
 *
 * GOM allows to reduce power usage and optimize GPU throughput by disabling GPU features.
 *
 * Each GOM is designed to meet specific user needs.
 */
typedef enum nvmlGom_enum
{
    NVML_GOM_ALL_ON                    = 0, //!< Everything is enabled and running at full speed

    NVML_GOM_COMPUTE                   = 1, //!< Designed for running only compute tasks. Graphics operations
                                            //!< are not allowed

    NVML_GOM_LOW_DP                    = 2  //!< Designed for running graphics applications that don't require
                                            //!< high bandwidth double precision
} nvmlGpuOperationMode_t;

/***************************************************************************************************/
/** @addtogroup nvmlClocksThrottleReasons
 *  @{
 */
/***************************************************************************************************/

/** Nothing is running on the GPU and the clocks are dropping to Idle state
 * \note This limiter may be removed in a later release
 */
#define nvmlClocksThrottleReasonGpuIdle                   0x0000000000000001LL

/** GPU clocks are limited by current setting of applications clocks
 *
 * @see nvmlDeviceSetApplicationsClocks
 * @see nvmlDeviceGetApplicationsClock
 */
#define nvmlClocksThrottleReasonApplicationsClocksSetting   0x0000000000000002LL

/**
 * @deprecated Renamed to \ref nvmlClocksThrottleReasonApplicationsClocksSetting
 *             as the name describes the situation more accurately.
 */
#define nvmlClocksThrottleReasonUserDefinedClocks         nvmlClocksThrottleReasonApplicationsClocksSetting

/** SW Power Scaling algorithm is reducing the clocks below requested clocks
 *
 * @see nvmlDeviceGetPowerUsage
 * @see nvmlDeviceSetPowerManagementLimit
 * @see nvmlDeviceGetPowerManagementLimit
 */
#define nvmlClocksThrottleReasonSwPowerCap                0x0000000000000004LL

/** HW Slowdown (reducing the core clocks by a factor of 2 or more) is engaged
 *
 * This is an indicator of:
 *   - temperature being too high
 *   - External Power Brake Assertion is triggered (e.g. by the system power supply)
 *   - Power draw is too high and Fast Trigger protection is reducing the clocks
 *   - May be also reported during PState or clock change
 *      - This behavior may be removed in a later release.
 *
 * @see nvmlDeviceGetTemperature
 * @see nvmlDeviceGetTemperatureThreshold
 * @see nvmlDeviceGetPowerUsage
 */
#define nvmlClocksThrottleReasonHwSlowdown                0x0000000000000008LL

/** Some other unspecified factor is reducing the clocks */
#define nvmlClocksThrottleReasonUnknown                   0x8000000000000000LL

/** Bit mask representing no clocks throttling
 *
 * Clocks are as high as possible.
 * */
#define nvmlClocksThrottleReasonNone                      0x0000000000000000LL

/*
 * End of declarations from nvml.h
 **/

typedef nvmlDevice_t HM_ADAPTER_NVML;

#if defined(_WIN32) || defined(__WIN32__)
#define NVML_API_CALL __stdcall
#else
#define NVML_API_CALL
#endif

typedef const char * (*NVML_API_CALL NVML_ERROR_STRING) (nvmlReturn_t);
typedef int (*NVML_API_CALL NVML_INIT) (void);
typedef int (*NVML_API_CALL NVML_SHUTDOWN) (void);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_COUNT) (unsigned int *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_NAME) (nvmlDevice_t, char *, unsigned int);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_HANDLE_BY_INDEX) (unsigned int, nvmlDevice_t *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_TEMPERATURE) (nvmlDevice_t, nvmlTemperatureSensors_t, unsigned int *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_FAN_SPEED) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_UTILIZATION_RATES) (nvmlDevice_t, nvmlUtilization_t *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_CLOCKINFO) (nvmlDevice_t, nvmlClockType_t, unsigned int *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_THRESHOLD) (nvmlDevice_t, nvmlTemperatureThresholds_t, unsigned int *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_CURRPCIELINKGENERATION) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_CURRPCIELINKWIDTH) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_CURRENTCLOCKSTHROTTLEREASONS) (nvmlDevice_t, unsigned long long *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_SUPPORTEDCLOCKSTHROTTLEREASONS) (nvmlDevice_t, unsigned long long *);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_SET_COMPUTEMODE) (nvmlDevice_t, nvmlComputeMode_t);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_SET_OPERATIONMODE) (nvmlDevice_t, nvmlGpuOperationMode_t);
typedef nvmlReturn_t (*NVML_API_CALL NVML_DEVICE_GET_PCIINFO) (nvmlDevice_t, nvmlPciInfo_t *);

typedef struct hm_nvml_lib
{
  hc_dynlib_t lib;

  NVML_ERROR_STRING nvmlErrorString;
  NVML_INIT nvmlInit;
  NVML_SHUTDOWN nvmlShutdown;
  NVML_DEVICE_GET_COUNT nvmlDeviceGetCount;
  NVML_DEVICE_GET_NAME nvmlDeviceGetName;
  NVML_DEVICE_GET_HANDLE_BY_INDEX nvmlDeviceGetHandleByIndex;
  NVML_DEVICE_GET_TEMPERATURE nvmlDeviceGetTemperature;
  NVML_DEVICE_GET_FAN_SPEED nvmlDeviceGetFanSpeed;
  NVML_DEVICE_GET_UTILIZATION_RATES nvmlDeviceGetUtilizationRates;
  NVML_DEVICE_GET_CLOCKINFO nvmlDeviceGetClockInfo;
  NVML_DEVICE_GET_THRESHOLD nvmlDeviceGetTemperatureThreshold;
  NVML_DEVICE_GET_CURRPCIELINKGENERATION nvmlDeviceGetCurrPcieLinkGeneration;
  NVML_DEVICE_GET_CURRPCIELINKWIDTH nvmlDeviceGetCurrPcieLinkWidth;
  NVML_DEVICE_GET_CURRENTCLOCKSTHROTTLEREASONS nvmlDeviceGetCurrentClocksThrottleReasons;
  NVML_DEVICE_GET_SUPPORTEDCLOCKSTHROTTLEREASONS nvmlDeviceGetSupportedClocksThrottleReasons;
  NVML_DEVICE_GET_PCIINFO nvmlDeviceGetPciInfo;

} hm_nvml_lib_t;

typedef hm_nvml_lib_t NVML_PTR;

int nvml_init (void *hashcat_ctx);
void nvml_close (void *hashcat_ctx);
const char *hm_NVML_nvmlErrorString (NVML_PTR *nvml, const nvmlReturn_t nvml_rc);

int hm_NVML_nvmlInit (void *hashcat_ctx);
int hm_NVML_nvmlShutdown (void *hashcat_ctx);
int hm_NVML_nvmlDeviceGetCount (void *hashcat_ctx, unsigned int *deviceCount);
int hm_NVML_nvmlDeviceGetHandleByIndex (void *hashcat_ctx, unsigned int device_index, nvmlDevice_t *device);
int hm_NVML_nvmlDeviceGetTemperature (void *hashcat_ctx, nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp);
int hm_NVML_nvmlDeviceGetFanSpeed (void *hashcat_ctx, nvmlDevice_t device, unsigned int *speed);
int hm_NVML_nvmlDeviceGetUtilizationRates (void *hashcat_ctx, nvmlDevice_t device, nvmlUtilization_t *utilization);
int hm_NVML_nvmlDeviceGetClockInfo (void *hashcat_ctx, nvmlDevice_t device, nvmlClockType_t type, unsigned int *clockfreq);
int hm_NVML_nvmlDeviceGetTemperatureThreshold (void *hashcat_ctx, nvmlDevice_t device, nvmlTemperatureThresholds_t thresholdType, unsigned int *temp);
int hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (void *hashcat_ctx, nvmlDevice_t device, unsigned int *currLinkWidth);
int hm_NVML_nvmlDeviceGetPciInfo (void *hashcat_ctx, nvmlDevice_t device, nvmlPciInfo_t *pci);

#endif // _NVML_H
