/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "dynloader.h"
#include "hwmon.h"

// nvml functions

int nvml_init (hashcat_ctx_t *hashcat_ctx)
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

    char *Buffer = (char *) mymalloc (BufferSize + 1);

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
        //  event_log_error (hashcat_ctx, "NVML library load failed, proceed without NVML HWMon enabled.");

        return -1;
      }

      RegCloseKey (hKey);
    }
    else
    {
      //if (user_options->quiet == false)
      //  event_log_error (hashcat_ctx, "NVML library load failed, proceed without NVML HWMon enabled.");

      return -1;
    }

    strcat (Buffer, "\\nvml.dll");

    nvml->lib = hc_dlopen (Buffer);

    myfree (Buffer);
  }

  #elif defined (_POSIX)
  nvml->lib = hc_dlopen ("libnvidia-ml.so", RTLD_NOW);
  #endif

  if (!nvml->lib)
  {
    //if (user_options->quiet == false)
    //  event_log_error (hashcat_ctx, "NVML library load failed, proceed without NVML HWMon enabled.");

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

void nvml_close (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  if (nvml)
  {
    if (nvml->lib)
      hc_dlclose (nvml->lib);

    myfree (nvml);
  }
}

static const char *hm_NVML_nvmlErrorString (NVML_PTR *nvml, const nvmlReturn_t nvml_rc)
{
  return nvml->nvmlErrorString (nvml_rc);
}

int hm_NVML_nvmlInit (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlInit ();

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlInit()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlShutdown (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlShutdown ();

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlShutdown()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetHandleByIndex (hashcat_ctx_t *hashcat_ctx, unsigned int index, nvmlDevice_t *device)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetHandleByIndex (index, device);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetHandleByIndex()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetName (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, char *name, unsigned int length)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetName (device, name, length);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetName()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetTemperature (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetTemperature (device, sensorType, temp);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetTemperature()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetFanSpeed (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *speed)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetFanSpeed (device, speed);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetFanSpeed()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetPowerUsage (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *power)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPowerUsage (device, power);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetPowerUsage()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetUtilizationRates (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlUtilization_t *utilization)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetUtilizationRates (device, utilization);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetUtilizationRates()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlClockType_t type, unsigned int *clock)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetClockInfo (device, type, clock);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetClockInfo()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlTemperatureThresholds_t thresholdType, unsigned int *temp)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetTemperatureThreshold (device, thresholdType, temp);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetTemperatureThreshold()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetCurrPcieLinkGeneration (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *currLinkGen)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetCurrPcieLinkGeneration (device, currLinkGen);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetCurrPcieLinkGeneration()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *currLinkWidth)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetCurrPcieLinkWidth (device, currLinkWidth);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetCurrPcieLinkWidth()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned long long *clocksThrottleReasons)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetCurrentClocksThrottleReasons (device, clocksThrottleReasons);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetCurrentClocksThrottleReasons()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned long long *supportedClocksThrottleReasons)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetSupportedClocksThrottleReasons (device, supportedClocksThrottleReasons);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetSupportedClocksThrottleReasons()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceSetComputeMode (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlComputeMode_t mode)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceSetComputeMode (device, mode);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceSetComputeMode()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceSetGpuOperationMode (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlGpuOperationMode_t mode)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceSetGpuOperationMode (device, mode);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceSetGpuOperationMode()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetPowerManagementLimitConstraints (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *minLimit, unsigned int *maxLimit)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPowerManagementLimitConstraints (device, minLimit, maxLimit);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetPowerManagementLimitConstraints()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceSetPowerManagementLimit (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int limit)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceSetPowerManagementLimit (device, limit);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceSetPowerManagementLimit()", nvml_rc, string);

    return -1;
  }

  return 0;
}

int hm_NVML_nvmlDeviceGetPowerManagementLimit (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *limit)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVML_PTR *nvml = hwmon_ctx->hm_nvml;

  const nvmlReturn_t nvml_rc = nvml->nvmlDeviceGetPowerManagementLimit (device, limit);

  if (nvml_rc != NVML_SUCCESS)
  {
    const char *string = hm_NVML_nvmlErrorString (nvml, nvml_rc);

    event_log_error (hashcat_ctx, "%s %d %s\n", "nvmlDeviceGetPowerManagementLimit()", nvml_rc, string);

    return -1;
  }

  return 0;
}

// nvapi functions

int nvapi_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  memset (nvapi, 0, sizeof (NVAPI_PTR));

  #if defined (_WIN)
  #if   defined (WIN64)
  nvapi->lib = hc_dlopen ("nvapi64.dll");
  #elif defined (WIN32)
  nvapi->lib = hc_dlopen ("nvapi.dll");
  #endif
  #else
  nvapi->lib = hc_dlopen ("nvapi.so", RTLD_NOW); // uhm yes, but .. yeah
  #endif

  if (!nvapi->lib)
  {
    //if (user_options->quiet == false)
    //  event_log_error (hashcat_ctx, "load NVAPI library failed, proceed without NVAPI HWMon enabled.");

    return -1;
  }

  HC_LOAD_FUNC(nvapi, nvapi_QueryInterface,             NVAPI_QUERYINTERFACE,             NVAPI,                0)
  HC_LOAD_ADDR(nvapi, NvAPI_Initialize,                 NVAPI_INITIALIZE,                 nvapi_QueryInterface, 0x0150E828, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_Unload,                     NVAPI_UNLOAD,                     nvapi_QueryInterface, 0xD22BDD7E, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GetErrorMessage,            NVAPI_GETERRORMESSAGE,            nvapi_QueryInterface, 0x6C2D048C, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_EnumPhysicalGPUs,           NVAPI_ENUMPHYSICALGPUS,           nvapi_QueryInterface, 0xE5AC921F, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetPerfPoliciesInfo,    NVAPI_GPU_GETPERFPOLICIESINFO,    nvapi_QueryInterface, 0x409D9841, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetPerfPoliciesStatus,  NVAPI_GPU_GETPERFPOLICIESSTATUS,  nvapi_QueryInterface, 0x3D358A0C, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_SetCoolerLevels,        NVAPI_GPU_SETCOOLERLEVELS,        nvapi_QueryInterface, 0x891FA0AE, NVAPI, 0)
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_RestoreCoolerSettings,  NVAPI_GPU_RESTORECOOLERSETTINGS,  nvapi_QueryInterface, 0x8F6ED0FB, NVAPI, 0)

  return 0;
}

void nvapi_close (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  if (nvapi)
  {
    if (nvapi->lib)
      hc_dlclose (nvapi->lib);

    myfree (nvapi);
  }
}

static void hm_NvAPI_GetErrorMessage (NVAPI_PTR *nvapi, const NvAPI_Status NvAPI_rc, NvAPI_ShortString string)
{
  nvapi->NvAPI_GetErrorMessage (NvAPI_rc, string);
}

int hm_NvAPI_Initialize (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_Initialize ();

  if (NvAPI_rc == NVAPI_LIBRARY_NOT_FOUND) return -1;

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "%s %d %s\n", "NvAPI_Initialize()", NvAPI_rc, string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_Unload (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_Unload ();

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "%s %d %s\n", "NvAPI_Unload()", NvAPI_rc, string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_EnumPhysicalGPUs (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle nvGPUHandle[NVAPI_MAX_PHYSICAL_GPUS], NvU32 *pGpuCount)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_EnumPhysicalGPUs (nvGPUHandle, pGpuCount);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "%s %d %s\n", "NvAPI_EnumPhysicalGPUs()", NvAPI_rc, string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_GPU_GetPerfPoliciesInfo (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_POLICIES_INFO_PARAMS_V1 *perfPolicies_info)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetPerfPoliciesInfo (hPhysicalGpu, perfPolicies_info);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "%s %d %s\n", "NvAPI_GPU_GetPerfPoliciesInfo()", NvAPI_rc, string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_GPU_GetPerfPoliciesStatus (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1 *perfPolicies_status)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetPerfPoliciesStatus (hPhysicalGpu, perfPolicies_status);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "%s %d %s\n", "NvAPI_GPU_GetPerfPoliciesStatus()", NvAPI_rc, string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_GPU_SetCoolerLevels (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NvU32 coolerIndex, NV_GPU_COOLER_LEVELS *pCoolerLevels)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_SetCoolerLevels (hPhysicalGpu, coolerIndex, pCoolerLevels);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "%s %d %s\n", "NvAPI_GPU_SetCoolerLevels()", NvAPI_rc, string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_GPU_RestoreCoolerSettings (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NvU32 coolerIndex)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  NVAPI_PTR *nvapi = hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_RestoreCoolerSettings (hPhysicalGpu, coolerIndex);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "%s %d %s\n", "NvAPI_GPU_RestoreCoolerSettings()", NvAPI_rc, string);

    return -1;
  }

  return 0;
}

#if defined (__MINGW64__)

void __security_check_cookie (uintptr_t _StackCookie)
{
  (void) _StackCookie;
}

void __GSHandlerCheck ()
{
}

#endif

// xnvctrl functions

int xnvctrl_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  memset (xnvctrl, 0, sizeof (XNVCTRL_PTR));

  #if defined (_WIN)

  // unsupport platform?
  return -1;

  #elif defined (_POSIX)

  xnvctrl->lib_x11 = dlopen ("libX11.so", RTLD_LAZY);

  if (xnvctrl->lib_x11 == NULL)
  {
    //if (user_options->quiet == false) event_log_error (hashcat_ctx, "Failed loading the X11 library: %s", dlerror());
    //if (user_options->quiet == false) event_log_info (hashcat_ctx, "         Please install libx11-dev package.");
    //if (user_options->quiet == false) event_log_info (hashcat_ctx, "");

    return -1;
  }

  xnvctrl->lib_xnvctrl = dlopen ("libXNVCtrl.so", RTLD_LAZY);

  if (xnvctrl->lib_xnvctrl == NULL)
  {
    //if (user_options->quiet == false) event_log_error (hashcat_ctx, "Failed loading the XNVCTRL library: %s", dlerror());
    //if (user_options->quiet == false) event_log_info (hashcat_ctx, "         Please install libxnvctrl-dev package.");
    //if (user_options->quiet == false) event_log_info (hashcat_ctx, "");

    return -1;
  }

  HC_LOAD_FUNC2 (xnvctrl, XOpenDisplay,  XOPENDISPLAY,  lib_x11, X11, 0);
  HC_LOAD_FUNC2 (xnvctrl, XCloseDisplay, XCLOSEDISPLAY, lib_x11, X11, 0);

  HC_LOAD_FUNC2 (xnvctrl, XNVCTRLQueryTargetAttribute, XNVCTRLQUERYTARGETATTRIBUTE, lib_xnvctrl, XNVCTRL, 0);
  HC_LOAD_FUNC2 (xnvctrl, XNVCTRLSetTargetAttribute,   XNVCTRLSETTARGETATTRIBUTE,   lib_xnvctrl, XNVCTRL, 0);

  #endif

  return 0;
}

void xnvctrl_close (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl)
  {
    #if defined (_POSIX)

    if (xnvctrl->lib_x11)
    {
      dlclose (xnvctrl->lib_x11);
    }

    if (xnvctrl->lib_xnvctrl)
    {
      dlclose (xnvctrl->lib_xnvctrl);
    }

    #endif

    myfree (xnvctrl);
  }
}

int hm_XNVCTRL_XOpenDisplay (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XOpenDisplay == NULL) return -1;

  void *dpy = xnvctrl->XOpenDisplay (NULL);

  if (dpy == NULL)
  {
    event_log_error (hashcat_ctx, "%s\n", "XOpenDisplay() failed");

    return -1;
  }

  xnvctrl->dpy = dpy;

  return 0;
}

void hm_XNVCTRL_XCloseDisplay (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XCloseDisplay == NULL) return;

  if (xnvctrl->dpy == NULL) return;

  xnvctrl->XCloseDisplay (xnvctrl->dpy);
}

int get_fan_control (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const bool rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_COOLER_MANUAL_CONTROL, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "%s\n", "XNVCTRLQueryTargetAttribute(NV_CTRL_GPU_COOLER_MANUAL_CONTROL) failed");

    return -1;
  }

  return 0;
}

int set_fan_control (hashcat_ctx_t *hashcat_ctx, const int gpu, int val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLSetTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  int cur;

  int rc = get_fan_control (hashcat_ctx, gpu, &cur);

  if (rc == -1) return -1;

  xnvctrl->XNVCTRLSetTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_COOLER_MANUAL_CONTROL, val);

  rc = get_fan_control (hashcat_ctx, gpu, &cur);

  if (rc == -1) return -1;

  if (cur != val) return -1;

  return 0;
}

int get_core_threshold (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const bool rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_CORE_THRESHOLD, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "%s\n", "XNVCTRLQueryTargetAttribute(NV_CTRL_GPU_CORE_THRESHOLD) failed");

    return -1;
  }

  return 0;
}

int get_fan_speed_current (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const bool rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_CURRENT_LEVEL, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "%s\n", "XNVCTRLQueryTargetAttribute(NV_CTRL_THERMAL_COOLER_CURRENT_LEVEL) failed");

    return -1;
  }

  return 0;
}

int get_fan_speed_target (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  const int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_LEVEL, val);

  if (rc == false)
  {
    event_log_error (hashcat_ctx, "%s\n", "XNVCTRLQueryTargetAttribute(NV_CTRL_THERMAL_COOLER_LEVEL) failed");

    return -1;
  }

  return 0;
}

int set_fan_speed_target (hashcat_ctx_t *hashcat_ctx, const int gpu, int val)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  XNVCTRL_PTR *xnvctrl = hwmon_ctx->hm_xnvctrl;

  if (xnvctrl->XNVCTRLSetTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  int cur;

  int rc = get_fan_speed_target (hashcat_ctx, gpu, &cur);

  if (rc == -1) return -1;

  xnvctrl->XNVCTRLSetTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_LEVEL, val);

  rc = get_fan_speed_target (hashcat_ctx, gpu, &cur);

  if (rc == -1) return -1;

  if (cur != val) return -1;

  return 0;
}

// ADL functions

int adl_init (hashcat_ctx_t *hashcat_ctx)
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
  #elif defined (_POSIX)
  adl->lib = hc_dlopen ("libatiadlxx.so", RTLD_NOW);
  #endif

  if (!adl->lib)
  {
    //if (user_options->quiet == false)
    //  event_log_error (hashcat_ctx, "load ADL library failed, proceed without ADL HWMon enabled.");

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
  HC_LOAD_FUNC(adl, ADL_Overdrive5_FanSpeed_Set, ADL_OVERDRIVE5_FANSPEED_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_FanSpeed_Set, ADL_OVERDRIVE6_FANSPEED_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_FanSpeedToDefault_Set, ADL_OVERDRIVE5_FANSPEEDTODEFAULT_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_ODParameters_Get, ADL_OVERDRIVE5_ODPARAMETERS_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_ODPerformanceLevels_Get, ADL_OVERDRIVE5_ODPERFORMANCELEVELS_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive5_ODPerformanceLevels_Set, ADL_OVERDRIVE5_ODPERFORMANCELEVELS_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_PowerControlInfo_Get, ADL_OVERDRIVE6_POWERCONTROLINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_PowerControl_Get, ADL_OVERDRIVE6_POWERCONTROL_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_PowerControl_Set, ADL_OVERDRIVE6_POWERCONTROL_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Adapter_Active_Get, ADL_ADAPTER_ACTIVE_GET, ADL, 0)
  //HC_LOAD_FUNC(adl, ADL_DisplayEnable_Set, ADL_DISPLAYENABLE_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive_Caps, ADL_OVERDRIVE_CAPS, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_PowerControl_Caps, ADL_OVERDRIVE6_POWERCONTROL_CAPS, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_Capabilities_Get, ADL_OVERDRIVE6_CAPABILITIES_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_StateInfo_Get, ADL_OVERDRIVE6_STATEINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_CurrentStatus_Get, ADL_OVERDRIVE6_CURRENTSTATUS_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_State_Set, ADL_OVERDRIVE6_STATE_SET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_TargetTemperatureData_Get, ADL_OVERDRIVE6_TARGETTEMPERATUREDATA_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_TargetTemperatureRangeInfo_Get, ADL_OVERDRIVE6_TARGETTEMPERATURERANGEINFO_GET, ADL, 0)
  HC_LOAD_FUNC(adl, ADL_Overdrive6_FanSpeed_Reset, ADL_OVERDRIVE6_FANSPEED_RESET, ADL, 0)

  return 0;
}

void adl_close (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  if (adl)
  {
    if (adl->lib)
      hc_dlclose (adl->lib);

    myfree (adl);
  }
}

int hm_ADL_Main_Control_Destroy (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Main_Control_Destroy ();

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Main_Control_Destroy()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Main_Control_Create (hashcat_ctx_t *hashcat_ctx, ADL_MAIN_MALLOC_CALLBACK callback, int iEnumConnectedAdapters)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Main_Control_Create (callback, iEnumConnectedAdapters);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Main_Control_Create()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Adapter_NumberOfAdapters_Get (hashcat_ctx_t *hashcat_ctx, int *lpNumAdapters)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Adapter_NumberOfAdapters_Get (lpNumAdapters);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Adapter_NumberOfAdapters_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Adapter_AdapterInfo_Get (hashcat_ctx_t *hashcat_ctx, LPAdapterInfo lpInfo, int iInputSize)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Adapter_AdapterInfo_Get (lpInfo, iInputSize);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Adapter_AdapterInfo_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Display_DisplayInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *iNumDisplays, ADLDisplayInfo **lppInfo, int iForceDetect)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Display_DisplayInfo_Get (iAdapterIndex, iNumDisplays, lppInfo, iForceDetect);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Display_DisplayInfo_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Adapter_ID_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *lpAdapterID)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Adapter_ID_Get (iAdapterIndex, lpAdapterID);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Adapter_ID_Get()", ADL_rc);

    return -1;
  }

  return ADL_rc;
}

int hm_ADL_Adapter_VideoBiosInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLBiosInfo *lpBiosInfo)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Adapter_VideoBiosInfo_Get (iAdapterIndex, lpBiosInfo);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Adapter_VideoBiosInfo_Get()", ADL_rc);

    return -1;
  }

  return ADL_rc;
}

int hm_ADL_Overdrive_ThermalDevices_Enum (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLThermalControllerInfo *lpThermalControllerInfo)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_ThermalDevices_Enum (iAdapterIndex, iThermalControllerIndex, lpThermalControllerInfo);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive5_ThermalDevices_Enum()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive5_Temperature_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_Temperature_Get (iAdapterIndex, iThermalControllerIndex, lpTemperature);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive5_Temperature_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive6_Temperature_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *iTemperature)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_Temperature_Get (iAdapterIndex, iTemperature);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_Temperature_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLPMActivity *lpActivity)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_CurrentActivity_Get (iAdapterIndex, lpActivity);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive5_CurrentActivity_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive5_FanSpeedInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedInfo *lpFanSpeedInfo)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_FanSpeedInfo_Get (iAdapterIndex, iThermalControllerIndex, lpFanSpeedInfo);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive5_FanSpeedInfo_Get()", ADL_rc);

    return -1;
  }

  return ADL_rc;
}

int hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_FanSpeed_Get (iAdapterIndex, iThermalControllerIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive5_FanSpeed_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive6_FanSpeed_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6FanSpeedInfo *lpFanSpeedInfo)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_FanSpeed_Get (iAdapterIndex, lpFanSpeedInfo);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_FanSpeed_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive5_FanSpeed_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_FanSpeed_Set (iAdapterIndex, iThermalControllerIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive5_FanSpeed_Set()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive6_FanSpeed_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6FanSpeedValue *lpFanSpeedValue)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_FanSpeed_Set (iAdapterIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_FanSpeed_Set()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive5_FanSpeedToDefault_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_FanSpeedToDefault_Set (iAdapterIndex, iThermalControllerIndex);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive5_FanSpeedToDefault_Set()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_ODParameters_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLODParameters *lpOdParameters)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_ODParameters_Get (iAdapterIndex, lpOdParameters);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive5_ODParameters_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_ODPerformanceLevels_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iDefault, ADLODPerformanceLevels *lpOdPerformanceLevels)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_ODPerformanceLevels_Get (iAdapterIndex, iDefault, lpOdPerformanceLevels);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive5_ODPerformanceLevels_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_ODPerformanceLevels_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLODPerformanceLevels *lpOdPerformanceLevels)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_ODPerformanceLevels_Set (iAdapterIndex, lpOdPerformanceLevels);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive5_ODPerformanceLevels_Set()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_PowerControlInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6PowerControlInfo *powertune)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_PowerControlInfo_Get (iAdapterIndex, powertune);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_PowerControlInfo_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_PowerControl_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *iCurrentValue)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  int default_value = 0;

  const int ADL_rc = adl->ADL_Overdrive6_PowerControl_Get (iAdapterIndex, iCurrentValue, &default_value);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_PowerControl_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_PowerControl_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int level)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

  const int hm_rc = hm_ADL_Overdrive_PowerControlInfo_Get (hashcat_ctx, iAdapterIndex, &powertune);

  if (hm_rc == -1) return -1;

  int min  = powertune.iMinValue;
  int max  = powertune.iMaxValue;
  int step = powertune.iStepValue;

  if (level < min || level > max)
  {
    event_log_error (hashcat_ctx, "ADL PowerControl level invalid");

    return -1;
  }

  if (level % step != 0)
  {
    event_log_error (hashcat_ctx, "ADL PowerControl step invalid");

    return -1;
  }

  const int ADL_rc = adl->ADL_Overdrive6_PowerControl_Set (iAdapterIndex, level);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_PowerControl_Set()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Adapter_Active_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *lpStatus)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Adapter_Active_Get (iAdapterIndex, lpStatus);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Adapter_Active_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

/*
int hm_ADL_DisplayEnable_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *lpDisplayIndexList, int iDisplayListSize, int bPersistOnly)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_DisplayEnable_Set (iAdapterIndex, lpDisplayIndexList, iDisplayListSize, bPersistOnly);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_DisplayEnable_Set()", ADL_rc);

    return -1;
  }

  return 0;
}
*/

int hm_ADL_Overdrive_Caps (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *od_supported, int *od_enabled, int *od_version)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive_Caps (iAdapterIndex, od_supported, od_enabled, od_version);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive_Caps()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive6_PowerControl_Caps (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *lpSupported)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_PowerControl_Caps (iAdapterIndex, lpSupported);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_PowerControl_Caps()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_Capabilities_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6Capabilities *caps)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_Capabilities_Get (iAdapterIndex, caps);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_Capabilities_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_StateInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int type, ADLOD6MemClockState *state)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_StateInfo_Get (iAdapterIndex, type, state);

  if (ADL_rc == ADL_OK)
  {
    // check if clocks are okay with step sizes
    // if not run a little hack: adjust the clocks to nearest clock size (clock down just a little bit)

    ADLOD6Capabilities caps;

    const int hm_rc = hm_ADL_Overdrive_Capabilities_Get (hashcat_ctx, iAdapterIndex, &caps);

    if (hm_rc == -1) return -1;

    if (state->state.aLevels[0].iEngineClock % caps.sEngineClockRange.iStep != 0)
    {
      event_log_error (hashcat_ctx, "ADL engine step size invalid for performance level 1");

      //state->state.aLevels[0].iEngineClock -= state->state.aLevels[0].iEngineClock % caps.sEngineClockRange.iStep;

      return -1;
    }

    if (state->state.aLevels[1].iEngineClock % caps.sEngineClockRange.iStep != 0)
    {
      event_log_error (hashcat_ctx, "ADL engine step size invalid for performance level 2");

      //state->state.aLevels[1].iEngineClock -= state->state.aLevels[1].iEngineClock % caps.sEngineClockRange.iStep;

      return -1;
    }

    if (state->state.aLevels[0].iMemoryClock % caps.sMemoryClockRange.iStep != 0)
    {
      event_log_error (hashcat_ctx, "ADL memory step size invalid for performance level 1");

      //state->state.aLevels[0].iMemoryClock -= state->state.aLevels[0].iMemoryClock % caps.sMemoryClockRange.iStep;

      return -1;
    }

    if (state->state.aLevels[1].iMemoryClock % caps.sMemoryClockRange.iStep != 0)
    {
      event_log_error (hashcat_ctx, "ADL memory step size invalid for performance level 2");

      //state->state.aLevels[1].iMemoryClock -= state->state.aLevels[1].iMemoryClock % caps.sMemoryClockRange.iStep;

      return -1;
    }
  }
  else
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_StateInfo_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_CurrentStatus_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6CurrentStatus *status)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_CurrentStatus_Get (iAdapterIndex, status);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_CurrentStatus_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_State_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int type, ADLOD6StateInfo *state)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  // sanity checks

  ADLOD6Capabilities caps;

  const int hm_rc = hm_ADL_Overdrive_Capabilities_Get (hashcat_ctx, iAdapterIndex, &caps);

  if (hm_rc == -1) return -1;

  if (state->aLevels[0].iEngineClock < caps.sEngineClockRange.iMin || state->aLevels[1].iEngineClock > caps.sEngineClockRange.iMax)
  {
    event_log_error (hashcat_ctx, "ADL engine clock outside valid range");

    return -1;
  }

  if (state->aLevels[1].iEngineClock % caps.sEngineClockRange.iStep != 0)
  {
    event_log_error (hashcat_ctx, "ADL engine step size invalid");

    return -1;
  }

  if (state->aLevels[0].iMemoryClock < caps.sMemoryClockRange.iMin || state->aLevels[1].iMemoryClock > caps.sMemoryClockRange.iMax)
  {
    event_log_error (hashcat_ctx, "ADL memory clock outside valid range");

    return -1;
  }

  if (state->aLevels[1].iMemoryClock % caps.sMemoryClockRange.iStep != 0)
  {
    event_log_error (hashcat_ctx, "ADL memory step size invalid");

    return -1;
  }

  const int ADL_rc = adl->ADL_Overdrive6_State_Set (iAdapterIndex, type, state);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_State_Set()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive6_TargetTemperatureData_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *cur_temp, int *default_temp)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_TargetTemperatureData_Get (iAdapterIndex, cur_temp, default_temp);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_TargetTemperatureData_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive6_TargetTemperatureRangeInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6ParameterRange *lpTargetTemperatureInfo)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_TargetTemperatureRangeInfo_Get (iAdapterIndex, lpTargetTemperatureInfo);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_TargetTemperatureRangeInfo_Get()", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive6_FanSpeed_Reset (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  ADL_PTR *adl = hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_FanSpeed_Reset (iAdapterIndex);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "%s: %d\n", "ADL_Overdrive6_FanSpeed_Reset()", ADL_rc);

    return -1;
  }

  return 0;
}

// general functions

static int get_adapters_num_adl (hashcat_ctx_t *hashcat_ctx, int *iNumberAdapters)
{
  const int hm_rc = hm_ADL_Adapter_NumberOfAdapters_Get (hashcat_ctx, iNumberAdapters);

  if (hm_rc == -1) return -1;

  if (iNumberAdapters == 0)
  {
    event_log_error (hashcat_ctx, "No ADL adapters found.");

    return -1;
  }

  return 0;
}

static LPAdapterInfo hm_get_adapter_info_adl (hashcat_ctx_t *hashcat_ctx, int iNumberAdapters)
{
  size_t AdapterInfoSize = iNumberAdapters * sizeof (AdapterInfo);

  LPAdapterInfo lpAdapterInfo = (LPAdapterInfo) mymalloc (AdapterInfoSize);

  if (hm_ADL_Adapter_AdapterInfo_Get (hashcat_ctx, lpAdapterInfo, AdapterInfoSize) == -1) return NULL;

  return lpAdapterInfo;
}

static int hm_get_adapter_index_nvapi (hashcat_ctx_t *hashcat_ctx, HM_ADAPTER_NVAPI *nvapiGPUHandle)
{
  NvU32 pGpuCount;

  if (hm_NvAPI_EnumPhysicalGPUs (hashcat_ctx, nvapiGPUHandle, &pGpuCount) != NVAPI_OK) return 0;

  if (pGpuCount == 0)
  {
    event_log_error (hashcat_ctx, "No NvAPI adapters found");

    return 0;
  }

  return (pGpuCount);
}

static int hm_get_adapter_index_nvml (hashcat_ctx_t *hashcat_ctx, HM_ADAPTER_NVML *nvmlGPUHandle)
{
  int pGpuCount = 0;

  for (u32 i = 0; i < DEVICES_MAX; i++)
  {
    if (hm_NVML_nvmlDeviceGetHandleByIndex (hashcat_ctx, i, &nvmlGPUHandle[i]) == -1) break;

    // can be used to determine if the device by index matches the cuda device by index
    // char name[100]; memset (name, 0, sizeof (name));
    // hm_NVML_nvmlDeviceGetName (hashcat_ctx, nvGPUHandle[i], name, sizeof (name) - 1);

    pGpuCount++;
  }

  if (pGpuCount == 0)
  {
    event_log_error (hashcat_ctx, "No NVML adapters found");

    return 0;
  }

  return (pGpuCount);
}

static void hm_sort_adl_adapters_by_busid_devid (u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  // basically bubble sort

  for (int i = 0; i < num_adl_adapters; i++)
  {
    for (int j = 0; j < num_adl_adapters - 1; j++)
    {
      // get info of adapter [x]

      u32 adapter_index_x = valid_adl_device_list[j];
      AdapterInfo info_x = lpAdapterInfo[adapter_index_x];

      u32 bus_num_x = info_x.iBusNumber;
      u32 dev_num_x = info_x.iDeviceNumber;

      // get info of adapter [y]

      u32 adapter_index_y = valid_adl_device_list[j + 1];
      AdapterInfo info_y = lpAdapterInfo[adapter_index_y];

      u32 bus_num_y = info_y.iBusNumber;
      u32 dev_num_y = info_y.iDeviceNumber;

      u32 need_swap = 0;

      if (bus_num_y < bus_num_x)
      {
        need_swap = 1;
      }
      else if (bus_num_y == bus_num_x)
      {
        if (dev_num_y < dev_num_x)
        {
          need_swap = 1;
        }
      }

      if (need_swap == 1)
      {
        u32 temp = valid_adl_device_list[j + 1];

        valid_adl_device_list[j + 1] = valid_adl_device_list[j];
        valid_adl_device_list[j + 0] = temp;
      }
    }
  }
}

static u32 *hm_get_list_valid_adl_adapters (int iNumberAdapters, int *num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  *num_adl_adapters = 0;

  u32 *adl_adapters = NULL;

  int *bus_numbers    = NULL;
  int *device_numbers = NULL;

  for (int i = 0; i < iNumberAdapters; i++)
  {
    AdapterInfo info = lpAdapterInfo[i];

    if (strlen (info.strUDID) < 1) continue;

    #if defined (_WIN)
    if (info.iVendorID !=   1002) continue;
    #else
    if (info.iVendorID != 0x1002) continue;
    #endif

    if (info.iBusNumber    < 0) continue;
    if (info.iDeviceNumber < 0) continue;

    int found = 0;

    for (int pos = 0; pos < *num_adl_adapters; pos++)
    {
      if ((bus_numbers[pos] == info.iBusNumber) && (device_numbers[pos] == info.iDeviceNumber))
      {
        found = 1;
        break;
      }
    }

    if (found) continue;

    // add it to the list

    adl_adapters = (u32 *) myrealloc (adl_adapters, (*num_adl_adapters) * sizeof (int), sizeof (int));

    adl_adapters[*num_adl_adapters] = i;

    // rest is just bookkeeping

    bus_numbers    = (int*) myrealloc (bus_numbers,    (*num_adl_adapters) * sizeof (int), sizeof (int));
    device_numbers = (int*) myrealloc (device_numbers, (*num_adl_adapters) * sizeof (int), sizeof (int));

    bus_numbers[*num_adl_adapters]    = info.iBusNumber;
    device_numbers[*num_adl_adapters] = info.iDeviceNumber;

    (*num_adl_adapters)++;
  }

  myfree (bus_numbers);
  myfree (device_numbers);

  // sort the list by increasing bus id, device id number

  hm_sort_adl_adapters_by_busid_devid (adl_adapters, *num_adl_adapters, lpAdapterInfo);

  return adl_adapters;
}

static int hm_check_fanspeed_control (hashcat_ctx_t *hashcat_ctx, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  // loop through all valid devices

  for (int i = 0; i < num_adl_adapters; i++)
  {
    u32 adapter_index = valid_adl_device_list[i];

    // get AdapterInfo

    AdapterInfo info = lpAdapterInfo[adapter_index];

    // unfortunately this doesn't work since bus id and dev id are not unique
    // int opencl_device_index = hm_get_opencl_device_index (hm_device, num_adl_adapters, info.iBusNumber, info.iDeviceNumber);
    // if (opencl_device_index == -1) continue;

    int opencl_device_index = i;

    // if (hm_show_performance_level (adl, info.iAdapterIndex) != 0) return -1;

    // get fanspeed info

    if (hm_device[opencl_device_index].od_version == 5)
    {
      ADLFanSpeedInfo FanSpeedInfo;

      memset (&FanSpeedInfo, 0, sizeof (ADLFanSpeedInfo));

      FanSpeedInfo.iSize = sizeof (ADLFanSpeedInfo);

      if (hm_ADL_Overdrive5_FanSpeedInfo_Get (hashcat_ctx, info.iAdapterIndex, 0, &FanSpeedInfo) == -1) return -1;

      // check read and write capability in fanspeedinfo

      if ((FanSpeedInfo.iFlags & ADL_DL_FANCTRL_SUPPORTS_PERCENT_READ) &&
          (FanSpeedInfo.iFlags & ADL_DL_FANCTRL_SUPPORTS_PERCENT_WRITE))
      {
        hm_device[opencl_device_index].fan_get_supported = true;
      }
      else
      {
        hm_device[opencl_device_index].fan_get_supported = false;
      }
    }
    else // od_version == 6
    {
      ADLOD6FanSpeedInfo faninfo;

      memset (&faninfo, 0, sizeof (faninfo));

      if (hm_ADL_Overdrive6_FanSpeed_Get (hashcat_ctx, info.iAdapterIndex, &faninfo) == -1) return -1;

      // check read capability in fanspeedinfo

      if (faninfo.iSpeedType & ADL_OD6_FANSPEED_TYPE_PERCENT)
      {
        hm_device[opencl_device_index].fan_get_supported = true;
      }
      else
      {
        hm_device[opencl_device_index].fan_get_supported = false;
      }
    }
  }

  return 0;
}

static int hm_get_overdrive_version (hashcat_ctx_t *hashcat_ctx, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  for (int i = 0; i < num_adl_adapters; i++)
  {
    u32 adapter_index = valid_adl_device_list[i];

    // get AdapterInfo

    AdapterInfo info = lpAdapterInfo[adapter_index];

    // get overdrive version

    int od_supported = 0;
    int od_enabled   = 0;
    int od_version   = 0;

    if (hm_ADL_Overdrive_Caps (hashcat_ctx, info.iAdapterIndex, &od_supported, &od_enabled, &od_version) == -1) return -1;

    // store the overdrive version in hm_device

    // unfortunately this doesn't work since bus id and dev id are not unique
    // int opencl_device_index = hm_get_opencl_device_index (hm_device, num_adl_adapters, info.iBusNumber, info.iDeviceNumber);
    // if (opencl_device_index == -1) continue;

    int opencl_device_index = i;

    hm_device[opencl_device_index].od_version = od_version;
  }

  return 0;
}

static int hm_get_adapter_index_adl (hashcat_ctx_t *hashcat_ctx, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  hm_attrs_t *hm_device = hwmon_ctx->hm_device;

  for (int i = 0; i < num_adl_adapters; i++)
  {
    const u32 adapter_index = valid_adl_device_list[i];

    // get AdapterInfo

    AdapterInfo info = lpAdapterInfo[adapter_index];

    // store the iAdapterIndex in hm_device

    // unfortunately this doesn't work since bus id and dev id are not unique
    // int opencl_device_index = hm_get_opencl_device_index (hm_device, num_adl_adapters, info.iBusNumber, info.iDeviceNumber);
    // if (opencl_device_index == -1) continue;

    int opencl_device_index = i;

    hm_device[opencl_device_index].adl = info.iAdapterIndex;
  }

  return num_adl_adapters;
}

int hm_get_threshold_slowdown_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {

      }
      else if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {
        int CurrentValue = 0;
        int DefaultValue = 0;

        if (hm_ADL_Overdrive6_TargetTemperatureData_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &CurrentValue, &DefaultValue) == -1) return -1;

        // the return value has never been tested since hm_ADL_Overdrive6_TargetTemperatureData_Get() never worked on any system. expect problems.

        return DefaultValue;
      }
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int target = 0;

    if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, (unsigned int *) &target) == -1) return -1;

    return target;
  }

  return -1;
}

int hm_get_threshold_shutdown_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {

      }
      else if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {

      }
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int target = 0;

    if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, NVML_TEMPERATURE_THRESHOLD_SHUTDOWN, (unsigned int *) &target) == -1) return -1;

    return target;
  }

  return -1;
}

int hm_get_temperature_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {
        ADLTemperature Temperature;

        Temperature.iSize = sizeof (ADLTemperature);

        if (hm_ADL_Overdrive5_Temperature_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, 0, &Temperature) == -1) return -1;

        return Temperature.iTemperature / 1000;
      }
      else if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {
        int Temperature = 0;

        if (hm_ADL_Overdrive6_Temperature_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &Temperature) == -1) return -1;

        return Temperature / 1000;
      }
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int temperature = 0;

    if (hm_NVML_nvmlDeviceGetTemperature (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, NVML_TEMPERATURE_GPU, (u32 *) &temperature) == -1) return -1;

    return temperature;
  }

  return -1;
}

int hm_get_fanpolicy_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (hwmon_ctx->hm_device[device_id].fan_get_supported == true)
  {
    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        if (hwmon_ctx->hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;

          if (hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, 0, &lpFanSpeedValue) == -1) return -1;

          return (lpFanSpeedValue.iFanSpeed & ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED) ? 0 : 1;
        }
        else // od_version == 6
        {
          return 1;
        }
      }
    }

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      return 1;
    }
  }

  return -1;
}

int hm_get_fanspeed_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (hwmon_ctx->hm_device[device_id].fan_get_supported == true)
  {
    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        if (hwmon_ctx->hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
          lpFanSpeedValue.iFlags     = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;

          if (hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, 0, &lpFanSpeedValue) == -1) return -1;

          return lpFanSpeedValue.iFanSpeed;
        }
        else // od_version == 6
        {
          ADLOD6FanSpeedInfo faninfo;

          memset (&faninfo, 0, sizeof (faninfo));

          if (hm_ADL_Overdrive6_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &faninfo) == -1) return -1;

          return faninfo.iFanSpeedPercent;
        }
      }
    }

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      int speed = 0;

      if (hm_NVML_nvmlDeviceGetFanSpeed (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, (u32 *) &speed) == -1) return -1;

      return speed;
    }
  }

  return -1;
}

int hm_get_buslanes_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &PMActivity) == -1) return -1;

      return PMActivity.iCurrentBusLanes;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int currLinkWidth;

    if (hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &currLinkWidth) == -1) return -1;

    return currLinkWidth;
  }

  return -1;
}

int hm_get_utilization_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &PMActivity) == -1) return -1;

      return PMActivity.iActivityPercent;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    nvmlUtilization_t utilization;

    if (hm_NVML_nvmlDeviceGetUtilizationRates (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &utilization) == -1) return -1;

    return utilization.gpu;
  }

  return -1;
}

int hm_get_memoryspeed_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &PMActivity) == -1) return -1;

      return PMActivity.iMemoryClock / 100;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int clock;

    if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, NVML_CLOCK_MEM, &clock) == -1) return -1;

    return clock;
  }

  return -1;
}

int hm_get_corespeed_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &PMActivity) == -1) return -1;

      return PMActivity.iEngineClock / 100;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int clock;

    if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, NVML_CLOCK_SM, &clock) == -1) return -1;

    return clock;
  }

  return -1;
}

int hm_get_throttle_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id)
{
  hwmon_ctx_t  *hwmon_ctx  = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {

  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned long long clocksThrottleReasons = 0;
    unsigned long long supportedThrottleReasons = 0;

    if (hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons   (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &clocksThrottleReasons)    == -1) return -1;
    if (hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &supportedThrottleReasons) == -1) return -1;

    clocksThrottleReasons &=  supportedThrottleReasons;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonGpuIdle;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonApplicationsClocksSetting;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonUnknown;

    if (opencl_ctx->kernel_power_final)
    {
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonHwSlowdown;
    }

    return (clocksThrottleReasons != nvmlClocksThrottleReasonNone);
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_adl (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed, const int fanpolicy)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fan_set_supported == true)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (fanpolicy == 1)
      {
        if (hwmon_ctx->hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
          lpFanSpeedValue.iFlags     = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;
          lpFanSpeedValue.iFanSpeed  = fanspeed;

          if (hm_ADL_Overdrive5_FanSpeed_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, 0, &lpFanSpeedValue) == -1) return -1;

          return 0;
        }
        else // od_version == 6
        {
          ADLOD6FanSpeedValue fan_speed_value;

          memset (&fan_speed_value, 0, sizeof (fan_speed_value));

          fan_speed_value.iSpeedType = ADL_OD6_FANSPEED_TYPE_PERCENT;
          fan_speed_value.iFanSpeed  = fanspeed;

          if (hm_ADL_Overdrive6_FanSpeed_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &fan_speed_value) == -1) return -1;

          return 0;
        }
      }
      else
      {
        if (hwmon_ctx->hm_device[device_id].od_version == 5)
        {
          if (hm_ADL_Overdrive5_FanSpeedToDefault_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, 0) == -1) return -1;

          return 0;
        }
        else // od_version == 6
        {
          if (hm_ADL_Overdrive6_FanSpeed_Reset (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl) == -1) return -1;

          return 0;
        }
      }
    }
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_nvapi (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed, const int fanpolicy)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fan_set_supported == true)
  {
    if (hwmon_ctx->hm_nvapi)
    {
      if (fanpolicy == 1)
      {
        NV_GPU_COOLER_LEVELS CoolerLevels;

        memset (&CoolerLevels, 0, sizeof (NV_GPU_COOLER_LEVELS));

        CoolerLevels.Version = GPU_COOLER_LEVELS_VER | sizeof (NV_GPU_COOLER_LEVELS);

        CoolerLevels.Levels[0].Level  = fanspeed;
        CoolerLevels.Levels[0].Policy = 1;

        if (hm_NvAPI_GPU_SetCoolerLevels (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvapi, 0, &CoolerLevels) != NVAPI_OK) return -1;

        return 0;
      }
      else
      {
        if (hm_NvAPI_GPU_RestoreCoolerSettings (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvapi, 0) != NVAPI_OK) return -1;

        return 0;
      }
    }
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_xnvctrl (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fan_set_supported == true)
  {
    if (hwmon_ctx->hm_xnvctrl)
    {
      if (set_fan_speed_target (hashcat_ctx, hwmon_ctx->hm_device[device_id].xnvctrl, fanspeed) == -1) return -1;

      return 0;
    }
  }

  return -1;
}

int hwmon_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t    *hwmon_ctx    = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t   *opencl_ctx   = hashcat_ctx->opencl_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  hwmon_ctx->enabled = false;

  if (user_options->keyspace          == true) return 0;
  if (user_options->left              == true) return 0;
  if (user_options->opencl_info       == true) return 0;
  if (user_options->show              == true) return 0;
  if (user_options->stdout_flag       == true) return 0;
  if (user_options->usage             == true) return 0;
  if (user_options->version           == true) return 0;
  if (user_options->gpu_temp_disable  == true) return 0;

  hwmon_ctx->hm_device = (hm_attrs_t *) mycalloc (DEVICES_MAX, sizeof (hm_attrs_t));

  /**
   * Initialize shared libraries
   */

  ADL_PTR     *adl     = (ADL_PTR *)     mymalloc (sizeof (ADL_PTR));
  NVAPI_PTR   *nvapi   = (NVAPI_PTR *)   mymalloc (sizeof (NVAPI_PTR));
  NVML_PTR    *nvml    = (NVML_PTR *)    mymalloc (sizeof (NVML_PTR));
  XNVCTRL_PTR *xnvctrl = (XNVCTRL_PTR *) mymalloc (sizeof (XNVCTRL_PTR));

  hm_attrs_t *hm_adapters_adl      = (hm_attrs_t *) mycalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_nvapi    = (hm_attrs_t *) mycalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_nvml     = (hm_attrs_t *) mycalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_xnvctrl  = (hm_attrs_t *) mycalloc (DEVICES_MAX, sizeof (hm_attrs_t));

  if (opencl_ctx->need_nvml == true)
  {
    hwmon_ctx->hm_nvml = nvml;

    if (nvml_init (hashcat_ctx) == -1)
    {
      myfree (hwmon_ctx->hm_nvml);

      hwmon_ctx->hm_nvml = NULL;
    }
  }

  if (opencl_ctx->need_nvapi == true)
  {
    hwmon_ctx->hm_nvapi = nvapi;

    if (nvapi_init (hashcat_ctx) == -1)
    {
      myfree (hwmon_ctx->hm_nvapi);

      hwmon_ctx->hm_nvapi = NULL;
    }
  }

  if (opencl_ctx->need_xnvctrl == true)
  {
    hwmon_ctx->hm_xnvctrl = xnvctrl;

    if (xnvctrl_init (hashcat_ctx) == -1)
    {
      myfree (hwmon_ctx->hm_xnvctrl);

      hwmon_ctx->hm_xnvctrl = NULL;
    }
  }

  if (opencl_ctx->need_adl == true)
  {
    hwmon_ctx->hm_adl = adl;

    if (adl_init (hashcat_ctx) == -1)
    {
      myfree (hwmon_ctx->hm_adl);

      hwmon_ctx->hm_adl = NULL;
    }
  }

  if (hwmon_ctx->hm_nvml)
  {
    if (hm_NVML_nvmlInit (hashcat_ctx) == 0)
    {
      HM_ADAPTER_NVML *nvmlGPUHandle = (HM_ADAPTER_NVML *) mycalloc (DEVICES_MAX, sizeof (HM_ADAPTER_NVML));

      int tmp_in = hm_get_adapter_index_nvml (hashcat_ctx, nvmlGPUHandle);

      int tmp_out = 0;

      for (int i = 0; i < tmp_in; i++)
      {
        hm_adapters_nvml[tmp_out++].nvml = nvmlGPUHandle[i];
      }

      for (int i = 0; i < tmp_out; i++)
      {
        unsigned int speed;

        if (hm_NVML_nvmlDeviceGetFanSpeed (hashcat_ctx, hm_adapters_nvml[i].nvml, &speed) == 0) hm_adapters_nvml[i].fan_get_supported = true;

        // doesn't seem to create any advantages
        //hm_NVML_nvmlDeviceSetComputeMode (hashcat_ctx, hm_adapters_nvml[i].nvml, NVML_COMPUTEMODE_EXCLUSIVE_PROCESS);
        //hm_NVML_nvmlDeviceSetGpuOperationMode (hashcat_ctx, hm_adapters_nvml[i].nvml, NVML_GOM_ALL_ON);
      }

      myfree (nvmlGPUHandle);
    }
  }

  if (hwmon_ctx->hm_nvapi)
  {
    if (hm_NvAPI_Initialize (hashcat_ctx) == 0)
    {
      HM_ADAPTER_NVAPI *nvGPUHandle = (HM_ADAPTER_NVAPI *) mycalloc (DEVICES_MAX, sizeof (HM_ADAPTER_NVAPI));

      int tmp_in = hm_get_adapter_index_nvapi (hashcat_ctx, nvGPUHandle);

      int tmp_out = 0;

      for (int i = 0; i < tmp_in; i++)
      {
        hm_adapters_nvapi[tmp_out++].nvapi = nvGPUHandle[i];
      }

      myfree (nvGPUHandle);
    }
  }

  if (hwmon_ctx->hm_xnvctrl)
  {
    if (hm_XNVCTRL_XOpenDisplay (hashcat_ctx) == 0)
    {
      for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        hm_adapters_xnvctrl[device_id].xnvctrl = device_id;

        int speed = 0;

        if (get_fan_speed_current (hashcat_ctx, device_id, &speed) == 0) hm_adapters_xnvctrl[device_id].fan_get_supported = true;
      }
    }
  }

  if (hwmon_ctx->hm_adl)
  {
    if (hm_ADL_Main_Control_Create (hashcat_ctx, ADL_Main_Memory_Alloc, 0) == 0)
    {
      // total number of adapters

      int hm_adapters_num;

      if (get_adapters_num_adl (hashcat_ctx, &hm_adapters_num) == -1) return -1;

      // adapter info

      LPAdapterInfo lpAdapterInfo = hm_get_adapter_info_adl (hashcat_ctx, hm_adapters_num);

      if (lpAdapterInfo == NULL) return -1;

      // get a list (of ids of) valid/usable adapters

      int num_adl_adapters = 0;

      u32 *valid_adl_device_list = hm_get_list_valid_adl_adapters (hm_adapters_num, &num_adl_adapters, lpAdapterInfo);

      if (num_adl_adapters > 0)
      {
        hm_get_adapter_index_adl (hashcat_ctx, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);

        hm_get_overdrive_version (hashcat_ctx, hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);

        hm_check_fanspeed_control (hashcat_ctx, hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);
      }

      myfree (valid_adl_device_list);

      myfree (lpAdapterInfo);
    }
  }

  if (hwmon_ctx->hm_adl == NULL && hwmon_ctx->hm_nvml == NULL && hwmon_ctx->hm_xnvctrl == NULL)
  {
    return 0;
  }

  /**
   * looks like we have some manageable device
   */

  hwmon_ctx->enabled = true;

  /**
   * save buffer required for later restores
   */

  hwmon_ctx->od_clock_mem_status = (ADLOD6MemClockState *) mycalloc (opencl_ctx->devices_cnt, sizeof (ADLOD6MemClockState));

  hwmon_ctx->od_power_control_status = (int *) mycalloc (opencl_ctx->devices_cnt, sizeof (int));

  hwmon_ctx->nvml_power_limit = (unsigned int *) mycalloc (opencl_ctx->devices_cnt, sizeof (unsigned int));

  /**
   * HM devices: copy
   */

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

    const u32 platform_devices_id = device_param->platform_devices_id;

    if (device_param->device_vendor_id == VENDOR_ID_AMD)
    {
      hwmon_ctx->hm_device[device_id].adl               = hm_adapters_adl[platform_devices_id].adl;
      hwmon_ctx->hm_device[device_id].nvapi             = 0;
      hwmon_ctx->hm_device[device_id].nvml              = 0;
      hwmon_ctx->hm_device[device_id].xnvctrl           = 0;
      hwmon_ctx->hm_device[device_id].od_version        = hm_adapters_adl[platform_devices_id].od_version;
      hwmon_ctx->hm_device[device_id].fan_get_supported = hm_adapters_adl[platform_devices_id].fan_get_supported;
      hwmon_ctx->hm_device[device_id].fan_set_supported = false;
    }

    if (device_param->device_vendor_id == VENDOR_ID_NV)
    {
      hwmon_ctx->hm_device[device_id].adl               = 0;
      hwmon_ctx->hm_device[device_id].nvapi             = hm_adapters_nvapi[platform_devices_id].nvapi;
      hwmon_ctx->hm_device[device_id].nvml              = hm_adapters_nvml[platform_devices_id].nvml;
      hwmon_ctx->hm_device[device_id].xnvctrl           = hm_adapters_xnvctrl[platform_devices_id].xnvctrl;
      hwmon_ctx->hm_device[device_id].od_version        = 0;
      hwmon_ctx->hm_device[device_id].fan_get_supported = hm_adapters_nvml[platform_devices_id].fan_get_supported;
      hwmon_ctx->hm_device[device_id].fan_set_supported = false;
    }
  }

  myfree (hm_adapters_adl);
  myfree (hm_adapters_nvapi);
  myfree (hm_adapters_nvml);
  myfree (hm_adapters_xnvctrl);

  /**
   * powertune on user request
   */

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      /**
       * Temporary fix:
       * with AMD r9 295x cards it seems that we need to set the powertune value just AFTER the ocl init stuff
       * otherwise after hc_clCreateContext () etc, powertune value was set back to "normal" and cards unfortunately
       * were not working @ full speed (setting hm_ADL_Overdrive_PowerControl_Set () here seems to fix the problem)
       * Driver / ADL bug?
       */

      if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {
        int ADL_rc;

        // check powertune capabilities first, if not available then skip device

        int powertune_supported = 0;

        if ((ADL_rc = hm_ADL_Overdrive6_PowerControl_Caps (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &powertune_supported)) == -1)
        {
          event_log_error (hashcat_ctx, "ERROR: Failed to get ADL PowerControl Capabilities");

          return -1;
        }

        // first backup current value, we will restore it later

        if (powertune_supported != 0)
        {
          // powercontrol settings

          ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

          if ((ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &powertune)) == ADL_OK)
          {
            ADL_rc = hm_ADL_Overdrive_PowerControl_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &hwmon_ctx->od_power_control_status[device_id]);
          }

          if (ADL_rc == -1)
          {
            event_log_error (hashcat_ctx, "ERROR: Failed to get current ADL PowerControl settings");

            return -1;
          }

          if ((ADL_rc = hm_ADL_Overdrive_PowerControl_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, powertune.iMaxValue)) == -1)
          {
            event_log_error (hashcat_ctx, "ERROR: Failed to set new ADL PowerControl values");

            return -1;
          }

          // clocks

          memset (&hwmon_ctx->od_clock_mem_status[device_id], 0, sizeof (ADLOD6MemClockState));

          hwmon_ctx->od_clock_mem_status[device_id].state.iNumberOfPerformanceLevels = 2;

          if ((ADL_rc = hm_ADL_Overdrive_StateInfo_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, ADL_OD6_GETSTATEINFO_CUSTOM_PERFORMANCE, &hwmon_ctx->od_clock_mem_status[device_id])) == -1)
          {
            event_log_error (hashcat_ctx, "ERROR: Failed to get ADL memory and engine clock frequency");

            return -1;
          }

          // Query capabilities only to see if profiles were not "damaged", if so output a warning but do accept the users profile settings

          ADLOD6Capabilities caps = {0, 0, 0, {0, 0, 0}, {0, 0, 0}, 0, 0};

          if ((ADL_rc = hm_ADL_Overdrive_Capabilities_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &caps)) == -1)
          {
            event_log_error (hashcat_ctx, "ERROR: Failed to get ADL device capabilities");

            return -1;
          }

          int engine_clock_max =       (int) (0.6666 * caps.sEngineClockRange.iMax);
          int memory_clock_max =       (int) (0.6250 * caps.sMemoryClockRange.iMax);

          int warning_trigger_engine = (int) (0.25   * engine_clock_max);
          int warning_trigger_memory = (int) (0.25   * memory_clock_max);

          int engine_clock_profile_max = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iEngineClock;
          int memory_clock_profile_max = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iMemoryClock;

          // warning if profile has too low max values

          if ((engine_clock_max - engine_clock_profile_max) > warning_trigger_engine)
          {
            event_log_error (hashcat_ctx, "The custom profile seems to have too low maximum engine clock values. You therefore may not reach full performance");
          }

          if ((memory_clock_max - memory_clock_profile_max) > warning_trigger_memory)
          {
            event_log_error (hashcat_ctx, "The custom profile seems to have too low maximum memory clock values. You therefore may not reach full performance");
          }

          ADLOD6StateInfo *performance_state = (ADLOD6StateInfo*) mycalloc (1, sizeof (ADLOD6StateInfo) + sizeof (ADLOD6PerformanceLevel));

          performance_state->iNumberOfPerformanceLevels = 2;

          performance_state->aLevels[0].iEngineClock = engine_clock_profile_max;
          performance_state->aLevels[1].iEngineClock = engine_clock_profile_max;
          performance_state->aLevels[0].iMemoryClock = memory_clock_profile_max;
          performance_state->aLevels[1].iMemoryClock = memory_clock_profile_max;

          if ((ADL_rc = hm_ADL_Overdrive_State_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, ADL_OD6_SETSTATE_PERFORMANCE, performance_state)) == -1)
          {
            event_log_info (hashcat_ctx, "ERROR: Failed to set ADL performance state");

            return -1;
          }

          myfree (performance_state);
        }

        // set powertune value only

        if (powertune_supported != 0)
        {
          // powertune set
          ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

          if ((ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &powertune)) == -1)
          {
            event_log_error (hashcat_ctx, "ERROR: Failed to get current ADL PowerControl settings");

            return -1;
          }

          if ((ADL_rc = hm_ADL_Overdrive_PowerControl_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, powertune.iMaxValue)) == -1)
          {
            event_log_error (hashcat_ctx, "ERROR: Failed to set new ADL PowerControl values");

            return -1;
          }
        }
      }
    }

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      // first backup current value, we will restore it later

      unsigned int limit;

      bool powertune_supported = false;

      if (hm_NVML_nvmlDeviceGetPowerManagementLimit (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &limit) == NVML_SUCCESS)
      {
        powertune_supported = true;
      }

      // if backup worked, activate the maximum allowed

      if (powertune_supported == true)
      {
        unsigned int minLimit;
        unsigned int maxLimit;

        if (hm_NVML_nvmlDeviceGetPowerManagementLimitConstraints (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, &minLimit, &maxLimit) == NVML_SUCCESS)
        {
          if (maxLimit > 0)
          {
            if (hm_NVML_nvmlDeviceSetPowerManagementLimit (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, maxLimit) == NVML_SUCCESS)
            {
              // now we can be sure we need to reset later

              hwmon_ctx->nvml_power_limit[device_id] = limit;
            }
          }
        }
      }
    }
  }

  /**
   * Store initial fanspeed if gpu_temp_retain is enabled
   */

  if (user_options->gpu_temp_retain)
  {
    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      if (hwmon_ctx->hm_device[device_id].fan_get_supported == true)
      {
        const int fanspeed  = hm_get_fanspeed_with_device_id  (hashcat_ctx, device_id);
        const int fanpolicy = hm_get_fanpolicy_with_device_id (hashcat_ctx, device_id);

        // we also set it to tell the OS we take control over the fan and it's automatic controller
        // if it was set to automatic. we do not control user-defined fanspeeds.

        if (fanpolicy == 1)
        {
          hwmon_ctx->hm_device[device_id].fan_set_supported = true;

          int rc = -1;

          if (device_param->device_vendor_id == VENDOR_ID_AMD)
          {
            rc = hm_set_fanspeed_with_device_id_adl (hashcat_ctx, device_id, fanspeed, 1);
          }
          else if (device_param->device_vendor_id == VENDOR_ID_NV)
          {
            #if defined (__linux__)
            rc = set_fan_control (hashcat_ctx, hwmon_ctx->hm_device[device_id].xnvctrl, NV_CTRL_GPU_COOLER_MANUAL_CONTROL_TRUE);
            #endif

            #if defined (_WIN)
            rc = hm_set_fanspeed_with_device_id_nvapi (hashcat_ctx, device_id, fanspeed, 1);
            #endif
          }

          if (rc == 0)
          {
            hwmon_ctx->hm_device[device_id].fan_set_supported = true;
          }
          else
          {
            event_log_error (hashcat_ctx, "Failed to set initial fan speed for device #%u", device_id + 1);

            hwmon_ctx->hm_device[device_id].fan_set_supported = false;
          }
        }
        else
        {
          hwmon_ctx->hm_device[device_id].fan_set_supported = false;
        }
      }
    }
  }

  return 0;
}

void hwmon_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t    *hwmon_ctx    = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t   *opencl_ctx   = hashcat_ctx->opencl_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (hwmon_ctx->enabled == false) return;

  // reset default fan speed

  if (user_options->gpu_temp_retain)
  {
    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      if (hwmon_ctx->hm_device[device_id].fan_set_supported == true)
      {
        int rc = -1;

        if (device_param->device_vendor_id == VENDOR_ID_AMD)
        {
          rc = hm_set_fanspeed_with_device_id_adl (hashcat_ctx, device_id, 100, 0);
        }
        else if (device_param->device_vendor_id == VENDOR_ID_NV)
        {
          #if defined (__linux__)
          rc = set_fan_control (hashcat_ctx, hwmon_ctx->hm_device[device_id].xnvctrl, NV_CTRL_GPU_COOLER_MANUAL_CONTROL_FALSE);
          #endif

          #if defined (_WIN)
          rc = hm_set_fanspeed_with_device_id_nvapi (hashcat_ctx, device_id, 100, 0);
          #endif
        }

        if (rc == -1) event_log_error (hashcat_ctx, "Failed to restore default fan speed and policy for device #%", device_id + 1);
      }
    }
  }

  // reset power tuning

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {
        // check powertune capabilities first, if not available then skip device

        int powertune_supported = 0;

        if ((hm_ADL_Overdrive6_PowerControl_Caps (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, &powertune_supported)) == -1)
        {
          event_log_error (hashcat_ctx, "ERROR: Failed to get ADL PowerControl Capabilities");

          continue;
        }

        if (powertune_supported != 0)
        {
          // powercontrol settings

          if ((hm_ADL_Overdrive_PowerControl_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, hwmon_ctx->od_power_control_status[device_id])) == -1)
          {
            event_log_info (hashcat_ctx, "ERROR: Failed to restore the ADL PowerControl values");

            continue;
          }

          // clocks

          ADLOD6StateInfo *performance_state = (ADLOD6StateInfo*) mycalloc (1, sizeof (ADLOD6StateInfo) + sizeof (ADLOD6PerformanceLevel));

          performance_state->iNumberOfPerformanceLevels = 2;

          performance_state->aLevels[0].iEngineClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[0].iEngineClock;
          performance_state->aLevels[1].iEngineClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iEngineClock;
          performance_state->aLevels[0].iMemoryClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[0].iMemoryClock;
          performance_state->aLevels[1].iMemoryClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iMemoryClock;

          if ((hm_ADL_Overdrive_State_Set (hashcat_ctx, hwmon_ctx->hm_device[device_id].adl, ADL_OD6_SETSTATE_PERFORMANCE, performance_state)) == -1)
          {
            event_log_info (hashcat_ctx, "ERROR: Failed to restore ADL performance state");

            continue;
          }

          myfree (performance_state);
        }
      }
    }

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      unsigned int power_limit = hwmon_ctx->nvml_power_limit[device_id];

      if (power_limit > 0)
      {
        hm_NVML_nvmlDeviceSetPowerManagementLimit (hashcat_ctx, hwmon_ctx->hm_device[device_id].nvml, power_limit);
      }
    }
  }

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

  if (hwmon_ctx->hm_xnvctrl)
  {
    hm_XNVCTRL_XCloseDisplay (hashcat_ctx);

    xnvctrl_close (hashcat_ctx);
  }

  if (hwmon_ctx->hm_adl)
  {
    hm_ADL_Main_Control_Destroy (hashcat_ctx);

    adl_close (hashcat_ctx);
  }

  // free memory

  myfree (hwmon_ctx->nvml_power_limit);
  myfree (hwmon_ctx->od_power_control_status);
  myfree (hwmon_ctx->od_clock_mem_status);

  myfree (hwmon_ctx->hm_device);

  memset (hwmon_ctx, 0, sizeof (hwmon_ctx_t));
}
