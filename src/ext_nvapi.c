/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_nvapi.h>

int hc_NvAPI_EnumPhysicalGPUs (NvPhysicalGpuHandle nvGPUHandle[NVAPI_MAX_PHYSICAL_GPUS], NvU32 *pGpuCount)
{
  NvAPI_Status NvAPI_rc = NvAPI_EnumPhysicalGPUs (nvGPUHandle, pGpuCount);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string;

    NvAPI_GetErrorMessage (NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_EnumPhysicalGPUs()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hc_NvAPI_GPU_GetThermalSettings (NvPhysicalGpuHandle hPhysicalGpu, NvU32 sensorIndex, NV_GPU_THERMAL_SETTINGS *pThermalSettings)
{
  NvAPI_Status NvAPI_rc = NvAPI_GPU_GetThermalSettings (hPhysicalGpu, sensorIndex, pThermalSettings);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string;

    NvAPI_GetErrorMessage (NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_GPU_GetThermalSettings()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hc_NvAPI_GPU_GetTachReading (NvPhysicalGpuHandle hPhysicalGPU, NvU32 *pValue)
{
  NvAPI_Status NvAPI_rc = NvAPI_GPU_GetTachReading (hPhysicalGPU, pValue);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string;

    NvAPI_GetErrorMessage (NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_GPU_GetTachReading()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hc_NvAPI_GPU_GetDynamicPstatesInfoEx (NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_DYNAMIC_PSTATES_INFO_EX *pDynamicPstatesInfoEx)
{
  NvAPI_Status NvAPI_rc = NvAPI_GPU_GetDynamicPstatesInfoEx (hPhysicalGpu, pDynamicPstatesInfoEx);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string;

    NvAPI_GetErrorMessage (NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_GPU_GetDynamicPstatesInfoEx()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

#ifdef __MINGW64__

void __security_check_cookie (uintptr_t _StackCookie)
{
  (void) _StackCookie;
}

void __GSHandlerCheck ()
{
}

#endif
