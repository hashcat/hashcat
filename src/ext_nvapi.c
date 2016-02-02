/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_nvapi.h>

int nvapi_init (NVAPI_PTR *nvapi)
{
  if (!nvapi) return (-1);

  memset (nvapi, 0, sizeof (NVAPI_PTR));

  #if __x86_64__
  nvapi->lib = hc_dlopen ("nvapi64.lib");
  #elif __x86__
  nvapi->lib = hc_dlopen ("nvapi.lib");
  #endif

  if (!nvapi->lib)
  {
    if (data.quiet == 0)
      log_info ("WARNING: load NVAPI library failed, proceed without NVAPI HWMon enabled.");

    return (-1);
  }

  HC_LOAD_FUNC(nvapi, NvAPI_Initialize, NVAPI_INITIALIZE, NVAPI, 0)
  HC_LOAD_FUNC(nvapi, NvAPI_Unload, NVAPI_UNLOAD, NVAPI, 0)
  HC_LOAD_FUNC(nvapi, NvAPI_GetErrorMessage, NVAPI_GETERRORMESSAGE, NVAPI, 0)
  HC_LOAD_FUNC(nvapi, NvAPI_EnumPhysicalGPUs, NVAPI_ENUMPHYSICALGPUS, NVAPI, 0)
  HC_LOAD_FUNC(nvapi, NvAPI_GPU_GetThermalSettings, NVAPI_GPU_GETTHERMALSETTINGS, NVAPI, 0)
  HC_LOAD_FUNC(nvapi, NvAPI_GPU_GetTachReading, NVAPI_GPU_GETTACHREADING, NVAPI, 0)
  HC_LOAD_FUNC(nvapi, NvAPI_GPU_GetDynamicPstatesInfoEx, NVAPI_GPU_GETDYNAMICPSTATESINFOEX, NVAPI, 0)

  return 0;
}

void nvapi_close (NVAPI_PTR *nvapi)
{
  if (nvapi)
  {
    if (nvapi->lib)
      hc_dlclose (nvapi->lib);

    myfree (nvapi);
  }
}

int hm_NvAPI_Initialize (NVAPI_PTR *nvapi)
{
  if (!nvapi) return (-1);

  NvAPI_Status NvAPI_rc = nvapi->NvAPI_Initialize ();

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string;

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_Initialize()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hm_NvAPI_Unload (NVAPI_PTR *nvapi)
{
  if (!nvapi) return (-1);

  NvAPI_Status NvAPI_rc = nvapi->NvAPI_Unload ();

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string;

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_Unload()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hm_NvAPI_GetErrorMessage (NVAPI_PTR *nvapi, NvAPI_Status NvAPI_rc, NvAPI_ShortString string)
{
  if (!nvapi) return (-1);

  return nvapi->NvAPI_GetErrorMessage (NvAPI_rc, string);
}

int hm_NvAPI_EnumPhysicalGPUs (NVAPI_PTR *nvapi, NvPhysicalGpuHandle nvGPUHandle[NVAPI_MAX_PHYSICAL_GPUS], NvU32 *pGpuCount)
{
  if (!nvapi) return (-1);

  NvAPI_Status NvAPI_rc = nvapi->NvAPI_EnumPhysicalGPUs (nvGPUHandle, pGpuCount);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string;

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_EnumPhysicalGPUs()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hm_NvAPI_GPU_GetThermalSettings (NVAPI_PTR *nvapi, NvPhysicalGpuHandle hPhysicalGpu, NvU32 sensorIndex, NV_GPU_THERMAL_SETTINGS *pThermalSettings)
{
  if (!nvapi) return (-1);

  NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetThermalSettings (hPhysicalGpu, sensorIndex, pThermalSettings);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string;

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_GPU_GetThermalSettings()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hm_NvAPI_GPU_GetTachReading (NVAPI_PTR *nvapi, NvPhysicalGpuHandle hPhysicalGPU, NvU32 *pValue)
{
  if (!nvapi) return (-1);

  NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetTachReading (hPhysicalGPU, pValue);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string;

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_GPU_GetTachReading()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hm_NvAPI_GPU_GetDynamicPstatesInfoEx (NVAPI_PTR *nvapi, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_DYNAMIC_PSTATES_INFO_EX *pDynamicPstatesInfoEx)
{
  if (!nvapi) return (-1);

  NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetDynamicPstatesInfoEx (hPhysicalGpu, pDynamicPstatesInfoEx);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string;

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

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
