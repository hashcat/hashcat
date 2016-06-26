/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#include <ext_nvapi.h>

int nvapi_init (NVAPI_PTR *nvapi)
{
  if (!nvapi) return (-1);

  memset (nvapi, 0, sizeof (NVAPI_PTR));

  #ifdef _WIN
  #if __x86_64__
  nvapi->lib = hc_dlopen ("nvapi64.dll");
  #elif __x86__
  nvapi->lib = hc_dlopen ("nvapi.dll");
  #endif
  #else
  nvapi->lib = hc_dlopen ("nvapi.so", RTLD_NOW); // uhm yes, but .. yeah
  #endif

  if (!nvapi->lib)
  {
    //if (data.quiet == 0)
    //  log_info ("WARNING: load NVAPI library failed, proceed without NVAPI HWMon enabled.");

    return (-1);
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

  if (NvAPI_rc == NVAPI_LIBRARY_NOT_FOUND) NvAPI_rc = NVAPI_OK; // not a bug

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

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
    NvAPI_ShortString string = { 0 };

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
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_EnumPhysicalGPUs()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hm_NvAPI_GPU_GetPerfPoliciesInfo (NVAPI_PTR *nvapi, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_POLICIES_INFO_PARAMS_V1 *perfPolicies_info)
{
  if (!nvapi) return (-1);

  NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetPerfPoliciesInfo (hPhysicalGpu, perfPolicies_info);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_GPU_GetPerfPoliciesInfo()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hm_NvAPI_GPU_GetPerfPoliciesStatus (NVAPI_PTR *nvapi, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1 *perfPolicies_status)
{
  if (!nvapi) return (-1);

  NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_GetPerfPoliciesStatus (hPhysicalGpu, perfPolicies_status);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_GPU_GetPerfPoliciesStatus()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hm_NvAPI_GPU_SetCoolerLevels (NVAPI_PTR *nvapi, NvPhysicalGpuHandle hPhysicalGpu, NvU32 coolerIndex, NV_GPU_COOLER_LEVELS *pCoolerLevels)
{
  if (!nvapi) return (-1);

  NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_SetCoolerLevels (hPhysicalGpu, coolerIndex, pCoolerLevels);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_GPU_SetCoolerLevels()", NvAPI_rc, string);
  }

  return NvAPI_rc;
}

int hm_NvAPI_GPU_RestoreCoolerSettings (NVAPI_PTR *nvapi, NvPhysicalGpuHandle hPhysicalGpu, NvU32 coolerIndex)
{
  if (!nvapi) return (-1);

  NvAPI_Status NvAPI_rc = nvapi->NvAPI_GPU_RestoreCoolerSettings (hPhysicalGpu, coolerIndex);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    log_info ("WARN: %s %d %s\n", "NvAPI_GPU_RestoreCoolerSettings()", NvAPI_rc, string);
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
