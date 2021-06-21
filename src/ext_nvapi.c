/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "ext_nvapi.h"

#include "dynloader.h"

int nvapi_init (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  NVAPI_PTR *nvapi = (NVAPI_PTR *) hwmon_ctx->hm_nvapi;

  memset (nvapi, 0, sizeof (NVAPI_PTR));

  #if defined (_WIN)

  #if defined (_WIN64)
  nvapi->lib = hc_dlopen ("nvapi64.dll");
  #else
  nvapi->lib = hc_dlopen ("nvapi.dll");
  #endif

  #else

  #if defined (__CYGWIN__)

  #if defined (__x86_x64__)
  nvapi->lib = hc_dlopen ("nvapi64.dll");
  #else
  nvapi->lib = hc_dlopen ("nvapi.dll");
  #endif

  #else
  nvapi->lib = hc_dlopen ("nvapi.so"); // uhm yes, but .. yeah
  #endif

  #endif

  if (!nvapi->lib)
  {
    //if (user_options->quiet == false)
    //  event_log_error (hashcat_ctx, "Load of NVAPI library failed. Proceeding without NVAPI HWMon enabled.");

    return -1;
  }

  HC_LOAD_FUNC(nvapi, nvapi_QueryInterface,             NVAPI_QUERYINTERFACE,             NVAPI,                0);
  HC_LOAD_ADDR(nvapi, NvAPI_Initialize,                 NVAPI_INITIALIZE,                 nvapi_QueryInterface, 0x0150E828U, NVAPI, 0);
  HC_LOAD_ADDR(nvapi, NvAPI_Unload,                     NVAPI_UNLOAD,                     nvapi_QueryInterface, 0xD22BDD7EU, NVAPI, 0);
  HC_LOAD_ADDR(nvapi, NvAPI_GetErrorMessage,            NVAPI_GETERRORMESSAGE,            nvapi_QueryInterface, 0x6C2D048CU, NVAPI, 0);
  HC_LOAD_ADDR(nvapi, NvAPI_EnumPhysicalGPUs,           NVAPI_ENUMPHYSICALGPUS,           nvapi_QueryInterface, 0xE5AC921FU, NVAPI, 0);
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetPerfPoliciesInfo,    NVAPI_GPU_GETPERFPOLICIESINFO,    nvapi_QueryInterface, 0x409D9841U, NVAPI, 0);
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetPerfPoliciesStatus,  NVAPI_GPU_GETPERFPOLICIESSTATUS,  nvapi_QueryInterface, 0x3D358A0CU, NVAPI, 0);
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetBusId,               NVAPI_GPU_GETBUSID,               nvapi_QueryInterface, 0x1BE0B8E5U, NVAPI, 0);
  HC_LOAD_ADDR(nvapi, NvAPI_GPU_GetBusSlotId,           NVAPI_GPU_GETBUSSLOTID,           nvapi_QueryInterface, 0x2A0A350FU, NVAPI, 0);

  return 0;
}

void nvapi_close (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  NVAPI_PTR *nvapi = (NVAPI_PTR *) hwmon_ctx->hm_nvapi;

  if (nvapi)
  {
    if (nvapi->lib)
      hc_dlclose (nvapi->lib);

    hcfree (nvapi);
  }
}

void hm_NvAPI_GetErrorMessage (NVAPI_PTR *nvapi, const NvAPI_Status NvAPI_rc, NvAPI_ShortString string)
{
  nvapi->NvAPI_GetErrorMessage (NvAPI_rc, string);
}

int hm_NvAPI_Initialize (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  NVAPI_PTR *nvapi = (NVAPI_PTR *) hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = (NvAPI_Status) nvapi->NvAPI_Initialize ();

  if (NvAPI_rc == NVAPI_LIBRARY_NOT_FOUND) return -1;

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_Initialize(): %s", string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_Unload (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  NVAPI_PTR *nvapi = (NVAPI_PTR *) hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = (NvAPI_Status) nvapi->NvAPI_Unload ();

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_Unload(): %s", string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_EnumPhysicalGPUs (void *hashcat_ctx, NvPhysicalGpuHandle nvGPUHandle[NVAPI_MAX_PHYSICAL_GPUS], NvU32 *pGpuCount)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  NVAPI_PTR *nvapi = (NVAPI_PTR *) hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = (NvAPI_Status) nvapi->NvAPI_EnumPhysicalGPUs (nvGPUHandle, pGpuCount);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_EnumPhysicalGPUs(): %s", string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_GPU_GetPerfPoliciesInfo (void *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_POLICIES_INFO_PARAMS_V1 *perfPolicies_info)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  NVAPI_PTR *nvapi = (NVAPI_PTR *) hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = (NvAPI_Status) nvapi->NvAPI_GPU_GetPerfPoliciesInfo (hPhysicalGpu, perfPolicies_info);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_GPU_GetPerfPoliciesInfo(): %s", string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_GPU_GetPerfPoliciesStatus (void *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1 *perfPolicies_status)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  NVAPI_PTR *nvapi = (NVAPI_PTR *) hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = (NvAPI_Status) nvapi->NvAPI_GPU_GetPerfPoliciesStatus (hPhysicalGpu, perfPolicies_status);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_GPU_GetPerfPoliciesStatus(): %s", string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_GPU_GetBusId (void *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pBusId)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  NVAPI_PTR *nvapi = (NVAPI_PTR *) hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = (NvAPI_Status) nvapi->NvAPI_GPU_GetBusId (hPhysicalGpu, pBusId);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_GPU_GetBusId(): %s", string);

    return -1;
  }

  return 0;
}

int hm_NvAPI_GPU_GetBusSlotId (void *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pBusSlotId)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  NVAPI_PTR *nvapi = (NVAPI_PTR *) hwmon_ctx->hm_nvapi;

  const NvAPI_Status NvAPI_rc = (NvAPI_Status) nvapi->NvAPI_GPU_GetBusSlotId (hPhysicalGpu, pBusSlotId);

  if (NvAPI_rc != NVAPI_OK)
  {
    NvAPI_ShortString string = { 0 };

    hm_NvAPI_GetErrorMessage (nvapi, NvAPI_rc, string);

    event_log_error (hashcat_ctx, "NvAPI_GPU_GetBusSlotId(): %s", string);

    return -1;
  }

  return 0;
}
