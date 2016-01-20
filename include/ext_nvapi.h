/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef EXT_NVAPI_H
#define EXT_NVAPI_H

#if defined(HAVE_HWMON) && defined(HAVE_NVAPI)

#include <common.h>

// Just annotations (they do nothing special)
#ifndef __success
#define __success(x)
#endif
#ifndef __in
#define __in
#endif
#ifndef __out
#define __out
#endif
#ifndef __in_ecount
#define __in_ecount(x)
#endif
#ifndef __out_ecount
#define __out_ecount(x)
#endif
#ifndef __in_opt
#define __in_opt
#endif
#ifndef __out_opt
#define __out_opt
#endif
#ifndef __inout
#define __inout
#endif
#ifndef __inout_opt
#define __inout_opt
#endif
#ifndef __inout_ecount
#define __inout_ecount(x)
#endif
#ifndef __inout_ecount_full
#define __inout_ecount_full(x)
#endif
#ifndef __inout_ecount_part_opt
#define __inout_ecount_part_opt(x,y)
#endif
#ifndef __inout_ecount_full_opt
#define __inout_ecount_full_opt(x,y)
#endif
#ifndef __out_ecount_full_opt
#define __out_ecount_full_opt(x)
#endif

#include <nvapi.h>

typedef NvPhysicalGpuHandle HM_ADAPTER_NV;

int hc_NvAPI_EnumPhysicalGPUs (NvPhysicalGpuHandle nvGPUHandle[NVAPI_MAX_PHYSICAL_GPUS], NvU32 *pGpuCount);
int hc_NvAPI_GPU_GetThermalSettings (NvPhysicalGpuHandle hPhysicalGpu, NvU32 sensorIndex, NV_GPU_THERMAL_SETTINGS *pThermalSettings);
int hc_NvAPI_GPU_GetTachReading (NvPhysicalGpuHandle hPhysicalGPU, NvU32 *pValue);
int hc_NvAPI_GPU_GetDynamicPstatesInfoEx (NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_DYNAMIC_PSTATES_INFO_EX *pDynamicPstatesInfoEx);

#endif // HAVE_HWMON && HAVE_NVAPI

#endif
