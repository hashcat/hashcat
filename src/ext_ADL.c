/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "ext_ADL.h"

#include "dynloader.h"

void *HC_API_CALL ADL_Main_Memory_Alloc (const int iSize)
{
  return malloc ((size_t) iSize);
}

int adl_init (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  memset (adl, 0, sizeof (ADL_PTR));

  #if defined (_WIN)
  adl->lib = hc_dlopen ("atiadlxx.dll");

  if (!adl->lib)
  {
    adl->lib = hc_dlopen ("atiadlxy.dll");
  }
  #elif defined (__CYGWIN__)
  adl->lib = hc_dlopen ("atiadlxx.dll");

  if (!adl->lib)
  {
    adl->lib = hc_dlopen ("atiadlxy.dll");
  }
  #elif defined (_POSIX)
  adl->lib = hc_dlopen ("libatiadlxx.so");
  #endif

  if (!adl->lib)
  {
    //if (user_options->quiet == false)
    //  event_log_error (hashcat_ctx, "Load of ADL library failed. Proceeding without ADL HWMon enabled.");

    return -1;
  }

  HC_LOAD_FUNC(adl, ADL_Adapter_Active_Get, ADL_ADAPTER_ACTIVE_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Adapter_AdapterInfo_Get, ADL_ADAPTER_ADAPTERINFO_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Adapter_NumberOfAdapters_Get, ADL_ADAPTER_NUMBEROFADAPTERS_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Main_Control_Create, ADL_MAIN_CONTROL_CREATE, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Main_Control_Destroy, ADL_MAIN_CONTROL_DESTROY, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive5_CurrentActivity_Get, ADL_OVERDRIVE5_CURRENTACTIVITY_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive5_FanSpeedInfo_Get, ADL_OVERDRIVE5_FANSPEEDINFO_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive5_FanSpeed_Get, ADL_OVERDRIVE5_FANSPEED_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive5_ODParameters_Get, ADL_OVERDRIVE5_ODPARAMETERS_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive5_ODPerformanceLevels_Get, ADL_OVERDRIVE5_ODPERFORMANCELEVELS_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive5_Temperature_Get, ADL_OVERDRIVE5_TEMPERATURE_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive5_ThermalDevices_Enum, ADL_OVERDRIVE5_THERMALDEVICES_ENUM, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive6_Capabilities_Get, ADL_OVERDRIVE6_CAPABILITIES_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive6_CurrentStatus_Get, ADL_OVERDRIVE6_CURRENTSTATUS_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive6_FanSpeed_Get, ADL_OVERDRIVE6_FANSPEED_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive6_StateInfo_Get, ADL_OVERDRIVE6_STATEINFO_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive6_Temperature_Get, ADL_OVERDRIVE6_TEMPERATURE_GET, ADL, 0);
  HC_LOAD_FUNC(adl, ADL_Overdrive_Caps, ADL_OVERDRIVE_CAPS, ADL, 0);
  HC_LOAD_FUNC(adl, ADL2_Overdrive_Caps, ADL2_OVERDRIVE_CAPS, ADL, 1);
  HC_LOAD_FUNC(adl, ADL2_New_QueryPMLogData_Get, ADL2_NEW_QUERYPMLOGDATA_GET, ADL, 1);

  return 0;
}

void adl_close (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  if (adl)
  {
    if (adl->lib)
      hc_dlclose (adl->lib);

    hcfree (adl);
  }
}

int hm_ADL_Main_Control_Destroy (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Main_Control_Destroy ();

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Main_Control_Destroy(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Main_Control_Create (void *hashcat_ctx, ADL_MAIN_MALLOC_CALLBACK callback, int iEnumConnectedAdapters)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Main_Control_Create (callback, iEnumConnectedAdapters);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Main_Control_Create(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Adapter_NumberOfAdapters_Get (void *hashcat_ctx, int *lpNumAdapters)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Adapter_NumberOfAdapters_Get (lpNumAdapters);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Adapter_NumberOfAdapters_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Adapter_AdapterInfo_Get (void *hashcat_ctx, LPAdapterInfo lpInfo, int iInputSize)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Adapter_AdapterInfo_Get (lpInfo, iInputSize);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Adapter_AdapterInfo_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive5_Temperature_Get (void *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_Temperature_Get (iAdapterIndex, iThermalControllerIndex, lpTemperature);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive5_Temperature_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive6_Temperature_Get (void *hashcat_ctx, int iAdapterIndex, int *iTemperature)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_Temperature_Get (iAdapterIndex, iTemperature);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_Temperature_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_CurrentActivity_Get (void *hashcat_ctx, int iAdapterIndex, ADLPMActivity *lpActivity)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_CurrentActivity_Get (iAdapterIndex, lpActivity);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive5_CurrentActivity_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive5_FanSpeed_Get (void *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive5_FanSpeed_Get (iAdapterIndex, iThermalControllerIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive5_FanSpeed_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive6_FanSpeed_Get (void *hashcat_ctx, int iAdapterIndex, ADLOD6FanSpeedInfo *lpFanSpeedInfo)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive6_FanSpeed_Get (iAdapterIndex, lpFanSpeedInfo);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive6_FanSpeed_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL_Overdrive_Caps (void *hashcat_ctx, int iAdapterIndex, int *od_supported, int *od_enabled, int *od_version)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL_Overdrive_Caps (iAdapterIndex, od_supported, od_enabled, od_version);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL_Overdrive_Caps(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL2_Overdrive_Caps (void *hashcat_ctx, int iAdapterIndex, int *iSupported, int *iEnabled, int *iVersion)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  // Not sure if that makes any sense...

  if (adl->ADL2_Overdrive_Caps == NULL)
  {
    return hm_ADL_Overdrive_Caps (hashcat_ctx, iAdapterIndex, iSupported, iEnabled, iVersion);
  }

  const int ADL_rc = adl->ADL2_Overdrive_Caps (NULL, iAdapterIndex, iSupported, iEnabled, iVersion);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL2_Overdrive_Caps(): %d", ADL_rc);

    return -1;
  }

  return 0;
}

int hm_ADL2_New_QueryPMLogData_Get (void *hashcat_ctx, int iAdapterIndex, ADLPMLogDataOutput *lpDataOutput)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  ADL_PTR *adl = (ADL_PTR *) hwmon_ctx->hm_adl;

  const int ADL_rc = adl->ADL2_New_QueryPMLogData_Get (NULL, iAdapterIndex, lpDataOutput);

  if (ADL_rc != ADL_OK)
  {
    event_log_error (hashcat_ctx, "ADL2_New_QueryPMLogData_Get(): %d", ADL_rc);

    return -1;
  }

  return 0;
}
