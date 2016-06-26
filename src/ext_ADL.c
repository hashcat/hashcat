/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_ADL.h>

int adl_init (ADL_PTR *adl)
{
  if (!adl) return (-1);

  memset (adl, 0, sizeof (ADL_PTR));

  #ifdef _WIN
  adl->lib = hc_dlopen ("atiadlxx.dll");

  if (!adl->lib)
  {
    adl->lib = hc_dlopen ("atiadlxy.dll");
  }
  #elif _POSIX
  adl->lib = hc_dlopen ("libatiadlxx.so", RTLD_NOW);
  #endif

  if (!adl->lib)
  {
    //if (data.quiet == 0)
    //  log_info ("WARNING: load ADL library failed, proceed without ADL HWMon enabled.");

    return (-1);
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

void adl_close (ADL_PTR *adl)
{
  if (adl)
  {
    if (adl->lib)
      hc_dlclose (adl->lib);

    myfree (adl);
  }
}

int hm_ADL_Main_Control_Destroy (ADL_PTR *adl)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Main_Control_Destroy ();

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Main_Control_Destroy()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Main_Control_Create (ADL_PTR *adl, ADL_MAIN_MALLOC_CALLBACK callback, int iEnumConnectedAdapters)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Main_Control_Create (callback, iEnumConnectedAdapters);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Main_Control_Create()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Adapter_NumberOfAdapters_Get (ADL_PTR *adl, int *lpNumAdapters)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Adapter_NumberOfAdapters_Get (lpNumAdapters);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Adapter_NumberOfAdapters_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Adapter_AdapterInfo_Get (ADL_PTR *adl, LPAdapterInfo lpInfo, int iInputSize)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Adapter_AdapterInfo_Get (lpInfo, iInputSize);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Adapter_AdapterInfo_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Display_DisplayInfo_Get (ADL_PTR *adl, int iAdapterIndex, int *iNumDisplays, ADLDisplayInfo **lppInfo, int iForceDetect)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Display_DisplayInfo_Get (iAdapterIndex, iNumDisplays, lppInfo, iForceDetect);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Display_DisplayInfo_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Adapter_ID_Get (ADL_PTR *adl, int iAdapterIndex, int *lpAdapterID)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Adapter_ID_Get (iAdapterIndex, lpAdapterID);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Adapter_ID_Get()", ADL_rc);
  }

  return ADL_rc;
}

int hm_ADL_Adapter_VideoBiosInfo_Get (ADL_PTR *adl, int iAdapterIndex, ADLBiosInfo *lpBiosInfo)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Adapter_VideoBiosInfo_Get (iAdapterIndex, lpBiosInfo);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Adapter_VideoBiosInfo_Get()", ADL_rc);
  }

  return ADL_rc;
}

int hm_ADL_Overdrive_ThermalDevices_Enum (ADL_PTR *adl, int iAdapterIndex, int iThermalControllerIndex, ADLThermalControllerInfo *lpThermalControllerInfo)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive5_ThermalDevices_Enum (iAdapterIndex, iThermalControllerIndex, lpThermalControllerInfo);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_ThermalDevices_Enum()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive5_Temperature_Get (ADL_PTR *adl, int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive5_Temperature_Get (iAdapterIndex, iThermalControllerIndex, lpTemperature);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_Temperature_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive6_Temperature_Get (ADL_PTR *adl, int iAdapterIndex, int *iTemperature)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_Temperature_Get (iAdapterIndex, iTemperature);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive6_Temperature_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive_CurrentActivity_Get (ADL_PTR *adl, int iAdapterIndex, ADLPMActivity *lpActivity)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive5_CurrentActivity_Get (iAdapterIndex, lpActivity);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_CurrentActivity_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive5_FanSpeedInfo_Get (ADL_PTR *adl, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedInfo *lpFanSpeedInfo)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive5_FanSpeedInfo_Get (iAdapterIndex, iThermalControllerIndex, lpFanSpeedInfo);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_FanSpeedInfo_Get()", ADL_rc);
  }

  return ADL_rc;
}

int hm_ADL_Overdrive5_FanSpeed_Get (ADL_PTR *adl, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive5_FanSpeed_Get (iAdapterIndex, iThermalControllerIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_FanSpeed_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive6_FanSpeed_Get (ADL_PTR *adl, int iAdapterIndex, ADLOD6FanSpeedInfo *lpFanSpeedInfo)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_FanSpeed_Get (iAdapterIndex, lpFanSpeedInfo);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive6_FanSpeed_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive5_FanSpeed_Set (ADL_PTR *adl, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive5_FanSpeed_Set (iAdapterIndex, iThermalControllerIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_FanSpeed_Set()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive6_FanSpeed_Set (ADL_PTR *adl, int iAdapterIndex, ADLOD6FanSpeedValue *lpFanSpeedValue)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_FanSpeed_Set (iAdapterIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive6_FanSpeed_Set()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive5_FanSpeedToDefault_Set (ADL_PTR *adl, int iAdapterIndex, int iThermalControllerIndex)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive5_FanSpeedToDefault_Set (iAdapterIndex, iThermalControllerIndex);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_FanSpeedToDefault_Set()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive_ODParameters_Get (ADL_PTR *adl, int iAdapterIndex, ADLODParameters *lpOdParameters)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive5_ODParameters_Get (iAdapterIndex, lpOdParameters);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_ODParameters_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive_ODPerformanceLevels_Get (ADL_PTR *adl, int iAdapterIndex, int iDefault, ADLODPerformanceLevels *lpOdPerformanceLevels)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive5_ODPerformanceLevels_Get (iAdapterIndex, iDefault, lpOdPerformanceLevels);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_ODPerformanceLevels_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive_ODPerformanceLevels_Set (ADL_PTR *adl, int iAdapterIndex, ADLODPerformanceLevels *lpOdPerformanceLevels)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive5_ODPerformanceLevels_Set (iAdapterIndex, lpOdPerformanceLevels);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_ODPerformanceLevels_Set()", ADL_rc);
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive_PowerControlInfo_Get (ADL_PTR *adl, int iAdapterIndex, ADLOD6PowerControlInfo *powertune)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_PowerControlInfo_Get (iAdapterIndex, powertune);

  return (ADL_rc);
}

int hm_ADL_Overdrive_PowerControl_Get (ADL_PTR *adl, int iAdapterIndex, int *iCurrentValue)
{
  if (!adl) return (-1);

  int default_value = 0;

  int ADL_rc = adl->ADL_Overdrive6_PowerControl_Get (iAdapterIndex, iCurrentValue, &default_value);

  return (ADL_rc);
}

int hm_ADL_Overdrive_PowerControl_Set (ADL_PTR *adl, int iAdapterIndex, int level)
{
  if (!adl) return (-1);

  int ADL_rc = ADL_ERR;

  ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

  if ((ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (adl, iAdapterIndex, &powertune)) != ADL_OK)
  {
    log_info ("WARN: %s\n", "ADL_Overdrive6_PowerControl_Get", ADL_rc);
  }
  else
  {
    int min  = powertune.iMinValue;
    int max  = powertune.iMaxValue;
    int step = powertune.iStepValue;

    if (level < min || level > max)
    {
      log_info ("WARN: ADL PowerControl level invalid");

      return ADL_ERR;
    }
    if (level % step != 0)
    {
      log_info ("WARN: ADL PowerControl step invalid");

      return ADL_ERR;
    }

    ADL_rc = adl->ADL_Overdrive6_PowerControl_Set (iAdapterIndex, level);
  }

  return (ADL_rc);
}

int hm_ADL_Adapter_Active_Get (ADL_PTR *adl, int iAdapterIndex, int *lpStatus)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Adapter_Active_Get (iAdapterIndex, lpStatus);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Adapter_Active_Get()", ADL_rc);
  }

  return (ADL_rc);
}

/*
int hm_ADL_DisplayEnable_Set (ADL_PTR *adl, int iAdapterIndex, int *lpDisplayIndexList, int iDisplayListSize, int bPersistOnly)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_DisplayEnable_Set (iAdapterIndex, lpDisplayIndexList, iDisplayListSize, bPersistOnly);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_DisplayEnable_Set()", ADL_rc);
  }

  return (ADL_rc);
}
*/

int hm_ADL_Overdrive_Caps (ADL_PTR *adl, int iAdapterIndex, int *od_supported, int *od_enabled, int *od_version)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive_Caps (iAdapterIndex, od_supported, od_enabled, od_version);

  return (ADL_rc);
}

int hm_ADL_Overdrive6_PowerControl_Caps (ADL_PTR *adl, int iAdapterIndex, int *lpSupported)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_PowerControl_Caps (iAdapterIndex, lpSupported);

  return (ADL_rc);
}

int hm_ADL_Overdrive_Capabilities_Get (ADL_PTR *adl, int iAdapterIndex, ADLOD6Capabilities *caps)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_Capabilities_Get (iAdapterIndex, caps);

  return (ADL_rc);
}

int hm_ADL_Overdrive_StateInfo_Get (ADL_PTR *adl, int iAdapterIndex, int type, ADLOD6MemClockState *state)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_StateInfo_Get (iAdapterIndex, type, state);

  if (ADL_rc == ADL_OK)
  {
    // check if clocks are okay with step sizes
    // if not run a little hack: adjust the clocks to nearest clock size (clock down just a little bit)

    ADLOD6Capabilities caps;

    if ((hm_ADL_Overdrive_Capabilities_Get (adl, iAdapterIndex, &caps)) != ADL_OK)
    {
      log_info ("ERROR: failed to get ADL device capabilities");

      exit (1);
    }

    if (state->state.aLevels[0].iEngineClock % caps.sEngineClockRange.iStep != 0)
    {
      log_info ("WARN: ADL engine step size invalid for performance level 1");
      state->state.aLevels[0].iEngineClock -= state->state.aLevels[0].iEngineClock % caps.sEngineClockRange.iStep;
    }

    if (state->state.aLevels[1].iEngineClock % caps.sEngineClockRange.iStep != 0)
    {
      log_info ("WARN: ADL engine step size invalid for performance level 2");
      state->state.aLevels[1].iEngineClock -= state->state.aLevels[1].iEngineClock % caps.sEngineClockRange.iStep;
    }

    if (state->state.aLevels[0].iMemoryClock % caps.sMemoryClockRange.iStep != 0)
    {
      log_info ("WARN: ADL memory step size invalid for performance level 1");
      state->state.aLevels[0].iMemoryClock -= state->state.aLevels[0].iMemoryClock % caps.sMemoryClockRange.iStep;
    }

    if (state->state.aLevels[1].iMemoryClock % caps.sMemoryClockRange.iStep != 0)
    {
      log_info ("WARN: ADL memory step size invalid for performance level 2");
      state->state.aLevels[1].iMemoryClock -= state->state.aLevels[1].iMemoryClock % caps.sMemoryClockRange.iStep;
    }
  }

  return (ADL_rc);
}

int hm_ADL_Overdrive_CurrentStatus_Get (ADL_PTR *adl, int iAdapterIndex, ADLOD6CurrentStatus *status)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_CurrentStatus_Get (iAdapterIndex, status);

  return (ADL_rc);
}

int hm_ADL_Overdrive_State_Set (ADL_PTR *adl, int iAdapterIndex, int type, ADLOD6StateInfo *state)
{
  if (!adl) return (-1);

  // sanity checks

  ADLOD6Capabilities caps;

  if ((hm_ADL_Overdrive_Capabilities_Get (adl, iAdapterIndex, &caps)) != ADL_OK)
  {
    log_info ("ERROR: failed to get ADL device capabilities");

    exit (1);
  }

  if (state->aLevels[0].iEngineClock < caps.sEngineClockRange.iMin || state->aLevels[1].iEngineClock > caps.sEngineClockRange.iMax)
  {
    log_info ("WARN: ADL engine clock outside valid range");

    return ADL_ERR;
  }

  if (state->aLevels[1].iEngineClock % caps.sEngineClockRange.iStep != 0)
  {
    log_info ("WARN: ADL engine step size invalid");

    return ADL_ERR;
  }

  if (state->aLevels[0].iMemoryClock < caps.sMemoryClockRange.iMin || state->aLevels[1].iMemoryClock > caps.sMemoryClockRange.iMax)
  {
    log_info ("WARN: ADL memory clock outside valid range");

    return ADL_ERR;
  }

  if (state->aLevels[1].iMemoryClock % caps.sMemoryClockRange.iStep != 0)
  {
    log_info ("WARN: ADL memory step size invalid");

    return ADL_ERR;
  }

  int ADL_rc = adl->ADL_Overdrive6_State_Set (iAdapterIndex, type, state);

  return (ADL_rc);
}

int hm_ADL_Overdrive6_TargetTemperatureData_Get (ADL_PTR *adl, int iAdapterIndex, int *cur_temp, int *default_temp)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_TargetTemperatureData_Get (iAdapterIndex, cur_temp, default_temp);

  return (ADL_rc);
}

int hm_ADL_Overdrive6_TargetTemperatureRangeInfo_Get (ADL_PTR *adl, int iAdapterIndex, ADLOD6ParameterRange *lpTargetTemperatureInfo)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_TargetTemperatureRangeInfo_Get (iAdapterIndex, lpTargetTemperatureInfo);

  return (ADL_rc);
}

int hm_ADL_Overdrive6_FanSpeed_Reset (ADL_PTR *adl, int iAdapterIndex)
{
  if (!adl) return (-1);

  int ADL_rc = adl->ADL_Overdrive6_FanSpeed_Reset (iAdapterIndex);

  return (ADL_rc);
}
