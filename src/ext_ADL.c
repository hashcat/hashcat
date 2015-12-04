/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_ADL.h>

#ifdef _POSIX
void *GetProcAddress (void *pLibrary, const char *name)
{
  return dlsym (pLibrary, name);
}
#endif

int hc_ADL_Main_Control_Destroy (HM_LIB hDLL)
{
  ADL_MAIN_CONTROL_DESTROY ADL_Main_Control_Destroy = (ADL_MAIN_CONTROL_DESTROY) GetProcAddress (hDLL, "ADL_Main_Control_Destroy");

  if (ADL_Main_Control_Destroy == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Main_Control_Destroy() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Main_Control_Destroy ();

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Main_Control_Destroy()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Main_Control_Create (HM_LIB hDLL, ADL_MAIN_MALLOC_CALLBACK callback, int iEnumConnectedAdapters)
{
  ADL_MAIN_CONTROL_CREATE ADL_Main_Control_Create = (ADL_MAIN_CONTROL_CREATE) GetProcAddress (hDLL, "ADL_Main_Control_Create");

  if (ADL_Main_Control_Create == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Main_Control_Create() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Main_Control_Create (callback, iEnumConnectedAdapters);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Main_Control_Create()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Adapter_NumberOfAdapters_Get (HM_LIB hDLL, int *lpNumAdapters)
{
  ADL_ADAPTER_NUMBEROFADAPTERS_GET ADL_Adapter_NumberOfAdapters_Get = (ADL_ADAPTER_NUMBEROFADAPTERS_GET) GetProcAddress (hDLL, "ADL_Adapter_NumberOfAdapters_Get");

  if (ADL_Adapter_NumberOfAdapters_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Adapter_NumberOfAdapters_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Adapter_NumberOfAdapters_Get (lpNumAdapters);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Adapter_NumberOfAdapters_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Adapter_AdapterInfo_Get (HM_LIB hDLL, LPAdapterInfo lpInfo, int iInputSize)
{
  ADL_ADAPTER_ADAPTERINFO_GET ADL_Adapter_AdapterInfo_Get = (ADL_ADAPTER_ADAPTERINFO_GET) GetProcAddress (hDLL, "ADL_Adapter_AdapterInfo_Get");

  if (ADL_Adapter_AdapterInfo_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Adapter_AdapterInfo_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Adapter_AdapterInfo_Get (lpInfo, iInputSize);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Adapter_AdapterInfo_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Display_DisplayInfo_Get (HM_LIB hDLL, int iAdapterIndex, int *iNumDisplays, ADLDisplayInfo **lppInfo, int iForceDetect)
{
  ADL_DISPLAY_DISPLAYINFO_GET ADL_Display_DisplayInfo_Get = (ADL_DISPLAY_DISPLAYINFO_GET) GetProcAddress (hDLL, "ADL_Display_DisplayInfo_Get");

  if (ADL_Display_DisplayInfo_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Display_DisplayInfo_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Display_DisplayInfo_Get (iAdapterIndex, iNumDisplays, lppInfo, iForceDetect);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Display_DisplayInfo_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Adapter_ID_Get (HM_LIB hDLL, int iAdapterIndex, int *lpAdapterID)
{
  HC_ADL_ADAPTER_ID_GET ADL_Adapter_ID_Get = (HC_ADL_ADAPTER_ID_GET) GetProcAddress (hDLL, "ADL_Adapter_ID_Get");

  if (ADL_Adapter_ID_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Adapter_ID_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Adapter_ID_Get (iAdapterIndex, lpAdapterID);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Adapter_ID_Get()", ADL_rc);
  }

  return ADL_rc;
}

int hc_ADL_Adapter_VideoBiosInfo_Get (HM_LIB hDLL, int iAdapterIndex, ADLBiosInfo *lpBiosInfo)
{
  HC_ADL_ADAPTER_VIDEOBIOSINFO_GET ADL_Adapter_VideoBiosInfo_Get = (HC_ADL_ADAPTER_VIDEOBIOSINFO_GET) GetProcAddress (hDLL, "ADL_Adapter_VideoBiosInfo_Get");

  if (ADL_Adapter_VideoBiosInfo_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Adapter_VideoBiosInfo_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Adapter_VideoBiosInfo_Get (iAdapterIndex, lpBiosInfo);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Adapter_VideoBiosInfo_Get()", ADL_rc);
  }

  return ADL_rc;
}

int hc_ADL_Overdrive_ThermalDevices_Enum (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex, ADLThermalControllerInfo *lpThermalControllerInfo)
{
  HC_ADL_OVERDRIVE5_THERMALDEVICES_ENUM ADL_Overdrive5_ThermalDevices_Enum = (HC_ADL_OVERDRIVE5_THERMALDEVICES_ENUM) GetProcAddress (hDLL, "ADL_Overdrive5_ThermalDevices_Enum");

  if (ADL_Overdrive5_ThermalDevices_Enum == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive5_ThermalDevices_Enum() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive5_ThermalDevices_Enum (iAdapterIndex, iThermalControllerIndex, lpThermalControllerInfo);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_ThermalDevices_Enum()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive5_Temperature_Get (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature)
{
  ADL_OVERDRIVE5_TEMPERATURE_GET ADL_Overdrive5_Temperature_Get = (ADL_OVERDRIVE5_TEMPERATURE_GET) GetProcAddress (hDLL, "ADL_Overdrive5_Temperature_Get");

  if (ADL_Overdrive5_Temperature_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive5_Temperature_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive5_Temperature_Get (iAdapterIndex, iThermalControllerIndex, lpTemperature);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_Temperature_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive6_Temperature_Get (HM_LIB hDLL, int iAdapterIndex, int *iTemperature)
{
  ADL_OVERDRIVE6_TEMPERATURE_GET ADL_Overdrive6_Temperature_Get = (ADL_OVERDRIVE6_TEMPERATURE_GET) GetProcAddress (hDLL, "ADL_Overdrive6_Temperature_Get");

  if (ADL_Overdrive6_Temperature_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_Temperature_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive6_Temperature_Get (iAdapterIndex, iTemperature);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive6_Temperature_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive_CurrentActivity_Get (HM_LIB hDLL, int iAdapterIndex, ADLPMActivity *lpActivity)
{
  HC_ADL_OVERDRIVE5_CURRENTACTIVITY_GET ADL_Overdrive5_CurrentActivity_Get = (HC_ADL_OVERDRIVE5_CURRENTACTIVITY_GET) GetProcAddress (hDLL, "ADL_Overdrive5_CurrentActivity_Get");

  if (ADL_Overdrive5_CurrentActivity_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive5_CurrentActivity_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive5_CurrentActivity_Get (iAdapterIndex, lpActivity);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_CurrentActivity_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive5_FanSpeedInfo_Get (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedInfo *lpFanSpeedInfo)
{
  HC_ADL_OVERDRIVE5_FANSPEEDINFO_GET ADL_Overdrive5_FanSpeedInfo_Get = (HC_ADL_OVERDRIVE5_FANSPEEDINFO_GET) GetProcAddress (hDLL, "ADL_Overdrive5_FanSpeedInfo_Get");

  if (ADL_Overdrive5_FanSpeedInfo_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive5_FanSpeedInfo_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive5_FanSpeedInfo_Get (iAdapterIndex, iThermalControllerIndex, lpFanSpeedInfo);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_FanSpeedInfo_Get()", ADL_rc);
  }

  return ADL_rc;
}

int hc_ADL_Overdrive5_FanSpeed_Get (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue)
{
  ADL_OVERDRIVE5_FANSPEED_GET ADL_Overdrive5_FanSpeed_Get = (ADL_OVERDRIVE5_FANSPEED_GET) GetProcAddress (hDLL, "ADL_Overdrive5_FanSpeed_Get");

  if (ADL_Overdrive5_FanSpeed_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive5_FanSpeed_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive5_FanSpeed_Get (iAdapterIndex, iThermalControllerIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_FanSpeed_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive6_FanSpeed_Get (HM_LIB hDLL, int iAdapterIndex, ADLOD6FanSpeedInfo *lpFanSpeedInfo)
{
  ADL_OVERDRIVE6_FANSPEED_GET ADL_Overdrive6_FanSpeed_Get = (ADL_OVERDRIVE6_FANSPEED_GET) GetProcAddress (hDLL, "ADL_Overdrive6_FanSpeed_Get");

  if (ADL_Overdrive6_FanSpeed_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_FanSpeed_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive6_FanSpeed_Get (iAdapterIndex, lpFanSpeedInfo);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive6_FanSpeed_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive5_FanSpeed_Set (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue)
{
  ADL_OVERDRIVE5_FANSPEED_SET ADL_Overdrive5_FanSpeed_Set = (ADL_OVERDRIVE5_FANSPEED_SET) GetProcAddress (hDLL, "ADL_Overdrive5_FanSpeed_Set");

  if (ADL_Overdrive5_FanSpeed_Set == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive5_FanSpeed_Set() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive5_FanSpeed_Set (iAdapterIndex, iThermalControllerIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_FanSpeed_Set()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive6_FanSpeed_Set (HM_LIB hDLL, int iAdapterIndex, ADLOD6FanSpeedValue *lpFanSpeedValue)
{
  ADL_OVERDRIVE6_FANSPEED_SET ADL_Overdrive6_FanSpeed_Set = (ADL_OVERDRIVE6_FANSPEED_SET) GetProcAddress (hDLL, "ADL_Overdrive6_FanSpeed_Set");

  if (ADL_Overdrive6_FanSpeed_Set == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_FanSpeed_Set() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive6_FanSpeed_Set (iAdapterIndex, lpFanSpeedValue);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive6_FanSpeed_Set()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive5_FanSpeedToDefault_Set (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex)
{
  ADL_OVERDRIVE5_FANSPEEDTODEFAULT_SET ADL_Overdrive5_FanSpeedToDefault_Set = (ADL_OVERDRIVE5_FANSPEEDTODEFAULT_SET) GetProcAddress (hDLL, "ADL_Overdrive5_FanSpeedToDefault_Set");

  if (ADL_Overdrive5_FanSpeedToDefault_Set == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive5_FanSpeedToDefault_Set() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive5_FanSpeedToDefault_Set (iAdapterIndex, iThermalControllerIndex);

  if ((ADL_rc != ADL_OK) && (ADL_rc != ADL_ERR_NOT_SUPPORTED)) // exception allowed only here
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_FanSpeedToDefault_Set()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive_ODParameters_Get (HM_LIB hDLL, int iAdapterIndex, ADLODParameters *lpOdParameters)
{
  HC_ADL_OVERDRIVE5_ODPARAMETERS_GET ADL_Overdrive5_ODParameters_Get = (HC_ADL_OVERDRIVE5_ODPARAMETERS_GET) GetProcAddress (hDLL, "ADL_Overdrive5_ODParameters_Get");

  if (ADL_Overdrive5_ODParameters_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive5_ODParameters_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive5_ODParameters_Get (iAdapterIndex, lpOdParameters);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_ODParameters_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive_ODPerformanceLevels_Get (HM_LIB hDLL, int iAdapterIndex, int iDefault, ADLODPerformanceLevels *lpOdPerformanceLevels)
{
  HC_ADL_OVERDRIVE5_ODPERFORMANCELEVELS_GET ADL_Overdrive5_ODPerformanceLevels_Get = (HC_ADL_OVERDRIVE5_ODPERFORMANCELEVELS_GET) GetProcAddress (hDLL, "ADL_Overdrive5_ODPerformanceLevels_Get");

  if (ADL_Overdrive5_ODPerformanceLevels_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive5_ODPerformanceLevels_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive5_ODPerformanceLevels_Get (iAdapterIndex, iDefault, lpOdPerformanceLevels);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_ODPerformanceLevels_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive_ODPerformanceLevels_Set (HM_LIB hDLL, int iAdapterIndex, ADLODPerformanceLevels *lpOdPerformanceLevels)
{
  HC_ADL_OVERDRIVE5_ODPERFORMANCELEVELS_SET ADL_Overdrive5_ODPerformanceLevels_Set = (HC_ADL_OVERDRIVE5_ODPERFORMANCELEVELS_SET) GetProcAddress (hDLL, "ADL_Overdrive5_ODPerformanceLevels_Set");

  if (ADL_Overdrive5_ODPerformanceLevels_Set == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive5_ODPerformanceLevels_Set() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive5_ODPerformanceLevels_Set (iAdapterIndex, lpOdPerformanceLevels);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Overdrive5_ODPerformanceLevels_Set()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive_PowerControlInfo_Get (HM_LIB hDLL, int iAdapterIndex, ADLOD6PowerControlInfo *powertune)
{
  HC_ADL_OVERDRIVE6_POWERCONTROLINFO_GET ADL_Overdrive6_PowerControlInfo_Get = (HC_ADL_OVERDRIVE6_POWERCONTROLINFO_GET) GetProcAddress (hDLL, "ADL_Overdrive6_PowerControlInfo_Get");

  if (ADL_Overdrive6_PowerControlInfo_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_PowerControlInfo_Get is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive6_PowerControlInfo_Get (iAdapterIndex, powertune);

  return (ADL_rc);
}

int hc_ADL_Overdrive_PowerControl_Get (HM_LIB hDLL, int iAdapterIndex, int *iCurrentValue)
{
  HC_ADL_OVERDRIVE6_POWERCONTROL_GET ADL_Overdrive6_PowerControl_Get = (HC_ADL_OVERDRIVE6_POWERCONTROL_GET) GetProcAddress (hDLL, "ADL_Overdrive6_PowerControl_Get");

  if (ADL_Overdrive6_PowerControl_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_PowerControl_Get is missing");

    exit (-1);
  }

  int default_value = 0;

  int ADL_rc = ADL_Overdrive6_PowerControl_Get (iAdapterIndex, iCurrentValue, &default_value);

  return (ADL_rc);
}

int hc_ADL_Overdrive_PowerControl_Set (HM_LIB hDLL, int iAdapterIndex, int level)
{
  HC_ADL_OVERDRIVE6_POWERCONTROL_SET ADL_Overdrive6_PowerControl_Set = (HC_ADL_OVERDRIVE6_POWERCONTROL_SET) GetProcAddress (hDLL, "ADL_Overdrive6_PowerControl_Set");

  int ADL_rc = ADL_ERR;

  ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

  if ((ADL_rc = hc_ADL_Overdrive_PowerControlInfo_Get (hDLL, iAdapterIndex, &powertune)) != ADL_OK)
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

    ADL_rc = ADL_Overdrive6_PowerControl_Set (iAdapterIndex, level);
  }

  return (ADL_rc);
}

int hc_ADL_Adapter_Active_Get (HM_LIB hDLL, int iAdapterIndex, int *lpStatus)
{
  ADL_ADAPTER_ACTIVE_GET ADL_Adapter_Active_Get = (ADL_ADAPTER_ACTIVE_GET) GetProcAddress (hDLL, "ADL_Adapter_Active_Get");

  if (ADL_Adapter_Active_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Adapter_Active_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Adapter_Active_Get (iAdapterIndex, lpStatus);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_Adapter_Active_Get()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_DisplayEnable_Set (HM_LIB hDLL, int iAdapterIndex, int *lpDisplayIndexList, int iDisplayListSize, int bPersistOnly)
{
  ADL_DISPLAYENABLE_SET ADL_DisplayEnable_Set = (ADL_DISPLAYENABLE_SET) GetProcAddress (hDLL, "ADL_DisplayEnable_Set");

  if (ADL_DisplayEnable_Set == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_DisplayEnable_Set() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_DisplayEnable_Set (iAdapterIndex, lpDisplayIndexList, iDisplayListSize, bPersistOnly);

  if (ADL_rc != ADL_OK)
  {
    log_info ("WARN: %s: %d\n", "ADL_DisplayEnable_Set()", ADL_rc);
  }

  return (ADL_rc);
}

int hc_ADL_Overdrive_Caps (HM_LIB hDLL, int iAdapterIndex, int *od_supported, int *od_enabled, int *od_version)
{
  ADL_OVERDRIVE_CAPS ADL_Overdrive_Caps = (ADL_OVERDRIVE_CAPS) GetProcAddress (hDLL, "ADL_Overdrive_Caps");

  if (ADL_Overdrive_Caps == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive_Caps() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive_Caps (iAdapterIndex, od_supported, od_enabled, od_version);

  return (ADL_rc) ;
}

int hc_ADL_Overdrive6_PowerControl_Caps (HM_LIB hDLL, int iAdapterIndex, int *lpSupported)
{
  ADL_OVERDRIVE6_POWERCONTROL_CAPS ADL_Overdrive6_PowerControl_Caps = (ADL_OVERDRIVE6_POWERCONTROL_CAPS) GetProcAddress (hDLL, "ADL_Overdrive6_PowerControl_Caps");

  if (ADL_Overdrive6_PowerControl_Caps == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_PowerControl_Caps() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive6_PowerControl_Caps (iAdapterIndex, lpSupported);

  return (ADL_rc) ;
}

int hc_ADL_Overdrive_Capabilities_Get (HM_LIB hDLL, int iAdapterIndex, ADLOD6Capabilities *caps)
{
  ADL_OVERDRIVE6_CAPABILITIES_GET ADL_Overdrive6_Capabilities_Get = (ADL_OVERDRIVE6_CAPABILITIES_GET) GetProcAddress (hDLL, "ADL_Overdrive6_Capabilities_Get");

  if (ADL_Overdrive6_Capabilities_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_Capabilities_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive6_Capabilities_Get (iAdapterIndex, caps);

  return (ADL_rc);
}

int hc_ADL_Overdrive_StateInfo_Get (HM_LIB hDLL, int iAdapterIndex, int type, ADLOD6MemClockState *state)
{
  ADL_OVERDRIVE6_STATEINFO_GET  ADL_Overdrive6_StateInfo_Get = (ADL_OVERDRIVE6_STATEINFO_GET) GetProcAddress (hDLL, "ADL_Overdrive6_StateInfo_Get");

  if (ADL_Overdrive6_StateInfo_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_StateInfo_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive6_StateInfo_Get (iAdapterIndex, type, state);

  if (ADL_rc == ADL_OK)
  {
    // check if clocks are okay with step sizes
    // if not run a little hack: adjust the clocks to nearest clock size (clock down just a little bit)

    ADLOD6Capabilities caps;

    if ((hc_ADL_Overdrive_Capabilities_Get (hDLL, iAdapterIndex, &caps)) != ADL_OK)
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

int hc_ADL_Overdrive_CurrentStatus_Get (HM_LIB hDLL, int iAdapterIndex, ADLOD6CurrentStatus *status)
{
  ADL_OVERDRIVE6_CURRENTSTATUS_GET ADL_Overdrive6_CurrentStatus_Get = (ADL_OVERDRIVE6_CURRENTSTATUS_GET) GetProcAddress (hDLL, "ADL_Overdrive6_CurrentStatus_Get");

  if (ADL_Overdrive6_CurrentStatus_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_CurrentStatus_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive6_CurrentStatus_Get (iAdapterIndex, status);

  return (ADL_rc);
}

int hc_ADL_Overdrive_State_Set (HM_LIB hDLL, int iAdapterIndex, int type, ADLOD6StateInfo *state)
{
  ADL_OVERDRIVE6_STATE_SET ADL_Overdrive6_State_Set = (ADL_OVERDRIVE6_STATE_SET) GetProcAddress (hDLL, "ADL_Overdrive6_State_Set");

  if (ADL_Overdrive6_State_Set == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_State_Set() is missing");

    exit (- 1);
  }

  // sanity checks

  ADLOD6Capabilities caps;

  if ((hc_ADL_Overdrive_Capabilities_Get (hDLL, iAdapterIndex, &caps)) != ADL_OK)
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

  int ADL_rc = ADL_Overdrive6_State_Set (iAdapterIndex, type, state);

  return (ADL_rc);
}

int hc_ADL_Overdrive6_TargetTemperatureData_Get (HM_LIB hDLL, int iAdapterIndex, int *cur_temp, int *default_temp)
{
  ADL_OVERDRIVE6_TARGETTEMPERATUREDATA_GET ADL_Overdrive6_TargetTemperatureData_Get = (ADL_OVERDRIVE6_TARGETTEMPERATUREDATA_GET) GetProcAddress (hDLL, "ADL_Overdrive6_TargetTemperatureData_Get");

  if (ADL_Overdrive6_TargetTemperatureData_Get == NULL)
  {
    log_error ("ERROR: %s\n", "ADL_Overdrive6_TargetTemperatureData_Get() is missing");

    exit (-1);
  }

  int ADL_rc = ADL_Overdrive6_TargetTemperatureData_Get (iAdapterIndex, cur_temp, default_temp);

  return (ADL_rc);
}
