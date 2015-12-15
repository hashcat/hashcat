/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef EXT_ADL_H
#define EXT_ADL_H

#include <common.h>

// this is ugly but ADL requires the bool datatype

typedef int bool;

#include <adl_sdk.h>

//typedef int HM_ADAPTER;

#ifdef _POSIX
void *GetProcAddress (void *pLibrary, const char *name);
#endif

typedef struct
{
  ADLOD6StateInfo state;
  ADLOD6PerformanceLevel level;

} ADLOD6MemClockState;

typedef int (*ADL_MAIN_CONTROL_DESTROY) ();
typedef int (*ADL_MAIN_CONTROL_CREATE) (ADL_MAIN_MALLOC_CALLBACK, int);
typedef int (*ADL_ADAPTER_NUMBEROFADAPTERS_GET) (int *);
typedef int (*ADL_ADAPTER_ADAPTERINFO_GET) (LPAdapterInfo, int);
typedef int (*ADL_DISPLAY_DISPLAYINFO_GET) (int, int *, ADLDisplayInfo **, int);
typedef int (*ADL_OVERDRIVE5_TEMPERATURE_GET) (int, int, ADLTemperature *);
typedef int (*ADL_OVERDRIVE6_TEMPERATURE_GET) (int, int *);
typedef int (*HC_ADL_OVERDRIVE5_CURRENTACTIVITY_GET) (int, ADLPMActivity *);
typedef int (*HC_ADL_OVERDRIVE5_THERMALDEVICES_ENUM) (int, int, ADLThermalControllerInfo *);
typedef int (*HC_ADL_ADAPTER_ID_GET) (int, int *);
typedef int (*HC_ADL_ADAPTER_VIDEOBIOSINFO_GET) (int, ADLBiosInfo *);
typedef int (*HC_ADL_OVERDRIVE5_FANSPEEDINFO_GET) (int, int, ADLFanSpeedInfo *);
typedef int (*ADL_OVERDRIVE5_FANSPEED_GET) (int, int, ADLFanSpeedValue *);
typedef int (*ADL_OVERDRIVE6_FANSPEED_GET) (int, ADLOD6FanSpeedInfo *);
typedef int (*ADL_OVERDRIVE5_FANSPEED_SET) (int, int, ADLFanSpeedValue *);
typedef int (*ADL_OVERDRIVE6_FANSPEED_SET) (int, ADLOD6FanSpeedValue *);
typedef int (*ADL_OVERDRIVE5_FANSPEEDTODEFAULT_SET) (int, int);
typedef int (*HC_ADL_OVERDRIVE5_ODPARAMETERS_GET) (int, ADLODParameters *);
typedef int (*HC_ADL_OVERDRIVE5_ODPERFORMANCELEVELS_GET) (int, int, ADLODPerformanceLevels *);
typedef int (*HC_ADL_OVERDRIVE5_ODPERFORMANCELEVELS_SET) (int, ADLODPerformanceLevels *);
typedef int (*HC_ADL_OVERDRIVE6_POWERCONTROL_SET) (int, int);
typedef int (*HC_ADL_OVERDRIVE6_POWERCONTROL_GET) (int, int *, int *);
typedef int (*HC_ADL_OVERDRIVE6_POWERCONTROLINFO_GET) (int, ADLOD6PowerControlInfo *);
typedef int (*ADL_ADAPTER_ACTIVE_GET) (int, int *);
typedef int (*ADL_DISPLAYENABLE_SET) (int, int *, int, int);
typedef int (*ADL_OVERDRIVE_CAPS) (int, int *, int *, int *);
typedef int (*ADL_OVERDRIVE6_CURRENTSTATUS_GET) (int, ADLOD6CurrentStatus *);
typedef int (*ADL_OVERDRIVE6_STATEINFO_GET) (int, int, ADLOD6MemClockState *);
typedef int (*ADL_OVERDRIVE6_CAPABILITIES_GET) (int, ADLOD6Capabilities *);
typedef int (*ADL_OVERDRIVE6_STATE_SET) (int, int, ADLOD6StateInfo *);
typedef int (*ADL_OVERDRIVE6_POWERCONTROL_CAPS) (int, int *);
typedef int (*ADL_OVERDRIVE6_TARGETTEMPERATUREDATA_GET) (int, int *, int *);

int hc_ADL_Main_Control_Destroy (HM_LIB hDLL);
int hc_ADL_Main_Control_Create (HM_LIB hDLL, ADL_MAIN_MALLOC_CALLBACK callback, int iEnumConnectedAdapters);
int hc_ADL_Adapter_NumberOfAdapters_Get (HM_LIB hDLL, int *lpNumAdapters);
int hc_ADL_Adapter_AdapterInfo_Get (HM_LIB hDLL, LPAdapterInfo lpInfo, int iInputSize);
int hc_ADL_Display_DisplayInfo_Get (HM_LIB hDLL, int iAdapterIndex, int *iNumDisplays, ADLDisplayInfo **lppInfo, int iForceDetect);
int hc_ADL_Overdrive5_Temperature_Get (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature);
int hc_ADL_Overdrive6_Temperature_Get (HM_LIB hDLL, int iAdapterIndex, int *iTemperature);
int hc_ADL_Overdrive_CurrentActivity_Get (HM_LIB hDLL, int iAdapterIndex, ADLPMActivity *lpActivity);
int hc_ADL_Overdrive_ThermalDevices_Enum (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex, ADLThermalControllerInfo *lpThermalControllerInfo);
int hc_ADL_Adapter_ID_Get (HM_LIB hDLL, int iAdapterIndex, int *lpAdapterID);
int hc_ADL_Adapter_VideoBiosInfo_Get (HM_LIB hDLL, int iAdapterIndex, ADLBiosInfo *lpBiosInfo);
int hc_ADL_Overdrive5_FanSpeedInfo_Get (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedInfo *lpFanSpeedInfo);
int hc_ADL_Overdrive5_FanSpeed_Get (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue);
int hc_ADL_Overdrive6_FanSpeed_Get (HM_LIB hDLL, int iAdapterIndex, ADLOD6FanSpeedInfo *lpFanSpeedInfo);
int hc_ADL_Overdrive5_FanSpeed_Set (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue);
int hc_ADL_Overdrive6_FanSpeed_Set (HM_LIB hDLL, int iAdapterIndex, ADLOD6FanSpeedValue *lpFanSpeedValue);
int hc_ADL_Overdrive5_FanSpeedToDefault_Set (HM_LIB hDLL, int iAdapterIndex, int iThermalControllerIndex);
int hc_ADL_Overdrive_ODParameters_Get (HM_LIB hDLL, int iAdapterIndex, ADLODParameters *lpOdParameters);
int hc_ADL_Overdrive_ODPerformanceLevels_Get (HM_LIB hDLL, int iAdapterIndex, int iDefault, ADLODPerformanceLevels *lpOdPerformanceLevels);
int hc_ADL_Overdrive_ODPerformanceLevels_Set (HM_LIB hDLL, int iAdapterIndex, ADLODPerformanceLevels *lpOdPerformanceLevels);
int hc_ADL_Overdrive_PowerControlInfo_Get (HM_LIB hDLL, int iAdapterIndex, ADLOD6PowerControlInfo *);
int hc_ADL_Overdrive_PowerControl_Get (HM_LIB hDLL, int iAdapterIndex, int *level);
int hc_ADL_Overdrive_PowerControl_Set (HM_LIB hDLL, int iAdapterIndex, int level);
int hc_ADL_Adapter_Active_Get (HM_LIB hDLL, int iAdapterIndex, int *lpStatus);
int hc_ADL_DisplayEnable_Set (HM_LIB hDLL, int iAdapterIndex, int *lpDisplayIndexList, int iDisplayListSize, int bPersistOnly);
int hc_ADL_Overdrive_Caps (HM_LIB hDLL, int iAdapterIndex, int *od_supported, int *od_enabled, int *od_version);
int hc_ADL_Overdrive_CurrentStatus_Get (HM_LIB hDLL, int iAdapterIndex, ADLOD6CurrentStatus *status);
int hc_ADL_Overdrive_StateInfo_Get (HM_LIB hDLL, int iAdapterIndex, int type, ADLOD6MemClockState *state);
int hc_ADL_Overdrive_Capabilities_Get (HM_LIB hDLL, int iAdapterIndex, ADLOD6Capabilities *caps);
int hc_ADL_Overdrive_State_Set (HM_LIB hDLL, int iAdapterIndex, int type, ADLOD6StateInfo *state);
int hc_ADL_Overdrive6_PowerControl_Caps (HM_LIB hDLL, int iAdapterIndex, int *lpSupported);
int hc_ADL_Overdrive6_TargetTemperatureData_Get (HM_LIB hDLL, int iAdapterIndex, int *cur_temp, int *default_temp);

#endif
