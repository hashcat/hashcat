/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef EXT_ADL_H
#define EXT_ADL_H

#if defined(HAVE_HWMON) && defined(HAVE_ADL)

#include <common.h>

/**
 * Declarations from adl_sdk.h and subheaders
 */

#define ADL_OK                                  0
#define ADL_ERR                                 -1
#define ADL_ERR_NOT_SUPPORTED                   -8

#define ADL_MAX_PATH                            256

#define ADL_DL_FANCTRL_SUPPORTS_PERCENT_READ    1
#define ADL_DL_FANCTRL_SUPPORTS_PERCENT_WRITE   2
#define ADL_DL_FANCTRL_SPEED_TYPE_PERCENT       1
#define ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED  1

#define ADL_OD6_SETSTATE_PERFORMANCE            0x00000001
#define ADL_OD6_GETSTATEINFO_CUSTOM_PERFORMANCE 0x00000004
#define ADL_OD6_FANSPEED_TYPE_PERCENT           0x00000001

typedef struct AdapterInfo
{
  int  iSize;
  int  iAdapterIndex;
  char strUDID[ADL_MAX_PATH];
  int  iBusNumber;
  int  iDeviceNumber;
  int  iFunctionNumber;
  int  iVendorID;
  char strAdapterName[ADL_MAX_PATH];
  char strDisplayName[ADL_MAX_PATH];
  int  iPresent;

#if defined (_WIN32) || defined (_WIN64)
  int  iExist;
  char strDriverPath[ADL_MAX_PATH];
  char strDriverPathExt[ADL_MAX_PATH];
  char strPNPString[ADL_MAX_PATH];
  int  iOSDisplayIndex;
#endif /* (_WIN32) || (_WIN64) */

#if defined (__linux__)
  int  iXScreenNum;
  int  iDrvIndex;
  char strXScreenConfigName[ADL_MAX_PATH];
#endif /* (__linux__) */
} AdapterInfo, *LPAdapterInfo;

typedef struct ADLThermalControllerInfo
{
  int iSize;
  int iThermalDomain;
  int iDomainIndex;
  int iFlags;
} ADLThermalControllerInfo;

typedef struct ADLTemperature
{
  int iSize;
  int iTemperature;
} ADLTemperature;

typedef struct ADLFanSpeedInfo
{
  int iSize;
  int iFlags;
  int iMinPercent;
  int iMaxPercent;
  int iMinRPM;
  int iMaxRPM;
} ADLFanSpeedInfo;

typedef struct ADLFanSpeedValue
{
  int iSize;
  int iSpeedType;
  int iFanSpeed;
  int iFlags;
} ADLFanSpeedValue;

typedef struct ADLDisplayID
{
  int iDisplayLogicalIndex;
  int iDisplayPhysicalIndex;
  int iDisplayLogicalAdapterIndex;
  int iDisplayPhysicalAdapterIndex;
} ADLDisplayID, *LPADLDisplayID;

typedef struct ADLDisplayInfo
{
  ADLDisplayID displayID;
  int  iDisplayControllerIndex;
  char strDisplayName[ADL_MAX_PATH];
  char strDisplayManufacturerName[ADL_MAX_PATH];
  int  iDisplayType;
  int  iDisplayOutputType;
  int  iDisplayConnector;
  int  iDisplayInfoMask;
  int  iDisplayInfoValue;
} ADLDisplayInfo, *LPADLDisplayInfo;

typedef struct ADLBiosInfo
{
  char strPartNumber[ADL_MAX_PATH];
  char strVersion[ADL_MAX_PATH];
  char strDate[ADL_MAX_PATH];
} ADLBiosInfo, *LPADLBiosInfo;

typedef struct ADLPMActivity
{
  int iSize;
  int iEngineClock;
  int iMemoryClock;
  int iVddc;
  int iActivityPercent;
  int iCurrentPerformanceLevel;
  int iCurrentBusSpeed;
  int iCurrentBusLanes;
  int iMaximumBusLanes;
  int iReserved;
} ADLPMActivity;

typedef struct ADLODParameterRange
{
  int iMin;
  int iMax;
  int iStep;
} ADLODParameterRange;

typedef struct ADLODParameters
{
  int iSize;
  int iNumberOfPerformanceLevels;
  int iActivityReportingSupported;
  int iDiscretePerformanceLevels;
  int iReserved;
  ADLODParameterRange sEngineClock;
  ADLODParameterRange sMemoryClock;
  ADLODParameterRange sVddc;
} ADLODParameters;

typedef struct ADLODPerformanceLevel
{
  int iEngineClock;
  int iMemoryClock;
  int iVddc;
} ADLODPerformanceLevel;

typedef struct ADLODPerformanceLevels
{
  int iSize;
  int iReserved;
  ADLODPerformanceLevel aLevels [1];
} ADLODPerformanceLevels;

typedef struct ADLOD6FanSpeedInfo
{
  int iSpeedType;
  int iFanSpeedPercent;
  int iFanSpeedRPM;
  int iExtValue;
  int iExtMask;
} ADLOD6FanSpeedInfo;

typedef struct ADLOD6FanSpeedValue
{
  int iSpeedType;
  int iFanSpeed;
  int iExtValue;
  int iExtMask;
} ADLOD6FanSpeedValue;

typedef struct ADLOD6CurrentStatus
{
  int iEngineClock;
  int iMemoryClock;
  int iActivityPercent;
  int iCurrentPerformanceLevel;
  int iCurrentBusSpeed;
  int iCurrentBusLanes;
  int iMaximumBusLanes;
  int iExtValue;
  int iExtMask;
} ADLOD6CurrentStatus;

typedef struct ADLOD6ParameterRange
{
  int iMin;
  int iMax;
  int iStep;
} ADLOD6ParameterRange;

typedef struct ADLOD6Capabilities
{
  int iCapabilities;
  int iSupportedStates;
  int iNumberOfPerformanceLevels;
  ADLOD6ParameterRange sEngineClockRange;
  ADLOD6ParameterRange sMemoryClockRange;
  int iExtValue;
  int iExtMask;
} ADLOD6Capabilities;

typedef struct ADLOD6PerformanceLevel
{
  int iEngineClock;
  int iMemoryClock;
} ADLOD6PerformanceLevel;

typedef struct ADLOD6StateInfo
{
  int iNumberOfPerformanceLevels;
  int iExtValue;
  int iExtMask;
  ADLOD6PerformanceLevel aLevels [1];
} ADLOD6StateInfo;

typedef struct ADLOD6PowerControlInfo
{
  int iMinValue;
  int iMaxValue;
  int iStepValue;
  int iExtValue;
  int iExtMask;
} ADLOD6PowerControlInfo;

#if !(defined (_WIN32) || defined (_WIN64))
#define __stdcall
#endif

typedef void* (__stdcall *ADL_MAIN_MALLOC_CALLBACK )( int );

/*
 * End of declarations from adl_sdk.h and subheaders
 **/

typedef int HM_ADAPTER_AMD;

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

#endif // HAVE_HWMON && HAVE_ADL

#endif // EXT_ADL_H
