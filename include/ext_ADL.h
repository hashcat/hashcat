/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_ADL_H
#define _EXT_ADL_H

#include <string.h>
#include <stdlib.h>

#if defined (_WIN)
#include <windows.h>
#endif // _WIN

/**
 * Declarations from adl_sdk.h and subheaders
 */

#define ADL_OK                                  0
#define ADL_ERR                                -1
#define ADL_ERR_NOT_SUPPORTED                  -8

#define ADL_MAX_PATH                            256

#define ADL_DL_FANCTRL_SPEED_TYPE_PERCENT       1
#define ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED  1

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

  #if defined (_WIN32) || defined (_WIN64) || defined (__CYGWIN__)
  int  iExist;
  char strDriverPath[ADL_MAX_PATH];
  char strDriverPathExt[ADL_MAX_PATH];
  char strPNPString[ADL_MAX_PATH];
  int  iOSDisplayIndex;
  #endif /* (_WIN32) || (_WIN64) || (__CYGWIN__) */

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

/*
 * Attention: we had to change this struct due to an out-of-bound problem mentioned here:
 * https://github.com/hashcat/hashcat/issues/244
 * the change: ADLODPerformanceLevel aLevels [1] -> ADLODPerformanceLevel aLevels [2]
 */

typedef struct ADLODPerformanceLevels
{
  int iSize;
  int iReserved;
  ADLODPerformanceLevel aLevels [2];
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

/*
 * Attention: we had to change this struct due to an out-of-bound problem mentioned here:
 * https://github.com/hashcat/hashcat/issues/244
 * the change: ADLOD6PerformanceLevel aLevels [1] -> ADLOD6PerformanceLevel aLevels [2]
 */

typedef struct ADLOD6StateInfo
{
  int iNumberOfPerformanceLevels;
  int iExtValue;
  int iExtMask;
  ADLOD6PerformanceLevel aLevels [2];
} ADLOD6StateInfo;

#if defined (__MSC_VER)
#define ADL_API_CALL __cdecl
#elif defined (_WIN32) || defined (__WIN32__)
#define ADL_API_CALL __stdcall
#else
#define ADL_API_CALL
#endif

typedef void* (ADL_API_CALL *ADL_MAIN_MALLOC_CALLBACK )( int );

/*
 * End of declarations from adl_sdk.h and subheaders
 **/

typedef int HM_ADAPTER_ADL;

typedef struct struct_ADLOD6MemClockState
{
  ADLOD6StateInfo state;
  ADLOD6PerformanceLevel level;

} ADLOD6MemClockState;

typedef int (ADL_API_CALL *ADL_MAIN_CONTROL_DESTROY) (void);
typedef int (ADL_API_CALL *ADL_MAIN_CONTROL_CREATE) (ADL_MAIN_MALLOC_CALLBACK, int);
typedef int (ADL_API_CALL *ADL_ADAPTER_NUMBEROFADAPTERS_GET) (int *);
typedef int (ADL_API_CALL *ADL_ADAPTER_ADAPTERINFO_GET) (LPAdapterInfo, int);
typedef int (ADL_API_CALL *ADL_DISPLAY_DISPLAYINFO_GET) (int, int *, ADLDisplayInfo **, int);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_TEMPERATURE_GET) (int, int, ADLTemperature *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_TEMPERATURE_GET) (int, int *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_CURRENTACTIVITY_GET) (int, ADLPMActivity *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_THERMALDEVICES_ENUM) (int, int, ADLThermalControllerInfo *);
typedef int (ADL_API_CALL *ADL_ADAPTER_ID_GET) (int, int *);
typedef int (ADL_API_CALL *ADL_ADAPTER_VIDEOBIOSINFO_GET) (int, ADLBiosInfo *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_FANSPEEDINFO_GET) (int, int, ADLFanSpeedInfo *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_FANSPEED_GET) (int, int, ADLFanSpeedValue *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_FANSPEED_GET) (int, ADLOD6FanSpeedInfo *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_ODPARAMETERS_GET) (int, ADLODParameters *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_ODPERFORMANCELEVELS_GET) (int, int, ADLODPerformanceLevels *);
typedef int (ADL_API_CALL *ADL_ADAPTER_ACTIVE_GET) (int, int *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE_CAPS) (int, int *, int *, int *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_CURRENTSTATUS_GET) (int, ADLOD6CurrentStatus *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_STATEINFO_GET) (int, int, ADLOD6MemClockState *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_CAPABILITIES_GET) (int, ADLOD6Capabilities *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_TARGETTEMPERATUREDATA_GET) (int, int *, int *);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_TARGETTEMPERATURERANGEINFO_GET) (int, ADLOD6ParameterRange *);

typedef struct hm_adl_lib
{
  hc_dynlib_t lib;

  ADL_MAIN_CONTROL_DESTROY ADL_Main_Control_Destroy;
  ADL_MAIN_CONTROL_CREATE ADL_Main_Control_Create;
  ADL_ADAPTER_NUMBEROFADAPTERS_GET ADL_Adapter_NumberOfAdapters_Get;
  ADL_ADAPTER_ADAPTERINFO_GET ADL_Adapter_AdapterInfo_Get;
  ADL_DISPLAY_DISPLAYINFO_GET ADL_Display_DisplayInfo_Get;
  ADL_ADAPTER_ID_GET ADL_Adapter_ID_Get;
  ADL_ADAPTER_VIDEOBIOSINFO_GET ADL_Adapter_VideoBiosInfo_Get;
  ADL_OVERDRIVE5_THERMALDEVICES_ENUM ADL_Overdrive5_ThermalDevices_Enum;
  ADL_OVERDRIVE5_TEMPERATURE_GET ADL_Overdrive5_Temperature_Get;
  ADL_OVERDRIVE6_TEMPERATURE_GET ADL_Overdrive6_Temperature_Get;
  ADL_OVERDRIVE5_CURRENTACTIVITY_GET ADL_Overdrive5_CurrentActivity_Get;
  ADL_OVERDRIVE5_FANSPEEDINFO_GET ADL_Overdrive5_FanSpeedInfo_Get;
  ADL_OVERDRIVE5_FANSPEED_GET ADL_Overdrive5_FanSpeed_Get;
  ADL_OVERDRIVE6_FANSPEED_GET ADL_Overdrive6_FanSpeed_Get;
  ADL_ADAPTER_ACTIVE_GET ADL_Adapter_Active_Get;
  ADL_OVERDRIVE_CAPS ADL_Overdrive_Caps;
  ADL_OVERDRIVE6_CAPABILITIES_GET ADL_Overdrive6_Capabilities_Get;
  ADL_OVERDRIVE6_STATEINFO_GET  ADL_Overdrive6_StateInfo_Get;
  ADL_OVERDRIVE6_CURRENTSTATUS_GET ADL_Overdrive6_CurrentStatus_Get;
  ADL_OVERDRIVE6_TARGETTEMPERATUREDATA_GET ADL_Overdrive6_TargetTemperatureData_Get;
  ADL_OVERDRIVE6_TARGETTEMPERATURERANGEINFO_GET ADL_Overdrive6_TargetTemperatureRangeInfo_Get;

} hm_adl_lib_t;

typedef hm_adl_lib_t ADL_PTR;

void *HC_API_CALL ADL_Main_Memory_Alloc (const int iSize);

#endif // _EXT_ADL_H
