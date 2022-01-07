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

// Declarations from:
// https://github.com/GPUOpen-LibrariesAndSDKs/display-library/blob/209538e1dc7273f7459411a3a5044ffe2437ed95/include/adl_defines.h
// https://github.com/GPUOpen-LibrariesAndSDKs/display-library/blob/209538e1dc7273f7459411a3a5044ffe2437ed95/include/adl_structures.h


/// Defines ADL_TRUE
#define ADL_TRUE    1
/// Defines ADL_FALSE
#define ADL_FALSE        0

//Define Performance Metrics Log max sensors number
#define ADL_PMLOG_MAX_SENSORS  256

typedef enum ADLSensorType
{
	SENSOR_MAXTYPES = 0,
	PMLOG_CLK_GFXCLK = 1,
	PMLOG_CLK_MEMCLK = 2,
	PMLOG_CLK_SOCCLK = 3,
	PMLOG_CLK_UVDCLK1 = 4,
	PMLOG_CLK_UVDCLK2 = 5,
	PMLOG_CLK_VCECLK = 6,
	PMLOG_CLK_VCNCLK = 7,
	PMLOG_TEMPERATURE_EDGE = 8,
	PMLOG_TEMPERATURE_MEM = 9,
	PMLOG_TEMPERATURE_VRVDDC = 10,
	PMLOG_TEMPERATURE_VRMVDD = 11,
	PMLOG_TEMPERATURE_LIQUID = 12,
	PMLOG_TEMPERATURE_PLX = 13,
	PMLOG_FAN_RPM = 14,
	PMLOG_FAN_PERCENTAGE = 15,
	PMLOG_SOC_VOLTAGE = 16,
	PMLOG_SOC_POWER = 17,
	PMLOG_SOC_CURRENT = 18,
	PMLOG_INFO_ACTIVITY_GFX = 19,
	PMLOG_INFO_ACTIVITY_MEM = 20,
	PMLOG_GFX_VOLTAGE = 21,
	PMLOG_MEM_VOLTAGE = 22,
	PMLOG_ASIC_POWER = 23,
	PMLOG_TEMPERATURE_VRSOC = 24,
	PMLOG_TEMPERATURE_VRMVDD0 = 25,
	PMLOG_TEMPERATURE_VRMVDD1 = 26,
	PMLOG_TEMPERATURE_HOTSPOT = 27,
        PMLOG_TEMPERATURE_GFX = 28,
        PMLOG_TEMPERATURE_SOC = 29,
        PMLOG_GFX_POWER = 30,
        PMLOG_GFX_CURRENT = 31,
        PMLOG_TEMPERATURE_CPU = 32,
        PMLOG_CPU_POWER = 33,
        PMLOG_CLK_CPUCLK = 34,
        PMLOG_THROTTLER_STATUS = 35,
        PMLOG_CLK_VCN1CLK1 = 36,
        PMLOG_CLK_VCN1CLK2 = 37,
        PMLOG_SMART_POWERSHIFT_CPU = 38,
        PMLOG_SMART_POWERSHIFT_DGPU = 39,
        PMLOG_BUS_SPEED = 40,
        PMLOG_BUS_LANES = 41,
	PMLOG_MAX_SENSORS_REAL
} ADLSensorType;

/// Defines the maximum string length
#define ADL_MAX_CHAR                                    4096
/// Defines the maximum string length
#define ADL_MAX_PATH                                    256
/// Defines the maximum number of supported adapters
#define ADL_MAX_ADAPTERS                               250
/// Defines the maxumum number of supported displays
#define ADL_MAX_DISPLAYS                                150
/// Defines the maxumum string length for device name
#define ADL_MAX_DEVICENAME                                32
/// Defines for all adapters
#define ADL_ADAPTER_INDEX_ALL                            -1

/// \defgroup define_adl_results Result Codes
/// This group of definitions are the various results returned by all ADL functions \n
/// @{
/// All OK, but need to wait
#define ADL_OK_WAIT                4
/// All OK, but need restart
#define ADL_OK_RESTART                3
/// All OK but need mode change
#define ADL_OK_MODE_CHANGE            2
/// All OK, but with warning
#define ADL_OK_WARNING                1
/// ADL function completed successfully
#define ADL_OK                    0
/// Generic Error. Most likely one or more of the Escape calls to the driver failed!
#define ADL_ERR                    -1
/// ADL not initialized
#define ADL_ERR_NOT_INIT            -2
/// One of the parameter passed is invalid
#define ADL_ERR_INVALID_PARAM            -3
/// One of the parameter size is invalid
#define ADL_ERR_INVALID_PARAM_SIZE        -4
/// Invalid ADL index passed
#define ADL_ERR_INVALID_ADL_IDX            -5
/// Invalid controller index passed
#define ADL_ERR_INVALID_CONTROLLER_IDX        -6
/// Invalid display index passed
#define ADL_ERR_INVALID_DIPLAY_IDX        -7
/// Function  not supported by the driver
#define ADL_ERR_NOT_SUPPORTED            -8
/// Null Pointer error
#define ADL_ERR_NULL_POINTER            -9
/// Call can't be made due to disabled adapter
#define ADL_ERR_DISABLED_ADAPTER        -10
/// Invalid Callback
#define ADL_ERR_INVALID_CALLBACK            -11
/// Display Resource conflict
#define ADL_ERR_RESOURCE_CONFLICT                -12
//Failed to update some of the values. Can be returned by set request that include multiple values if not all values were successfully committed.
#define ADL_ERR_SET_INCOMPLETE                 -20
/// There's no Linux XDisplay in Linux Console environment
#define ADL_ERR_NO_XDISPLAY                    -21

//values for ADLFanSpeedValue.iSpeedType
#define ADL_DL_FANCTRL_SPEED_TYPE_PERCENT    1
#define ADL_DL_FANCTRL_SPEED_TYPE_RPM        2

//values for ADLFanSpeedValue.iFlags
#define ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED   1

/**
 * Declarations from adl_structures.h
 */

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the graphics adapter.
///
/// This structure is used to store various information about the graphics adapter.  This
/// information can be returned to the user. Alternatively, it can be used to access various driver calls to set
/// or fetch various settings upon the user's request.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct AdapterInfo
{
/// \ALL_STRUCT_MEM

/// Size of the structure.
    int iSize;
/// The ADL index handle. One GPU may be associated with one or two index handles
    int iAdapterIndex;
/// The unique device ID associated with this adapter.
    char strUDID[ADL_MAX_PATH];
/// The BUS number associated with this adapter.
    int iBusNumber;
/// The driver number associated with this adapter.
    int iDeviceNumber;
/// The function number.
    int iFunctionNumber;
/// The vendor ID associated with this adapter.
    int iVendorID;
/// Adapter name.
    char strAdapterName[ADL_MAX_PATH];
/// Display name. For example, "\\\\Display0" for Windows or ":0:0" for Linux.
    char strDisplayName[ADL_MAX_PATH];
/// Present or not; 1 if present and 0 if not present.It the logical adapter is present, the display name such as \\\\.\\Display1 can be found from OS
    int iPresent;

#if defined (_WIN32) || defined (_WIN64)
/// \WIN_STRUCT_MEM

/// Exist or not; 1 is exist and 0 is not present.
    int iExist;
/// Driver registry path.
    char strDriverPath[ADL_MAX_PATH];
/// Driver registry path Ext for.
    char strDriverPathExt[ADL_MAX_PATH];
/// PNP string from Windows.
    char strPNPString[ADL_MAX_PATH];
/// It is generated from EnumDisplayDevices.
    int iOSDisplayIndex;

#endif /* (_WIN32) || (_WIN64) */

#if defined (LINUX)
/// \LNX_STRUCT_MEM

/// Internal X screen number from GPUMapInfo (DEPRICATED use XScreenInfo)
    int iXScreenNum;
/// Internal driver index from GPUMapInfo
    int iDrvIndex;
/// \deprecated Internal x config file screen identifier name. Use XScreenInfo instead.
    char strXScreenConfigName[ADL_MAX_PATH];

#endif /* (LINUX) */
} AdapterInfo, *LPAdapterInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about thermal controller.
///
/// This structure is used to store information about thermal controller.
/// This structure is used by ADL_PM_ThermalDevices_Enum.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLThermalControllerInfo
{
/// Must be set to the size of the structure
  int iSize;
/// Possible valies: \ref ADL_DL_THERMAL_DOMAIN_OTHER or \ref ADL_DL_THERMAL_DOMAIN_GPU.
  int iThermalDomain;
///    GPU 0, 1, etc.
  int iDomainIndex;
/// Possible valies: \ref ADL_DL_THERMAL_FLAG_INTERRUPT or \ref ADL_DL_THERMAL_FLAG_FANCONTROL
  int iFlags;
} ADLThermalControllerInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about thermal controller temperature.
///
/// This structure is used to store information about thermal controller temperature.
/// This structure is used by the ADL_PM_Temperature_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLTemperature
{
/// Must be set to the size of the structure
  int iSize;
/// Temperature in millidegrees Celsius.
  int iTemperature;
} ADLTemperature;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about thermal controller fan speed.
///
/// This structure is used to store information about thermal controller fan speed.
/// This structure is used by the ADL_PM_FanSpeedInfo_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLFanSpeedInfo
{
/// Must be set to the size of the structure
  int iSize;
/// \ref define_fanctrl
  int iFlags;
/// Minimum possible fan speed value in percents.
  int iMinPercent;
/// Maximum possible fan speed value in percents.
  int iMaxPercent;
/// Minimum possible fan speed value in RPM.
  int iMinRPM;
/// Maximum possible fan speed value in RPM.
  int iMaxRPM;
} ADLFanSpeedInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about fan speed reported by thermal controller.
///
/// This structure is used to store information about fan speed reported by thermal controller.
/// This structure is used by the ADL_Overdrive5_FanSpeed_Get() and ADL_Overdrive5_FanSpeed_Set() functions.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLFanSpeedValue
{
/// Must be set to the size of the structure
  int iSize;
/// Possible valies: \ref ADL_DL_FANCTRL_SPEED_TYPE_PERCENT or \ref ADL_DL_FANCTRL_SPEED_TYPE_RPM
  int iSpeedType;
/// Fan speed value
  int iFanSpeed;
/// The only flag for now is: \ref ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED
  int iFlags;
} ADLFanSpeedValue;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about current power management related activity.
///
/// This structure is used to store information about current power management related activity.
/// This structure (Overdrive 5 interfaces) is used by the ADL_PM_CurrentActivity_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLPMActivity
{
/// Must be set to the size of the structure
    int iSize;
/// Current engine clock.
    int iEngineClock;
/// Current memory clock.
    int iMemoryClock;
/// Current core voltage.
    int iVddc;
/// GPU utilization.
    int iActivityPercent;
/// Performance level index.
    int iCurrentPerformanceLevel;
/// Current PCIE bus speed.
    int iCurrentBusSpeed;
/// Number of PCIE bus lanes.
    int iCurrentBusLanes;
/// Maximum number of PCIE bus lanes.
    int iMaximumBusLanes;
/// Reserved for future purposes.
    int iReserved;
} ADLPMActivity;

////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing the range of Overdrive parameter.
///
/// This structure is used to store information about the range of Overdrive parameter.
/// This structure is used by ADLODParameters.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLODParameterRange
{
/// Minimum parameter value.
  int iMin;
/// Maximum parameter value.
  int iMax;
/// Parameter step value.
  int iStep;
} ADLODParameterRange;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive parameters.
///
/// This structure is used to store information about Overdrive parameters.
/// This structure is used by the ADL_Overdrive5_ODParameters_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLODParameters
{
/// Must be set to the size of the structure
  int iSize;
/// Number of standard performance states.
  int iNumberOfPerformanceLevels;
/// Indicates whether the GPU is capable to measure its activity.
  int iActivityReportingSupported;
/// Indicates whether the GPU supports discrete performance levels or performance range.
  int iDiscretePerformanceLevels;
/// Reserved for future use.
  int iReserved;
/// Engine clock range.
  ADLODParameterRange sEngineClock;
/// Memory clock range.
  ADLODParameterRange sMemoryClock;
/// Core voltage range.
  ADLODParameterRange sVddc;
} ADLODParameters;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 fan speed information
///
/// This structure is used to store information about Overdrive 6 fan speed information
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLOD6FanSpeedInfo
{
    /// Contains a bitmap of the valid fan speed type flags.  Possible values: \ref ADL_OD6_FANSPEED_TYPE_PERCENT, \ref ADL_OD6_FANSPEED_TYPE_RPM, \ref ADL_OD6_FANSPEED_USER_DEFINED
    int     iSpeedType;
    /// Contains current fan speed in percent (if valid flag exists in iSpeedType)
    int     iFanSpeedPercent;
    /// Contains current fan speed in RPM (if valid flag exists in iSpeedType)
    int        iFanSpeedRPM;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6FanSpeedInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 fan speed value
///
/// This structure is used to store information about Overdrive 6 fan speed value
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLOD6FanSpeedValue
{
    /// Indicates the units of the fan speed.  Possible values: \ref ADL_OD6_FANSPEED_TYPE_PERCENT, \ref ADL_OD6_FANSPEED_TYPE_RPM
    int     iSpeedType;
    /// Fan speed value (units as indicated above)
    int     iFanSpeed;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6FanSpeedValue;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about current Overdrive 6 performance status.
///
/// This structure is used to store information about current Overdrive 6 performance status.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLOD6CurrentStatus
{
    /// Current engine clock in 10 KHz.
    int     iEngineClock;
    /// Current memory clock in 10 KHz.
    int     iMemoryClock;
    /// Current GPU activity in percent.  This
    /// indicates how "busy" the GPU is.
    int     iActivityPercent;
    /// Not used.  Reserved for future use.
    int     iCurrentPerformanceLevel;
    /// Current PCI-E bus speed
    int     iCurrentBusSpeed;
    /// Current PCI-E bus # of lanes
    int     iCurrentBusLanes;
    /// Maximum possible PCI-E bus # of lanes
    int     iMaximumBusLanes;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6CurrentStatus;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 clock range
///
/// This structure is used to store information about Overdrive 6 clock range
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLOD6ParameterRange
{
    /// The starting value of the clock range
    int     iMin;
    /// The ending value of the clock range
    int     iMax;
    /// The minimum increment between clock values
    int     iStep;

} ADLOD6ParameterRange;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 capabilities
///
/// This structure is used to store information about Overdrive 6 capabilities
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLOD6Capabilities
{
    /// Contains a bitmap of the OD6 capability flags.  Possible values: \ref ADL_OD6_CAPABILITY_SCLK_CUSTOMIZATION,
    /// \ref ADL_OD6_CAPABILITY_MCLK_CUSTOMIZATION, \ref ADL_OD6_CAPABILITY_GPU_ACTIVITY_MONITOR
    int     iCapabilities;
    /// Contains a bitmap indicating the power states
    /// supported by OD6.  Currently only the performance state
    /// is supported. Possible Values: \ref ADL_OD6_SUPPORTEDSTATE_PERFORMANCE
    int     iSupportedStates;
    /// Number of levels. OD6 will always use 2 levels, which describe
    /// the minimum to maximum clock ranges.
    /// The 1st level indicates the minimum clocks, and the 2nd level
    /// indicates the maximum clocks.
    int     iNumberOfPerformanceLevels;
    /// Contains the hard limits of the sclk range.  Overdrive
    /// clocks cannot be set outside this range.
    ADLOD6ParameterRange     sEngineClockRange;
    /// Contains the hard limits of the mclk range.  Overdrive
    /// clocks cannot be set outside this range.
    ADLOD6ParameterRange     sMemoryClockRange;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6Capabilities;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive level.
///
/// This structure is used to store information about Overdrive level.
/// This structure is used by ADLODPerformanceLevels.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLODPerformanceLevel
{
/// Engine clock.
  int iEngineClock;
/// Memory clock.
  int iMemoryClock;
/// Core voltage.
  int iVddc;
} ADLODPerformanceLevel;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 clock values.
///
/// This structure is used to store information about Overdrive 6 clock values.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLOD6PerformanceLevel
{
    /// Engine (core) clock.
    int iEngineClock;
    /// Memory clock.
    int iMemoryClock;

} ADLOD6PerformanceLevel;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 clocks.
///
/// This structure is used to store information about Overdrive 6 clocks.  This is a
/// variable-sized structure.  iNumberOfPerformanceLevels indicate how many elements
/// are contained in the aLevels array.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLOD6StateInfo
{
    /// Number of levels.  OD6 uses clock ranges instead of discrete performance levels.
    /// iNumberOfPerformanceLevels is always 2.  The 1st level indicates the minimum clocks
    /// in the range.  The 2nd level indicates the maximum clocks in the range.
    int     iNumberOfPerformanceLevels;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

    /// Variable-sized array of levels.
    /// The number of elements in the array is specified by iNumberofPerformanceLevels.
    ADLOD6PerformanceLevel aLevels [1];

} ADLOD6StateInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive performance levels.
///
/// This structure is used to store information about Overdrive performance levels.
/// This structure is used by the ADL_Overdrive5_ODPerformanceLevels_Get() and ADL_Overdrive5_ODPerformanceLevels_Set() functions.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLODPerformanceLevels
{
/// Must be set to sizeof( \ref ADLODPerformanceLevels ) + sizeof( \ref ADLODPerformanceLevel ) * (ADLODParameters.iNumberOfPerformanceLevels - 1)
  int iSize;
  int iReserved;
/// Array of performance state descriptors. Must have ADLODParameters.iNumberOfPerformanceLevels elements.
  ADLODPerformanceLevel aLevels [1];
} ADLODPerformanceLevels;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Performance Metrics data
///
/// This structure is used to store information about Performance Metrics data output
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLSingleSensorData
{
    int supported;
    int  value;
} ADLSingleSensorData;

typedef struct ADLPMLogDataOutput
{
    int size;
    ADLSingleSensorData sensors[ADL_PMLOG_MAX_SENSORS];
}ADLPMLogDataOutput;

/// \brief Handle to ADL client context.
///
///  ADL clients obtain context handle from initial call to \ref ADL2_Main_Control_Create.
///  Clients have to pass the handle to each subsequent ADL call and finally destroy
///  the context with call to \ref ADL2_Main_Control_Destroy
/// \nosubgrouping
typedef void *ADL_CONTEXT_HANDLE;

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

typedef int (ADL_API_CALL *ADL_ADAPTER_ACTIVE_GET ) ( int, int* );
typedef int (ADL_API_CALL *ADL_ADAPTER_ADAPTERINFO_GET ) ( LPAdapterInfo, int );
typedef int (ADL_API_CALL *ADL_ADAPTER_NUMBEROFADAPTERS_GET ) ( int* );
typedef int (ADL_API_CALL *ADL_MAIN_CONTROL_CREATE )(ADL_MAIN_MALLOC_CALLBACK, int );
typedef int (ADL_API_CALL *ADL_MAIN_CONTROL_DESTROY )();
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_CURRENTACTIVITY_GET ) (int iAdapterIndex, ADLPMActivity *lpActivity);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_FANSPEEDINFO_GET ) (int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedInfo *lpFanSpeedInfo);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_FANSPEED_GET ) (int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_ODPARAMETERS_GET ) (int iAdapterIndex, ADLODParameters *lpOdParameters);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_ODPERFORMANCELEVELS_GET ) (int iAdapterIndex, int iDefault, ADLODPerformanceLevels *lpOdPerformanceLevels);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_TEMPERATURE_GET ) (int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature);
typedef int (ADL_API_CALL *ADL_OVERDRIVE5_THERMALDEVICES_ENUM ) (int iAdapterIndex, int iThermalControllerIndex, ADLThermalControllerInfo *lpThermalControllerInfo);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_CAPABILITIES_GET ) (int iAdapterIndex, ADLOD6Capabilities *lpODCapabilities);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_CURRENTSTATUS_GET )(int iAdapterIndex, ADLOD6CurrentStatus *lpCurrentStatus);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_FANSPEED_GET )(int iAdapterIndex, ADLOD6FanSpeedInfo *lpFanSpeedInfo);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_STATEINFO_GET )(int iAdapterIndex, int iStateType, ADLOD6StateInfo *lpStateInfo);
typedef int (ADL_API_CALL *ADL_OVERDRIVE6_TEMPERATURE_GET )(int iAdapterIndex, int *lpTemperature);
typedef int (ADL_API_CALL *ADL_OVERDRIVE_CAPS ) (int iAdapterIndex, int *iSupported, int *iEnabled, int *iVersion);
typedef int (ADL_API_CALL *ADL2_OVERDRIVE_CAPS) (ADL_CONTEXT_HANDLE context, int iAdapterIndex, int * iSupported, int * iEnabled, int * iVersion);
typedef int (ADL_API_CALL *ADL2_NEW_QUERYPMLOGDATA_GET) (ADL_CONTEXT_HANDLE, int, ADLPMLogDataOutput*);

typedef struct hm_adl_lib
{
  hc_dynlib_t lib;

  ADL_ADAPTER_ACTIVE_GET ADL_Adapter_Active_Get;
  ADL_ADAPTER_ADAPTERINFO_GET ADL_Adapter_AdapterInfo_Get;
  ADL_ADAPTER_NUMBEROFADAPTERS_GET ADL_Adapter_NumberOfAdapters_Get;
  ADL_MAIN_CONTROL_CREATE ADL_Main_Control_Create;
  ADL_MAIN_CONTROL_DESTROY ADL_Main_Control_Destroy;
  ADL_OVERDRIVE5_CURRENTACTIVITY_GET ADL_Overdrive5_CurrentActivity_Get;
  ADL_OVERDRIVE5_FANSPEEDINFO_GET ADL_Overdrive5_FanSpeedInfo_Get;
  ADL_OVERDRIVE5_FANSPEED_GET ADL_Overdrive5_FanSpeed_Get;
  ADL_OVERDRIVE5_ODPARAMETERS_GET ADL_Overdrive5_ODParameters_Get;
  ADL_OVERDRIVE5_ODPERFORMANCELEVELS_GET ADL_Overdrive5_ODPerformanceLevels_Get;
  ADL_OVERDRIVE5_TEMPERATURE_GET ADL_Overdrive5_Temperature_Get;
  ADL_OVERDRIVE5_THERMALDEVICES_ENUM ADL_Overdrive5_ThermalDevices_Enum;
  ADL_OVERDRIVE6_CAPABILITIES_GET ADL_Overdrive6_Capabilities_Get;
  ADL_OVERDRIVE6_CURRENTSTATUS_GET ADL_Overdrive6_CurrentStatus_Get;
  ADL_OVERDRIVE6_FANSPEED_GET ADL_Overdrive6_FanSpeed_Get;
  ADL_OVERDRIVE6_STATEINFO_GET  ADL_Overdrive6_StateInfo_Get;
  ADL_OVERDRIVE6_TEMPERATURE_GET ADL_Overdrive6_Temperature_Get;
  ADL_OVERDRIVE_CAPS ADL_Overdrive_Caps;
  ADL2_OVERDRIVE_CAPS ADL2_Overdrive_Caps;
  ADL2_NEW_QUERYPMLOGDATA_GET ADL2_New_QueryPMLogData_Get;

} hm_adl_lib_t;

typedef hm_adl_lib_t ADL_PTR;

void *HC_API_CALL ADL_Main_Memory_Alloc (const int iSize);

int adl_init (void *hashcat_ctx);
void adl_close (void *hashcat_ctx);
int hm_ADL_Main_Control_Destroy (void *hashcat_ctx);
int hm_ADL_Main_Control_Create (void *hashcat_ctx, ADL_MAIN_MALLOC_CALLBACK callback, int iEnumConnectedAdapters);
int hm_ADL_Adapter_NumberOfAdapters_Get (void *hashcat_ctx, int *lpNumAdapters);
int hm_ADL_Adapter_AdapterInfo_Get (void *hashcat_ctx, LPAdapterInfo lpInfo, int iInputSize);
int hm_ADL_Overdrive5_Temperature_Get (void *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature);
int hm_ADL_Overdrive6_Temperature_Get (void *hashcat_ctx, int iAdapterIndex, int *iTemperature);
int hm_ADL_Overdrive_CurrentActivity_Get (void *hashcat_ctx, int iAdapterIndex, ADLPMActivity *lpActivity);
int hm_ADL_Overdrive5_FanSpeed_Get (void *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue);
int hm_ADL_Overdrive6_FanSpeed_Get (void *hashcat_ctx, int iAdapterIndex, ADLOD6FanSpeedInfo *lpFanSpeedInfo);
int hm_ADL_Overdrive_Caps (void *hashcat_ctx, int iAdapterIndex, int *od_supported, int *od_enabled, int *od_version);
int hm_ADL2_Overdrive_Caps (void *hashcat_ctx, int iAdapterIndex, int *od_supported, int *od_enabled, int *od_version);
int hm_ADL2_New_QueryPMLogData_Get (void *hashcat_ctx, int iAdapterIndex, ADLPMLogDataOutput *lpDataOutput);

#endif // _EXT_ADL_H
