/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HWMON_H
#define _HWMON_H

// nvml functions

int  nvml_init  (hashcat_ctx_t *hashcat_ctx);
void nvml_close (hashcat_ctx_t *hashcat_ctx);

int hm_NVML_nvmlInit     (hashcat_ctx_t *hashcat_ctx);
int hm_NVML_nvmlShutdown (hashcat_ctx_t *hashcat_ctx);

int hm_NVML_nvmlDeviceGetHandleByIndex                   (hashcat_ctx_t *hashcat_ctx, unsigned int index, nvmlDevice_t *device);

int hm_NVML_nvmlDeviceGetName                            (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, char *name, unsigned int length);
int hm_NVML_nvmlDeviceGetTemperature                     (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, unsigned int *temp);
int hm_NVML_nvmlDeviceGetFanSpeed                        (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *speed);
int hm_NVML_nvmlDeviceGetPowerUsage                      (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *power);
int hm_NVML_nvmlDeviceGetUtilizationRates                (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlUtilization_t *utilization);
int hm_NVML_nvmlDeviceGetClockInfo                       (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlClockType_t type, unsigned int *clock);
int hm_NVML_nvmlDeviceGetTemperatureThreshold            (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlTemperatureThresholds_t thresholdType, unsigned int *temp);
int hm_NVML_nvmlDeviceGetCurrPcieLinkGeneration          (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *currLinkGen);
int hm_NVML_nvmlDeviceGetCurrPcieLinkWidth               (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *currLinkWidth);
int hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons    (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned long long *clocksThrottleReasons);
int hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons  (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned long long *supportedClocksThrottleReasons);
int hm_NVML_nvmlDeviceSetComputeMode                     (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlComputeMode_t mode);
int hm_NVML_nvmlDeviceSetGpuOperationMode                (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, nvmlGpuOperationMode_t mode);
int hm_NVML_nvmlDeviceGetPowerManagementLimitConstraints (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *minLimit, unsigned int *maxLimit);
int hm_NVML_nvmlDeviceSetPowerManagementLimit            (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int limit);
int hm_NVML_nvmlDeviceGetPowerManagementLimit            (hashcat_ctx_t *hashcat_ctx, nvmlDevice_t device, unsigned int *limit);

// nvapi functions

int  nvapi_init  (hashcat_ctx_t *hashcat_ctx);
void nvapi_close (hashcat_ctx_t *hashcat_ctx);

int hm_NvAPI_QueryInterface (hashcat_ctx_t *hashcat_ctx, unsigned int offset);

int hm_NvAPI_Initialize (hashcat_ctx_t *hashcat_ctx);
int hm_NvAPI_Unload (hashcat_ctx_t *hashcat_ctx);

int hm_NvAPI_EnumPhysicalGPUs          (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle nvGPUHandle[NVAPI_MAX_PHYSICAL_GPUS], NvU32 *pGpuCount);
int hm_NvAPI_GPU_GetPerfPoliciesInfo   (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_POLICIES_INFO_PARAMS_V1 *perfPolicies_info);
int hm_NvAPI_GPU_GetPerfPoliciesStatus (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1 *perfPolicies_status);
int hm_NvAPI_GPU_SetCoolerLevels       (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NvU32 coolerIndex, NV_GPU_COOLER_LEVELS *pCoolerLevels);
int hm_NvAPI_GPU_RestoreCoolerSettings (hashcat_ctx_t *hashcat_ctx, NvPhysicalGpuHandle hPhysicalGpu, NvU32 coolerIndex);

// xnvctrl functions

int  xnvctrl_init         (hashcat_ctx_t *hashcat_ctx);
void xnvctrl_close        (hashcat_ctx_t *hashcat_ctx);

int  hm_XNVCTRL_XOpenDisplay  (hashcat_ctx_t *hashcat_ctx);
void hm_XNVCTRL_XCloseDisplay (hashcat_ctx_t *hashcat_ctx);

int get_core_threshold    (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val);

int get_fan_control       (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val);
int set_fan_control       (hashcat_ctx_t *hashcat_ctx, const int gpu, int  val);

int get_fan_speed_current (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val);
int get_fan_speed_target  (hashcat_ctx_t *hashcat_ctx, const int gpu, int *val);
int set_fan_speed_target  (hashcat_ctx_t *hashcat_ctx, const int gpu, int  val);

// ADL functions

int  adl_init  (hashcat_ctx_t *hashcat_ctx);
void adl_close (hashcat_ctx_t *hashcat_ctx);

int hm_ADL_Main_Control_Destroy (hashcat_ctx_t *hashcat_ctx);
int hm_ADL_Main_Control_Create (hashcat_ctx_t *hashcat_ctx, ADL_MAIN_MALLOC_CALLBACK callback, int iEnumConnectedAdapters);

int hm_ADL_Adapter_NumberOfAdapters_Get (hashcat_ctx_t *hashcat_ctx, int *lpNumAdapters);
int hm_ADL_Adapter_AdapterInfo_Get (hashcat_ctx_t *hashcat_ctx, LPAdapterInfo lpInfo, int iInputSize);
int hm_ADL_Display_DisplayInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *iNumDisplays, ADLDisplayInfo **lppInfo, int iForceDetect);
int hm_ADL_Overdrive5_Temperature_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature);
int hm_ADL_Overdrive6_Temperature_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *iTemperature);
int hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLPMActivity *lpActivity);
int hm_ADL_Overdrive_ThermalDevices_Enum (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLThermalControllerInfo *lpThermalControllerInfo);
int hm_ADL_Adapter_ID_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *lpAdapterID);
int hm_ADL_Adapter_VideoBiosInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLBiosInfo *lpBiosInfo);
int hm_ADL_Overdrive5_FanSpeedInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedInfo *lpFanSpeedInfo);
int hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue);
int hm_ADL_Overdrive6_FanSpeed_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6FanSpeedInfo *lpFanSpeedInfo);
int hm_ADL_Overdrive5_FanSpeed_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue);
int hm_ADL_Overdrive6_FanSpeed_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6FanSpeedValue *lpFanSpeedValue);
int hm_ADL_Overdrive5_FanSpeedToDefault_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iThermalControllerIndex);
int hm_ADL_Overdrive_ODParameters_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLODParameters *lpOdParameters);
int hm_ADL_Overdrive_ODPerformanceLevels_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int iDefault, ADLODPerformanceLevels *lpOdPerformanceLevels);
int hm_ADL_Overdrive_ODPerformanceLevels_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLODPerformanceLevels *lpOdPerformanceLevels);
int hm_ADL_Overdrive_PowerControlInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6PowerControlInfo *);
int hm_ADL_Overdrive_PowerControl_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *level);
int hm_ADL_Overdrive_PowerControl_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int level);
int hm_ADL_Adapter_Active_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *lpStatus);
//int hm_ADL_DisplayEnable_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *lpDisplayIndexList, int iDisplayListSize, int bPersistOnly);
int hm_ADL_Overdrive_Caps (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *od_supported, int *od_enabled, int *od_version);
int hm_ADL_Overdrive_CurrentStatus_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6CurrentStatus *status);
int hm_ADL_Overdrive_StateInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int type, ADLOD6MemClockState *state);
int hm_ADL_Overdrive_Capabilities_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6Capabilities *caps);
int hm_ADL_Overdrive_State_Set (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int type, ADLOD6StateInfo *state);
int hm_ADL_Overdrive6_PowerControl_Caps (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *lpSupported);
int hm_ADL_Overdrive6_TargetTemperatureData_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, int *cur_temp, int *default_temp);
int hm_ADL_Overdrive6_TargetTemperatureRangeInfo_Get (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex, ADLOD6ParameterRange *lpTargetTemperatureInfo);
int hm_ADL_Overdrive6_FanSpeed_Reset (hashcat_ctx_t *hashcat_ctx, int iAdapterIndex);

// general functions

int hm_get_threshold_slowdown_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id);
int hm_get_threshold_shutdown_with_device_id (hashcat_ctx_t *hashcat_ctx, const u32 device_id);
int hm_get_temperature_with_device_id        (hashcat_ctx_t *hashcat_ctx, const u32 device_id);
int hm_get_fanpolicy_with_device_id          (hashcat_ctx_t *hashcat_ctx, const u32 device_id);
int hm_get_fanspeed_with_device_id           (hashcat_ctx_t *hashcat_ctx, const u32 device_id);
int hm_get_buslanes_with_device_id           (hashcat_ctx_t *hashcat_ctx, const u32 device_id);
int hm_get_utilization_with_device_id        (hashcat_ctx_t *hashcat_ctx, const u32 device_id);
int hm_get_memoryspeed_with_device_id        (hashcat_ctx_t *hashcat_ctx, const u32 device_id);
int hm_get_corespeed_with_device_id          (hashcat_ctx_t *hashcat_ctx, const u32 device_id);
int hm_get_throttle_with_device_id           (hashcat_ctx_t *hashcat_ctx, const u32 device_id);
int hm_set_fanspeed_with_device_id_adl       (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed, const int fanpolicy);
int hm_set_fanspeed_with_device_id_nvapi     (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed, const int fanpolicy);
int hm_set_fanspeed_with_device_id_xnvctrl   (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed);

int  hwmon_ctx_init    (hashcat_ctx_t *hashcat_ctx);
void hwmon_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // _HWMON_H
