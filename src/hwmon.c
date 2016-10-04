/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "hwmon.h"

static int get_adapters_num_adl (ADL_PTR *adl, int *iNumberAdapters)
{
  if (hm_ADL_Adapter_NumberOfAdapters_Get (adl, iNumberAdapters) != ADL_OK) return -1;

  if (iNumberAdapters == 0)
  {
    log_info ("WARN: No ADL adapters found.");

    return -1;
  }

  return 0;
}

static LPAdapterInfo hm_get_adapter_info_adl (ADL_PTR *adl, int iNumberAdapters)
{
  size_t AdapterInfoSize = iNumberAdapters * sizeof (AdapterInfo);

  LPAdapterInfo lpAdapterInfo = (LPAdapterInfo) mymalloc (AdapterInfoSize);

  if (hm_ADL_Adapter_AdapterInfo_Get (adl, lpAdapterInfo, AdapterInfoSize) != ADL_OK) return NULL;

  return lpAdapterInfo;
}

static int hm_get_adapter_index_nvapi (const hwmon_ctx_t *hwmon_ctx, HM_ADAPTER_NVAPI *nvapiGPUHandle)
{
  NvU32 pGpuCount;

  if (hm_NvAPI_EnumPhysicalGPUs (hwmon_ctx->hm_nvapi, nvapiGPUHandle, &pGpuCount) != NVAPI_OK) return 0;

  if (pGpuCount == 0)
  {
    log_info ("WARN: No NvAPI adapters found");

    return 0;
  }

  return (pGpuCount);
}

static int hm_get_adapter_index_nvml (const hwmon_ctx_t *hwmon_ctx, HM_ADAPTER_NVML *nvmlGPUHandle)
{
  int pGpuCount = 0;

  for (u32 i = 0; i < DEVICES_MAX; i++)
  {
    if (hm_NVML_nvmlDeviceGetHandleByIndex (hwmon_ctx->hm_nvml, 1, i, &nvmlGPUHandle[i]) != NVML_SUCCESS) break;

    // can be used to determine if the device by index matches the cuda device by index
    // char name[100]; memset (name, 0, sizeof (name));
    // hm_NVML_nvmlDeviceGetName (hwmon_ctx->hm_nvml, nvGPUHandle[i], name, sizeof (name) - 1);

    pGpuCount++;
  }

  if (pGpuCount == 0)
  {
    log_info ("WARN: No NVML adapters found");

    return 0;
  }

  return (pGpuCount);
}

static void hm_sort_adl_adapters_by_busid_devid (u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  // basically bubble sort

  for (int i = 0; i < num_adl_adapters; i++)
  {
    for (int j = 0; j < num_adl_adapters - 1; j++)
    {
      // get info of adapter [x]

      u32 adapter_index_x = valid_adl_device_list[j];
      AdapterInfo info_x = lpAdapterInfo[adapter_index_x];

      u32 bus_num_x = info_x.iBusNumber;
      u32 dev_num_x = info_x.iDeviceNumber;

      // get info of adapter [y]

      u32 adapter_index_y = valid_adl_device_list[j + 1];
      AdapterInfo info_y = lpAdapterInfo[adapter_index_y];

      u32 bus_num_y = info_y.iBusNumber;
      u32 dev_num_y = info_y.iDeviceNumber;

      u32 need_swap = 0;

      if (bus_num_y < bus_num_x)
      {
        need_swap = 1;
      }
      else if (bus_num_y == bus_num_x)
      {
        if (dev_num_y < dev_num_x)
        {
          need_swap = 1;
        }
      }

      if (need_swap == 1)
      {
        u32 temp = valid_adl_device_list[j + 1];

        valid_adl_device_list[j + 1] = valid_adl_device_list[j];
        valid_adl_device_list[j + 0] = temp;
      }
    }
  }
}

static u32 *hm_get_list_valid_adl_adapters (int iNumberAdapters, int *num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  *num_adl_adapters = 0;

  u32 *adl_adapters = NULL;

  int *bus_numbers    = NULL;
  int *device_numbers = NULL;

  for (int i = 0; i < iNumberAdapters; i++)
  {
    AdapterInfo info = lpAdapterInfo[i];

    if (strlen (info.strUDID) < 1) continue;

    #if defined (_WIN)
    if (info.iVendorID !=   1002) continue;
    #else
    if (info.iVendorID != 0x1002) continue;
    #endif

    if (info.iBusNumber    < 0) continue;
    if (info.iDeviceNumber < 0) continue;

    int found = 0;

    for (int pos = 0; pos < *num_adl_adapters; pos++)
    {
      if ((bus_numbers[pos] == info.iBusNumber) && (device_numbers[pos] == info.iDeviceNumber))
      {
        found = 1;
        break;
      }
    }

    if (found) continue;

    // add it to the list

    adl_adapters = (u32 *) myrealloc (adl_adapters, (*num_adl_adapters) * sizeof (int), sizeof (int));

    adl_adapters[*num_adl_adapters] = i;

    // rest is just bookkeeping

    bus_numbers    = (int*) myrealloc (bus_numbers,    (*num_adl_adapters) * sizeof (int), sizeof (int));
    device_numbers = (int*) myrealloc (device_numbers, (*num_adl_adapters) * sizeof (int), sizeof (int));

    bus_numbers[*num_adl_adapters]    = info.iBusNumber;
    device_numbers[*num_adl_adapters] = info.iDeviceNumber;

    (*num_adl_adapters)++;
  }

  myfree (bus_numbers);
  myfree (device_numbers);

  // sort the list by increasing bus id, device id number

  hm_sort_adl_adapters_by_busid_devid (adl_adapters, *num_adl_adapters, lpAdapterInfo);

  return adl_adapters;
}

static int hm_check_fanspeed_control (ADL_PTR *adl, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  // loop through all valid devices

  for (int i = 0; i < num_adl_adapters; i++)
  {
    u32 adapter_index = valid_adl_device_list[i];

    // get AdapterInfo

    AdapterInfo info = lpAdapterInfo[adapter_index];

    // unfortunately this doesn't work since bus id and dev id are not unique
    // int opencl_device_index = hm_get_opencl_device_index (hm_device, num_adl_adapters, info.iBusNumber, info.iDeviceNumber);
    // if (opencl_device_index == -1) continue;

    int opencl_device_index = i;

    // if (hm_show_performance_level (adl, info.iAdapterIndex) != 0) return -1;

    // get fanspeed info

    if (hm_device[opencl_device_index].od_version == 5)
    {
      ADLFanSpeedInfo FanSpeedInfo;

      memset (&FanSpeedInfo, 0, sizeof (ADLFanSpeedInfo));

      FanSpeedInfo.iSize = sizeof (ADLFanSpeedInfo);

      if (hm_ADL_Overdrive5_FanSpeedInfo_Get (adl, info.iAdapterIndex, 0, &FanSpeedInfo) != ADL_OK) return -1;

      // check read and write capability in fanspeedinfo

      if ((FanSpeedInfo.iFlags & ADL_DL_FANCTRL_SUPPORTS_PERCENT_READ) &&
          (FanSpeedInfo.iFlags & ADL_DL_FANCTRL_SUPPORTS_PERCENT_WRITE))
      {
        hm_device[opencl_device_index].fan_get_supported = true;
      }
      else
      {
        hm_device[opencl_device_index].fan_get_supported = false;
      }
    }
    else // od_version == 6
    {
      ADLOD6FanSpeedInfo faninfo;

      memset (&faninfo, 0, sizeof (faninfo));

      if (hm_ADL_Overdrive6_FanSpeed_Get (adl, info.iAdapterIndex, &faninfo) != ADL_OK) return -1;

      // check read capability in fanspeedinfo

      if (faninfo.iSpeedType & ADL_OD6_FANSPEED_TYPE_PERCENT)
      {
        hm_device[opencl_device_index].fan_get_supported = true;
      }
      else
      {
        hm_device[opencl_device_index].fan_get_supported = false;
      }
    }
  }

  return 0;
}

static int hm_get_overdrive_version (ADL_PTR *adl, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  for (int i = 0; i < num_adl_adapters; i++)
  {
    u32 adapter_index = valid_adl_device_list[i];

    // get AdapterInfo

    AdapterInfo info = lpAdapterInfo[adapter_index];

    // get overdrive version

    int od_supported = 0;
    int od_enabled   = 0;
    int od_version   = 0;

    if (hm_ADL_Overdrive_Caps (adl, info.iAdapterIndex, &od_supported, &od_enabled, &od_version) != ADL_OK) return -1;

    // store the overdrive version in hm_device

    // unfortunately this doesn't work since bus id and dev id are not unique
    // int opencl_device_index = hm_get_opencl_device_index (hm_device, num_adl_adapters, info.iBusNumber, info.iDeviceNumber);
    // if (opencl_device_index == -1) continue;

    int opencl_device_index = i;

    hm_device[opencl_device_index].od_version = od_version;
  }

  return 0;
}

static int hm_get_adapter_index_adl (hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  for (int i = 0; i < num_adl_adapters; i++)
  {
    u32 adapter_index = valid_adl_device_list[i];

    // get AdapterInfo

    AdapterInfo info = lpAdapterInfo[adapter_index];

    // store the iAdapterIndex in hm_device

    // unfortunately this doesn't work since bus id and dev id are not unique
    // int opencl_device_index = hm_get_opencl_device_index (hm_device, num_adl_adapters, info.iBusNumber, info.iDeviceNumber);
    // if (opencl_device_index == -1) continue;

    int opencl_device_index = i;

    hm_device[opencl_device_index].adl = info.iAdapterIndex;
  }

  return num_adl_adapters;
}

int hm_get_threshold_slowdown_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id)
{
  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {

      }
      else if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {
        int CurrentValue = 0;
        int DefaultValue = 0;

        if (hm_ADL_Overdrive6_TargetTemperatureData_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &CurrentValue, &DefaultValue) != ADL_OK) return -1;

        // the return value has never been tested since hm_ADL_Overdrive6_TargetTemperatureData_Get() never worked on any system. expect problems.

        return DefaultValue;
      }
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int target = 0;

    if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hwmon_ctx->hm_nvml, 1, hwmon_ctx->hm_device[device_id].nvml, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, (unsigned int *) &target) != NVML_SUCCESS) return -1;

    return target;
  }

  return -1;
}

int hm_get_threshold_shutdown_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id)
{
  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {

      }
      else if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {

      }
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int target = 0;

    if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hwmon_ctx->hm_nvml, 1, hwmon_ctx->hm_device[device_id].nvml, NVML_TEMPERATURE_THRESHOLD_SHUTDOWN, (unsigned int *) &target) != NVML_SUCCESS) return -1;

    return target;
  }

  return -1;
}

int hm_get_temperature_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id)
{
  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 5)
      {
        ADLTemperature Temperature;

        Temperature.iSize = sizeof (ADLTemperature);

        if (hm_ADL_Overdrive5_Temperature_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, 0, &Temperature) != ADL_OK) return -1;

        return Temperature.iTemperature / 1000;
      }
      else if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {
        int Temperature = 0;

        if (hm_ADL_Overdrive6_Temperature_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &Temperature) != ADL_OK) return -1;

        return Temperature / 1000;
      }
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int temperature = 0;

    if (hm_NVML_nvmlDeviceGetTemperature (hwmon_ctx->hm_nvml, 1, hwmon_ctx->hm_device[device_id].nvml, NVML_TEMPERATURE_GPU, (u32 *) &temperature) != NVML_SUCCESS) return -1;

    return temperature;
  }

  return -1;
}

int hm_get_fanpolicy_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id)
{
  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (hwmon_ctx->hm_device[device_id].fan_get_supported == true)
  {
    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        if (hwmon_ctx->hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;

          if (hm_ADL_Overdrive5_FanSpeed_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, 0, &lpFanSpeedValue) != ADL_OK) return -1;

          return (lpFanSpeedValue.iFanSpeed & ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED) ? 0 : 1;
        }
        else // od_version == 6
        {
          return 1;
        }
      }
    }

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      return 1;
    }
  }

  return -1;
}

int hm_get_fanspeed_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id)
{
  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (hwmon_ctx->hm_device[device_id].fan_get_supported == true)
  {
    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_adl)
      {
        if (hwmon_ctx->hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
          lpFanSpeedValue.iFlags     = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;

          if (hm_ADL_Overdrive5_FanSpeed_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, 0, &lpFanSpeedValue) != ADL_OK) return -1;

          return lpFanSpeedValue.iFanSpeed;
        }
        else // od_version == 6
        {
          ADLOD6FanSpeedInfo faninfo;

          memset (&faninfo, 0, sizeof (faninfo));

          if (hm_ADL_Overdrive6_FanSpeed_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &faninfo) != ADL_OK) return -1;

          return faninfo.iFanSpeedPercent;
        }
      }
    }

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      int speed = 0;

      if (hm_NVML_nvmlDeviceGetFanSpeed (hwmon_ctx->hm_nvml, 0, hwmon_ctx->hm_device[device_id].nvml, (u32 *) &speed) != NVML_SUCCESS) return -1;

      return speed;
    }
  }

  return -1;
}

int hm_get_buslanes_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id)
{
  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iCurrentBusLanes;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int currLinkWidth;

    if (hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (hwmon_ctx->hm_nvml, 1, hwmon_ctx->hm_device[device_id].nvml, &currLinkWidth) != NVML_SUCCESS) return -1;

    return currLinkWidth;
  }

  return -1;
}

int hm_get_utilization_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id)
{
  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iActivityPercent;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    nvmlUtilization_t utilization;

    if (hm_NVML_nvmlDeviceGetUtilizationRates (hwmon_ctx->hm_nvml, 1, hwmon_ctx->hm_device[device_id].nvml, &utilization) != NVML_SUCCESS) return -1;

    return utilization.gpu;
  }

  return -1;
}

int hm_get_memoryspeed_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id)
{
  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iMemoryClock / 100;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int clock;

    if (hm_NVML_nvmlDeviceGetClockInfo (hwmon_ctx->hm_nvml, 1, hwmon_ctx->hm_device[device_id].nvml, NVML_CLOCK_MEM, &clock) != NVML_SUCCESS) return -1;

    return clock;
  }

  return -1;
}

int hm_get_corespeed_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id)
{
  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (hwmon_ctx->hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iEngineClock / 100;
    }
  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int clock;

    if (hm_NVML_nvmlDeviceGetClockInfo (hwmon_ctx->hm_nvml, 1, hwmon_ctx->hm_device[device_id].nvml, NVML_CLOCK_SM, &clock) != NVML_SUCCESS) return -1;

    return clock;
  }

  return -1;
}

int hm_get_throttle_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id)
{
  if (hwmon_ctx->enabled == false) return -1;

  if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {

  }

  if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned long long clocksThrottleReasons = 0;
    unsigned long long supportedThrottleReasons = 0;

    if (hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons   (hwmon_ctx->hm_nvml, 1, hwmon_ctx->hm_device[device_id].nvml, &clocksThrottleReasons)    != NVML_SUCCESS) return -1;
    if (hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (hwmon_ctx->hm_nvml, 1, hwmon_ctx->hm_device[device_id].nvml, &supportedThrottleReasons) != NVML_SUCCESS) return -1;

    clocksThrottleReasons &=  supportedThrottleReasons;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonGpuIdle;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonApplicationsClocksSetting;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonUnknown;

    if (opencl_ctx->kernel_power_final)
    {
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonHwSlowdown;
    }

    return (clocksThrottleReasons != nvmlClocksThrottleReasonNone);
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_adl (const hwmon_ctx_t *hwmon_ctx, const u32 device_id, const int fanspeed, const int fanpolicy)
{
  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fan_set_supported == true)
  {
    if (hwmon_ctx->hm_adl)
    {
      if (fanpolicy == 1)
      {
        if (hwmon_ctx->hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
          lpFanSpeedValue.iFlags     = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;
          lpFanSpeedValue.iFanSpeed  = fanspeed;

          if (hm_ADL_Overdrive5_FanSpeed_Set (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, 0, &lpFanSpeedValue) != ADL_OK) return -1;

          return 0;
        }
        else // od_version == 6
        {
          ADLOD6FanSpeedValue fan_speed_value;

          memset (&fan_speed_value, 0, sizeof (fan_speed_value));

          fan_speed_value.iSpeedType = ADL_OD6_FANSPEED_TYPE_PERCENT;
          fan_speed_value.iFanSpeed  = fanspeed;

          if (hm_ADL_Overdrive6_FanSpeed_Set (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &fan_speed_value) != ADL_OK) return -1;

          return 0;
        }
      }
      else
      {
        if (hwmon_ctx->hm_device[device_id].od_version == 5)
        {
          if (hm_ADL_Overdrive5_FanSpeedToDefault_Set (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, 0) != ADL_OK) return -1;

          return 0;
        }
        else // od_version == 6
        {
          if (hm_ADL_Overdrive6_FanSpeed_Reset (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl) != ADL_OK) return -1;

          return 0;
        }
      }
    }
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_nvapi (const hwmon_ctx_t *hwmon_ctx, const u32 device_id, const int fanspeed, const int fanpolicy)
{
  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fan_set_supported == true)
  {
    if (hwmon_ctx->hm_nvapi)
    {
      if (fanpolicy == 1)
      {
        NV_GPU_COOLER_LEVELS CoolerLevels;

        memset (&CoolerLevels, 0, sizeof (NV_GPU_COOLER_LEVELS));

        CoolerLevels.Version = GPU_COOLER_LEVELS_VER | sizeof (NV_GPU_COOLER_LEVELS);

        CoolerLevels.Levels[0].Level  = fanspeed;
        CoolerLevels.Levels[0].Policy = 1;

        if (hm_NvAPI_GPU_SetCoolerLevels (hwmon_ctx->hm_nvapi, hwmon_ctx->hm_device[device_id].nvapi, 0, &CoolerLevels) != NVAPI_OK) return -1;

        return 0;
      }
      else
      {
        if (hm_NvAPI_GPU_RestoreCoolerSettings (hwmon_ctx->hm_nvapi, hwmon_ctx->hm_device[device_id].nvapi, 0) != NVAPI_OK) return -1;

        return 0;
      }
    }
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_xnvctrl (const hwmon_ctx_t *hwmon_ctx, const u32 device_id, const int fanspeed)
{
  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[device_id].fan_set_supported == true)
  {
    if (hwmon_ctx->hm_xnvctrl)
    {
      if (set_fan_speed_target (hwmon_ctx->hm_xnvctrl, hwmon_ctx->hm_device[device_id].xnvctrl, fanspeed) != 0) return -1;

      return 0;
    }
  }

  return -1;
}

int hwmon_ctx_init (hwmon_ctx_t *hwmon_ctx, const user_options_t *user_options, const opencl_ctx_t *opencl_ctx)
{
  hwmon_ctx->enabled = false;

  if (user_options->keyspace          == true) return 0;
  if (user_options->left              == true) return 0;
  if (user_options->opencl_info       == true) return 0;
  if (user_options->show              == true) return 0;
  if (user_options->stdout_flag       == true) return 0;
  if (user_options->usage             == true) return 0;
  if (user_options->version           == true) return 0;
  if (user_options->gpu_temp_disable  == true) return 0;

  hwmon_ctx->hm_device = (hm_attrs_t *) mycalloc (DEVICES_MAX, sizeof (hm_attrs_t));

  /**
   * Initialize shared libraries
   */

  ADL_PTR     *adl     = (ADL_PTR *)     mymalloc (sizeof (ADL_PTR));
  NVAPI_PTR   *nvapi   = (NVAPI_PTR *)   mymalloc (sizeof (NVAPI_PTR));
  NVML_PTR    *nvml    = (NVML_PTR *)    mymalloc (sizeof (NVML_PTR));
  XNVCTRL_PTR *xnvctrl = (XNVCTRL_PTR *) mymalloc (sizeof (XNVCTRL_PTR));

  hwmon_ctx->hm_adl     = NULL;
  hwmon_ctx->hm_nvapi   = NULL;
  hwmon_ctx->hm_nvml    = NULL;
  hwmon_ctx->hm_xnvctrl = NULL;

  hm_attrs_t *hm_adapters_adl      = (hm_attrs_t *) mycalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_nvapi    = (hm_attrs_t *) mycalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_nvml     = (hm_attrs_t *) mycalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_xnvctrl  = (hm_attrs_t *) mycalloc (DEVICES_MAX, sizeof (hm_attrs_t));

  if ((opencl_ctx->need_nvml == true) && (nvml_init (nvml) == 0))
  {
    hwmon_ctx->hm_nvml = nvml;
  }

  if (hwmon_ctx->hm_nvml)
  {
    if (hm_NVML_nvmlInit (hwmon_ctx->hm_nvml) == NVML_SUCCESS)
    {
      HM_ADAPTER_NVML *nvmlGPUHandle = (HM_ADAPTER_NVML *) mycalloc (DEVICES_MAX, sizeof (HM_ADAPTER_NVML));

      int tmp_in = hm_get_adapter_index_nvml (hwmon_ctx, nvmlGPUHandle);

      int tmp_out = 0;

      for (int i = 0; i < tmp_in; i++)
      {
        hm_adapters_nvml[tmp_out++].nvml = nvmlGPUHandle[i];
      }

      for (int i = 0; i < tmp_out; i++)
      {
        unsigned int speed;

        if (hm_NVML_nvmlDeviceGetFanSpeed (hwmon_ctx->hm_nvml, 0, hm_adapters_nvml[i].nvml, &speed) == NVML_SUCCESS) hm_adapters_nvml[i].fan_get_supported = true;

        // doesn't seem to create any advantages
        //hm_NVML_nvmlDeviceSetComputeMode (hwmon_ctx->hm_nvml, 1, hm_adapters_nvml[i].nvml, NVML_COMPUTEMODE_EXCLUSIVE_PROCESS);
        //hm_NVML_nvmlDeviceSetGpuOperationMode (hwmon_ctx->hm_nvml, 1, hm_adapters_nvml[i].nvml, NVML_GOM_ALL_ON);
      }

      myfree (nvmlGPUHandle);
    }
  }

  if ((opencl_ctx->need_nvapi == true) && (nvapi_init (nvapi) == 0))
  {
    hwmon_ctx->hm_nvapi = nvapi;
  }

  if (hwmon_ctx->hm_nvapi)
  {
    if (hm_NvAPI_Initialize (hwmon_ctx->hm_nvapi) == NVAPI_OK)
    {
      HM_ADAPTER_NVAPI *nvGPUHandle = (HM_ADAPTER_NVAPI *) mycalloc (DEVICES_MAX, sizeof (HM_ADAPTER_NVAPI));

      int tmp_in = hm_get_adapter_index_nvapi (hwmon_ctx, nvGPUHandle);

      int tmp_out = 0;

      for (int i = 0; i < tmp_in; i++)
      {
        hm_adapters_nvapi[tmp_out++].nvapi = nvGPUHandle[i];
      }

      myfree (nvGPUHandle);
    }
  }

  if ((opencl_ctx->need_xnvctrl == true) && (xnvctrl_init (xnvctrl) == 0))
  {
    hwmon_ctx->hm_xnvctrl = xnvctrl;
  }

  if (hwmon_ctx->hm_xnvctrl)
  {
    if (hm_XNVCTRL_XOpenDisplay (hwmon_ctx->hm_xnvctrl) == 0)
    {
      for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        hm_adapters_xnvctrl[device_id].xnvctrl = device_id;

        int speed = 0;

        if (get_fan_speed_current (hwmon_ctx->hm_xnvctrl, device_id, &speed) == 0) hm_adapters_xnvctrl[device_id].fan_get_supported = true;
      }
    }
  }

  if ((opencl_ctx->need_adl == true) && (adl_init (adl) == 0))
  {
    hwmon_ctx->hm_adl = adl;
  }

  if (hwmon_ctx->hm_adl)
  {
    if (hm_ADL_Main_Control_Create (hwmon_ctx->hm_adl, ADL_Main_Memory_Alloc, 0) == ADL_OK)
    {
      // total number of adapters

      int hm_adapters_num;

      if (get_adapters_num_adl (hwmon_ctx->hm_adl, &hm_adapters_num) != 0) return -1;

      // adapter info

      LPAdapterInfo lpAdapterInfo = hm_get_adapter_info_adl (hwmon_ctx->hm_adl, hm_adapters_num);

      if (lpAdapterInfo == NULL) return -1;

      // get a list (of ids of) valid/usable adapters

      int num_adl_adapters = 0;

      u32 *valid_adl_device_list = hm_get_list_valid_adl_adapters (hm_adapters_num, &num_adl_adapters, lpAdapterInfo);

      if (num_adl_adapters > 0)
      {
        hm_get_adapter_index_adl (hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);

        hm_get_overdrive_version (hwmon_ctx->hm_adl, hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);

        hm_check_fanspeed_control (hwmon_ctx->hm_adl, hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);
      }

      myfree (valid_adl_device_list);

      myfree (lpAdapterInfo);
    }
  }

  if (hwmon_ctx->hm_adl == NULL && hwmon_ctx->hm_nvml == NULL && hwmon_ctx->hm_xnvctrl == NULL)
  {
    return 0;
  }

  /**
   * looks like we have some manageable device
   */

  hwmon_ctx->enabled = true;

  /**
   * save buffer required for later restores
   */

  hwmon_ctx->od_clock_mem_status = (ADLOD6MemClockState *) mycalloc (opencl_ctx->devices_cnt, sizeof (ADLOD6MemClockState));

  hwmon_ctx->od_power_control_status = (int *) mycalloc (opencl_ctx->devices_cnt, sizeof (int));

  hwmon_ctx->nvml_power_limit = (unsigned int *) mycalloc (opencl_ctx->devices_cnt, sizeof (unsigned int));

  /**
   * HM devices: copy
   */

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

    const u32 platform_devices_id = device_param->platform_devices_id;

    if (device_param->device_vendor_id == VENDOR_ID_AMD)
    {
      hwmon_ctx->hm_device[device_id].adl               = hm_adapters_adl[platform_devices_id].adl;
      hwmon_ctx->hm_device[device_id].nvapi             = 0;
      hwmon_ctx->hm_device[device_id].nvml              = 0;
      hwmon_ctx->hm_device[device_id].xnvctrl           = 0;
      hwmon_ctx->hm_device[device_id].od_version        = hm_adapters_adl[platform_devices_id].od_version;
      hwmon_ctx->hm_device[device_id].fan_get_supported = hm_adapters_adl[platform_devices_id].fan_get_supported;
      hwmon_ctx->hm_device[device_id].fan_set_supported = false;
    }

    if (device_param->device_vendor_id == VENDOR_ID_NV)
    {
      hwmon_ctx->hm_device[device_id].adl               = 0;
      hwmon_ctx->hm_device[device_id].nvapi             = hm_adapters_nvapi[platform_devices_id].nvapi;
      hwmon_ctx->hm_device[device_id].nvml              = hm_adapters_nvml[platform_devices_id].nvml;
      hwmon_ctx->hm_device[device_id].xnvctrl           = hm_adapters_xnvctrl[platform_devices_id].xnvctrl;
      hwmon_ctx->hm_device[device_id].od_version        = 0;
      hwmon_ctx->hm_device[device_id].fan_get_supported = hm_adapters_nvml[platform_devices_id].fan_get_supported;
      hwmon_ctx->hm_device[device_id].fan_set_supported = false;
    }
  }

  myfree (hm_adapters_adl);
  myfree (hm_adapters_nvapi);
  myfree (hm_adapters_nvml);
  myfree (hm_adapters_xnvctrl);

  /**
   * powertune on user request
   */

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      /**
       * Temporary fix:
       * with AMD r9 295x cards it seems that we need to set the powertune value just AFTER the ocl init stuff
       * otherwise after hc_clCreateContext () etc, powertune value was set back to "normal" and cards unfortunately
       * were not working @ full speed (setting hm_ADL_Overdrive_PowerControl_Set () here seems to fix the problem)
       * Driver / ADL bug?
       */

      if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {
        int ADL_rc;

        // check powertune capabilities first, if not available then skip device

        int powertune_supported = 0;

        if ((ADL_rc = hm_ADL_Overdrive6_PowerControl_Caps (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &powertune_supported)) != ADL_OK)
        {
          log_error ("ERROR: Failed to get ADL PowerControl Capabilities");

          return -1;
        }

        // first backup current value, we will restore it later

        if (powertune_supported != 0)
        {
          // powercontrol settings

          ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

          if ((ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &powertune)) == ADL_OK)
          {
            ADL_rc = hm_ADL_Overdrive_PowerControl_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &hwmon_ctx->od_power_control_status[device_id]);
          }

          if (ADL_rc != ADL_OK)
          {
            log_error ("ERROR: Failed to get current ADL PowerControl settings");

            return -1;
          }

          if ((ADL_rc = hm_ADL_Overdrive_PowerControl_Set (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, powertune.iMaxValue)) != ADL_OK)
          {
            log_error ("ERROR: Failed to set new ADL PowerControl values");

            return -1;
          }

          // clocks

          memset (&hwmon_ctx->od_clock_mem_status[device_id], 0, sizeof (ADLOD6MemClockState));

          hwmon_ctx->od_clock_mem_status[device_id].state.iNumberOfPerformanceLevels = 2;

          if ((ADL_rc = hm_ADL_Overdrive_StateInfo_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, ADL_OD6_GETSTATEINFO_CUSTOM_PERFORMANCE, &hwmon_ctx->od_clock_mem_status[device_id])) != ADL_OK)
          {
            log_error ("ERROR: Failed to get ADL memory and engine clock frequency");

            return -1;
          }

          // Query capabilities only to see if profiles were not "damaged", if so output a warning but do accept the users profile settings

          ADLOD6Capabilities caps = {0, 0, 0, {0, 0, 0}, {0, 0, 0}, 0, 0};

          if ((ADL_rc = hm_ADL_Overdrive_Capabilities_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &caps)) != ADL_OK)
          {
            log_error ("ERROR: Failed to get ADL device capabilities");

            return -1;
          }

          int engine_clock_max =       (int) (0.6666 * caps.sEngineClockRange.iMax);
          int memory_clock_max =       (int) (0.6250 * caps.sMemoryClockRange.iMax);

          int warning_trigger_engine = (int) (0.25   * engine_clock_max);
          int warning_trigger_memory = (int) (0.25   * memory_clock_max);

          int engine_clock_profile_max = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iEngineClock;
          int memory_clock_profile_max = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iMemoryClock;

          // warning if profile has too low max values

          if ((engine_clock_max - engine_clock_profile_max) > warning_trigger_engine)
          {
            log_info ("WARN: The custom profile seems to have too low maximum engine clock values. You therefore may not reach full performance");
          }

          if ((memory_clock_max - memory_clock_profile_max) > warning_trigger_memory)
          {
            log_info ("WARN: The custom profile seems to have too low maximum memory clock values. You therefore may not reach full performance");
          }

          ADLOD6StateInfo *performance_state = (ADLOD6StateInfo*) mycalloc (1, sizeof (ADLOD6StateInfo) + sizeof (ADLOD6PerformanceLevel));

          performance_state->iNumberOfPerformanceLevels = 2;

          performance_state->aLevels[0].iEngineClock = engine_clock_profile_max;
          performance_state->aLevels[1].iEngineClock = engine_clock_profile_max;
          performance_state->aLevels[0].iMemoryClock = memory_clock_profile_max;
          performance_state->aLevels[1].iMemoryClock = memory_clock_profile_max;

          if ((ADL_rc = hm_ADL_Overdrive_State_Set (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, ADL_OD6_SETSTATE_PERFORMANCE, performance_state)) != ADL_OK)
          {
            log_info ("ERROR: Failed to set ADL performance state");

            return -1;
          }

          myfree (performance_state);
        }

        // set powertune value only

        if (powertune_supported != 0)
        {
          // powertune set
          ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

          if ((ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &powertune)) != ADL_OK)
          {
            log_error ("ERROR: Failed to get current ADL PowerControl settings");

            return -1;
          }

          if ((ADL_rc = hm_ADL_Overdrive_PowerControl_Set (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, powertune.iMaxValue)) != ADL_OK)
          {
            log_error ("ERROR: Failed to set new ADL PowerControl values");

            return -1;
          }
        }
      }
    }

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      // first backup current value, we will restore it later

      unsigned int limit;

      bool powertune_supported = false;

      if (hm_NVML_nvmlDeviceGetPowerManagementLimit (hwmon_ctx->hm_nvml, 0, hwmon_ctx->hm_device[device_id].nvml, &limit) == NVML_SUCCESS)
      {
        powertune_supported = true;
      }

      // if backup worked, activate the maximum allowed

      if (powertune_supported == true)
      {
        unsigned int minLimit;
        unsigned int maxLimit;

        if (hm_NVML_nvmlDeviceGetPowerManagementLimitConstraints (hwmon_ctx->hm_nvml, 0, hwmon_ctx->hm_device[device_id].nvml, &minLimit, &maxLimit) == NVML_SUCCESS)
        {
          if (maxLimit > 0)
          {
            if (hm_NVML_nvmlDeviceSetPowerManagementLimit (hwmon_ctx->hm_nvml, 0, hwmon_ctx->hm_device[device_id].nvml, maxLimit) == NVML_SUCCESS)
            {
              // now we can be sure we need to reset later

              hwmon_ctx->nvml_power_limit[device_id] = limit;
            }
          }
        }
      }
    }
  }

  /**
   * Store initial fanspeed if gpu_temp_retain is enabled
   */

  if (user_options->gpu_temp_retain)
  {
    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      if (hwmon_ctx->hm_device[device_id].fan_get_supported == true)
      {
        const int fanspeed  = hm_get_fanspeed_with_device_id  (hwmon_ctx, opencl_ctx, device_id);
        const int fanpolicy = hm_get_fanpolicy_with_device_id (hwmon_ctx, opencl_ctx, device_id);

        // we also set it to tell the OS we take control over the fan and it's automatic controller
        // if it was set to automatic. we do not control user-defined fanspeeds.

        if (fanpolicy == 1)
        {
          hwmon_ctx->hm_device[device_id].fan_set_supported = true;

          int rc = -1;

          if (device_param->device_vendor_id == VENDOR_ID_AMD)
          {
            rc = hm_set_fanspeed_with_device_id_adl (hwmon_ctx, device_id, fanspeed, 1);
          }
          else if (device_param->device_vendor_id == VENDOR_ID_NV)
          {
            #if defined (__linux__)
            rc = set_fan_control (hwmon_ctx->hm_xnvctrl, hwmon_ctx->hm_device[device_id].xnvctrl, NV_CTRL_GPU_COOLER_MANUAL_CONTROL_TRUE);
            #endif

            #if defined (_WIN)
            rc = hm_set_fanspeed_with_device_id_nvapi (hwmon_ctx, device_id, fanspeed, 1);
            #endif
          }

          if (rc == 0)
          {
            hwmon_ctx->hm_device[device_id].fan_set_supported = true;
          }
          else
          {
            log_info ("WARNING: Failed to set initial fan speed for device #%u", device_id + 1);

            hwmon_ctx->hm_device[device_id].fan_set_supported = false;
          }
        }
        else
        {
          hwmon_ctx->hm_device[device_id].fan_set_supported = false;
        }
      }
    }
  }

  return 0;
}

void hwmon_ctx_destroy (hwmon_ctx_t *hwmon_ctx, const user_options_t *user_options, const opencl_ctx_t *opencl_ctx)
{
  if (hwmon_ctx->enabled == false) return;

  // reset default fan speed

  if (user_options->gpu_temp_retain)
  {
    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      if (hwmon_ctx->hm_device[device_id].fan_set_supported == true)
      {
        int rc = -1;

        if (device_param->device_vendor_id == VENDOR_ID_AMD)
        {
          rc = hm_set_fanspeed_with_device_id_adl (hwmon_ctx, device_id, 100, 0);
        }
        else if (device_param->device_vendor_id == VENDOR_ID_NV)
        {
          #if defined (__linux__)
          rc = set_fan_control (hwmon_ctx->hm_xnvctrl, hwmon_ctx->hm_device[device_id].xnvctrl, NV_CTRL_GPU_COOLER_MANUAL_CONTROL_FALSE);
          #endif

          #if defined (_WIN)
          rc = hm_set_fanspeed_with_device_id_nvapi (hwmon_ctx, device_id, 100, 0);
          #endif
        }

        if (rc == -1) log_info ("WARNING: Failed to restore default fan speed and policy for device #%", device_id + 1);
      }
    }
  }

  // reset power tuning

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      if (hwmon_ctx->hm_device[device_id].od_version == 6)
      {
        // check powertune capabilities first, if not available then skip device

        int powertune_supported = 0;

        if ((hm_ADL_Overdrive6_PowerControl_Caps (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, &powertune_supported)) != ADL_OK)
        {
          log_error ("ERROR: Failed to get ADL PowerControl Capabilities");

          continue;
        }

        if (powertune_supported != 0)
        {
          // powercontrol settings

          if ((hm_ADL_Overdrive_PowerControl_Set (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, hwmon_ctx->od_power_control_status[device_id])) != ADL_OK)
          {
            log_info ("ERROR: Failed to restore the ADL PowerControl values");

            continue;
          }

          // clocks

          ADLOD6StateInfo *performance_state = (ADLOD6StateInfo*) mycalloc (1, sizeof (ADLOD6StateInfo) + sizeof (ADLOD6PerformanceLevel));

          performance_state->iNumberOfPerformanceLevels = 2;

          performance_state->aLevels[0].iEngineClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[0].iEngineClock;
          performance_state->aLevels[1].iEngineClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iEngineClock;
          performance_state->aLevels[0].iMemoryClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[0].iMemoryClock;
          performance_state->aLevels[1].iMemoryClock = hwmon_ctx->od_clock_mem_status[device_id].state.aLevels[1].iMemoryClock;

          if ((hm_ADL_Overdrive_State_Set (hwmon_ctx->hm_adl, hwmon_ctx->hm_device[device_id].adl, ADL_OD6_SETSTATE_PERFORMANCE, performance_state)) != ADL_OK)
          {
            log_info ("ERROR: Failed to restore ADL performance state");

            continue;
          }

          myfree (performance_state);
        }
      }
    }

    if (opencl_ctx->devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      unsigned int power_limit = hwmon_ctx->nvml_power_limit[device_id];

      if (power_limit > 0)
      {
        hm_NVML_nvmlDeviceSetPowerManagementLimit (hwmon_ctx->hm_nvml, 0, hwmon_ctx->hm_device[device_id].nvml, power_limit);
      }
    }
  }

  // unload shared libraries

  if (hwmon_ctx->hm_nvml)
  {
    hm_NVML_nvmlShutdown (hwmon_ctx->hm_nvml);

    nvml_close (hwmon_ctx->hm_nvml);
  }

  if (hwmon_ctx->hm_nvapi)
  {
    hm_NvAPI_Unload (hwmon_ctx->hm_nvapi);

    nvapi_close (hwmon_ctx->hm_nvapi);
  }

  if (hwmon_ctx->hm_xnvctrl)
  {
    hm_XNVCTRL_XCloseDisplay (hwmon_ctx->hm_xnvctrl);

    xnvctrl_close (hwmon_ctx->hm_xnvctrl);
  }

  if (hwmon_ctx->hm_adl)
  {
    hm_ADL_Main_Control_Destroy (hwmon_ctx->hm_adl);

    adl_close (hwmon_ctx->hm_adl);
  }

  // free memory

  myfree (hwmon_ctx->nvml_power_limit);
  myfree (hwmon_ctx->od_power_control_status);
  myfree (hwmon_ctx->od_clock_mem_status);

  myfree (hwmon_ctx->hm_device);

  memset (hwmon_ctx, 0, sizeof (hwmon_ctx_t));
}
