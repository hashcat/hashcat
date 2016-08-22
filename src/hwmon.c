#include <config.h>

#ifdef HAVE_HWMON
#include <hc_global_data_t.h>
#include <hc_global.h>
#include <hwmon.h>
#include <shared.h>
#include <consts/devices_vendors.h>
#include <logging.h>


int get_adapters_num_adl(ADL_PTR *adl, int *iNumberAdapters)
{
  if (hm_ADL_Adapter_NumberOfAdapters_Get(adl, iNumberAdapters) != ADL_OK) return -1;

  if (iNumberAdapters == 0)
  {
    log_info("WARN: No ADL adapters found.");

    return -1;
  }

  return 0;
}

/*
int hm_show_performance_level(HM_LIB hm_dll, int iAdapterIndex)
{
  ADLODPerformanceLevels *lpOdPerformanceLevels = NULL;
  ADLODParameters lpOdParameters;

  lpOdParameters.iSize = sizeof(ADLODParameters);
  size_t plevels_size = 0;

  if (hm_ADL_Overdrive_ODParameters_Get(hm_dll, iAdapterIndex, &lpOdParameters) != ADL_OK) return -1;

  log_info("[DEBUG] %s, adapter %d performance level (%d) : %s %s",
    __func__, iAdapterIndex,
    lpOdParameters.iNumberOfPerformanceLevels,
    (lpOdParameters.iActivityReportingSupported) ? "activity reporting" : "",
    (lpOdParameters.iDiscretePerformanceLevels) ? "discrete performance levels" : "performance ranges");

  plevels_size = sizeof(ADLODPerformanceLevels) + sizeof(ADLODPerformanceLevel) * (lpOdParameters.iNumberOfPerformanceLevels - 1);

  lpOdPerformanceLevels = (ADLODPerformanceLevels *)mymalloc(plevels_size);

  lpOdPerformanceLevels->iSize = sizeof(ADLODPerformanceLevels) + sizeof(ADLODPerformanceLevel) * (lpOdParameters.iNumberOfPerformanceLevels - 1);

  if (hm_ADL_Overdrive_ODPerformanceLevels_Get(hm_dll, iAdapterIndex, 0, lpOdPerformanceLevels) != ADL_OK) return -1;

  for (int j = 0; j < lpOdParameters.iNumberOfPerformanceLevels; j++)
    log_info("[DEBUG] %s, adapter %d, level %d : engine %d, memory %d, voltage: %d",
      __func__, iAdapterIndex, j,
      lpOdPerformanceLevels->aLevels[j].iEngineClock / 100, lpOdPerformanceLevels->aLevels[j].iMemoryClock / 100, lpOdPerformanceLevels->aLevels[j].iVddc);

  myfree(lpOdPerformanceLevels);

  return 0;
}
*/

LPAdapterInfo hm_get_adapter_info_adl(ADL_PTR *adl, int iNumberAdapters)
{
  size_t AdapterInfoSize = iNumberAdapters * sizeof(AdapterInfo);

  LPAdapterInfo lpAdapterInfo = (LPAdapterInfo)mymalloc(AdapterInfoSize);

  if (hm_ADL_Adapter_AdapterInfo_Get((ADL_PTR *)adl, lpAdapterInfo, AdapterInfoSize) != ADL_OK) return NULL;

  return lpAdapterInfo;
}

int hm_get_adapter_index_nvapi(HM_ADAPTER_NVAPI nvapiGPUHandle[DEVICES_MAX])
{
  NvU32 pGpuCount;

  if (hm_NvAPI_EnumPhysicalGPUs(data.hm_nvapi, nvapiGPUHandle, &pGpuCount) != NVAPI_OK) return 0;

  if (pGpuCount == 0)
  {
    log_info("WARN: No NvAPI adapters found");

    return 0;
  }

  return (pGpuCount);
}

int hm_get_adapter_index_nvml(HM_ADAPTER_NVML nvmlGPUHandle[DEVICES_MAX])
{
  int pGpuCount = 0;

  for (uint i = 0; i < DEVICES_MAX; i++)
  {
    if (hm_NVML_nvmlDeviceGetHandleByIndex(data.hm_nvml, 1, i, &nvmlGPUHandle[i]) != NVML_SUCCESS) break;

    // can be used to determine if the device by index matches the cuda device by index
    // char name[100]; memset (name, 0, sizeof (name));
    // hm_NVML_nvmlDeviceGetName (data.hm_nvml, nvGPUHandle[i], name, sizeof (name) - 1);

    pGpuCount++;
  }

  if (pGpuCount == 0)
  {
    log_info("WARN: No NVML adapters found");

    return 0;
  }

  return (pGpuCount);
}

/*
//
// does not help at all, since ADL does not assign different bus id, device id when we have multi GPU setups
//

int hm_get_opencl_device_index(hm_attrs_t *hm_device, uint num_adl_adapters, int bus_num, int dev_num)
{
  u32 idx = -1;

  for (uint i = 0; i < num_adl_adapters; i++)
  {
    int opencl_bus_num = hm_device[i].busid;
    int opencl_dev_num = hm_device[i].devid;

    if ((opencl_bus_num == bus_num) && (opencl_dev_num == dev_num))
    {
      idx = i;

      break;
    }
  }

  if (idx >= DEVICES_MAX) return -1;

  return idx;
}

void hm_get_opencl_busid_devid(hm_attrs_t *hm_device, uint opencl_num_devices, cl_device_id *devices)
{
  for (uint i = 0; i < opencl_num_devices; i++)
  {
    cl_device_topology_amd device_topology;

    hc_clGetDeviceInfo(devices[i], CL_DEVICE_TOPOLOGY_AMD, sizeof(device_topology), &device_topology, NULL);

    hm_device[i].busid = device_topology.pcie.bus;
    hm_device[i].devid = device_topology.pcie.device;
  }
}
*/

void hm_sort_adl_adapters_by_busid_devid(u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
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

      uint need_swap = 0;

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

u32 *hm_get_list_valid_adl_adapters(int iNumberAdapters, int *num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  *num_adl_adapters = 0;

  u32 *adl_adapters = NULL;

  int *bus_numbers = NULL;
  int *device_numbers = NULL;

  for (int i = 0; i < iNumberAdapters; i++)
  {
    AdapterInfo info = lpAdapterInfo[i];

    if (strlen(info.strUDID) < 1) continue;

#ifdef WIN
    if (info.iVendorID != 1002) continue;
#else
    if (info.iVendorID != 0x1002) continue;
#endif

    if (info.iBusNumber < 0) continue;
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

    adl_adapters = (u32 *)myrealloc(adl_adapters, (*num_adl_adapters) * sizeof(int), sizeof(int));

    adl_adapters[*num_adl_adapters] = i;

    // rest is just bookkeeping

    bus_numbers = (int*)myrealloc(bus_numbers, (*num_adl_adapters) * sizeof(int), sizeof(int));
    device_numbers = (int*)myrealloc(device_numbers, (*num_adl_adapters) * sizeof(int), sizeof(int));

    bus_numbers[*num_adl_adapters] = info.iBusNumber;
    device_numbers[*num_adl_adapters] = info.iDeviceNumber;

    (*num_adl_adapters)++;
  }

  myfree(bus_numbers);
  myfree(device_numbers);

  // sort the list by increasing bus id, device id number

  hm_sort_adl_adapters_by_busid_devid(adl_adapters, *num_adl_adapters, lpAdapterInfo);

  return adl_adapters;
}

int hm_check_fanspeed_control(ADL_PTR *adl, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
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

      memset(&FanSpeedInfo, 0, sizeof(ADLFanSpeedInfo));

      FanSpeedInfo.iSize = sizeof(ADLFanSpeedInfo);

      if (hm_ADL_Overdrive5_FanSpeedInfo_Get(adl, info.iAdapterIndex, 0, &FanSpeedInfo) != ADL_OK) return -1;

      // check read and write capability in fanspeedinfo

      if ((FanSpeedInfo.iFlags & ADL_DL_FANCTRL_SUPPORTS_PERCENT_READ) &&
        (FanSpeedInfo.iFlags & ADL_DL_FANCTRL_SUPPORTS_PERCENT_WRITE))
      {
        hm_device[opencl_device_index].fan_get_supported = 1;
      }
      else
      {
        hm_device[opencl_device_index].fan_get_supported = 0;
      }
    }
    else // od_version == 6
    {
      ADLOD6FanSpeedInfo faninfo;

      memset(&faninfo, 0, sizeof(faninfo));

      if (hm_ADL_Overdrive6_FanSpeed_Get(adl, info.iAdapterIndex, &faninfo) != ADL_OK) return -1;

      // check read capability in fanspeedinfo

      if (faninfo.iSpeedType & ADL_OD6_FANSPEED_TYPE_PERCENT)
      {
        hm_device[opencl_device_index].fan_get_supported = 1;
      }
      else
      {
        hm_device[opencl_device_index].fan_get_supported = 0;
      }
    }
  }

  return 0;
}

int hm_get_overdrive_version(ADL_PTR *adl, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  for (int i = 0; i < num_adl_adapters; i++)
  {
    u32 adapter_index = valid_adl_device_list[i];

    // get AdapterInfo

    AdapterInfo info = lpAdapterInfo[adapter_index];

    // get overdrive version

    int od_supported = 0;
    int od_enabled = 0;
    int od_version = 0;

    if (hm_ADL_Overdrive_Caps(adl, info.iAdapterIndex, &od_supported, &od_enabled, &od_version) != ADL_OK) return -1;

    // store the overdrive version in hm_device

    // unfortunately this doesn't work since bus id and dev id are not unique
    // int opencl_device_index = hm_get_opencl_device_index (hm_device, num_adl_adapters, info.iBusNumber, info.iDeviceNumber);
    // if (opencl_device_index == -1) continue;

    int opencl_device_index = i;

    hm_device[opencl_device_index].od_version = od_version;
  }

  return 0;
}

int hm_get_adapter_index_adl(hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
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

int hm_get_threshold_slowdown_with_device_id(const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      if (data.hm_device[device_id].od_version == 5)
      {

      }
      else if (data.hm_device[device_id].od_version == 6)
      {
        int CurrentValue = 0;
        int DefaultValue = 0;

        if (hm_ADL_Overdrive6_TargetTemperatureData_Get(data.hm_adl, data.hm_device[device_id].adl, &CurrentValue, &DefaultValue) != ADL_OK) return -1;

        // the return value has never been tested since hm_ADL_Overdrive6_TargetTemperatureData_Get() never worked on any system. expect problems.

        return DefaultValue;
      }
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int target = 0;

    if (hm_NVML_nvmlDeviceGetTemperatureThreshold(data.hm_nvml, 1, data.hm_device[device_id].nvml, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, (unsigned int *)&target) != NVML_SUCCESS) return -1;

    return target;
  }

  return -1;
}

int hm_get_threshold_shutdown_with_device_id(const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      if (data.hm_device[device_id].od_version == 5)
      {

      }
      else if (data.hm_device[device_id].od_version == 6)
      {

      }
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int target = 0;

    if (hm_NVML_nvmlDeviceGetTemperatureThreshold(data.hm_nvml, 1, data.hm_device[device_id].nvml, NVML_TEMPERATURE_THRESHOLD_SHUTDOWN, (unsigned int *)&target) != NVML_SUCCESS) return -1;

    return target;
  }

  return -1;
}

int hm_get_temperature_with_device_id(const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      if (data.hm_device[device_id].od_version == 5)
      {
        ADLTemperature Temperature;

        Temperature.iSize = sizeof(ADLTemperature);

        if (hm_ADL_Overdrive5_Temperature_Get(data.hm_adl, data.hm_device[device_id].adl, 0, &Temperature) != ADL_OK) return -1;

        return Temperature.iTemperature / 1000;
      }
      else if (data.hm_device[device_id].od_version == 6)
      {
        int Temperature = 0;

        if (hm_ADL_Overdrive6_Temperature_Get(data.hm_adl, data.hm_device[device_id].adl, &Temperature) != ADL_OK) return -1;

        return Temperature / 1000;
      }
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int temperature = 0;

    if (hm_NVML_nvmlDeviceGetTemperature(data.hm_nvml, 1, data.hm_device[device_id].nvml, NVML_TEMPERATURE_GPU, (uint *)&temperature) != NVML_SUCCESS) return -1;

    return temperature;
  }

  return -1;
}

int hm_get_fanpolicy_with_device_id(const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.hm_device[device_id].fan_get_supported == 1)
  {
    if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      if (data.hm_adl)
      {
        if (data.hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset(&lpFanSpeedValue, 0, sizeof(lpFanSpeedValue));

          lpFanSpeedValue.iSize = sizeof(lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;

          if (hm_ADL_Overdrive5_FanSpeed_Get(data.hm_adl, data.hm_device[device_id].adl, 0, &lpFanSpeedValue) != ADL_OK) return -1;

          return (lpFanSpeedValue.iFanSpeed & ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED) ? 0 : 1;
        }
        else // od_version == 6
        {
          return 1;
        }
      }
    }

    if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      return 1;
    }
  }

  return -1;
}

int hm_get_fanspeed_with_device_id(const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.hm_device[device_id].fan_get_supported == 1)
  {
    if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      if (data.hm_adl)
      {
        if (data.hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset(&lpFanSpeedValue, 0, sizeof(lpFanSpeedValue));

          lpFanSpeedValue.iSize = sizeof(lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
          lpFanSpeedValue.iFlags = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;

          if (hm_ADL_Overdrive5_FanSpeed_Get(data.hm_adl, data.hm_device[device_id].adl, 0, &lpFanSpeedValue) != ADL_OK) return -1;

          return lpFanSpeedValue.iFanSpeed;
        }
        else // od_version == 6
        {
          ADLOD6FanSpeedInfo faninfo;

          memset(&faninfo, 0, sizeof(faninfo));

          if (hm_ADL_Overdrive6_FanSpeed_Get(data.hm_adl, data.hm_device[device_id].adl, &faninfo) != ADL_OK) return -1;

          return faninfo.iFanSpeedPercent;
        }
      }
    }

    if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      int speed = 0;

      if (hm_NVML_nvmlDeviceGetFanSpeed(data.hm_nvml, 0, data.hm_device[device_id].nvml, (uint *)&speed) != NVML_SUCCESS) return -1;

      return speed;
    }
  }

  return -1;
}

int hm_get_buslanes_with_device_id(const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof(ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get(data.hm_adl, data.hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iCurrentBusLanes;
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int currLinkWidth;

    if (hm_NVML_nvmlDeviceGetCurrPcieLinkWidth(data.hm_nvml, 1, data.hm_device[device_id].nvml, &currLinkWidth) != NVML_SUCCESS) return -1;

    return currLinkWidth;
  }

  return -1;
}

int hm_get_utilization_with_device_id(const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof(ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get(data.hm_adl, data.hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iActivityPercent;
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    nvmlUtilization_t utilization;

    if (hm_NVML_nvmlDeviceGetUtilizationRates(data.hm_nvml, 1, data.hm_device[device_id].nvml, &utilization) != NVML_SUCCESS) return -1;

    return utilization.gpu;
  }

  return -1;
}

int hm_get_memoryspeed_with_device_id(const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof(ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get(data.hm_adl, data.hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iMemoryClock / 100;
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int clock;

    if (hm_NVML_nvmlDeviceGetClockInfo(data.hm_nvml, 1, data.hm_device[device_id].nvml, NVML_CLOCK_MEM, &clock) != NVML_SUCCESS) return -1;

    return clock;
  }

  return -1;
}

int hm_get_corespeed_with_device_id(const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof(ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get(data.hm_adl, data.hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iEngineClock / 100;
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int clock;

    if (hm_NVML_nvmlDeviceGetClockInfo(data.hm_nvml, 1, data.hm_device[device_id].nvml, NVML_CLOCK_SM, &clock) != NVML_SUCCESS) return -1;

    return clock;
  }

  return -1;
}

int hm_get_throttle_with_device_id(const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {

  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned long long clocksThrottleReasons = 0;
    unsigned long long supportedThrottleReasons = 0;

    if (hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons(data.hm_nvml, 1, data.hm_device[device_id].nvml, &clocksThrottleReasons) != NVML_SUCCESS) return -1;
    if (hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons(data.hm_nvml, 1, data.hm_device[device_id].nvml, &supportedThrottleReasons) != NVML_SUCCESS) return -1;

    clocksThrottleReasons &= supportedThrottleReasons;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonGpuIdle;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonApplicationsClocksSetting;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonUnknown;

    if (data.kernel_power_final)
    {
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonHwSlowdown;
    }

    return (clocksThrottleReasons != nvmlClocksThrottleReasonNone);
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_adl(const uint device_id, const int fanspeed, const int fanpolicy)
{
  if (data.hm_device[device_id].fan_set_supported == 1)
  {
    if (data.hm_adl)
    {
      if (fanpolicy == 1)
      {
        if (data.hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset(&lpFanSpeedValue, 0, sizeof(lpFanSpeedValue));

          lpFanSpeedValue.iSize = sizeof(lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
          lpFanSpeedValue.iFlags = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;
          lpFanSpeedValue.iFanSpeed = fanspeed;

          if (hm_ADL_Overdrive5_FanSpeed_Set(data.hm_adl, data.hm_device[device_id].adl, 0, &lpFanSpeedValue) != ADL_OK) return -1;

          return 0;
        }
        else // od_version == 6
        {
          ADLOD6FanSpeedValue fan_speed_value;

          memset(&fan_speed_value, 0, sizeof(fan_speed_value));

          fan_speed_value.iSpeedType = ADL_OD6_FANSPEED_TYPE_PERCENT;
          fan_speed_value.iFanSpeed = fanspeed;

          if (hm_ADL_Overdrive6_FanSpeed_Set(data.hm_adl, data.hm_device[device_id].adl, &fan_speed_value) != ADL_OK) return -1;

          return 0;
        }
      }
      else
      {
        if (data.hm_device[device_id].od_version == 5)
        {
          if (hm_ADL_Overdrive5_FanSpeedToDefault_Set(data.hm_adl, data.hm_device[device_id].adl, 0) != ADL_OK) return -1;

          return 0;
        }
        else // od_version == 6
        {
          if (hm_ADL_Overdrive6_FanSpeed_Reset(data.hm_adl, data.hm_device[device_id].adl) != ADL_OK) return -1;

          return 0;
        }
      }
    }
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_nvapi(const uint device_id, const int fanspeed, const int fanpolicy)
{
  if (data.hm_device[device_id].fan_set_supported == 1)
  {
    if (data.hm_nvapi)
    {
      if (fanpolicy == 1)
      {
        NV_GPU_COOLER_LEVELS CoolerLevels;

        memset(&CoolerLevels, 0, sizeof(NV_GPU_COOLER_LEVELS));

        CoolerLevels.Version = GPU_COOLER_LEVELS_VER | sizeof(NV_GPU_COOLER_LEVELS);

        CoolerLevels.Levels[0].Level = fanspeed;
        CoolerLevels.Levels[0].Policy = 1;

        if (hm_NvAPI_GPU_SetCoolerLevels(data.hm_nvapi, data.hm_device[device_id].nvapi, 0, &CoolerLevels) != NVAPI_OK) return -1;

        return 0;
      }
      else
      {
        if (hm_NvAPI_GPU_RestoreCoolerSettings(data.hm_nvapi, data.hm_device[device_id].nvapi, 0) != NVAPI_OK) return -1;

        return 0;
      }
    }
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_xnvctrl(const uint device_id, const int fanspeed)
{
  if (data.hm_device[device_id].fan_set_supported == 1)
  {
    if (data.hm_xnvctrl)
    {
      if (set_fan_speed_target(data.hm_xnvctrl, data.hm_device[device_id].xnvctrl, fanspeed) != 0) return -1;

      return 0;
    }
  }

  return -1;
}

#endif
