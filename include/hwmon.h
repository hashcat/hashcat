/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#pragma once

typedef struct
{
  HM_ADAPTER_ADL     adl;
  HM_ADAPTER_NVML    nvml;
  HM_ADAPTER_NVAPI   nvapi;
  HM_ADAPTER_XNVCTRL xnvctrl;

  int od_version;

  int fan_get_supported;
  int fan_set_supported;

} hm_attrs_t;

int get_adapters_num_adl (void *adl, int *iNumberAdapters);

int hm_get_adapter_index_adl (hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo);

int hm_get_adapter_index_nvapi (HM_ADAPTER_NVAPI nvapiGPUHandle[DEVICES_MAX]);

int hm_get_adapter_index_nvml (HM_ADAPTER_NVML nvmlGPUHandle[DEVICES_MAX]);

LPAdapterInfo hm_get_adapter_info_adl (void *adl, int iNumberAdapters);

u32 *hm_get_list_valid_adl_adapters (int iNumberAdapters, int *num_adl_adapters, LPAdapterInfo lpAdapterInfo);

int hm_get_overdrive_version  (void *adl, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo);
int hm_check_fanspeed_control (void *adl, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo);

// int hm_get_device_num (void *adl, HM_ADAPTER_ADL hm_adapter_index, int *hm_device_num);
// void hm_get_opencl_busid_devid (hm_attrs_t *hm_device, uint opencl_num_devices, cl_device_id *devices);

int hm_get_threshold_slowdown_with_device_id (const uint device_id);
int hm_get_threshold_shutdown_with_device_id (const uint device_id);
int hm_get_temperature_with_device_id        (const uint device_id);
int hm_get_fanspeed_with_device_id           (const uint device_id);
int hm_get_fanpolicy_with_device_id          (const uint device_id);
int hm_get_buslanes_with_device_id           (const uint device_id);
int hm_get_utilization_with_device_id        (const uint device_id);
int hm_get_memoryspeed_with_device_id        (const uint device_id);
int hm_get_corespeed_with_device_id          (const uint device_id);
int hm_get_throttle_with_device_id           (const uint device_id);
int hm_set_fanspeed_with_device_id_adl       (const uint device_id, const int fanspeed, const int fanpolicy);
int hm_set_fanspeed_with_device_id_nvapi     (const uint device_id, const int fanspeed, const int fanpolicy);
int hm_set_fanspeed_with_device_id_xnvctrl   (const uint device_id, const int fanspeed);

void hm_device_val_to_str (char *target_buf, int max_buf_size, char *suffix, int value);
