/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HWMON_H
#define _HWMON_H

int hm_get_threshold_slowdown_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id);
int hm_get_threshold_shutdown_with_device_id (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id);
int hm_get_temperature_with_device_id        (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id);
int hm_get_fanpolicy_with_device_id          (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id);
int hm_get_fanspeed_with_device_id           (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id);
int hm_get_buslanes_with_device_id           (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id);
int hm_get_utilization_with_device_id        (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id);
int hm_get_memoryspeed_with_device_id        (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id);
int hm_get_corespeed_with_device_id          (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id);
int hm_get_throttle_with_device_id           (const hwmon_ctx_t *hwmon_ctx, const opencl_ctx_t *opencl_ctx, const u32 device_id);
int hm_set_fanspeed_with_device_id_adl       (const hwmon_ctx_t *hwmon_ctx, const u32 device_id, const int fanspeed, const int fanpolicy);
int hm_set_fanspeed_with_device_id_nvapi     (const hwmon_ctx_t *hwmon_ctx, const u32 device_id, const int fanspeed, const int fanpolicy);
int hm_set_fanspeed_with_device_id_xnvctrl   (const hwmon_ctx_t *hwmon_ctx, const u32 device_id, const int fanspeed);

int  hwmon_ctx_init    (hwmon_ctx_t *hwmon_ctx, const user_options_t *user_options, const opencl_ctx_t *opencl_ctx);
void hwmon_ctx_destroy (hwmon_ctx_t *hwmon_ctx, const user_options_t *user_options, const opencl_ctx_t *opencl_ctx);

#endif // _HWMON_H
