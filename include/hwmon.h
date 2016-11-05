/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <errno.h>

#ifndef _HWMON_H
#define _HWMON_H

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
int hm_set_fanspeed_with_device_id_sysfs     (hashcat_ctx_t *hashcat_ctx, const u32 device_id, const int fanspeed);

int  hwmon_ctx_init    (hashcat_ctx_t *hashcat_ctx);
void hwmon_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // _HWMON_H
