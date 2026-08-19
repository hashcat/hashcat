/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <errno.h>
#if defined (__CYGWIN__)
#include <sys/cygwin.h>
#endif

#ifndef HC_HWMON_H
#define HC_HWMON_H

// How many of a group's members the temperature field names before it starts counting them instead.
// Five fits the line however large the group is and still shows the hottest member.

#define HWMON_GROUP_SHOW 5

bool hm_is_hwmon_group_leader (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
bool hm_bridge_owns_device    (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);

bool hm_get_bridge_buslanes_str    (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, char *buf, const size_t len);
bool hm_get_bridge_temperature_str   (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, char *buf, const size_t len);
u32  hm_get_bridge_temperature_abort (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int  hm_get_bridge_temperature_unwatched (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);

HC_API void hm_temperature_abort_banner            (hashcat_ctx_t *hashcat_ctx);

int hm_get_threshold_slowdown_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int hm_get_threshold_shutdown_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int hm_get_device_temperature                  (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int hm_get_temperature_with_devices_idx        (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int hm_get_fanpolicy_with_devices_idx          (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int hm_get_fanspeed_with_devices_idx           (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
#if defined(__APPLE__)
int hm_get_fanspeed_apple                      (hashcat_ctx_t *hashcat_ctx, char *fan_speed_buf);
#endif
int hm_get_buslanes_with_devices_idx           (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int hm_get_utilization_with_devices_idx        (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int hm_get_memoryspeed_with_devices_idx        (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int hm_get_corespeed_with_devices_idx          (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int hm_get_throttle_with_devices_idx           (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
u64 hm_get_memoryused_with_devices_idx         (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int64_t hm_get_power_with_devices_idx          (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);

int  hwmon_ctx_init    (hashcat_ctx_t *hashcat_ctx);
void hwmon_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // HC_HWMON_H
