/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <errno.h>
#if defined (__CYGWIN__)
#include <sys/cygwin.h>
#endif

#ifndef _HWMON_H
#define _HWMON_H

int hm_get_threshold_slowdown_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
int hm_get_threshold_shutdown_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx);
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

int  hwmon_ctx_init    (hashcat_ctx_t *hashcat_ctx);
void hwmon_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // _HWMON_H
