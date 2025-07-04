/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_AUTOTUNE_H
#define HC_AUTOTUNE_H

int find_tuning_function (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);

HC_API_CALL void *thread_autotune (void *p);

#endif // HC_AUTOTUNE_H
