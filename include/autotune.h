/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _AUTOTUNE_H
#define _AUTOTUNE_H

int autotune (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, hashconfig_t *hashconfig, const user_options_t *user_options, const user_options_extra_t *user_options_extra, const straight_ctx_t *straight_ctx, status_ctx_t *status_ctx);

void *thread_autotune (void *p);

#endif // _AUTOTUNE_H
