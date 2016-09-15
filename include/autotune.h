/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _AUTOTUNE_H
#define _AUTOTUNE_H

#define OPENCL_VECTOR_WIDTH     0

int autotune (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, hashconfig_t *hashconfig);

void *thread_autotune (void *p);

#endif // _AUTOTUNE_H
