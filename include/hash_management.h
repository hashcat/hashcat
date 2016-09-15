/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HASH_MANAGEMENT_H
#define _HASH_MANAGEMENT_H

#define USERNAME 0

int sort_by_digest_p0p1  (const void *v1, const void *v2);
int sort_by_salt         (const void *v1, const void *v2);
int sort_by_hash         (const void *v1, const void *v2);
int sort_by_hash_no_salt (const void *v1, const void *v2);

void save_hash ();

void check_hash (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, plain_t *plain);

int check_cracked (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const uint salt_pos, hashconfig_t *hashconfig);

#endif // _HASH_MANAGEMENT_H
