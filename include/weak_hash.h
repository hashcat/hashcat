/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _WEAK_HASH_H
#define _WEAK_HASH_H

#define WEAK_HASH_THRESHOLD 100

void weak_hash_check (hc_device_param_t *device_param, hashconfig_t *hashconfig, const uint salt_pos);

#endif // _WEAK_HASH_H
