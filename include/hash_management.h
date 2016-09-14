/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HASH_MANAGEMENT_H
#define _HASH_MANAGEMENT_H

#define USERNAME 0

void save_hash ();

void check_hash (hc_device_param_t *device_param, plain_t *plain);

int check_cracked (hc_device_param_t *device_param, const uint salt_pos, hashconfig_t *hashconfig);

#endif // _HASH_MANAGEMENT_H
