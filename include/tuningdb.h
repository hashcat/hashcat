/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _TUNINGDB_H
#define _TUNINGDB_H

#include <stdio.h>
#include <errno.h>

#define TUNING_DB_FILE "hashcat.hctune"

int  tuning_db_init    (hashcat_ctx_t *hashcat_ctx);
void tuning_db_destroy (hashcat_ctx_t *hashcat_ctx);

tuning_db_entry_t *tuning_db_search (hashcat_ctx_t *hashcat_ctx, const char *device_name, const cl_device_type device_type, int attack_mode, const int hash_mode);

#endif // _TUNINGDB_H
