/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _TUNINGDB_H
#define _TUNINGDB_H

#include <stdio.h>
#include <errno.h>

#define TUNING_DB_FILE "hashcat.hctune"

void tuning_db_destroy (tuning_db_t *tuning_db);
tuning_db_t *tuning_db_alloc (FILE *fp);
tuning_db_t *tuning_db_init (const char *tuning_db_file);
tuning_db_entry_t *tuning_db_search (const tuning_db_t *tuning_db, const char *device_name, const cl_device_type device_type, int attack_mode, const int hash_type);

#endif // _TUNINGDB_H
