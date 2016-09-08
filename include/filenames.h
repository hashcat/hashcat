/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _FILENAMES_H
#define _FILENAMES_H

#include <stdio.h>

void generate_dictstat_filename (char *profile_dir, char *dictstat_filename);
void generate_source_kernel_filename (const uint attack_exec, const uint attack_kern, const uint kern_type, char *shared_dir, char *source_file);
void generate_cached_kernel_filename (const uint attack_exec, const uint attack_kern, const uint kern_type, char *profile_dir, const char *device_name_chksum, char *cached_file);
void generate_source_kernel_mp_filename (const uint opti_type, const uint opts_type, char *shared_dir, char *source_file);
void generate_cached_kernel_mp_filename (const uint opti_type, const uint opts_type, char *profile_dir, const char *device_name_chksum, char *cached_file);
void generate_source_kernel_amp_filename (const uint attack_kern, char *shared_dir, char *source_file);
void generate_cached_kernel_amp_filename (const uint attack_kern, char *profile_dir, const char *device_name_chksum, char *cached_file);

char *filename_from_filepath (char *filepath);

#endif // _FILENAMES_H
