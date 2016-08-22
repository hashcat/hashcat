#pragma once
#include "common.h"
#include "consts/hash_options.h"
#include "consts/optimizer_options.h"
#include "consts/hashcat_modes.h"

void generate_source_kernel_filename(const uint attack_exec, const uint attack_kern, const uint kern_type, char *shared_dir, char *source_file);

void generate_cached_kernel_filename(const uint attack_exec, const uint attack_kern, const uint kern_type, char *profile_dir, const char *device_name_chksum, char *cached_file);

void generate_source_kernel_mp_filename(const uint opti_type, const uint opts_type, char *shared_dir, char *source_file);

void generate_cached_kernel_mp_filename(const uint opti_type, const uint opts_type, char *profile_dir, const char *device_name_chksum, char *cached_file);

void generate_source_kernel_amp_filename(const uint attack_kern, char *shared_dir, char *source_file);

void generate_cached_kernel_amp_filename(const uint attack_kern, char *profile_dir, const char *device_name_chksum, char *cached_file);

char *filename_from_filepath(char *filepath);
