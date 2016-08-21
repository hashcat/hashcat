#include "filenames_generators.h"

void generate_source_kernel_filename(const ATTACK_EXEC_SIDE_KERNEL attack_exec, const ATTACK_KERN attack_kern, const uint kern_type, const char *shared_dir, char *source_file)
{
  if (attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    switch (attack_kern) {
    case ATTACK_KERN_STRAIGHT:
      snprintf(source_file, 255, "%s/OpenCL/m%05d_a0.cl", shared_dir, (int)kern_type);
      break;
    case ATTACK_KERN_COMBI:
      snprintf(source_file, 255, "%s/OpenCL/m%05d_a1.cl", shared_dir, (int)kern_type);
      break;
    case ATTACK_KERN_BF:
      snprintf(source_file, 255, "%s/OpenCL/m%05d_a3.cl", shared_dir, (int)kern_type);
      break;
    }
  }
  else
    snprintf(source_file, 255, "%s/OpenCL/m%05d.cl", shared_dir, (int)kern_type);
}

void generate_cached_kernel_filename(const ATTACK_EXEC_SIDE_KERNEL attack_exec, const ATTACK_KERN attack_kern, const uint kern_type, char *profile_dir, const char *device_name_chksum, char *cached_file)
{
  if (attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    switch (attack_kern) {
    case ATTACK_KERN_STRAIGHT:
      snprintf(cached_file, 255, "%s/kernels/m%05d_a0.%s.kernel", profile_dir, (int)kern_type, device_name_chksum);
      break;
    case ATTACK_KERN_COMBI:
      snprintf(cached_file, 255, "%s/kernels/m%05d_a1.%s.kernel", profile_dir, (int)kern_type, device_name_chksum);
      break;
    case ATTACK_KERN_BF:
      snprintf(cached_file, 255, "%s/kernels/m%05d_a3.%s.kernel", profile_dir, (int)kern_type, device_name_chksum);
      break;
    }
  }
  else
  {
    snprintf(cached_file, 255, "%s/kernels/m%05d.%s.kernel", profile_dir, (int)kern_type, device_name_chksum);
  }
}

void generate_source_kernel_mp_filename(const OPTI_TYPE opti_type, const OPTS_TYPE opts_type, char *shared_dir, char *source_file)
{
  if ((opti_type & OPTI_TYPE_BRUTE_FORCE) && (opts_type & OPTS_TYPE_PT_GENERATE_BE))
  {
    snprintf(source_file, 255, "%s/OpenCL/markov_be.cl", shared_dir);
  }
  else
  {
    snprintf(source_file, 255, "%s/OpenCL/markov_le.cl", shared_dir);
  }
}

void generate_cached_kernel_mp_filename(const OPTI_TYPE opti_type, const OPTS_TYPE opts_type, char *profile_dir, const char *device_name_chksum, char *cached_file)
{
  if ((opti_type & OPTI_TYPE_BRUTE_FORCE) && (opts_type & OPTS_TYPE_PT_GENERATE_BE))
  {
    snprintf(cached_file, 255, "%s/kernels/markov_be.%s.kernel", profile_dir, device_name_chksum);
  }
  else
  {
    snprintf(cached_file, 255, "%s/kernels/markov_le.%s.kernel", profile_dir, device_name_chksum);
  }
}

void generate_source_kernel_amp_filename(const ATTACK_KERN attack_kern, char *shared_dir, char *source_file)
{
  snprintf(source_file, 255, "%s/OpenCL/amp_a%d.cl", shared_dir, attack_kern);
}

void generate_cached_kernel_amp_filename(const ATTACK_KERN attack_kern, char *profile_dir, const char *device_name_chksum, char *cached_file)
{
  snprintf(cached_file, 255, "%s/kernels/amp_a%d.%s.kernel", profile_dir, attack_kern, device_name_chksum);
}

char *filename_from_filepath(char *filepath)
{
  char *ptr = NULL;

  if ((ptr = strrchr(filepath, '/')) != NULL)
  {
    ptr++;
  }
  else if ((ptr = strrchr(filepath, '\\')) != NULL)
  {
    ptr++;
  }
  else
  {
    ptr = filepath;
  }

  return ptr;
}
