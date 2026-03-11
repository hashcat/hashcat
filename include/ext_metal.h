/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EXT_METAL_H
#define HC_EXT_METAL_H

#if defined (__APPLE__)

#include <objc/runtime.h>
#include <CoreFoundation/CoreFoundation.h>

#define mtl_device_id id
#define mtl_command_queue id
#define mtl_function id
#define mtl_pipeline id
#define mtl_library id
#define mtl_command_buffer id
#define mtl_command_encoder id
#define mtl_blit_command_encoder id
#define mtl_compute_command_encoder id
#define mtl_command_allocator id
#define mtl_argument_table id

#define GPU_FAMILY_METAL3  5001
#define GPU_FAMILY_METAL4  5002

#define FEATURE_SET_MAC_FAMILY1_V1  10000
#define FEATURE_SET_MAC_FAMILY1_V2  10001
#define FEATURE_SET_MAC_FAMILY1_V3  10003
#define FEATURE_SET_MAC_FAMILY1_V4  10004
#define FEATURE_SET_MAC_FAMILY2_V1  10005

#define METAL4_SCRATCH_SIZE 4096

typedef struct mtl_mem
{
  id buf_ptr;

  unsigned int buf_mode;

} mtl_mem_t;

typedef enum metalResourceStorageMode
{
  MTL_STORAGE_MODE_PRIVATE = 0, // only the GPU can access
  MTL_STORAGE_MODE_SHARED,      // both the CPU and the GPU can access
  MTL_STORAGE_MODE_MANAGED,     // double allocations

} metalResourceStorageMode_t;

typedef enum metalBufferStorageModeId
{
  metal_d_pws_buf_storageMode,
  metal_d_pws_amp_buf_storageMode,
  metal_d_pws_comp_buf_storageMode,
  metal_d_pws_idx_storageMode,
  metal_d_rules_storageMode,
  metal_d_rules_c_storageMode,
  metal_d_combs_storageMode,
  metal_d_combs_c_storageMode,
  metal_d_bfs_storageMode,
  metal_d_bfs_c_storageMode,
  metal_d_tm_c_storageMode,
  metal_d_bitmap_s1_a_storageMode,
  metal_d_bitmap_s1_b_storageMode,
  metal_d_bitmap_s1_c_storageMode,
  metal_d_bitmap_s1_d_storageMode,
  metal_d_bitmap_s2_a_storageMode,
  metal_d_bitmap_s2_b_storageMode,
  metal_d_bitmap_s2_c_storageMode,
  metal_d_bitmap_s2_d_storageMode,
  metal_d_plain_bufs_storageMode,
  metal_d_digests_buf_storageMode,
  metal_d_digests_shown_storageMode,
  metal_d_salt_bufs_storageMode,
  metal_d_esalt_bufs_storageMode,
  metal_d_tmps_storageMode,
  metal_d_hooks_storageMode,
  metal_d_result_storageMode,
  metal_d_extra0_buf_storageMode,
  metal_d_extra1_buf_storageMode,
  metal_d_extra2_buf_storageMode,
  metal_d_extra3_buf_storageMode,
  metal_d_root_css_buf_storageMode,
  metal_d_markov_css_buf_storageMode,
  metal_d_st_digests_buf_storageMode,
  metal_d_st_salts_buf_storageMode,
  metal_d_st_esalts_buf_storageMode,
  metal_d_kernel_param_storageMode,
  metal_d_fake_buf_storageMode,
  metal_d_pcfg_data_buffer_storageMode,
  metal_d_pcfg_term_blocks_storageMode,
  metal_d_pcfg_structure_storageMode,
  metal_d_pcfg_cumulative_storageMode,
  metal_d_pcfg_omen_structures_storageMode,
  metal_d_pcfg_omen_slot_maps_storageMode,
  metal_d_pcfg_omen_batch_entries_storageMode,
  metal_d_pcfg_omen_partitions_storageMode,
  metal_d_pcfg_data_buffer_part_p1_storageMode,
  metal_d_pcfg_data_buffer_part_p2_storageMode,
  metal_d_pcfg_data_buffer_part_p3_storageMode,
  metal_d_pcfg_data_buffer_part_p4_storageMode,
  metal_d_pcfg_data_buffer_part_p5_storageMode,
  metal_d_pcfg_data_buffer_part_p6_storageMode,
  metal_d_pcfg_data_buffer_part_p7_storageMode,
  metal_d_pcfg_data_buffer_part_p8_storageMode,
  metal_d_pcfg_part_offsets_storageMode,
  //
  metal_private_storageMode,
  metal_shared_storageMode,
  metal_managed_storageMode,
  MTL_BUFFER_CNT

} metalBufferStorageModeId_t;

static const metalResourceStorageMode_t metalResourceStorageModes[MTL_BUFFER_CNT] =
{
  [metal_d_pws_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pws_amp_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pws_comp_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pws_idx_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_rules_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_rules_c_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_combs_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_combs_c_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_bfs_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_bfs_c_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_tm_c_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_bitmap_s1_a_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_bitmap_s1_b_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_bitmap_s1_c_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_bitmap_s1_d_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_bitmap_s2_a_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_bitmap_s2_b_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_bitmap_s2_c_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_bitmap_s2_d_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_plain_bufs_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_digests_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_digests_shown_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_salt_bufs_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_esalt_bufs_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_tmps_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_hooks_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_result_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_extra0_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_extra1_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_extra2_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_extra3_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_root_css_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_markov_css_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_st_digests_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_st_salts_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_st_esalts_buf_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_kernel_param_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_fake_buf_storageMode] = MTL_STORAGE_MODE_PRIVATE,
  [metal_d_pcfg_data_buffer_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_term_blocks_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_structure_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_cumulative_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_omen_structures_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_omen_slot_maps_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_omen_batch_entries_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_omen_partitions_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_data_buffer_part_p1_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_data_buffer_part_p2_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_data_buffer_part_p3_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_data_buffer_part_p4_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_data_buffer_part_p5_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_data_buffer_part_p6_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_data_buffer_part_p7_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_data_buffer_part_p8_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_d_pcfg_part_offsets_storageMode] = MTL_STORAGE_MODE_SHARED,
  //
  [metal_private_storageMode] = MTL_STORAGE_MODE_PRIVATE,
  [metal_shared_storageMode] = MTL_STORAGE_MODE_SHARED,
  [metal_managed_storageMode] = MTL_STORAGE_MODE_MANAGED
};

#define HC_MTL_CREATEBUFFER(ctx, dev_param, size, ptr, buf_name)               \
  do {                                                                         \
    if (hc_mtlCreateBuffer(ctx, dev_param, device_param->metal_device, size,   \
                           ptr, &device_param->metal_d_##buf_name,             \
                           metal_d_##buf_name##_storageMode) == -1) return -1; \
  } while (0)

#define HC_MTL_SELECTOR(obj, obj_name, sel_str, sel_var, err_ctx, err_ret) \
  SEL sel_var = NSSelectorFromString (sel_str);                            \
  if ([obj respondsToSelector:sel_var] == false) {                         \
      event_log_error (err_ctx, "%s(): %s doesn't respond to %s",          \
                       __func__, obj_name, #sel_str);                      \
    return err_ret;                                                        \
  }

#define HC_MTL_SELECTOR_SET(obj, obj_name, sel_str, sel_var, err_ctx, err_ret) \
  sel_var = NSSelectorFromString (sel_str);                                    \
  if ([obj respondsToSelector:sel_var] == false) {                             \
      event_log_error (err_ctx, "%s(): %s doesn't respond to %s",              \
                        __func__, obj_name, #sel_str);                         \
    return err_ret;                                                            \
  }

typedef enum metalDeviceAttribute
{
  MTL_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT = 1,
  MTL_DEVICE_ATTRIBUTE_UNIFIED_MEMORY,
  MTL_DEVICE_ATTRIBUTE_WARP_SIZE,
  MTL_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
  MTL_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
  MTL_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
  MTL_DEVICE_ATTRIBUTE_CLOCK_RATE,
  MTL_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK,
  MTL_DEVICE_ATTRIBUTE_MAX_TRANSFER_RATE,
  MTL_DEVICE_ATTRIBUTE_HEADLESS,
  MTL_DEVICE_ATTRIBUTE_LOW_POWER,
  MTL_DEVICE_ATTRIBUTE_REMOVABLE,
  MTL_DEVICE_ATTRIBUTE_REGISTRY_ID,
  MTL_DEVICE_ATTRIBUTE_PHYSICAL_LOCATION,
  MTL_DEVICE_ATTRIBUTE_LOCATION_NUMBER,
  MTL_DEVICE_ATTRIBUTE_METAL_VERSION,

} metalDeviceAttribute_t;

typedef enum metalDeviceLocation
{
  // MTLDeviceLocationBuiltIn
  // The GPU is built into the device
  MTL_DEVICE_LOCATION_BUILTIN = 0,

  // MTLDeviceLocationSlot
  // The GPU is connected to a slot inside the computer
  MTL_DEVICE_LOCATION_SLOT = 1,

  // MTLDeviceLocationExternal
  // The GPU is connected via an external interface, such as Thunderbolt
  MTL_DEVICE_LOCATION_EXTERNAL = 2,

  // MTLDeviceLocationUnspecified
  // The GPU's location is not specified or cannot be determined
  MTL_DEVICE_LOCATION_UNSPECIFIED = 4294967295,

} metalDeviceLocation_t;

typedef struct hc_metal
{
  CFArrayRef devices;

} hc_metal_t;

typedef hc_metal_t MTL_PTR;

int  mtl_init                               (void *hashcat_ctx);
void mtl_close                              (void *hashcat_ctx);

int  hc_mtlRuntimeGetVersionString          (void *hashcat_ctx, char *runtimeVersion_str, size_t *size);

int  hc_mtlDeviceGetCount                   (void *hashcat_ctx, int *count);
int  hc_mtlDeviceGet                        (void *hashcat_ctx, mtl_device_id *metal_device, int ordinal);
int  hc_mtlDeviceGetName                    (void *hashcat_ctx, char *name, size_t len, mtl_device_id metal_device);
int  hc_mtlDeviceGetAttribute               (void *hashcat_ctx, int *pi, metalDeviceAttribute_t attrib, mtl_device_id metal_device);
int  hc_mtlDeviceUsedMem                    (void *hashcat_ctx, size_t *bytes, mtl_device_id metal_device);
int  hc_mtlDeviceTotalMem                   (void *hashcat_ctx, size_t *bytes, mtl_device_id metal_device);
int  hc_mtlDeviceMaxMemAlloc                (void *hashcat_ctx, size_t *bytes, mtl_device_id metal_device);
int  hc_mtlMemGetInfo                       (void *hashcat_ctx, size_t *mem_free, size_t *mem_total);

int  hc_mtlCreateCommandQueue               (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, mtl_command_queue *command_queue);
int  hc_mtlCreateBuffer                     (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, size_t size, void *ptr, mtl_mem_t *mem, metalBufferStorageModeId_t metal_storage_mode);
int  hc_mtlCreateKernel                     (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, mtl_library metal_library, const char *func_name, mtl_function *metal_function, mtl_pipeline *metal_pipeline);

int  hc_mtlGetMaxTotalThreadsPerThreadgroup (void *hashcat_ctx, mtl_pipeline metal_pipeline, unsigned int *maxTotalThreadsPerThreadgroup);
int  hc_mtlGetThreadExecutionWidth          (void *hashcat_ctx, mtl_pipeline metal_pipeline, unsigned int *threadExecutionWidth);
int  hc_mtlGetStaticThreadgroupMemoryLength (void *hashcat_ctx, mtl_pipeline metal_pipeline, unsigned int *staticThreadgroupMemoryLength);

// copy buffer
int  hc_mtlMemcpyDtoD                       (void *hashcat_ctx, void *device_param_ptr, mtl_command_queue command_queue, mtl_mem_t mem_dst, size_t mem_dst_off, mtl_mem_t mem_src, size_t mem_src_off, size_t buf_size);
// write
int  hc_mtlMemcpyHtoD                       (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, mtl_command_queue command_queue, mtl_mem_t mem_dst, size_t mem_dst_off, const void *mem_src, size_t buf_size);
// read
int  hc_mtlMemcpyDtoH                       (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, mtl_command_queue command_queue, void *mem_dst, mtl_mem_t mem_src, size_t mem_src_off, size_t buf_size);

int  hc_mtlReleaseMemObject                 (void *hashcat_ctx, mtl_mem_t *metal_buffer);
int  hc_mtlReleaseFunction                  (void *hashcat_ctx, mtl_function *metal_function);
int  hc_mtlReleaseLibrary                   (void *hashcat_ctx, mtl_function *metal_library);
int  hc_mtlReleaseCommandQueue              (void *hashcat_ctx, mtl_command_queue *command_queue);
int  hc_mtlReleaseDevice                    (void *hashcat_ctx, mtl_device_id *metal_device);

int  hc_mtlCreateLibraryWithSource          (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, const char *kernel_sources, const char *build_options_buf, const char *include_path, mtl_library *metal_library);
int  hc_mtlCreateLibraryWithFile            (void *hashcat_ctx, mtl_device_id metal_device, const char *cached_file, mtl_library *metal_library);

int  hc_mtlEncodeComputeCommand_pre         (void *hashcat_ctx, void *device_param_ptr, mtl_pipeline metal_pipeline, mtl_command_queue metal_command_queue, mtl_command_buffer *metal_command_buffer, mtl_command_encoder *metal_command_encoder);
int  hc_mtlSetCommandEncoderArg             (void *hashcat_ctx, void *device_param_ptr, mtl_command_encoder metal_command_encoder, size_t off, size_t idx, id buf, void *host_data, size_t host_data_size);

int  hc_mtlEncodeComputeCommand             (void *hashcat_ctx, void *device_param_ptr, mtl_command_encoder metal_command_encoder, mtl_command_buffer metal_command_buffer, const unsigned int work_dim, const size_t global_work_size[3], const size_t local_work_size[3], double *ms);

int  hc_mtlFinish                           (void *hashcat_ctx, void *device_param_ptr, mtl_command_queue command_queue);

#endif // __APPLE__

#endif // HC_EXT_METAL_H
