/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_METAL_H
#define _EXT_METAL_H

#if defined (__APPLE__)

#include <objc/runtime.h>
#include <CoreFoundation/CoreFoundation.h>

#define mtl_device_id id
#define mtl_command_queue id
#define mtl_function id
#define mtl_pipeline id
#define mtl_mem id
#define mtl_library id
#define mtl_command_buffer id
#define mtl_command_encoder id
#define mtl_blit_command_encoder id
#define mtl_compute_command_encoder id

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
  MTL_DEVICE_ATTRIBUTE_TOTAL_CONSTANT_MEMORY,
  MTL_DEVICE_ATTRIBUTE_MAX_TRANSFER_RATE,
  MTL_DEVICE_ATTRIBUTE_HEADLESS,
  MTL_DEVICE_ATTRIBUTE_LOW_POWER,
  MTL_DEVICE_ATTRIBUTE_REMOVABLE,
  MTL_DEVICE_ATTRIBUTE_REGISTRY_ID,
  MTL_DEVICE_ATTRIBUTE_PHYSICAL_LOCATION,
  MTL_DEVICE_ATTRIBUTE_LOCATION_NUMBER,

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

int  mtl_init                       (void *hashcat_ctx);
void mtl_close                      (void *hashcat_ctx);

int  hc_mtlRuntimeGetVersionString  (void *hashcat_ctx, char *runtimeVersion_str, size_t *size);

int  hc_mtlDeviceGetCount           (void *hashcat_ctx, int *count);
int  hc_mtlDeviceGet                (void *hashcat_ctx, mtl_device_id *metal_device, int ordinal);
int  hc_mtlDeviceGetName            (void *hashcat_ctx, char *name, size_t len, mtl_device_id metal_device);
int  hc_mtlDeviceGetAttribute       (void *hashcat_ctx, int *pi, metalDeviceAttribute_t attrib, mtl_device_id metal_device);
int  hc_mtlDeviceTotalMem           (void *hashcat_ctx, size_t *bytes, mtl_device_id metal_device);
int  hc_mtlDeviceMaxMemAlloc        (void *hashcat_ctx, size_t *bytes, mtl_device_id metal_device);
int  hc_mtlMemGetInfo               (void *hashcat_ctx, size_t *mem_free, size_t *mem_total);

int  hc_mtlCreateCommandQueue       (void *hashcat_ctx, mtl_device_id metal_device, mtl_command_queue *command_queue);
int  hc_mtlCreateBuffer             (void *hashcat_ctx, mtl_device_id metal_device, size_t size, void *ptr, mtl_mem *metal_buffer);

int  hc_mtlCreateKernel             (void *hashcat_ctx, mtl_device_id metal_device, mtl_library metal_library, const char *func_name, mtl_function *metal_function, mtl_pipeline *metal_pipeline);

int  hc_mtlGetMaxTotalThreadsPerThreadgroup (void *hashcat_ctx, mtl_pipeline metal_pipeline, unsigned int *maxTotalThreadsPerThreadgroup);
int  hc_mtlGetThreadExecutionWidth  (void *hashcat_ctx, mtl_pipeline metal_pipeline, unsigned int *threadExecutionWidth);

// copy buffer
int  hc_mtlMemcpyDtoD               (void *hashcat_ctx, mtl_command_queue command_queue, mtl_mem buf_dst, size_t buf_dst_off, mtl_mem buf_src, size_t buf_src_off, size_t buf_size);
// write
int  hc_mtlMemcpyHtoD               (void *hashcat_ctx, mtl_command_queue command_queue, mtl_mem buf_dst, size_t buf_dst_off, const void *buf_src, size_t buf_size);
// read
int  hc_mtlMemcpyDtoH               (void *hashcat_ctx, mtl_command_queue command_queue, void *buf_dst, mtl_mem buf_src, size_t buf_src_off, size_t buf_size);

int  hc_mtlReleaseMemObject         (void *hashcat_ctx, mtl_mem metal_buffer);
int  hc_mtlReleaseFunction          (void *hashcat_ctx, mtl_function metal_function);
int  hc_mtlReleaseLibrary           (void *hashcat_ctx, mtl_function metal_library);
int  hc_mtlReleaseCommandQueue      (void *hashcat_ctx, mtl_command_queue command_queue);
int  hc_mtlReleaseDevice            (void *hashcat_ctx, mtl_device_id metal_device);

int  hc_mtlCreateLibraryWithSource  (void *hashcat_ctx, mtl_device_id metal_device, const char *kernel_sources, const char *build_options_buf, const char *include_path, mtl_library *metal_library);
int  hc_mtlCreateLibraryWithFile    (void *hashcat_ctx, mtl_device_id metal_device, const char *cached_file, mtl_library *metal_library);

int  hc_mtlEncodeComputeCommand_pre (void *hashcat_ctx, mtl_pipeline metal_pipeline, mtl_command_queue metal_command_queue, mtl_command_buffer *metal_command_buffer, mtl_command_encoder *metal_command_encoder);
int  hc_mtlSetCommandEncoderArg     (void *hashcat_ctx, mtl_command_encoder metal_command_encoder, size_t off, size_t idx, mtl_mem buf, void *host_data, size_t host_data_size);

int  hc_mtlEncodeComputeCommand     (void *hashcat_ctx, mtl_command_encoder metal_command_encoder, mtl_command_buffer metal_command_buffer, size_t global_work_size, size_t local_work_size, double *ms);

#endif // __APPLE__

#endif // _EXT_METAL_H
