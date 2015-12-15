/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef EXT_OPENCL_H
#define EXT_OPENCL_H

#include <common.h>

#ifdef OSX
#include <OpenCL/cl.h>
#endif

#ifdef WIN
#include <CL/cl.h>
// #include <CL/cl_ext.h> // used for CL_DEVICE_TOPOLOGY_AMD but broken for dual GPU
#endif

#ifdef LINUX
#include <CL/cl.h>
// #include <CL/cl_ext.h> // used for CL_DEVICE_TOPOLOGY_AMD but broken for dual GPU
#endif

void hc_clBuildProgram (cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data);
cl_mem hc_clCreateBuffer (cl_context context, cl_mem_flags flags, size_t size, void *host_ptr);
cl_command_queue hc_clCreateCommandQueue (cl_context context, cl_device_id device, cl_command_queue_properties properties);
//cl_command_queue hc_clCreateCommandQueueWithProperties (cl_context context, cl_device_id device, const cl_queue_properties *properties);
cl_context hc_clCreateContext (cl_context_properties *properties, cl_uint num_devices, const cl_device_id *devices, void (CL_CALLBACK *pfn_notify) (const char *, const void *, size_t, void *), void *user_data);
cl_kernel hc_clCreateKernel (cl_program program, const char *kernel_name);
cl_program hc_clCreateProgramWithSource (cl_context context, cl_uint count, const char **strings, const size_t *lengths);
cl_program hc_clCreateProgramWithBinary (cl_context context, cl_uint num_devices, const cl_device_id *device_list, const size_t *lengths, const unsigned char **binaries, cl_int *binary_status);
void hc_clEnqueueNDRangeKernel (cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clEnqueueReadBuffer (cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t cb, void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clEnqueueWriteBuffer (cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t cb, const void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clEnqueueCopyBuffer (cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clFlush (cl_command_queue command_queue);
void hc_clFinish (cl_command_queue command_queue);
void hc_clGetDeviceIDs (cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id *devices, cl_uint *num_devices);
void hc_clGetDeviceInfo (cl_device_id device, cl_device_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
void hc_clGetPlatformIDs (cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms);
void hc_clGetPlatformInfo (cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
void hc_clReleaseCommandQueue (cl_command_queue command_queue);
void hc_clReleaseContext (cl_context context);
void hc_clReleaseKernel (cl_kernel kernel);
void hc_clReleaseMemObject (cl_mem mem);
void hc_clReleaseProgram (cl_program program);
void hc_clSetKernelArg (cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void *arg_value);
void *hc_clEnqueueMapBuffer (cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clEnqueueUnmapMemObject (cl_command_queue command_queue, cl_mem memobj, void *mapped_ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clEnqueueFillBuffer (cl_command_queue command_queue, cl_mem buffer, const void *pattern, size_t pattern_size, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);

#endif
