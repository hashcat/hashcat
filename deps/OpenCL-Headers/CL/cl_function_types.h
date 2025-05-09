/*
 * Copyright (c) 2023 The Khronos Group Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * OpenCL is a trademark of Apple Inc. used under license by Khronos.
 */

#ifndef OPENCL_CL_FUNCTION_TYPES_H_
#define OPENCL_CL_FUNCTION_TYPES_H_

#include <CL/cl.h>

typedef cl_int CL_API_CALL clGetPlatformIDs_t(
    cl_uint num_entries,
    cl_platform_id* platforms,
    cl_uint* num_platforms);

typedef clGetPlatformIDs_t *
clGetPlatformIDs_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetPlatformInfo_t(
    cl_platform_id platform,
    cl_platform_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetPlatformInfo_t *
clGetPlatformInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetDeviceIDs_t(
    cl_platform_id platform,
    cl_device_type device_type,
    cl_uint num_entries,
    cl_device_id* devices,
    cl_uint* num_devices);

typedef clGetDeviceIDs_t *
clGetDeviceIDs_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetDeviceInfo_t(
    cl_device_id device,
    cl_device_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetDeviceInfo_t *
clGetDeviceInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_context CL_API_CALL clCreateContext_t(
    const cl_context_properties* properties,
    cl_uint num_devices,
    const cl_device_id* devices,
    void (CL_CALLBACK* pfn_notify)(const char* errinfo, const void* private_info, size_t cb, void* user_data),
    void* user_data,
    cl_int* errcode_ret);

typedef clCreateContext_t *
clCreateContext_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_context CL_API_CALL clCreateContextFromType_t(
    const cl_context_properties* properties,
    cl_device_type device_type,
    void (CL_CALLBACK* pfn_notify)(const char* errinfo, const void* private_info, size_t cb, void* user_data),
    void* user_data,
    cl_int* errcode_ret);

typedef clCreateContextFromType_t *
clCreateContextFromType_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clRetainContext_t(
    cl_context context);

typedef clRetainContext_t *
clRetainContext_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clReleaseContext_t(
    cl_context context);

typedef clReleaseContext_t *
clReleaseContext_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetContextInfo_t(
    cl_context context,
    cl_context_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetContextInfo_t *
clGetContextInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clRetainCommandQueue_t(
    cl_command_queue command_queue);

typedef clRetainCommandQueue_t *
clRetainCommandQueue_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clReleaseCommandQueue_t(
    cl_command_queue command_queue);

typedef clReleaseCommandQueue_t *
clReleaseCommandQueue_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetCommandQueueInfo_t(
    cl_command_queue command_queue,
    cl_command_queue_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetCommandQueueInfo_t *
clGetCommandQueueInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_mem CL_API_CALL clCreateBuffer_t(
    cl_context context,
    cl_mem_flags flags,
    size_t size,
    void* host_ptr,
    cl_int* errcode_ret);

typedef clCreateBuffer_t *
clCreateBuffer_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clRetainMemObject_t(
    cl_mem memobj);

typedef clRetainMemObject_t *
clRetainMemObject_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clReleaseMemObject_t(
    cl_mem memobj);

typedef clReleaseMemObject_t *
clReleaseMemObject_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetSupportedImageFormats_t(
    cl_context context,
    cl_mem_flags flags,
    cl_mem_object_type image_type,
    cl_uint num_entries,
    cl_image_format* image_formats,
    cl_uint* num_image_formats);

typedef clGetSupportedImageFormats_t *
clGetSupportedImageFormats_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetMemObjectInfo_t(
    cl_mem memobj,
    cl_mem_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetMemObjectInfo_t *
clGetMemObjectInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetImageInfo_t(
    cl_mem image,
    cl_image_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetImageInfo_t *
clGetImageInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clRetainSampler_t(
    cl_sampler sampler);

typedef clRetainSampler_t *
clRetainSampler_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clReleaseSampler_t(
    cl_sampler sampler);

typedef clReleaseSampler_t *
clReleaseSampler_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetSamplerInfo_t(
    cl_sampler sampler,
    cl_sampler_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetSamplerInfo_t *
clGetSamplerInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_program CL_API_CALL clCreateProgramWithSource_t(
    cl_context context,
    cl_uint count,
    const char** strings,
    const size_t* lengths,
    cl_int* errcode_ret);

typedef clCreateProgramWithSource_t *
clCreateProgramWithSource_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_program CL_API_CALL clCreateProgramWithBinary_t(
    cl_context context,
    cl_uint num_devices,
    const cl_device_id* device_list,
    const size_t* lengths,
    const unsigned char** binaries,
    cl_int* binary_status,
    cl_int* errcode_ret);

typedef clCreateProgramWithBinary_t *
clCreateProgramWithBinary_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clRetainProgram_t(
    cl_program program);

typedef clRetainProgram_t *
clRetainProgram_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clReleaseProgram_t(
    cl_program program);

typedef clReleaseProgram_t *
clReleaseProgram_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clBuildProgram_t(
    cl_program program,
    cl_uint num_devices,
    const cl_device_id* device_list,
    const char* options,
    void (CL_CALLBACK* pfn_notify)(cl_program program, void* user_data),
    void* user_data);

typedef clBuildProgram_t *
clBuildProgram_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetProgramInfo_t(
    cl_program program,
    cl_program_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetProgramInfo_t *
clGetProgramInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetProgramBuildInfo_t(
    cl_program program,
    cl_device_id device,
    cl_program_build_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetProgramBuildInfo_t *
clGetProgramBuildInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_kernel CL_API_CALL clCreateKernel_t(
    cl_program program,
    const char* kernel_name,
    cl_int* errcode_ret);

typedef clCreateKernel_t *
clCreateKernel_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clCreateKernelsInProgram_t(
    cl_program program,
    cl_uint num_kernels,
    cl_kernel* kernels,
    cl_uint* num_kernels_ret);

typedef clCreateKernelsInProgram_t *
clCreateKernelsInProgram_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clRetainKernel_t(
    cl_kernel kernel);

typedef clRetainKernel_t *
clRetainKernel_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clReleaseKernel_t(
    cl_kernel kernel);

typedef clReleaseKernel_t *
clReleaseKernel_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clSetKernelArg_t(
    cl_kernel kernel,
    cl_uint arg_index,
    size_t arg_size,
    const void* arg_value);

typedef clSetKernelArg_t *
clSetKernelArg_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetKernelInfo_t(
    cl_kernel kernel,
    cl_kernel_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetKernelInfo_t *
clGetKernelInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetKernelWorkGroupInfo_t(
    cl_kernel kernel,
    cl_device_id device,
    cl_kernel_work_group_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetKernelWorkGroupInfo_t *
clGetKernelWorkGroupInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clWaitForEvents_t(
    cl_uint num_events,
    const cl_event* event_list);

typedef clWaitForEvents_t *
clWaitForEvents_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetEventInfo_t(
    cl_event event,
    cl_event_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetEventInfo_t *
clGetEventInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clRetainEvent_t(
    cl_event event);

typedef clRetainEvent_t *
clRetainEvent_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clReleaseEvent_t(
    cl_event event);

typedef clReleaseEvent_t *
clReleaseEvent_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clGetEventProfilingInfo_t(
    cl_event event,
    cl_profiling_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetEventProfilingInfo_t *
clGetEventProfilingInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clFlush_t(
    cl_command_queue command_queue);

typedef clFlush_t *
clFlush_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clFinish_t(
    cl_command_queue command_queue);

typedef clFinish_t *
clFinish_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueReadBuffer_t(
    cl_command_queue command_queue,
    cl_mem buffer,
    cl_bool blocking_read,
    size_t offset,
    size_t size,
    void* ptr,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueReadBuffer_t *
clEnqueueReadBuffer_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueWriteBuffer_t(
    cl_command_queue command_queue,
    cl_mem buffer,
    cl_bool blocking_write,
    size_t offset,
    size_t size,
    const void* ptr,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueWriteBuffer_t *
clEnqueueWriteBuffer_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueCopyBuffer_t(
    cl_command_queue command_queue,
    cl_mem src_buffer,
    cl_mem dst_buffer,
    size_t src_offset,
    size_t dst_offset,
    size_t size,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueCopyBuffer_t *
clEnqueueCopyBuffer_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueReadImage_t(
    cl_command_queue command_queue,
    cl_mem image,
    cl_bool blocking_read,
    const size_t* origin,
    const size_t* region,
    size_t row_pitch,
    size_t slice_pitch,
    void* ptr,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueReadImage_t *
clEnqueueReadImage_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueWriteImage_t(
    cl_command_queue command_queue,
    cl_mem image,
    cl_bool blocking_write,
    const size_t* origin,
    const size_t* region,
    size_t input_row_pitch,
    size_t input_slice_pitch,
    const void* ptr,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueWriteImage_t *
clEnqueueWriteImage_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueCopyImage_t(
    cl_command_queue command_queue,
    cl_mem src_image,
    cl_mem dst_image,
    const size_t* src_origin,
    const size_t* dst_origin,
    const size_t* region,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueCopyImage_t *
clEnqueueCopyImage_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueCopyImageToBuffer_t(
    cl_command_queue command_queue,
    cl_mem src_image,
    cl_mem dst_buffer,
    const size_t* src_origin,
    const size_t* region,
    size_t dst_offset,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueCopyImageToBuffer_t *
clEnqueueCopyImageToBuffer_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueCopyBufferToImage_t(
    cl_command_queue command_queue,
    cl_mem src_buffer,
    cl_mem dst_image,
    size_t src_offset,
    const size_t* dst_origin,
    const size_t* region,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueCopyBufferToImage_t *
clEnqueueCopyBufferToImage_fn CL_API_SUFFIX__VERSION_1_0;

typedef void* CL_API_CALL clEnqueueMapBuffer_t(
    cl_command_queue command_queue,
    cl_mem buffer,
    cl_bool blocking_map,
    cl_map_flags map_flags,
    size_t offset,
    size_t size,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event,
    cl_int* errcode_ret);

typedef clEnqueueMapBuffer_t *
clEnqueueMapBuffer_fn CL_API_SUFFIX__VERSION_1_0;

typedef void* CL_API_CALL clEnqueueMapImage_t(
    cl_command_queue command_queue,
    cl_mem image,
    cl_bool blocking_map,
    cl_map_flags map_flags,
    const size_t* origin,
    const size_t* region,
    size_t* image_row_pitch,
    size_t* image_slice_pitch,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event,
    cl_int* errcode_ret);

typedef clEnqueueMapImage_t *
clEnqueueMapImage_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueUnmapMemObject_t(
    cl_command_queue command_queue,
    cl_mem memobj,
    void* mapped_ptr,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueUnmapMemObject_t *
clEnqueueUnmapMemObject_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueNDRangeKernel_t(
    cl_command_queue command_queue,
    cl_kernel kernel,
    cl_uint work_dim,
    const size_t* global_work_offset,
    const size_t* global_work_size,
    const size_t* local_work_size,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueNDRangeKernel_t *
clEnqueueNDRangeKernel_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clEnqueueNativeKernel_t(
    cl_command_queue command_queue,
    void (CL_CALLBACK* user_func)(void*),
    void* args,
    size_t cb_args,
    cl_uint num_mem_objects,
    const cl_mem* mem_list,
    const void** args_mem_loc,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueNativeKernel_t *
clEnqueueNativeKernel_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL clSetCommandQueueProperty_t(
    cl_command_queue command_queue,
    cl_command_queue_properties properties,
    cl_bool enable,
    cl_command_queue_properties* old_properties);

typedef clSetCommandQueueProperty_t *
clSetCommandQueueProperty_fn CL_API_SUFFIX__VERSION_1_0_DEPRECATED;

typedef cl_mem CL_API_CALL clCreateImage2D_t(
    cl_context context,
    cl_mem_flags flags,
    const cl_image_format* image_format,
    size_t image_width,
    size_t image_height,
    size_t image_row_pitch,
    void* host_ptr,
    cl_int* errcode_ret);

typedef clCreateImage2D_t *
clCreateImage2D_fn CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

typedef cl_mem CL_API_CALL clCreateImage3D_t(
    cl_context context,
    cl_mem_flags flags,
    const cl_image_format* image_format,
    size_t image_width,
    size_t image_height,
    size_t image_depth,
    size_t image_row_pitch,
    size_t image_slice_pitch,
    void* host_ptr,
    cl_int* errcode_ret);

typedef clCreateImage3D_t *
clCreateImage3D_fn CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

typedef cl_int CL_API_CALL clEnqueueMarker_t(
    cl_command_queue command_queue,
    cl_event* event);

typedef clEnqueueMarker_t *
clEnqueueMarker_fn CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

typedef cl_int CL_API_CALL clEnqueueWaitForEvents_t(
    cl_command_queue command_queue,
    cl_uint num_events,
    const cl_event* event_list);

typedef clEnqueueWaitForEvents_t *
clEnqueueWaitForEvents_fn CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

typedef cl_int CL_API_CALL clEnqueueBarrier_t(
    cl_command_queue command_queue);

typedef clEnqueueBarrier_t *
clEnqueueBarrier_fn CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

typedef cl_int CL_API_CALL clUnloadCompiler_t(
    void );

typedef clUnloadCompiler_t *
clUnloadCompiler_fn CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

typedef void* CL_API_CALL clGetExtensionFunctionAddress_t(
    const char* func_name);

typedef clGetExtensionFunctionAddress_t *
clGetExtensionFunctionAddress_fn CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

typedef cl_command_queue CL_API_CALL clCreateCommandQueue_t(
    cl_context context,
    cl_device_id device,
    cl_command_queue_properties properties,
    cl_int* errcode_ret);

typedef clCreateCommandQueue_t *
clCreateCommandQueue_fn CL_API_SUFFIX__VERSION_1_2_DEPRECATED;

typedef cl_sampler CL_API_CALL clCreateSampler_t(
    cl_context context,
    cl_bool normalized_coords,
    cl_addressing_mode addressing_mode,
    cl_filter_mode filter_mode,
    cl_int* errcode_ret);

typedef clCreateSampler_t *
clCreateSampler_fn CL_API_SUFFIX__VERSION_1_2_DEPRECATED;

typedef cl_int CL_API_CALL clEnqueueTask_t(
    cl_command_queue command_queue,
    cl_kernel kernel,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueTask_t *
clEnqueueTask_fn CL_API_SUFFIX__VERSION_1_2_DEPRECATED;

#ifdef CL_VERSION_1_1

typedef cl_mem CL_API_CALL clCreateSubBuffer_t(
    cl_mem buffer,
    cl_mem_flags flags,
    cl_buffer_create_type buffer_create_type,
    const void* buffer_create_info,
    cl_int* errcode_ret);

typedef clCreateSubBuffer_t *
clCreateSubBuffer_fn CL_API_SUFFIX__VERSION_1_1;

typedef cl_int CL_API_CALL clSetMemObjectDestructorCallback_t(
    cl_mem memobj,
    void (CL_CALLBACK* pfn_notify)(cl_mem memobj, void* user_data),
    void* user_data);

typedef clSetMemObjectDestructorCallback_t *
clSetMemObjectDestructorCallback_fn CL_API_SUFFIX__VERSION_1_1;

typedef cl_event CL_API_CALL clCreateUserEvent_t(
    cl_context context,
    cl_int* errcode_ret);

typedef clCreateUserEvent_t *
clCreateUserEvent_fn CL_API_SUFFIX__VERSION_1_1;

typedef cl_int CL_API_CALL clSetUserEventStatus_t(
    cl_event event,
    cl_int execution_status);

typedef clSetUserEventStatus_t *
clSetUserEventStatus_fn CL_API_SUFFIX__VERSION_1_1;

typedef cl_int CL_API_CALL clSetEventCallback_t(
    cl_event event,
    cl_int command_exec_callback_type,
    void (CL_CALLBACK* pfn_notify)(cl_event event, cl_int event_command_status, void *user_data),
    void* user_data);

typedef clSetEventCallback_t *
clSetEventCallback_fn CL_API_SUFFIX__VERSION_1_1;

typedef cl_int CL_API_CALL clEnqueueReadBufferRect_t(
    cl_command_queue command_queue,
    cl_mem buffer,
    cl_bool blocking_read,
    const size_t* buffer_origin,
    const size_t* host_origin,
    const size_t* region,
    size_t buffer_row_pitch,
    size_t buffer_slice_pitch,
    size_t host_row_pitch,
    size_t host_slice_pitch,
    void* ptr,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueReadBufferRect_t *
clEnqueueReadBufferRect_fn CL_API_SUFFIX__VERSION_1_1;

typedef cl_int CL_API_CALL clEnqueueWriteBufferRect_t(
    cl_command_queue command_queue,
    cl_mem buffer,
    cl_bool blocking_write,
    const size_t* buffer_origin,
    const size_t* host_origin,
    const size_t* region,
    size_t buffer_row_pitch,
    size_t buffer_slice_pitch,
    size_t host_row_pitch,
    size_t host_slice_pitch,
    const void* ptr,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueWriteBufferRect_t *
clEnqueueWriteBufferRect_fn CL_API_SUFFIX__VERSION_1_1;

typedef cl_int CL_API_CALL clEnqueueCopyBufferRect_t(
    cl_command_queue command_queue,
    cl_mem src_buffer,
    cl_mem dst_buffer,
    const size_t* src_origin,
    const size_t* dst_origin,
    const size_t* region,
    size_t src_row_pitch,
    size_t src_slice_pitch,
    size_t dst_row_pitch,
    size_t dst_slice_pitch,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueCopyBufferRect_t *
clEnqueueCopyBufferRect_fn CL_API_SUFFIX__VERSION_1_1;

#endif /* CL_VERSION_1_1 */

#ifdef CL_VERSION_1_2

typedef cl_int CL_API_CALL clCreateSubDevices_t(
    cl_device_id in_device,
    const cl_device_partition_property* properties,
    cl_uint num_devices,
    cl_device_id* out_devices,
    cl_uint* num_devices_ret);

typedef clCreateSubDevices_t *
clCreateSubDevices_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_int CL_API_CALL clRetainDevice_t(
    cl_device_id device);

typedef clRetainDevice_t *
clRetainDevice_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_int CL_API_CALL clReleaseDevice_t(
    cl_device_id device);

typedef clReleaseDevice_t *
clReleaseDevice_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_mem CL_API_CALL clCreateImage_t(
    cl_context context,
    cl_mem_flags flags,
    const cl_image_format* image_format,
    const cl_image_desc* image_desc,
    void* host_ptr,
    cl_int* errcode_ret);

typedef clCreateImage_t *
clCreateImage_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_program CL_API_CALL clCreateProgramWithBuiltInKernels_t(
    cl_context context,
    cl_uint num_devices,
    const cl_device_id* device_list,
    const char* kernel_names,
    cl_int* errcode_ret);

typedef clCreateProgramWithBuiltInKernels_t *
clCreateProgramWithBuiltInKernels_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_int CL_API_CALL clCompileProgram_t(
    cl_program program,
    cl_uint num_devices,
    const cl_device_id* device_list,
    const char* options,
    cl_uint num_input_headers,
    const cl_program* input_headers,
    const char** header_include_names,
    void (CL_CALLBACK* pfn_notify)(cl_program program, void* user_data),
    void* user_data);

typedef clCompileProgram_t *
clCompileProgram_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_program CL_API_CALL clLinkProgram_t(
    cl_context context,
    cl_uint num_devices,
    const cl_device_id* device_list,
    const char* options,
    cl_uint num_input_programs,
    const cl_program* input_programs,
    void (CL_CALLBACK* pfn_notify)(cl_program program, void* user_data),
    void* user_data,
    cl_int* errcode_ret);

typedef clLinkProgram_t *
clLinkProgram_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_int CL_API_CALL clUnloadPlatformCompiler_t(
    cl_platform_id platform);

typedef clUnloadPlatformCompiler_t *
clUnloadPlatformCompiler_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_int CL_API_CALL clGetKernelArgInfo_t(
    cl_kernel kernel,
    cl_uint arg_index,
    cl_kernel_arg_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetKernelArgInfo_t *
clGetKernelArgInfo_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_int CL_API_CALL clEnqueueFillBuffer_t(
    cl_command_queue command_queue,
    cl_mem buffer,
    const void* pattern,
    size_t pattern_size,
    size_t offset,
    size_t size,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueFillBuffer_t *
clEnqueueFillBuffer_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_int CL_API_CALL clEnqueueFillImage_t(
    cl_command_queue command_queue,
    cl_mem image,
    const void* fill_color,
    const size_t* origin,
    const size_t* region,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueFillImage_t *
clEnqueueFillImage_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_int CL_API_CALL clEnqueueMigrateMemObjects_t(
    cl_command_queue command_queue,
    cl_uint num_mem_objects,
    const cl_mem* mem_objects,
    cl_mem_migration_flags flags,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueMigrateMemObjects_t *
clEnqueueMigrateMemObjects_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_int CL_API_CALL clEnqueueMarkerWithWaitList_t(
    cl_command_queue command_queue,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueMarkerWithWaitList_t *
clEnqueueMarkerWithWaitList_fn CL_API_SUFFIX__VERSION_1_2;

typedef cl_int CL_API_CALL clEnqueueBarrierWithWaitList_t(
    cl_command_queue command_queue,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueBarrierWithWaitList_t *
clEnqueueBarrierWithWaitList_fn CL_API_SUFFIX__VERSION_1_2;

typedef void* CL_API_CALL clGetExtensionFunctionAddressForPlatform_t(
    cl_platform_id platform,
    const char* func_name);

typedef clGetExtensionFunctionAddressForPlatform_t *
clGetExtensionFunctionAddressForPlatform_fn CL_API_SUFFIX__VERSION_1_2;

#endif /* CL_VERSION_1_2 */

#ifdef CL_VERSION_2_0

typedef cl_command_queue CL_API_CALL clCreateCommandQueueWithProperties_t(
    cl_context context,
    cl_device_id device,
    const cl_queue_properties* properties,
    cl_int* errcode_ret);

typedef clCreateCommandQueueWithProperties_t *
clCreateCommandQueueWithProperties_fn CL_API_SUFFIX__VERSION_2_0;

typedef cl_mem CL_API_CALL clCreatePipe_t(
    cl_context context,
    cl_mem_flags flags,
    cl_uint pipe_packet_size,
    cl_uint pipe_max_packets,
    const cl_pipe_properties* properties,
    cl_int* errcode_ret);

typedef clCreatePipe_t *
clCreatePipe_fn CL_API_SUFFIX__VERSION_2_0;

typedef cl_int CL_API_CALL clGetPipeInfo_t(
    cl_mem pipe,
    cl_pipe_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetPipeInfo_t *
clGetPipeInfo_fn CL_API_SUFFIX__VERSION_2_0;

typedef void* CL_API_CALL clSVMAlloc_t(
    cl_context context,
    cl_svm_mem_flags flags,
    size_t size,
    cl_uint alignment);

typedef clSVMAlloc_t *
clSVMAlloc_fn CL_API_SUFFIX__VERSION_2_0;

typedef void CL_API_CALL clSVMFree_t(
    cl_context context,
    void* svm_pointer);

typedef clSVMFree_t *
clSVMFree_fn CL_API_SUFFIX__VERSION_2_0;

typedef cl_sampler CL_API_CALL clCreateSamplerWithProperties_t(
    cl_context context,
    const cl_sampler_properties* sampler_properties,
    cl_int* errcode_ret);

typedef clCreateSamplerWithProperties_t *
clCreateSamplerWithProperties_fn CL_API_SUFFIX__VERSION_2_0;

typedef cl_int CL_API_CALL clSetKernelArgSVMPointer_t(
    cl_kernel kernel,
    cl_uint arg_index,
    const void* arg_value);

typedef clSetKernelArgSVMPointer_t *
clSetKernelArgSVMPointer_fn CL_API_SUFFIX__VERSION_2_0;

typedef cl_int CL_API_CALL clSetKernelExecInfo_t(
    cl_kernel kernel,
    cl_kernel_exec_info param_name,
    size_t param_value_size,
    const void* param_value);

typedef clSetKernelExecInfo_t *
clSetKernelExecInfo_fn CL_API_SUFFIX__VERSION_2_0;

typedef cl_int CL_API_CALL clEnqueueSVMFree_t(
    cl_command_queue command_queue,
    cl_uint num_svm_pointers,
    void* svm_pointers[],
    void (CL_CALLBACK* pfn_free_func)(cl_command_queue queue, cl_uint num_svm_pointers, void* svm_pointers[], void* user_data),
    void* user_data,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueSVMFree_t *
clEnqueueSVMFree_fn CL_API_SUFFIX__VERSION_2_0;

typedef cl_int CL_API_CALL clEnqueueSVMMemcpy_t(
    cl_command_queue command_queue,
    cl_bool blocking_copy,
    void* dst_ptr,
    const void* src_ptr,
    size_t size,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueSVMMemcpy_t *
clEnqueueSVMMemcpy_fn CL_API_SUFFIX__VERSION_2_0;

typedef cl_int CL_API_CALL clEnqueueSVMMemFill_t(
    cl_command_queue command_queue,
    void* svm_ptr,
    const void* pattern,
    size_t pattern_size,
    size_t size,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueSVMMemFill_t *
clEnqueueSVMMemFill_fn CL_API_SUFFIX__VERSION_2_0;

typedef cl_int CL_API_CALL clEnqueueSVMMap_t(
    cl_command_queue command_queue,
    cl_bool blocking_map,
    cl_map_flags flags,
    void* svm_ptr,
    size_t size,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueSVMMap_t *
clEnqueueSVMMap_fn CL_API_SUFFIX__VERSION_2_0;

typedef cl_int CL_API_CALL clEnqueueSVMUnmap_t(
    cl_command_queue command_queue,
    void* svm_ptr,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueSVMUnmap_t *
clEnqueueSVMUnmap_fn CL_API_SUFFIX__VERSION_2_0;

#endif /* CL_VERSION_2_0 */

#ifdef CL_VERSION_2_1

typedef cl_int CL_API_CALL clSetDefaultDeviceCommandQueue_t(
    cl_context context,
    cl_device_id device,
    cl_command_queue command_queue);

typedef clSetDefaultDeviceCommandQueue_t *
clSetDefaultDeviceCommandQueue_fn CL_API_SUFFIX__VERSION_2_1;

typedef cl_int CL_API_CALL clGetDeviceAndHostTimer_t(
    cl_device_id device,
    cl_ulong* device_timestamp,
    cl_ulong* host_timestamp);

typedef clGetDeviceAndHostTimer_t *
clGetDeviceAndHostTimer_fn CL_API_SUFFIX__VERSION_2_1;

typedef cl_int CL_API_CALL clGetHostTimer_t(
    cl_device_id device,
    cl_ulong* host_timestamp);

typedef clGetHostTimer_t *
clGetHostTimer_fn CL_API_SUFFIX__VERSION_2_1;

typedef cl_program CL_API_CALL clCreateProgramWithIL_t(
    cl_context context,
    const void* il,
    size_t length,
    cl_int* errcode_ret);

typedef clCreateProgramWithIL_t *
clCreateProgramWithIL_fn CL_API_SUFFIX__VERSION_2_1;

typedef cl_kernel CL_API_CALL clCloneKernel_t(
    cl_kernel source_kernel,
    cl_int* errcode_ret);

typedef clCloneKernel_t *
clCloneKernel_fn CL_API_SUFFIX__VERSION_2_1;

typedef cl_int CL_API_CALL clGetKernelSubGroupInfo_t(
    cl_kernel kernel,
    cl_device_id device,
    cl_kernel_sub_group_info param_name,
    size_t input_value_size,
    const void* input_value,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetKernelSubGroupInfo_t *
clGetKernelSubGroupInfo_fn CL_API_SUFFIX__VERSION_2_1;

typedef cl_int CL_API_CALL clEnqueueSVMMigrateMem_t(
    cl_command_queue command_queue,
    cl_uint num_svm_pointers,
    const void** svm_pointers,
    const size_t* sizes,
    cl_mem_migration_flags flags,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueSVMMigrateMem_t *
clEnqueueSVMMigrateMem_fn CL_API_SUFFIX__VERSION_2_1;

#endif /* CL_VERSION_2_1 */

#ifdef CL_VERSION_2_2

typedef cl_int CL_API_CALL clSetProgramSpecializationConstant_t(
    cl_program program,
    cl_uint spec_id,
    size_t spec_size,
    const void* spec_value);

typedef clSetProgramSpecializationConstant_t *
clSetProgramSpecializationConstant_fn CL_API_SUFFIX__VERSION_2_2;

typedef cl_int CL_API_CALL clSetProgramReleaseCallback_t(
    cl_program program,
    void (CL_CALLBACK* pfn_notify)(cl_program program, void* user_data),
    void* user_data);

typedef clSetProgramReleaseCallback_t *
clSetProgramReleaseCallback_fn CL_API_SUFFIX__VERSION_2_2_DEPRECATED;

#endif /* CL_VERSION_2_2 */

#ifdef CL_VERSION_3_0

typedef cl_int CL_API_CALL clSetContextDestructorCallback_t(
    cl_context context,
    void (CL_CALLBACK* pfn_notify)(cl_context context, void* user_data),
    void* user_data);

typedef clSetContextDestructorCallback_t *
clSetContextDestructorCallback_fn CL_API_SUFFIX__VERSION_3_0;

typedef cl_mem CL_API_CALL clCreateBufferWithProperties_t(
    cl_context context,
    const cl_mem_properties* properties,
    cl_mem_flags flags,
    size_t size,
    void* host_ptr,
    cl_int* errcode_ret);

typedef clCreateBufferWithProperties_t *
clCreateBufferWithProperties_fn CL_API_SUFFIX__VERSION_3_0;

typedef cl_mem CL_API_CALL clCreateImageWithProperties_t(
    cl_context context,
    const cl_mem_properties* properties,
    cl_mem_flags flags,
    const cl_image_format* image_format,
    const cl_image_desc* image_desc,
    void* host_ptr,
    cl_int* errcode_ret);

typedef clCreateImageWithProperties_t *
clCreateImageWithProperties_fn CL_API_SUFFIX__VERSION_3_0;

#endif /* CL_VERSION_3_0 */

#endif /* OPENCL_CL_FUNCTION_TYPES_H_ */
