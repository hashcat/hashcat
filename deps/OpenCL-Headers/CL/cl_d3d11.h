/*******************************************************************************
 * Copyright (c) 2008-2023 The Khronos Group Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

#ifndef OPENCL_CL_D3D11_H_
#define OPENCL_CL_D3D11_H_

/*
** This header is generated from the Khronos OpenCL XML API Registry.
*/

#if defined(_MSC_VER)
#if _MSC_VER >=1500
#pragma warning( push )
#pragma warning( disable : 4201 )
#pragma warning( disable : 5105 )
#endif
#endif
#include <d3d11.h>
#if defined(_MSC_VER)
#if _MSC_VER >=1500
#pragma warning( pop )
#endif
#endif

#include <CL/cl.h>

/* CL_NO_PROTOTYPES implies CL_NO_EXTENSION_PROTOTYPES: */
#if defined(CL_NO_PROTOTYPES) && !defined(CL_NO_EXTENSION_PROTOTYPES)
#define CL_NO_EXTENSION_PROTOTYPES
#endif

/* CL_NO_EXTENSION_PROTOTYPES implies
   CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES and
   CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES: */
#if defined(CL_NO_EXTENSION_PROTOTYPES) && \
    !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES)
#define CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES
#endif
#if defined(CL_NO_EXTENSION_PROTOTYPES) && \
    !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES)
#define CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES
#endif

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************
* cl_khr_d3d11_sharing
***************************************************************/
#define cl_khr_d3d11_sharing 1
#define CL_KHR_D3D11_SHARING_EXTENSION_NAME \
    "cl_khr_d3d11_sharing"

typedef cl_uint             cl_d3d11_device_source_khr;
typedef cl_uint             cl_d3d11_device_set_khr;

/* Error codes */
#define CL_INVALID_D3D11_DEVICE_KHR                         -1006
#define CL_INVALID_D3D11_RESOURCE_KHR                       -1007
#define CL_D3D11_RESOURCE_ALREADY_ACQUIRED_KHR              -1008
#define CL_D3D11_RESOURCE_NOT_ACQUIRED_KHR                  -1009

/* cl_d3d11_device_source_khr */
#define CL_D3D11_DEVICE_KHR                                 0x4019
#define CL_D3D11_DXGI_ADAPTER_KHR                           0x401A

/* cl_d3d11_device_set_khr */
#define CL_PREFERRED_DEVICES_FOR_D3D11_KHR                  0x401B
#define CL_ALL_DEVICES_FOR_D3D11_KHR                        0x401C

/* cl_context_info */
#define CL_CONTEXT_D3D11_DEVICE_KHR                         0x401D
#define CL_CONTEXT_D3D11_PREFER_SHARED_RESOURCES_KHR        0x402D

/* cl_mem_info */
#define CL_MEM_D3D11_RESOURCE_KHR                           0x401E

/* cl_image_info */
#define CL_IMAGE_D3D11_SUBRESOURCE_KHR                      0x401F

/* cl_command_type */
#define CL_COMMAND_ACQUIRE_D3D11_OBJECTS_KHR                0x4020
#define CL_COMMAND_RELEASE_D3D11_OBJECTS_KHR                0x4021


typedef cl_int (CL_API_CALL *
clGetDeviceIDsFromD3D11KHR_fn)(
    cl_platform_id platform,
    cl_d3d11_device_source_khr d3d_device_source,
    void* d3d_object,
    cl_d3d11_device_set_khr d3d_device_set,
    cl_uint num_entries,
    cl_device_id* devices,
    cl_uint* num_devices) CL_API_SUFFIX__VERSION_1_2;

typedef cl_mem (CL_API_CALL *
clCreateFromD3D11BufferKHR_fn)(
    cl_context context,
    cl_mem_flags flags,
    ID3D11Buffer* resource,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_2;

typedef cl_mem (CL_API_CALL *
clCreateFromD3D11Texture2DKHR_fn)(
    cl_context context,
    cl_mem_flags flags,
    ID3D11Texture2D* resource,
    UINT subresource,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_2;

typedef cl_mem (CL_API_CALL *
clCreateFromD3D11Texture3DKHR_fn)(
    cl_context context,
    cl_mem_flags flags,
    ID3D11Texture3D* resource,
    UINT subresource,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_2;

typedef cl_int (CL_API_CALL *
clEnqueueAcquireD3D11ObjectsKHR_fn)(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event) CL_API_SUFFIX__VERSION_1_2;

typedef cl_int (CL_API_CALL *
clEnqueueReleaseD3D11ObjectsKHR_fn)(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event) CL_API_SUFFIX__VERSION_1_2;

#if !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_int CL_API_CALL
clGetDeviceIDsFromD3D11KHR(
    cl_platform_id platform,
    cl_d3d11_device_source_khr d3d_device_source,
    void* d3d_object,
    cl_d3d11_device_set_khr d3d_device_set,
    cl_uint num_entries,
    cl_device_id* devices,
    cl_uint* num_devices) CL_API_SUFFIX__VERSION_1_2;

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateFromD3D11BufferKHR(
    cl_context context,
    cl_mem_flags flags,
    ID3D11Buffer* resource,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_2;

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateFromD3D11Texture2DKHR(
    cl_context context,
    cl_mem_flags flags,
    ID3D11Texture2D* resource,
    UINT subresource,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_2;

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateFromD3D11Texture3DKHR(
    cl_context context,
    cl_mem_flags flags,
    ID3D11Texture3D* resource,
    UINT subresource,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_2;

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueAcquireD3D11ObjectsKHR(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event) CL_API_SUFFIX__VERSION_1_2;

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueReleaseD3D11ObjectsKHR(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event) CL_API_SUFFIX__VERSION_1_2;

#endif /* !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

/***************************************************************
* cl_intel_sharing_format_query_d3d11
***************************************************************/
#define cl_intel_sharing_format_query_d3d11 1
#define CL_INTEL_SHARING_FORMAT_QUERY_D3D11_EXTENSION_NAME \
    "cl_intel_sharing_format_query_d3d11"

/* when cl_khr_d3d11_sharing is supported */

typedef cl_int (CL_API_CALL *
clGetSupportedD3D11TextureFormatsINTEL_fn)(
    cl_context context,
    cl_mem_flags flags,
    cl_mem_object_type image_type,
    cl_uint plane,
    cl_uint num_entries,
    DXGI_FORMAT* d3d11_formats,
    cl_uint* num_texture_formats) ;

#if !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_int CL_API_CALL
clGetSupportedD3D11TextureFormatsINTEL(
    cl_context context,
    cl_mem_flags flags,
    cl_mem_object_type image_type,
    cl_uint plane,
    cl_uint num_entries,
    DXGI_FORMAT* d3d11_formats,
    cl_uint* num_texture_formats) ;

#endif /* !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

#ifdef __cplusplus
}
#endif

#endif /* OPENCL_CL_D3D11_H_ */
