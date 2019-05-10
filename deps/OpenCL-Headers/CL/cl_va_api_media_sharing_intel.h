/**********************************************************************************
 * Copyright (c) 2008-2019 The Khronos Group Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and/or associated documentation files (the
 * "Materials"), to deal in the Materials without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Materials, and to
 * permit persons to whom the Materials are furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Materials.
 *
 * MODIFICATIONS TO THIS FILE MAY MEAN IT NO LONGER ACCURATELY REFLECTS
 * KHRONOS STANDARDS. THE UNMODIFIED, NORMATIVE VERSIONS OF KHRONOS
 * SPECIFICATIONS AND HEADER INFORMATION ARE LOCATED AT
 *    https://www.khronos.org/registry/
 *
 * THE MATERIALS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * MATERIALS OR THE USE OR OTHER DEALINGS IN THE MATERIALS.
 **********************************************************************************/
/*****************************************************************************\

Copyright (c) 2013-2019 Intel Corporation All Rights Reserved.

THESE MATERIALS ARE PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR ITS
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THESE
MATERIALS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

File Name: cl_va_api_media_sharing_intel.h

Abstract:

Notes:

\*****************************************************************************/


#ifndef __OPENCL_CL_VA_API_MEDIA_SHARING_INTEL_H
#define __OPENCL_CL_VA_API_MEDIA_SHARING_INTEL_H

#include <CL/cl.h>
#include <CL/cl_platform.h>
#include <va/va.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************
* cl_intel_va_api_media_sharing extension *
*******************************************/

#define cl_intel_va_api_media_sharing 1

/* error codes */
#define CL_INVALID_VA_API_MEDIA_ADAPTER_INTEL               -1098
#define CL_INVALID_VA_API_MEDIA_SURFACE_INTEL               -1099
#define CL_VA_API_MEDIA_SURFACE_ALREADY_ACQUIRED_INTEL      -1100
#define CL_VA_API_MEDIA_SURFACE_NOT_ACQUIRED_INTEL          -1101

/* cl_va_api_device_source_intel */
#define CL_VA_API_DISPLAY_INTEL                             0x4094

/* cl_va_api_device_set_intel */
#define CL_PREFERRED_DEVICES_FOR_VA_API_INTEL               0x4095
#define CL_ALL_DEVICES_FOR_VA_API_INTEL                     0x4096

/* cl_context_info */
#define CL_CONTEXT_VA_API_DISPLAY_INTEL                     0x4097

/* cl_mem_info */
#define CL_MEM_VA_API_MEDIA_SURFACE_INTEL                   0x4098

/* cl_image_info */
#define CL_IMAGE_VA_API_PLANE_INTEL                         0x4099

/* cl_command_type */
#define CL_COMMAND_ACQUIRE_VA_API_MEDIA_SURFACES_INTEL      0x409A
#define CL_COMMAND_RELEASE_VA_API_MEDIA_SURFACES_INTEL      0x409B

typedef cl_uint cl_va_api_device_source_intel;
typedef cl_uint cl_va_api_device_set_intel;

extern CL_API_ENTRY cl_int CL_API_CALL
clGetDeviceIDsFromVA_APIMediaAdapterINTEL(
    cl_platform_id                platform,
    cl_va_api_device_source_intel media_adapter_type,
    void*                         media_adapter,
    cl_va_api_device_set_intel    media_adapter_set,
    cl_uint                       num_entries,
    cl_device_id*                 devices,
    cl_uint*                      num_devices) CL_EXT_SUFFIX__VERSION_1_2;

typedef CL_API_ENTRY cl_int (CL_API_CALL * clGetDeviceIDsFromVA_APIMediaAdapterINTEL_fn)(
    cl_platform_id                platform,
    cl_va_api_device_source_intel media_adapter_type,
    void*                         media_adapter,
    cl_va_api_device_set_intel    media_adapter_set,
    cl_uint                       num_entries,
    cl_device_id*                 devices,
    cl_uint*                      num_devices) CL_EXT_SUFFIX__VERSION_1_2;

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateFromVA_APIMediaSurfaceINTEL(
    cl_context                    context,
    cl_mem_flags                  flags,
    VASurfaceID*                  surface,
    cl_uint                       plane,
    cl_int*                       errcode_ret) CL_EXT_SUFFIX__VERSION_1_2;

typedef CL_API_ENTRY cl_mem (CL_API_CALL * clCreateFromVA_APIMediaSurfaceINTEL_fn)(
    cl_context                    context,
    cl_mem_flags                  flags,
    VASurfaceID*                  surface,
    cl_uint                       plane,
    cl_int*                       errcode_ret) CL_EXT_SUFFIX__VERSION_1_2;

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueAcquireVA_APIMediaSurfacesINTEL(
    cl_command_queue              command_queue,
    cl_uint                       num_objects,
    const cl_mem*                 mem_objects,
    cl_uint                       num_events_in_wait_list,
    const cl_event*               event_wait_list,
    cl_event*                     event) CL_EXT_SUFFIX__VERSION_1_2;

typedef CL_API_ENTRY cl_int (CL_API_CALL *clEnqueueAcquireVA_APIMediaSurfacesINTEL_fn)(
    cl_command_queue              command_queue,
    cl_uint                       num_objects,
    const cl_mem*                 mem_objects,
    cl_uint                       num_events_in_wait_list,
    const cl_event*               event_wait_list,
    cl_event*                     event) CL_EXT_SUFFIX__VERSION_1_2;

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueReleaseVA_APIMediaSurfacesINTEL(
    cl_command_queue              command_queue,
    cl_uint                       num_objects,
    const cl_mem*                 mem_objects,
    cl_uint                       num_events_in_wait_list,
    const cl_event*               event_wait_list,
    cl_event*                     event) CL_EXT_SUFFIX__VERSION_1_2;

typedef CL_API_ENTRY cl_int (CL_API_CALL *clEnqueueReleaseVA_APIMediaSurfacesINTEL_fn)(
    cl_command_queue              command_queue,
    cl_uint                       num_objects,
    const cl_mem*                 mem_objects,
    cl_uint                       num_events_in_wait_list,
    const cl_event*               event_wait_list,
    cl_event*                     event) CL_EXT_SUFFIX__VERSION_1_2;

#ifdef __cplusplus
}
#endif

#endif  /* __OPENCL_CL_VA_API_MEDIA_SHARING_INTEL_H */

