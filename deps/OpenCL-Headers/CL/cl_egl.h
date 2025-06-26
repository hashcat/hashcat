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

#ifndef OPENCL_CL_EGL_H_
#define OPENCL_CL_EGL_H_

/*
** This header is generated from the Khronos OpenCL XML API Registry.
*/

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
* cl_khr_egl_image
***************************************************************/
#define cl_khr_egl_image 1
#define CL_KHR_EGL_IMAGE_EXTENSION_NAME \
    "cl_khr_egl_image"


#define CL_KHR_EGL_IMAGE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)

/* Command type for events created with clEnqueueAcquireEGLObjectsKHR */
#define CL_COMMAND_EGL_FENCE_SYNC_OBJECT_KHR                0x202F
#define CL_COMMAND_ACQUIRE_EGL_OBJECTS_KHR                  0x202D
#define CL_COMMAND_RELEASE_EGL_OBJECTS_KHR                  0x202E

/* Error type for clCreateFromEGLImageKHR */
#define CL_INVALID_EGL_OBJECT_KHR                           -1093
#define CL_EGL_RESOURCE_NOT_ACQUIRED_KHR                    -1092

/* CLeglImageKHR is an opaque handle to an EGLImage */
typedef void*               CLeglImageKHR;

/* CLeglDisplayKHR is an opaque handle to an EGLDisplay */
typedef void*               CLeglDisplayKHR;

/* properties passed to clCreateFromEGLImageKHR */
typedef intptr_t            cl_egl_image_properties_khr;


typedef cl_mem CL_API_CALL
clCreateFromEGLImageKHR_t(
    cl_context context,
    CLeglDisplayKHR egldisplay,
    CLeglImageKHR eglimage,
    cl_mem_flags flags,
    const cl_egl_image_properties_khr* properties,
    cl_int* errcode_ret);

typedef clCreateFromEGLImageKHR_t *
clCreateFromEGLImageKHR_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL
clEnqueueAcquireEGLObjectsKHR_t(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueAcquireEGLObjectsKHR_t *
clEnqueueAcquireEGLObjectsKHR_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL
clEnqueueReleaseEGLObjectsKHR_t(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueReleaseEGLObjectsKHR_t *
clEnqueueReleaseEGLObjectsKHR_fn CL_API_SUFFIX__VERSION_1_0;

#if !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateFromEGLImageKHR(
    cl_context context,
    CLeglDisplayKHR egldisplay,
    CLeglImageKHR eglimage,
    cl_mem_flags flags,
    const cl_egl_image_properties_khr* properties,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_0;

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueAcquireEGLObjectsKHR(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event) CL_API_SUFFIX__VERSION_1_0;

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueReleaseEGLObjectsKHR(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event) CL_API_SUFFIX__VERSION_1_0;

#endif /* !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

/***************************************************************
* cl_khr_egl_event
***************************************************************/
#define cl_khr_egl_event 1
#define CL_KHR_EGL_EVENT_EXTENSION_NAME \
    "cl_khr_egl_event"


#define CL_KHR_EGL_EVENT_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)

/* CLeglDisplayKHR is an opaque handle to an EGLDisplay */
/* type CLeglDisplayKHR */

/* CLeglSyncKHR is an opaque handle to an EGLSync object */
typedef void*               CLeglSyncKHR;


typedef cl_event CL_API_CALL
clCreateEventFromEGLSyncKHR_t(
    cl_context context,
    CLeglSyncKHR sync,
    CLeglDisplayKHR display,
    cl_int* errcode_ret);

typedef clCreateEventFromEGLSyncKHR_t *
clCreateEventFromEGLSyncKHR_fn CL_API_SUFFIX__VERSION_1_0;

#if !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_event CL_API_CALL
clCreateEventFromEGLSyncKHR(
    cl_context context,
    CLeglSyncKHR sync,
    CLeglDisplayKHR display,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_0;

#endif /* !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

#ifdef __cplusplus
}
#endif

#endif /* OPENCL_CL_EGL_H_ */
