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

#ifndef OPENCL_CL_GL_H_
#define OPENCL_CL_GL_H_

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
* cl_khr_gl_sharing
***************************************************************/
#define cl_khr_gl_sharing 1
#define CL_KHR_GL_SHARING_EXTENSION_NAME \
    "cl_khr_gl_sharing"


#define CL_KHR_GL_SHARING_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)

typedef int                 cl_GLint;
typedef unsigned int        cl_GLenum;
typedef unsigned int        cl_GLuint;

typedef cl_uint             cl_gl_context_info;

/* Error codes */
#define CL_INVALID_GL_SHAREGROUP_REFERENCE_KHR              -1000

/* cl_gl_context_info */
#define CL_CURRENT_DEVICE_FOR_GL_CONTEXT_KHR                0x2006
#define CL_DEVICES_FOR_GL_CONTEXT_KHR                       0x2007

/* Additional cl_context_properties */
#define CL_GL_CONTEXT_KHR                                   0x2008
#define CL_EGL_DISPLAY_KHR                                  0x2009
#define CL_GLX_DISPLAY_KHR                                  0x200A
#define CL_WGL_HDC_KHR                                      0x200B
#define CL_CGL_SHAREGROUP_KHR                               0x200C

typedef cl_uint             cl_gl_object_type;
typedef cl_uint             cl_gl_texture_info;
typedef cl_uint             cl_gl_platform_info;

/* cl_gl_object_type */
#define CL_GL_OBJECT_BUFFER                                 0x2000
#define CL_GL_OBJECT_TEXTURE2D                              0x2001
#define CL_GL_OBJECT_TEXTURE3D                              0x2002
#define CL_GL_OBJECT_RENDERBUFFER                           0x2003

#if defined(CL_VERSION_1_2)
/* cl_gl_object_type */
#define CL_GL_OBJECT_TEXTURE2D_ARRAY                        0x200E
#define CL_GL_OBJECT_TEXTURE1D                              0x200F
#define CL_GL_OBJECT_TEXTURE1D_ARRAY                        0x2010
#define CL_GL_OBJECT_TEXTURE_BUFFER                         0x2011

#endif /* defined(CL_VERSION_1_2) */

/* cl_gl_texture_info */
#define CL_GL_TEXTURE_TARGET                                0x2004
#define CL_GL_MIPMAP_LEVEL                                  0x2005


typedef cl_int CL_API_CALL
clGetGLContextInfoKHR_t(
    const cl_context_properties* properties,
    cl_gl_context_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetGLContextInfoKHR_t *
clGetGLContextInfoKHR_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_mem CL_API_CALL
clCreateFromGLBuffer_t(
    cl_context context,
    cl_mem_flags flags,
    cl_GLuint bufobj,
    cl_int* errcode_ret);

typedef clCreateFromGLBuffer_t *
clCreateFromGLBuffer_fn CL_API_SUFFIX__VERSION_1_0;

#if !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_int CL_API_CALL
clGetGLContextInfoKHR(
    const cl_context_properties* properties,
    cl_gl_context_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret) CL_API_SUFFIX__VERSION_1_0;

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateFromGLBuffer(
    cl_context context,
    cl_mem_flags flags,
    cl_GLuint bufobj,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_0;

#endif /* !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

#if defined(CL_VERSION_1_2)

typedef cl_mem CL_API_CALL
clCreateFromGLTexture_t(
    cl_context context,
    cl_mem_flags flags,
    cl_GLenum target,
    cl_GLint miplevel,
    cl_GLuint texture,
    cl_int* errcode_ret);

typedef clCreateFromGLTexture_t *
clCreateFromGLTexture_fn CL_API_SUFFIX__VERSION_1_2;

#if !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateFromGLTexture(
    cl_context context,
    cl_mem_flags flags,
    cl_GLenum target,
    cl_GLint miplevel,
    cl_GLuint texture,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_2;

#endif /* !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

#endif /* defined(CL_VERSION_1_2) */


typedef cl_mem CL_API_CALL
clCreateFromGLRenderbuffer_t(
    cl_context context,
    cl_mem_flags flags,
    cl_GLuint renderbuffer,
    cl_int* errcode_ret);

typedef clCreateFromGLRenderbuffer_t *
clCreateFromGLRenderbuffer_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL
clGetGLObjectInfo_t(
    cl_mem memobj,
    cl_gl_object_type* gl_object_type,
    cl_GLuint* gl_object_name);

typedef clGetGLObjectInfo_t *
clGetGLObjectInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL
clGetGLTextureInfo_t(
    cl_mem memobj,
    cl_gl_texture_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetGLTextureInfo_t *
clGetGLTextureInfo_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL
clEnqueueAcquireGLObjects_t(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueAcquireGLObjects_t *
clEnqueueAcquireGLObjects_fn CL_API_SUFFIX__VERSION_1_0;

typedef cl_int CL_API_CALL
clEnqueueReleaseGLObjects_t(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event);

typedef clEnqueueReleaseGLObjects_t *
clEnqueueReleaseGLObjects_fn CL_API_SUFFIX__VERSION_1_0;

#if !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateFromGLRenderbuffer(
    cl_context context,
    cl_mem_flags flags,
    cl_GLuint renderbuffer,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_0;

extern CL_API_ENTRY cl_int CL_API_CALL
clGetGLObjectInfo(
    cl_mem memobj,
    cl_gl_object_type* gl_object_type,
    cl_GLuint* gl_object_name) CL_API_SUFFIX__VERSION_1_0;

extern CL_API_ENTRY cl_int CL_API_CALL
clGetGLTextureInfo(
    cl_mem memobj,
    cl_gl_texture_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret) CL_API_SUFFIX__VERSION_1_0;

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueAcquireGLObjects(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event) CL_API_SUFFIX__VERSION_1_0;

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueReleaseGLObjects(
    cl_command_queue command_queue,
    cl_uint num_objects,
    const cl_mem* mem_objects,
    cl_uint num_events_in_wait_list,
    const cl_event* event_wait_list,
    cl_event* event) CL_API_SUFFIX__VERSION_1_0;

#endif /* !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

/* OpenCL 1.0 APIs that were deprecated in OpenCL 1.2 */

typedef cl_mem CL_API_CALL
clCreateFromGLTexture2D_t(
    cl_context context,
    cl_mem_flags flags,
    cl_GLenum target,
    cl_GLint miplevel,
    cl_GLuint texture,
    cl_int* errcode_ret);

typedef clCreateFromGLTexture2D_t *
clCreateFromGLTexture2D_fn CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

typedef cl_mem CL_API_CALL
clCreateFromGLTexture3D_t(
    cl_context context,
    cl_mem_flags flags,
    cl_GLenum target,
    cl_GLint miplevel,
    cl_GLuint texture,
    cl_int* errcode_ret);

typedef clCreateFromGLTexture3D_t *
clCreateFromGLTexture3D_fn CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

#if !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateFromGLTexture2D(
    cl_context context,
    cl_mem_flags flags,
    cl_GLenum target,
    cl_GLint miplevel,
    cl_GLuint texture,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateFromGLTexture3D(
    cl_context context,
    cl_mem_flags flags,
    cl_GLenum target,
    cl_GLint miplevel,
    cl_GLuint texture,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_1_DEPRECATED;

#endif /* !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

/***************************************************************
* cl_khr_gl_event
***************************************************************/
#define cl_khr_gl_event 1
#define CL_KHR_GL_EVENT_EXTENSION_NAME \
    "cl_khr_gl_event"


#define CL_KHR_GL_EVENT_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)

typedef struct __GLsync *   cl_GLsync;

/* cl_command_type */
#define CL_COMMAND_GL_FENCE_SYNC_OBJECT_KHR                 0x200D


typedef cl_event CL_API_CALL
clCreateEventFromGLsyncKHR_t(
    cl_context context,
    cl_GLsync sync,
    cl_int* errcode_ret);

typedef clCreateEventFromGLsyncKHR_t *
clCreateEventFromGLsyncKHR_fn CL_API_SUFFIX__VERSION_1_1;

#if !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_event CL_API_CALL
clCreateEventFromGLsyncKHR(
    cl_context context,
    cl_GLsync sync,
    cl_int* errcode_ret) CL_API_SUFFIX__VERSION_1_1;

#endif /* !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

/***************************************************************
* cl_khr_gl_depth_images
***************************************************************/
#define cl_khr_gl_depth_images 1
#define CL_KHR_GL_DEPTH_IMAGES_EXTENSION_NAME \
    "cl_khr_gl_depth_images"


#define CL_KHR_GL_DEPTH_IMAGES_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)

/* cl_channel_order */
#define CL_DEPTH_STENCIL                                    0x10BE

/* cl_channel_type */
#define CL_UNORM_INT24                                      0x10DF

/***************************************************************
* cl_khr_gl_msaa_sharing
***************************************************************/
#define cl_khr_gl_msaa_sharing 1
#define CL_KHR_GL_MSAA_SHARING_EXTENSION_NAME \
    "cl_khr_gl_msaa_sharing"


#define CL_KHR_GL_MSAA_SHARING_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)

/* cl_gl_texture_info */
#define CL_GL_NUM_SAMPLES                                   0x2012

/***************************************************************
* cl_intel_sharing_format_query_gl
***************************************************************/
#define cl_intel_sharing_format_query_gl 1
#define CL_INTEL_SHARING_FORMAT_QUERY_GL_EXTENSION_NAME \
    "cl_intel_sharing_format_query_gl"


#define CL_INTEL_SHARING_FORMAT_QUERY_GL_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)

/* when cl_khr_gl_sharing is supported */

typedef cl_int CL_API_CALL
clGetSupportedGLTextureFormatsINTEL_t(
    cl_context context,
    cl_mem_flags flags,
    cl_mem_object_type image_type,
    cl_uint num_entries,
    cl_GLenum* gl_formats,
    cl_uint* num_texture_formats);

typedef clGetSupportedGLTextureFormatsINTEL_t *
clGetSupportedGLTextureFormatsINTEL_fn ;

#if !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_int CL_API_CALL
clGetSupportedGLTextureFormatsINTEL(
    cl_context context,
    cl_mem_flags flags,
    cl_mem_object_type image_type,
    cl_uint num_entries,
    cl_GLenum* gl_formats,
    cl_uint* num_texture_formats) ;

#endif /* !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

#ifdef __cplusplus
}
#endif

#endif /* OPENCL_CL_GL_H_ */
