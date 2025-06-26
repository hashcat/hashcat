/*******************************************************************************
 * Copyright (c) 2019-2020 The Khronos Group Inc.
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

#ifndef OPENCL_CL_ICD_H
#define OPENCL_CL_ICD_H

#include <CL/cl.h>
#include <CL/cl_function_types.h>
#include <CL/cl_egl.h>
#include <CL/cl_ext.h>
#include <CL/cl_gl.h>

#if defined(_WIN32)
#include <CL/cl_d3d11.h>
#include <CL/cl_d3d10.h>
#include <CL/cl_dx9_media_sharing.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Vendor dispatch table structure */

typedef struct _cl_icd_dispatch {
  /* OpenCL 1.0 */
  clGetPlatformIDs_t *clGetPlatformIDs;
  clGetPlatformInfo_t *clGetPlatformInfo;
  clGetDeviceIDs_t *clGetDeviceIDs;
  clGetDeviceInfo_t *clGetDeviceInfo;
  clCreateContext_t *clCreateContext;
  clCreateContextFromType_t *clCreateContextFromType;
  clRetainContext_t *clRetainContext;
  clReleaseContext_t *clReleaseContext;
  clGetContextInfo_t *clGetContextInfo;
  clCreateCommandQueue_t *clCreateCommandQueue;
  clRetainCommandQueue_t *clRetainCommandQueue;
  clReleaseCommandQueue_t *clReleaseCommandQueue;
  clGetCommandQueueInfo_t *clGetCommandQueueInfo;
  clSetCommandQueueProperty_t *clSetCommandQueueProperty;
  clCreateBuffer_t *clCreateBuffer;
  clCreateImage2D_t *clCreateImage2D;
  clCreateImage3D_t *clCreateImage3D;
  clRetainMemObject_t *clRetainMemObject;
  clReleaseMemObject_t *clReleaseMemObject;
  clGetSupportedImageFormats_t *clGetSupportedImageFormats;
  clGetMemObjectInfo_t *clGetMemObjectInfo;
  clGetImageInfo_t *clGetImageInfo;
  clCreateSampler_t *clCreateSampler;
  clRetainSampler_t *clRetainSampler;
  clReleaseSampler_t *clReleaseSampler;
  clGetSamplerInfo_t *clGetSamplerInfo;
  clCreateProgramWithSource_t *clCreateProgramWithSource;
  clCreateProgramWithBinary_t *clCreateProgramWithBinary;
  clRetainProgram_t *clRetainProgram;
  clReleaseProgram_t *clReleaseProgram;
  clBuildProgram_t *clBuildProgram;
  clUnloadCompiler_t *clUnloadCompiler;
  clGetProgramInfo_t *clGetProgramInfo;
  clGetProgramBuildInfo_t *clGetProgramBuildInfo;
  clCreateKernel_t *clCreateKernel;
  clCreateKernelsInProgram_t *clCreateKernelsInProgram;
  clRetainKernel_t *clRetainKernel;
  clReleaseKernel_t *clReleaseKernel;
  clSetKernelArg_t *clSetKernelArg;
  clGetKernelInfo_t *clGetKernelInfo;
  clGetKernelWorkGroupInfo_t *clGetKernelWorkGroupInfo;
  clWaitForEvents_t *clWaitForEvents;
  clGetEventInfo_t *clGetEventInfo;
  clRetainEvent_t *clRetainEvent;
  clReleaseEvent_t *clReleaseEvent;
  clGetEventProfilingInfo_t *clGetEventProfilingInfo;
  clFlush_t *clFlush;
  clFinish_t *clFinish;
  clEnqueueReadBuffer_t *clEnqueueReadBuffer;
  clEnqueueWriteBuffer_t *clEnqueueWriteBuffer;
  clEnqueueCopyBuffer_t *clEnqueueCopyBuffer;
  clEnqueueReadImage_t *clEnqueueReadImage;
  clEnqueueWriteImage_t *clEnqueueWriteImage;
  clEnqueueCopyImage_t *clEnqueueCopyImage;
  clEnqueueCopyImageToBuffer_t *clEnqueueCopyImageToBuffer;
  clEnqueueCopyBufferToImage_t *clEnqueueCopyBufferToImage;
  clEnqueueMapBuffer_t *clEnqueueMapBuffer;
  clEnqueueMapImage_t *clEnqueueMapImage;
  clEnqueueUnmapMemObject_t *clEnqueueUnmapMemObject;
  clEnqueueNDRangeKernel_t *clEnqueueNDRangeKernel;
  clEnqueueTask_t *clEnqueueTask;
  clEnqueueNativeKernel_t *clEnqueueNativeKernel;
  clEnqueueMarker_t *clEnqueueMarker;
  clEnqueueWaitForEvents_t *clEnqueueWaitForEvents;
  clEnqueueBarrier_t *clEnqueueBarrier;
  clGetExtensionFunctionAddress_t *clGetExtensionFunctionAddress;
  clCreateFromGLBuffer_t *clCreateFromGLBuffer;
  clCreateFromGLTexture2D_t *clCreateFromGLTexture2D;
  clCreateFromGLTexture3D_t *clCreateFromGLTexture3D;
  clCreateFromGLRenderbuffer_t *clCreateFromGLRenderbuffer;
  clGetGLObjectInfo_t *clGetGLObjectInfo;
  clGetGLTextureInfo_t *clGetGLTextureInfo;
  clEnqueueAcquireGLObjects_t *clEnqueueAcquireGLObjects;
  clEnqueueReleaseGLObjects_t *clEnqueueReleaseGLObjects;
  clGetGLContextInfoKHR_t *clGetGLContextInfoKHR;

  /* cl_khr_d3d10_sharing */
#ifdef _WIN32
  clGetDeviceIDsFromD3D10KHR_t *clGetDeviceIDsFromD3D10KHR;
  clCreateFromD3D10BufferKHR_t *clCreateFromD3D10BufferKHR;
  clCreateFromD3D10Texture2DKHR_t *clCreateFromD3D10Texture2DKHR;
  clCreateFromD3D10Texture3DKHR_t *clCreateFromD3D10Texture3DKHR;
  clEnqueueAcquireD3D10ObjectsKHR_t *clEnqueueAcquireD3D10ObjectsKHR;
  clEnqueueReleaseD3D10ObjectsKHR_t *clEnqueueReleaseD3D10ObjectsKHR;
#else
  void *clGetDeviceIDsFromD3D10KHR;
  void *clCreateFromD3D10BufferKHR;
  void *clCreateFromD3D10Texture2DKHR;
  void *clCreateFromD3D10Texture3DKHR;
  void *clEnqueueAcquireD3D10ObjectsKHR;
  void *clEnqueueReleaseD3D10ObjectsKHR;
#endif

  /* OpenCL 1.1 */
#ifdef CL_VERSION_1_1
  clSetEventCallback_t *clSetEventCallback;
  clCreateSubBuffer_t *clCreateSubBuffer;
  clSetMemObjectDestructorCallback_t *clSetMemObjectDestructorCallback;
  clCreateUserEvent_t *clCreateUserEvent;
  clSetUserEventStatus_t *clSetUserEventStatus;
  clEnqueueReadBufferRect_t *clEnqueueReadBufferRect;
  clEnqueueWriteBufferRect_t *clEnqueueWriteBufferRect;
  clEnqueueCopyBufferRect_t *clEnqueueCopyBufferRect;
#else
  void *clSetEventCallback;
  void *clCreateSubBuffer;
  void *clSetMemObjectDestructorCallback;
  void *clCreateUserEvent;
  void *clSetUserEventStatus;
  void *clEnqueueReadBufferRect;
  void *clEnqueueWriteBufferRect;
  void *clEnqueueCopyBufferRect;
#endif

  /* cl_ext_device_fission */
  clCreateSubDevicesEXT_t *clCreateSubDevicesEXT;
  clRetainDeviceEXT_t *clRetainDeviceEXT;
  clReleaseDeviceEXT_t *clReleaseDeviceEXT;

  /* cl_khr_gl_event */
  clCreateEventFromGLsyncKHR_t *clCreateEventFromGLsyncKHR;

  /* OpenCL 1.2 */
#ifdef CL_VERSION_1_2
  clCreateSubDevices_t *clCreateSubDevices;
  clRetainDevice_t *clRetainDevice;
  clReleaseDevice_t *clReleaseDevice;
  clCreateImage_t *clCreateImage;
  clCreateProgramWithBuiltInKernels_t *clCreateProgramWithBuiltInKernels;
  clCompileProgram_t *clCompileProgram;
  clLinkProgram_t *clLinkProgram;
  clUnloadPlatformCompiler_t *clUnloadPlatformCompiler;
  clGetKernelArgInfo_t *clGetKernelArgInfo;
  clEnqueueFillBuffer_t *clEnqueueFillBuffer;
  clEnqueueFillImage_t *clEnqueueFillImage;
  clEnqueueMigrateMemObjects_t *clEnqueueMigrateMemObjects;
  clEnqueueMarkerWithWaitList_t *clEnqueueMarkerWithWaitList;
  clEnqueueBarrierWithWaitList_t *clEnqueueBarrierWithWaitList;
  clGetExtensionFunctionAddressForPlatform_t *
      clGetExtensionFunctionAddressForPlatform;
  clCreateFromGLTexture_t *clCreateFromGLTexture;
#else
  void *clCreateSubDevices;
  void *clRetainDevice;
  void *clReleaseDevice;
  void *clCreateImage;
  void *clCreateProgramWithBuiltInKernels;
  void *clCompileProgram;
  void *clLinkProgram;
  void *clUnloadPlatformCompiler;
  void *clGetKernelArgInfo;
  void *clEnqueueFillBuffer;
  void *clEnqueueFillImage;
  void *clEnqueueMigrateMemObjects;
  void *clEnqueueMarkerWithWaitList;
  void *clEnqueueBarrierWithWaitList;
  void *clGetExtensionFunctionAddressForPlatform;
  void *clCreateFromGLTexture;
#endif

  /* cl_khr_d3d11_sharing and cl_khr_dx9_media_sharing */
#ifdef _WIN32
  clGetDeviceIDsFromD3D11KHR_t *clGetDeviceIDsFromD3D11KHR;
  clCreateFromD3D11BufferKHR_t *clCreateFromD3D11BufferKHR;
  clCreateFromD3D11Texture2DKHR_t *clCreateFromD3D11Texture2DKHR;
  clCreateFromD3D11Texture3DKHR_t *clCreateFromD3D11Texture3DKHR;
  clCreateFromDX9MediaSurfaceKHR_t *clCreateFromDX9MediaSurfaceKHR;
  clEnqueueAcquireD3D11ObjectsKHR_t *clEnqueueAcquireD3D11ObjectsKHR;
  clEnqueueReleaseD3D11ObjectsKHR_t *clEnqueueReleaseD3D11ObjectsKHR;
  clGetDeviceIDsFromDX9MediaAdapterKHR_t *
      clGetDeviceIDsFromDX9MediaAdapterKHR;
  clEnqueueAcquireDX9MediaSurfacesKHR_t *
      clEnqueueAcquireDX9MediaSurfacesKHR;
  clEnqueueReleaseDX9MediaSurfacesKHR_t *
      clEnqueueReleaseDX9MediaSurfacesKHR;
#else
  void *clGetDeviceIDsFromD3D11KHR;
  void *clCreateFromD3D11BufferKHR;
  void *clCreateFromD3D11Texture2DKHR;
  void *clCreateFromD3D11Texture3DKHR;
  void *clCreateFromDX9MediaSurfaceKHR;
  void *clEnqueueAcquireD3D11ObjectsKHR;
  void *clEnqueueReleaseD3D11ObjectsKHR;
  void *clGetDeviceIDsFromDX9MediaAdapterKHR;
  void *clEnqueueAcquireDX9MediaSurfacesKHR;
  void *clEnqueueReleaseDX9MediaSurfacesKHR;
#endif

  /* cl_khr_egl_image */
  clCreateFromEGLImageKHR_t *clCreateFromEGLImageKHR;
  clEnqueueAcquireEGLObjectsKHR_t *clEnqueueAcquireEGLObjectsKHR;
  clEnqueueReleaseEGLObjectsKHR_t *clEnqueueReleaseEGLObjectsKHR;

  /* cl_khr_egl_event */
  clCreateEventFromEGLSyncKHR_t *clCreateEventFromEGLSyncKHR;

  /* OpenCL 2.0 */
#ifdef CL_VERSION_2_0
  clCreateCommandQueueWithProperties_t *clCreateCommandQueueWithProperties;
  clCreatePipe_t *clCreatePipe;
  clGetPipeInfo_t *clGetPipeInfo;
  clSVMAlloc_t *clSVMAlloc;
  clSVMFree_t *clSVMFree;
  clEnqueueSVMFree_t *clEnqueueSVMFree;
  clEnqueueSVMMemcpy_t *clEnqueueSVMMemcpy;
  clEnqueueSVMMemFill_t *clEnqueueSVMMemFill;
  clEnqueueSVMMap_t *clEnqueueSVMMap;
  clEnqueueSVMUnmap_t *clEnqueueSVMUnmap;
  clCreateSamplerWithProperties_t *clCreateSamplerWithProperties;
  clSetKernelArgSVMPointer_t *clSetKernelArgSVMPointer;
  clSetKernelExecInfo_t *clSetKernelExecInfo;
#else
  void *clCreateCommandQueueWithProperties;
  void *clCreatePipe;
  void *clGetPipeInfo;
  void *clSVMAlloc;
  void *clSVMFree;
  void *clEnqueueSVMFree;
  void *clEnqueueSVMMemcpy;
  void *clEnqueueSVMMemFill;
  void *clEnqueueSVMMap;
  void *clEnqueueSVMUnmap;
  void *clCreateSamplerWithProperties;
  void *clSetKernelArgSVMPointer;
  void *clSetKernelExecInfo;
#endif

  /* cl_khr_sub_groups */
  clGetKernelSubGroupInfoKHR_t *clGetKernelSubGroupInfoKHR;

  /* OpenCL 2.1 */
#ifdef CL_VERSION_2_1
  clCloneKernel_t *clCloneKernel;
  clCreateProgramWithIL_t *clCreateProgramWithIL;
  clEnqueueSVMMigrateMem_t *clEnqueueSVMMigrateMem;
  clGetDeviceAndHostTimer_t *clGetDeviceAndHostTimer;
  clGetHostTimer_t *clGetHostTimer;
  clGetKernelSubGroupInfo_t *clGetKernelSubGroupInfo;
  clSetDefaultDeviceCommandQueue_t *clSetDefaultDeviceCommandQueue;
#else
  void *clCloneKernel;
  void *clCreateProgramWithIL;
  void *clEnqueueSVMMigrateMem;
  void *clGetDeviceAndHostTimer;
  void *clGetHostTimer;
  void *clGetKernelSubGroupInfo;
  void *clSetDefaultDeviceCommandQueue;
#endif

  /* OpenCL 2.2 */
#ifdef CL_VERSION_2_2
  clSetProgramReleaseCallback_t *clSetProgramReleaseCallback;
  clSetProgramSpecializationConstant_t *clSetProgramSpecializationConstant;
#else
  void *clSetProgramReleaseCallback;
  void *clSetProgramSpecializationConstant;
#endif

  /* OpenCL 3.0 */
#ifdef CL_VERSION_3_0
  clCreateBufferWithProperties_t *clCreateBufferWithProperties;
  clCreateImageWithProperties_t *clCreateImageWithProperties;
  clSetContextDestructorCallback_t *clSetContextDestructorCallback;
#else
  void *clCreateBufferWithProperties;
  void *clCreateImageWithProperties;
  void *clSetContextDestructorCallback;
#endif

} cl_icd_dispatch;

#ifdef __cplusplus
}
#endif

#endif /* #ifndef OPENCL_CL_ICD_H */
