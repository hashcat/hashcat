/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "ext_OpenCL.h"

#include "dynloader.h"

const char *val2cstr_cl (cl_int CL_err)
{
  #define CLERR(a) case a: return #a

  switch (CL_err)
  {
    /**
     * OpenCL runtime errors
     */

    #if defined (CL_VERSION_1_0)
    CLERR (CL_SUCCESS);
    CLERR (CL_DEVICE_NOT_FOUND);
    CLERR (CL_DEVICE_NOT_AVAILABLE);
    CLERR (CL_COMPILER_NOT_AVAILABLE);
    CLERR (CL_MEM_OBJECT_ALLOCATION_FAILURE);
    CLERR (CL_OUT_OF_RESOURCES);
    CLERR (CL_OUT_OF_HOST_MEMORY);
    CLERR (CL_PROFILING_INFO_NOT_AVAILABLE);
    CLERR (CL_MEM_COPY_OVERLAP);
    CLERR (CL_IMAGE_FORMAT_MISMATCH);
    CLERR (CL_IMAGE_FORMAT_NOT_SUPPORTED);
    CLERR (CL_BUILD_PROGRAM_FAILURE);
    CLERR (CL_MAP_FAILURE);
    #endif

    #if defined (CL_VERSION_1_1)
    CLERR (CL_MISALIGNED_SUB_BUFFER_OFFSET);
    CLERR (CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST);
    #endif

    #if defined (CL_VERSION_1_2)
    CLERR (CL_COMPILE_PROGRAM_FAILURE);
    CLERR (CL_LINKER_NOT_AVAILABLE);
    CLERR (CL_LINK_PROGRAM_FAILURE);
    CLERR (CL_DEVICE_PARTITION_FAILED);
    CLERR (CL_KERNEL_ARG_INFO_NOT_AVAILABLE);
    #endif

    /**
     * OpenCL compile-time errors
     */

    #if defined (CL_VERSION_1_0)
    CLERR (CL_INVALID_VALUE);
    CLERR (CL_INVALID_DEVICE_TYPE);
    CLERR (CL_INVALID_PLATFORM);
    CLERR (CL_INVALID_DEVICE);
    CLERR (CL_INVALID_CONTEXT);
    CLERR (CL_INVALID_QUEUE_PROPERTIES);
    CLERR (CL_INVALID_COMMAND_QUEUE);
    CLERR (CL_INVALID_HOST_PTR);
    CLERR (CL_INVALID_MEM_OBJECT);
    CLERR (CL_INVALID_IMAGE_FORMAT_DESCRIPTOR);
    CLERR (CL_INVALID_IMAGE_SIZE);
    CLERR (CL_INVALID_SAMPLER);
    CLERR (CL_INVALID_BINARY);
    CLERR (CL_INVALID_BUILD_OPTIONS);
    CLERR (CL_INVALID_PROGRAM);
    CLERR (CL_INVALID_PROGRAM_EXECUTABLE);
    CLERR (CL_INVALID_KERNEL_NAME);
    CLERR (CL_INVALID_KERNEL_DEFINITION);
    CLERR (CL_INVALID_KERNEL);
    CLERR (CL_INVALID_ARG_INDEX);
    CLERR (CL_INVALID_ARG_VALUE);
    CLERR (CL_INVALID_ARG_SIZE);
    CLERR (CL_INVALID_KERNEL_ARGS);
    CLERR (CL_INVALID_WORK_DIMENSION);
    CLERR (CL_INVALID_WORK_GROUP_SIZE);
    CLERR (CL_INVALID_WORK_ITEM_SIZE);
    CLERR (CL_INVALID_GLOBAL_OFFSET);
    CLERR (CL_INVALID_EVENT_WAIT_LIST);
    CLERR (CL_INVALID_EVENT);
    CLERR (CL_INVALID_OPERATION);
    CLERR (CL_INVALID_GL_OBJECT);
    CLERR (CL_INVALID_BUFFER_SIZE);
    CLERR (CL_INVALID_MIP_LEVEL);
    CLERR (CL_INVALID_GLOBAL_WORK_SIZE);
    #endif

    #if defined (CL_VERSION_1_1)
    CLERR (CL_INVALID_PROPERTY);
    #endif

    #if defined (CL_VERSION_1_2)
    CLERR (CL_INVALID_IMAGE_DESCRIPTOR);
    CLERR (CL_INVALID_COMPILER_OPTIONS);
    CLERR (CL_INVALID_LINKER_OPTIONS);
    CLERR (CL_INVALID_DEVICE_PARTITION_COUNT);
    #endif

    #if defined (CL_VERSION_2_0)
    CLERR (CL_INVALID_PIPE_SIZE);
    CLERR (CL_INVALID_DEVICE_QUEUE);
    #endif

    /**
     * OpenCL extension error values
     */

    #if defined (__OPENCL_CL_GL_H) && defined (cl_khr_gl_sharing)
    CLERR (CL_INVALID_GL_SHAREGROUP_REFERENCE_KHR);
    #endif

    #if defined (__CL_EXT_H) && defined (cl_khr_icd)
    CLERR (CL_PLATFORM_NOT_FOUND_KHR);
    #else
    case -1001: return "CL_PLATFORM_NOT_FOUND_KHR";
    #endif

    #if defined (__OPENCL_CL_D3D10_H)
    CLERR (CL_INVALID_D3D10_DEVICE_KHR);
    CLERR (CL_INVALID_D3D10_RESOURCE_KHR);
    CLERR (CL_D3D10_RESOURCE_ALREADY_ACQUIRED_KHR);
    CLERR (CL_D3D10_RESOURCE_NOT_ACQUIRED_KHR);
    #endif

    #if defined (__OPENCL_CL_D3D11_H)
    CLERR (CL_INVALID_D3D11_DEVICE_KHR);
    CLERR (CL_INVALID_D3D11_RESOURCE_KHR);
    CLERR (CL_D3D11_RESOURCE_ALREADY_ACQUIRED_KHR);
    CLERR (CL_D3D11_RESOURCE_NOT_ACQUIRED_KHR);
    #endif

    #if defined (__OPENCL_CL_DX9_MEDIA_SHARING_H)
    CLERR (CL_INVALID_DX9_MEDIA_ADAPTER_KHR);
    CLERR (CL_INVALID_DX9_MEDIA_SURFACE_KHR);
    CLERR (CL_DX9_MEDIA_SURFACE_ALREADY_ACQUIRED_KHR);
    CLERR (CL_DX9_MEDIA_SURFACE_NOT_ACQUIRED_KHR);
    #endif

    #if defined (__CL_EXT_H) && defined (cl_ext_device_fission)
    CLERR (CL_DEVICE_PARTITION_FAILED_EXT);
    CLERR (CL_INVALID_PARTITION_COUNT_EXT);
    CLERR (CL_INVALID_PARTITION_NAME_EXT);
    #endif

    #if defined (__OPENCL_CL_EGL_H)
    CLERR (CL_EGL_RESOURCE_NOT_ACQUIRED_KHR);
    CLERR (CL_INVALID_EGL_OBJECT_KHR);
    #endif

    #if defined (__CL_EXT_H) && defined (cl_intel_accelerator)
    CLERR (CL_INVALID_ACCELERATOR_INTEL);
    CLERR (CL_INVALID_ACCELERATOR_TYPE_INTEL);
    CLERR (CL_INVALID_ACCELERATOR_DESCRIPTOR_INTEL);
    CLERR (CL_ACCELERATOR_TYPE_NOT_SUPPORTED_INTEL);
    #endif
  }

  #undef CLERR

  return "CL_UNKNOWN_ERROR";
}

int ocl_init (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  memset (ocl, 0, sizeof (OCL_PTR));

  #if   defined (_WIN)
  ocl->lib = hc_dlopen ("OpenCL");
  #elif defined (__APPLE__)
  ocl->lib = hc_dlopen ("/System/Library/Frameworks/OpenCL.framework/OpenCL");
  #elif defined (__CYGWIN__)
  ocl->lib = hc_dlopen ("opencl.dll");

  if (ocl->lib == NULL) ocl->lib = hc_dlopen ("cygOpenCL-1.dll");
  #else
  ocl->lib = hc_dlopen ("libOpenCL.so");

  if (ocl->lib == NULL) ocl->lib = hc_dlopen ("libOpenCL.so.1");
  #endif

  if (ocl->lib == NULL) return -1;

  HC_LOAD_FUNC (ocl, clBuildProgram,            OCL_CLBUILDPROGRAM,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCompileProgram,          OCL_CLCOMPILEPROGRAM,           OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateBuffer,            OCL_CLCREATEBUFFER,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateCommandQueue,      OCL_CLCREATECOMMANDQUEUE,       OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateContext,           OCL_CLCREATECONTEXT,            OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateKernel,            OCL_CLCREATEKERNEL,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateProgramWithBinary, OCL_CLCREATEPROGRAMWITHBINARY,  OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateProgramWithSource, OCL_CLCREATEPROGRAMWITHSOURCE,  OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueCopyBuffer,       OCL_CLENQUEUECOPYBUFFER,        OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueFillBuffer,       OCL_CLENQUEUEFILLBUFFER,        OpenCL, -1);
  HC_LOAD_FUNC (ocl, clEnqueueMapBuffer,        OCL_CLENQUEUEMAPBUFFER,         OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueNDRangeKernel,    OCL_CLENQUEUENDRANGEKERNEL,     OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueReadBuffer,       OCL_CLENQUEUEREADBUFFER,        OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueUnmapMemObject,   OCL_CLENQUEUEUNMAPMEMOBJECT,    OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueWriteBuffer,      OCL_CLENQUEUEWRITEBUFFER,       OpenCL, 1);
  HC_LOAD_FUNC (ocl, clFinish,                  OCL_CLFINISH,                   OpenCL, 1);
  HC_LOAD_FUNC (ocl, clFlush,                   OCL_CLFLUSH,                    OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetDeviceIDs,            OCL_CLGETDEVICEIDS,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetDeviceInfo,           OCL_CLGETDEVICEINFO,            OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetEventInfo,            OCL_CLGETEVENTINFO,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetKernelWorkGroupInfo,  OCL_CLGETKERNELWORKGROUPINFO,   OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetPlatformIDs,          OCL_CLGETPLATFORMIDS,           OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetPlatformInfo,         OCL_CLGETPLATFORMINFO,          OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetProgramBuildInfo,     OCL_CLGETPROGRAMBUILDINFO,      OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetProgramInfo,          OCL_CLGETPROGRAMINFO,           OpenCL, 1);
  HC_LOAD_FUNC (ocl, clLinkProgram,             OCL_CLLINKPROGRAM,              OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseCommandQueue,     OCL_CLRELEASECOMMANDQUEUE,      OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseContext,          OCL_CLRELEASECONTEXT,           OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseKernel,           OCL_CLRELEASEKERNEL,            OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseMemObject,        OCL_CLRELEASEMEMOBJECT,         OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseProgram,          OCL_CLRELEASEPROGRAM,           OpenCL, 1);
  HC_LOAD_FUNC (ocl, clSetKernelArg,            OCL_CLSETKERNELARG,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clWaitForEvents,           OCL_CLWAITFOREVENTS,            OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetEventProfilingInfo,   OCL_CLGETEVENTPROFILINGINFO,    OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseEvent,            OCL_CLRELEASEEVENT,             OpenCL, 1);
  //HC_LOAD_FUNC (ocl, clUnloadPlatformCompiler,  OCL_CLUNLOADPLATFORMCOMPILER,   OpenCL, 1);

  return 0;
}

void ocl_close (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  if (ocl)
  {
    if (ocl->lib)
    {
      hc_dlclose (ocl->lib);
    }

    hcfree (backend_ctx->ocl);

    backend_ctx->ocl = NULL;
  }
}

int hc_clEnqueueNDRangeKernel (void *hashcat_ctx, cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueNDRangeKernel (command_queue, kernel, work_dim, global_work_offset, global_work_size, local_work_size, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueNDRangeKernel(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetEventInfo (void *hashcat_ctx, cl_event event, cl_event_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clGetEventInfo (event, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetEventInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clFlush (void *hashcat_ctx, cl_command_queue command_queue)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clFlush (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clFlush(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clFinish (void *hashcat_ctx, cl_command_queue command_queue)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clFinish (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clFinish(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clSetKernelArg (void *hashcat_ctx, cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void *arg_value)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clSetKernelArg (kernel, arg_index, arg_size, arg_value);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clSetKernelArg(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueWriteBuffer (void *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t size, const void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueWriteBuffer (command_queue, buffer, blocking_write, offset, size, ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueWriteBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueCopyBuffer (void *hashcat_ctx, cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueCopyBuffer (command_queue, src_buffer, dst_buffer, src_offset, dst_offset, size, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueCopyBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueFillBuffer (void *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, const void *pattern, size_t pattern_size, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  const backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;
  const OCL_PTR       *ocl         = backend_ctx->ocl;

  cl_int CL_err = ocl->clEnqueueFillBuffer (command_queue, buffer, pattern, pattern_size, offset, size, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueFillBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueReadBuffer (void *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t size, void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueReadBuffer (command_queue, buffer, blocking_read, offset, size, ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueReadBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetPlatformIDs (void *hashcat_ctx, cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clGetPlatformIDs (num_entries, platforms, num_platforms);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetPlatformIDs(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetPlatformInfo (void *hashcat_ctx, cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clGetPlatformInfo (platform, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetPlatformInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetDeviceIDs (void *hashcat_ctx, cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id *devices, cl_uint *num_devices)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clGetDeviceIDs (platform, device_type, num_entries, devices, num_devices);

  if (CL_err != CL_SUCCESS)
  {
    #ifndef DEBUG
    if (CL_err != CL_DEVICE_NOT_FOUND)
    #endif
    {
      event_log_error (hashcat_ctx, "clGetDeviceIDs(): %s", val2cstr_cl (CL_err));
    }

    return -1;
  }

  return 0;
}

int hc_clGetDeviceInfo (void *hashcat_ctx, cl_device_id device, cl_device_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clGetDeviceInfo (device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetDeviceInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateContext (void *hashcat_ctx, const cl_context_properties *properties, cl_uint num_devices, const cl_device_id *devices, void (CL_CALLBACK *pfn_notify) (const char *errinfo, const void *private_info, size_t cb, void *user_data), void *user_data, cl_context *context)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  cl_int CL_err;

  *context = ocl->clCreateContext (properties, num_devices, devices, pfn_notify, user_data, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateContext(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateCommandQueue (void *hashcat_ctx, cl_context context, cl_device_id device, cl_command_queue_properties properties, cl_command_queue *command_queue)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  cl_int CL_err;

  *command_queue = ocl->clCreateCommandQueue (context, device, properties, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateCommandQueue(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateBuffer (void *hashcat_ctx, cl_context context, cl_mem_flags flags, size_t size, void *host_ptr, cl_mem *mem)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  cl_int CL_err;

  *mem = ocl->clCreateBuffer (context, flags, size, host_ptr, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateProgramWithSource (void *hashcat_ctx, cl_context context, cl_uint count, const char **strings, const size_t *lengths, cl_program *program)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  cl_int CL_err;

  *program = ocl->clCreateProgramWithSource (context, count, strings, lengths, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateProgramWithSource(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateProgramWithBinary (void *hashcat_ctx, cl_context context, cl_uint num_devices, const cl_device_id *device_list, const size_t *lengths, const unsigned char **binaries, cl_int *binary_status, cl_program *program)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  cl_int CL_err;

  *program = ocl->clCreateProgramWithBinary (context, num_devices, device_list, lengths, binaries, binary_status, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateProgramWithBinary(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clBuildProgram (void *hashcat_ctx, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clBuildProgram (program, num_devices, device_list, options, pfn_notify, user_data);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clBuildProgram(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCompileProgram (void *hashcat_ctx, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, cl_uint num_input_headers, const cl_program *input_headers, const char **header_include_names, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clCompileProgram (program, num_devices, device_list, options, num_input_headers, input_headers, header_include_names, pfn_notify, user_data);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCompileProgram(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clLinkProgram (void *hashcat_ctx, cl_context context, cl_uint num_devices, const cl_device_id *device_list, const char *options, cl_uint num_input_programs, const cl_program *input_programs, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data, cl_program *program)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  cl_int CL_err;

  *program = ocl->clLinkProgram (context, num_devices, device_list, options, num_input_programs, input_programs, pfn_notify, user_data, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clLinkProgram(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateKernel (void *hashcat_ctx, cl_program program, const char *kernel_name, cl_kernel *kernel)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  cl_int CL_err;

  *kernel = ocl->clCreateKernel (program, kernel_name, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateKernel(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseMemObject (void *hashcat_ctx, cl_mem mem)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseMemObject (mem);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseMemObject(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseKernel (void *hashcat_ctx, cl_kernel kernel)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseKernel (kernel);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseKernel(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseProgram (void *hashcat_ctx, cl_program program)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseProgram (program);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseProgram(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseCommandQueue (void *hashcat_ctx, cl_command_queue command_queue)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseCommandQueue (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseCommandQueue(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseContext (void *hashcat_ctx, cl_context context)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseContext (context);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseContext(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueMapBuffer (void *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event, void **buf)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  cl_int CL_err;

  *buf = ocl->clEnqueueMapBuffer (command_queue, buffer, blocking_map, map_flags, offset, size, num_events_in_wait_list, event_wait_list, event, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueMapBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueUnmapMemObject (void *hashcat_ctx, cl_command_queue command_queue, cl_mem memobj, void *mapped_ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueUnmapMemObject (command_queue, memobj, mapped_ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueUnmapMemObject(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetKernelWorkGroupInfo (void *hashcat_ctx, cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clGetKernelWorkGroupInfo (kernel, device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetKernelWorkGroupInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetProgramBuildInfo (void *hashcat_ctx, cl_program program, cl_device_id device, cl_program_build_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clGetProgramBuildInfo (program, device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetProgramBuildInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetProgramInfo (void *hashcat_ctx, cl_program program, cl_program_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clGetProgramInfo (program, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetProgramInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clWaitForEvents (void *hashcat_ctx, cl_uint num_events, const cl_event *event_list)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clWaitForEvents (num_events, event_list);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clWaitForEvents(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetEventProfilingInfo (void *hashcat_ctx, cl_event event, cl_profiling_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clGetEventProfilingInfo (event, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetEventProfilingInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseEvent (void *hashcat_ctx, cl_event event)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseEvent (event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseEvent(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

/*
int hc_clUnloadPlatformCompiler (void *hashcat_ctx, cl_platform_id platform)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  const cl_int CL_err = ocl->clUnloadPlatformCompiler (platform);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clUnloadPlatformCompiler(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}
*/
