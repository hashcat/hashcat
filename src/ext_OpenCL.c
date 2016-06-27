/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#include <ext_OpenCL.h>

const char *val2cstr_cl (cl_int CL_err)
{
  #define CLERR(a) case a: return #a

  switch (CL_err)
  {
    CLERR (CL_BUILD_PROGRAM_FAILURE);
    CLERR (CL_COMPILER_NOT_AVAILABLE);
    CLERR (CL_DEVICE_NOT_FOUND);
    CLERR (CL_INVALID_ARG_INDEX);
    CLERR (CL_INVALID_ARG_SIZE);
    CLERR (CL_INVALID_ARG_VALUE);
    CLERR (CL_INVALID_BINARY);
    CLERR (CL_INVALID_BUFFER_SIZE);
    CLERR (CL_INVALID_BUILD_OPTIONS);
    CLERR (CL_INVALID_COMMAND_QUEUE);
    CLERR (CL_INVALID_CONTEXT);
    CLERR (CL_INVALID_DEVICE);
    CLERR (CL_INVALID_DEVICE_TYPE);
    CLERR (CL_INVALID_EVENT);
    CLERR (CL_INVALID_EVENT_WAIT_LIST);
    CLERR (CL_INVALID_GLOBAL_OFFSET);
    CLERR (CL_INVALID_HOST_PTR);
    CLERR (CL_INVALID_KERNEL);
    CLERR (CL_INVALID_KERNEL_ARGS);
    CLERR (CL_INVALID_KERNEL_DEFINITION);
    CLERR (CL_INVALID_KERNEL_NAME);
    CLERR (CL_INVALID_MEM_OBJECT);
    CLERR (CL_INVALID_OPERATION);
    CLERR (CL_INVALID_PLATFORM);
    CLERR (CL_INVALID_PROGRAM);
    CLERR (CL_INVALID_PROGRAM_EXECUTABLE);
    CLERR (CL_INVALID_QUEUE_PROPERTIES);
    CLERR (CL_INVALID_SAMPLER);
    CLERR (CL_INVALID_VALUE);
    CLERR (CL_INVALID_WORK_DIMENSION);
    CLERR (CL_INVALID_WORK_GROUP_SIZE);
    CLERR (CL_INVALID_WORK_ITEM_SIZE);
    CLERR (CL_MISALIGNED_SUB_BUFFER_OFFSET);
    CLERR (CL_MAP_FAILURE);
    CLERR (CL_MEM_COPY_OVERLAP);
    CLERR (CL_MEM_OBJECT_ALLOCATION_FAILURE);
    CLERR (CL_OUT_OF_HOST_MEMORY);
    CLERR (CL_OUT_OF_RESOURCES);
  }

  return "CL_UNKNOWN_ERROR";
}

int ocl_init (OCL_PTR *ocl)
{
  if (!ocl)
  {
    log_error ("ERROR: OpenCL library pointer is null");

    exit (-1);
  }

  memset (ocl, 0, sizeof (hc_opencl_lib_t));

  #ifdef _WIN
  ocl->lib = hc_dlopen ("OpenCL");
  #elif DARWIN
  ocl->lib = hc_dlopen ("/System/Library/Frameworks/OpenCL.framework/OpenCL", RTLD_NOW);
  #else
  ocl->lib = hc_dlopen ("libOpenCL.so", RTLD_NOW);

  if (ocl->lib == NULL) ocl->lib = hc_dlopen ("libOpenCL.so.1", RTLD_NOW);
  #endif

  if (ocl->lib == NULL)
  {
    log_info ("");
    log_info ("ATTENTION! Can't find OpenCL ICD loader library");
    log_info ("");
    #if defined (LINUX)
    log_info ("You're probably missing the \"ocl-icd-libopencl1\" package (Debian/Ubuntu)");
    log_info ("  sudo apt-get install ocl-icd-libopencl1");
    log_info ("");
    #elif defined (WIN)
    log_info ("You're probably missing the OpenCL runtime installation");
    log_info ("  AMD users require AMD drivers 14.9 or later (recommended 15.12 or later)");
    log_info ("  Intel users require Intel OpenCL Runtime 14.2 or later (recommended 15.1 or later)");
    log_info ("  NVidia users require NVidia drivers 346.59 or later (recommended 361.x or later)");
    log_info ("");
    #endif

    exit (-1);
  }

  HC_LOAD_FUNC(ocl, clBuildProgram, OCL_CLBUILDPROGRAM, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateBuffer, OCL_CLCREATEBUFFER, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateCommandQueue, OCL_CLCREATECOMMANDQUEUE, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateContext, OCL_CLCREATECONTEXT, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateKernel, OCL_CLCREATEKERNEL, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateProgramWithBinary, OCL_CLCREATEPROGRAMWITHBINARY, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateProgramWithSource, OCL_CLCREATEPROGRAMWITHSOURCE, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueCopyBuffer, OCL_CLENQUEUECOPYBUFFER, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueFillBuffer, OCL_CLENQUEUEFILLBUFFER, OpenCL, -1)
  HC_LOAD_FUNC(ocl, clEnqueueMapBuffer, OCL_CLENQUEUEMAPBUFFER, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueNDRangeKernel, OCL_CLENQUEUENDRANGEKERNEL, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueReadBuffer, OCL_CLENQUEUEREADBUFFER, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueUnmapMemObject, OCL_CLENQUEUEUNMAPMEMOBJECT, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueWriteBuffer, OCL_CLENQUEUEWRITEBUFFER, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clFinish, OCL_CLFINISH, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clFlush, OCL_CLFLUSH, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetDeviceIDs, OCL_CLGETDEVICEIDS, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetDeviceInfo, OCL_CLGETDEVICEINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetEventInfo, OCL_CLGETEVENTINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetKernelWorkGroupInfo, OCL_CLGETKERNELWORKGROUPINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetPlatformIDs, OCL_CLGETPLATFORMIDS, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetPlatformInfo, OCL_CLGETPLATFORMINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetProgramBuildInfo, OCL_CLGETPROGRAMBUILDINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetProgramInfo, OCL_CLGETPROGRAMINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseCommandQueue, OCL_CLRELEASECOMMANDQUEUE, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseContext, OCL_CLRELEASECONTEXT, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseKernel, OCL_CLRELEASEKERNEL, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseMemObject, OCL_CLRELEASEMEMOBJECT, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseProgram, OCL_CLRELEASEPROGRAM, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clSetKernelArg, OCL_CLSETKERNELARG, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clWaitForEvents, OCL_CLWAITFOREVENTS, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetEventProfilingInfo, OCL_CLGETEVENTPROFILINGINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseEvent, OCL_CLRELEASEEVENT, OpenCL, 1)

  return 0;
}

void ocl_close (OCL_PTR *ocl)
{
  if (ocl)
  {
    if (ocl->lib)
      hc_dlclose (ocl->lib);

    free (ocl);
  }
}

void hc_clEnqueueNDRangeKernel (OCL_PTR *ocl, cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = ocl->clEnqueueNDRangeKernel (command_queue, kernel, work_dim, global_work_offset, global_work_size, local_work_size, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clEnqueueNDRangeKernel()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clGetEventInfo (OCL_PTR *ocl, cl_event event, cl_event_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  cl_int CL_err = ocl->clGetEventInfo (event, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clGetEventInfo()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clFlush (OCL_PTR *ocl, cl_command_queue command_queue)
{
  cl_int CL_err = ocl->clFlush (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clFlush()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clFinish (OCL_PTR *ocl, cl_command_queue command_queue)
{
  cl_int CL_err = ocl->clFinish (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clFinish()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clSetKernelArg (OCL_PTR *ocl, cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void *arg_value)
{
  cl_int CL_err = ocl->clSetKernelArg (kernel, arg_index, arg_size, arg_value);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clSetKernelArg()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clEnqueueWriteBuffer (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t cb, const void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = ocl->clEnqueueWriteBuffer (command_queue, buffer, blocking_write, offset, cb, ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clEnqueueWriteBuffer()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clEnqueueCopyBuffer (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = ocl->clEnqueueCopyBuffer (command_queue, src_buffer, dst_buffer, src_offset, dst_offset, cb, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clEnqueueCopyBuffer()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clEnqueueReadBuffer (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t cb, void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = ocl->clEnqueueReadBuffer (command_queue, buffer, blocking_read, offset, cb, ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clEnqueueReadBuffer()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clGetPlatformIDs (OCL_PTR *ocl, cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms)
{
  cl_int CL_err = ocl->clGetPlatformIDs (num_entries, platforms, num_platforms);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clGetPlatformIDs()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clGetPlatformInfo (OCL_PTR *ocl, cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  cl_int CL_err = ocl->clGetPlatformInfo (platform, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clGetPlatformInfo()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clGetDeviceIDs (OCL_PTR *ocl, cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id *devices, cl_uint *num_devices)
{
  cl_int CL_err = ocl->clGetDeviceIDs (platform, device_type, num_entries, devices, num_devices);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clGetDeviceIDs()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clGetDeviceInfo (OCL_PTR *ocl, cl_device_id device, cl_device_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  cl_int CL_err = ocl->clGetDeviceInfo (device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clGetDeviceInfo()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

cl_context hc_clCreateContext (OCL_PTR *ocl, cl_context_properties *properties, cl_uint num_devices, const cl_device_id *devices, void (CL_CALLBACK *pfn_notify) (const char *, const void *, size_t, void *), void *user_data)
{
  cl_int CL_err;

  cl_context context = ocl->clCreateContext (properties, num_devices, devices, pfn_notify, user_data, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clCreateContext()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }

  return (context);
}

cl_command_queue hc_clCreateCommandQueue (OCL_PTR *ocl, cl_context context, cl_device_id device, cl_command_queue_properties properties)
{
  cl_int CL_err;

  cl_command_queue command_queue = ocl->clCreateCommandQueue (context, device, properties, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clCreateCommandQueue()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }

  return (command_queue);
}

/*
cl_command_queue hc_clCreateCommandQueueWithProperties (cl_context context, cl_device_id device, const cl_queue_properties *properties)
{
  cl_int CL_err;

  cl_command_queue command_queue = clCreateCommandQueueWithProperties (context, device, properties, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clCreateCommandQueueWithProperties()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }

  return (command_queue);
}
*/

cl_mem hc_clCreateBuffer (OCL_PTR *ocl, cl_context context, cl_mem_flags flags, size_t size, void *host_ptr)
{
  cl_int CL_err;

  cl_mem mem = ocl->clCreateBuffer (context, flags, size, host_ptr, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clCreateBuffer()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }

  return (mem);
}

cl_program hc_clCreateProgramWithSource (OCL_PTR *ocl, cl_context context, cl_uint count, const char **strings, const size_t *lengths)
{
  cl_int CL_err;

  cl_program program = ocl->clCreateProgramWithSource (context, count, strings, lengths, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clCreateProgramWithSource()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }

  return (program);
}

cl_program hc_clCreateProgramWithBinary (OCL_PTR *ocl, cl_context context, cl_uint num_devices, const cl_device_id *device_list, const size_t *lengths, const unsigned char **binaries, cl_int *binary_status)
{
  cl_int CL_err;

  cl_program program = ocl->clCreateProgramWithBinary (context, num_devices, device_list, lengths, binaries, binary_status, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clCreateProgramWithBinary()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }

  return (program);
}

cl_int hc_clBuildProgram (OCL_PTR *ocl, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data, bool exitOnFail)
{
  cl_int CL_err = ocl->clBuildProgram (program, num_devices, device_list, options, pfn_notify, user_data);

  if (CL_err != CL_SUCCESS)
  {
    size_t len = strlen (options) + 256;

    char *options_update = (char *) mymalloc (len + 1);

    snprintf (options_update, len, "%s -cl-opt-disable", options);

    if (data.quiet == 0) log_error ("\n=== Build failed, retry with optimization disabled ===\n");

    CL_err = ocl->clBuildProgram (program, num_devices, device_list, options_update, pfn_notify, user_data);

    myfree (options_update);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: %s : %d : %s\n", "clBuildProgram()", CL_err, val2cstr_cl (CL_err));

      log_error ("\n=== Build Options : %s ===\n", options);

      size_t len = 0;

      cl_int err = hc_clGetProgramBuildInfo (ocl, program, *device_list, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);

      if (err == CL_SUCCESS && len > 0)
      {
        char *buf = (char *) mymalloc (len + 1);

        if (hc_clGetProgramBuildInfo (ocl, program, *device_list, CL_PROGRAM_BUILD_LOG, len, buf, NULL) == CL_SUCCESS)
        {
          fprintf (stderr, "\n=== Build Log (start) ===\n%s\n=== Build Log (end) ===\n", buf);
        }

        myfree (buf);
      }

      if (exitOnFail) exit (-1);

      return (-1);
    }
  }

  return 0;
}

cl_kernel hc_clCreateKernel (OCL_PTR *ocl, cl_program program, const char *kernel_name)
{
  cl_int CL_err;

  cl_kernel kernel = ocl->clCreateKernel (program, kernel_name, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d - %s\n", "clCreateKernel()", CL_err, kernel_name);

    exit (-1);
  }

  return (kernel);
}

void hc_clReleaseMemObject (OCL_PTR *ocl, cl_mem mem)
{
  cl_int CL_err = ocl->clReleaseMemObject (mem);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clReleaseMemObject()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clReleaseKernel (OCL_PTR *ocl, cl_kernel kernel)
{
  cl_int CL_err = ocl->clReleaseKernel (kernel);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clReleaseProgram()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clReleaseProgram (OCL_PTR *ocl, cl_program program)
{
  cl_int CL_err = ocl->clReleaseProgram (program);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clReleaseProgram()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clReleaseCommandQueue (OCL_PTR *ocl, cl_command_queue command_queue)
{
  cl_int CL_err = ocl->clReleaseCommandQueue (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clReleaseCommandQueue()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clReleaseContext (OCL_PTR *ocl, cl_context context)
{
  cl_int CL_err = ocl->clReleaseContext (context);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clReleaseContext()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void *hc_clEnqueueMapBuffer (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, cl_map_flags map_flags, size_t offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err;

  void *buf = ocl->clEnqueueMapBuffer (command_queue, buffer, blocking_read, map_flags, offset, cb, num_events_in_wait_list, event_wait_list, event, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clEnqueueMapBuffer()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }

  return buf;
}

void hc_clEnqueueUnmapMemObject (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem memobj, void *mapped_ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = ocl->clEnqueueUnmapMemObject (command_queue, memobj, mapped_ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clEnqueueUnmapMemObject()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

cl_int hc_clEnqueueFillBuffer (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, const void *pattern, size_t pattern_size, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = -1;

  if (ocl->clEnqueueFillBuffer)
  {
    CL_err = ocl->clEnqueueFillBuffer (command_queue, buffer, pattern, pattern_size, offset, size, num_events_in_wait_list, event_wait_list, event);

    if (CL_err != CL_SUCCESS && data.quiet == 0)
      log_error ("WARNING: %s : %d : %s\n", "clEnqueueFillBuffer()", CL_err, val2cstr_cl (CL_err));
  }

  return CL_err;
}

void hc_clGetKernelWorkGroupInfo (OCL_PTR *ocl, cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  cl_int CL_err = ocl->clGetKernelWorkGroupInfo (kernel, device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clGetKernelWorkGroupInfo()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

cl_int hc_clGetProgramBuildInfo (OCL_PTR *ocl, cl_program program, cl_device_id device, cl_program_build_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  cl_int CL_err = ocl->clGetProgramBuildInfo (program, device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clGetProgramBuildInfo()", CL_err, val2cstr_cl (CL_err));

    return (-1);
  }

  return CL_err;
}

void hc_clGetProgramInfo (OCL_PTR *ocl, cl_program program, cl_program_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  cl_int CL_err = ocl->clGetProgramInfo (program, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clGetProgramInfo()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clWaitForEvents (OCL_PTR *ocl, cl_uint num_events, const cl_event *event_list)
{
  cl_int CL_err = ocl->clWaitForEvents (num_events, event_list);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clWaitForEvents()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clGetEventProfilingInfo (OCL_PTR *ocl, cl_event event, cl_profiling_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  cl_int CL_err = ocl->clGetEventProfilingInfo (event, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clGetEventProfilingInfo()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}

void hc_clReleaseEvent (OCL_PTR *ocl, cl_event event)
{
  cl_int CL_err = ocl->clReleaseEvent (event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s : %d : %s\n", "clReleaseEvent()", CL_err, val2cstr_cl (CL_err));

    exit (-1);
  }
}
