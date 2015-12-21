/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_OpenCL.h>

void hc_clEnqueueNDRangeKernel (cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = clEnqueueNDRangeKernel (command_queue, kernel, work_dim, global_work_offset, global_work_size, local_work_size, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clEnqueueNDRangeKernel()", CL_err);

    exit (-1);
  }
}

void hc_clGetEventInfo (cl_event event, cl_event_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  cl_int CL_err = clGetEventInfo (event, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clGetEventInfo()", CL_err);

    exit (-1);
  }
}

void hc_clFlush (cl_command_queue command_queue)
{
  cl_int CL_err = clFlush (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clFlush()", CL_err);

    exit (-1);
  }
}

void hc_clFinish (cl_command_queue command_queue)
{
  cl_int CL_err = clFinish (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clFinish()", CL_err);

    exit (-1);
  }
}

void hc_clSetKernelArg (cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void *arg_value)
{
  cl_int CL_err = clSetKernelArg (kernel, arg_index, arg_size, arg_value);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clSetKernelArg()", CL_err);

    exit (-1);
  }
}

void hc_clEnqueueWriteBuffer (cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t cb, const void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = clEnqueueWriteBuffer (command_queue, buffer, blocking_write, offset, cb, ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clEnqueueWriteBuffer()", CL_err);

    exit (-1);
  }
}

void hc_clEnqueueCopyBuffer (cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = clEnqueueCopyBuffer (command_queue, src_buffer, dst_buffer, src_offset, dst_offset, cb, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clEnqueueCopyBuffer()", CL_err);

    exit (-1);
  }
}

void hc_clEnqueueReadBuffer (cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t cb, void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = clEnqueueReadBuffer (command_queue, buffer, blocking_read, offset, cb, ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clEnqueueReadBuffer()", CL_err);

    exit (-1);
  }
}

void hc_clGetPlatformIDs (cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms)
{
  cl_int CL_err = clGetPlatformIDs (num_entries, platforms, num_platforms);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clGetPlatformIDs()", CL_err);

    exit (-1);
  }
}

void hc_clGetPlatformInfo (cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  cl_int CL_err = clGetPlatformInfo (platform, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clGetPlatformInfo()", CL_err);

    exit (-1);
  }
}

void hc_clGetDeviceIDs (cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id *devices, cl_uint *num_devices)
{
  cl_int CL_err = clGetDeviceIDs (platform, device_type, num_entries, devices, num_devices);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clGetDeviceIDs()", CL_err);

    exit (-1);
  }
}

void hc_clGetDeviceInfo (cl_device_id device, cl_device_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  cl_int CL_err = clGetDeviceInfo (device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clGetDeviceInfo()", CL_err);

    exit (-1);
  }
}

cl_context hc_clCreateContext (cl_context_properties *properties, cl_uint num_devices, const cl_device_id *devices, void (CL_CALLBACK *pfn_notify) (const char *, const void *, size_t, void *), void *user_data)
{
  cl_int CL_err;

  cl_context context = clCreateContext (properties, num_devices, devices, pfn_notify, user_data, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clCreateContext()", CL_err);

    exit (-1);
  }

  return (context);
}


cl_command_queue hc_clCreateCommandQueue (cl_context context, cl_device_id device, cl_command_queue_properties properties)
{
  cl_int CL_err;

  cl_command_queue command_queue = clCreateCommandQueue (context, device, properties, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clCreateCommandQueue()", CL_err);

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
    log_error ("ERROR: %s %d\n", "clCreateCommandQueueWithProperties()", CL_err);

    exit (-1);
  }

  return (command_queue);
}
*/

cl_mem hc_clCreateBuffer (cl_context context, cl_mem_flags flags, size_t size, void *host_ptr)
{
  cl_int CL_err;

  cl_mem mem = clCreateBuffer (context, flags, size, host_ptr, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clCreateBuffer()", CL_err);

    exit (-1);
  }

  return (mem);
}

cl_program hc_clCreateProgramWithSource (cl_context context, cl_uint count, const char **strings, const size_t *lengths)
{
  cl_int CL_err;

  cl_program program = clCreateProgramWithSource (context, count, strings, lengths, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clCreateProgramWithSource()", CL_err);

    exit (-1);
  }

  return (program);
}

cl_program hc_clCreateProgramWithBinary (cl_context context, cl_uint num_devices, const cl_device_id *device_list, const size_t *lengths, const unsigned char **binaries, cl_int *binary_status)
{
  cl_int CL_err;

  cl_program program = clCreateProgramWithBinary (context, num_devices, device_list, lengths, binaries, binary_status, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clCreateProgramWithBinary()", CL_err);

    exit (-1);
  }

  return (program);
}

void hc_clBuildProgram (cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data)
{
  cl_int CL_err = clBuildProgram (program, num_devices, device_list, options, pfn_notify, user_data);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clBuildProgram()", CL_err);

    exit (-1);
  }
}

cl_kernel hc_clCreateKernel (cl_program program, const char *kernel_name)
{
  cl_int CL_err;

  cl_kernel kernel = clCreateKernel (program, kernel_name, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d - %s\n", "clCreateKernel()", CL_err, kernel_name);

    exit (-1);
  }

  return (kernel);
}

void hc_clReleaseMemObject (cl_mem mem)
{
  cl_int CL_err = clReleaseMemObject (mem);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clReleaseMemObject()", CL_err);

    exit (-1);
  }
}

void hc_clReleaseKernel (cl_kernel kernel)
{
  cl_int CL_err = clReleaseKernel (kernel);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clReleaseProgram()", CL_err);

    exit (-1);
  }
}

void hc_clReleaseProgram (cl_program program)
{
  cl_int CL_err = clReleaseProgram (program);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clReleaseProgram()", CL_err);

    exit (-1);
  }
}

void hc_clReleaseCommandQueue (cl_command_queue command_queue)
{
  cl_int CL_err = clReleaseCommandQueue (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clReleaseCommandQueue()", CL_err);

    exit (-1);
  }
}

void hc_clReleaseContext (cl_context context)
{
  cl_int CL_err = clReleaseContext (context);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clReleaseContext()", CL_err);

    exit (-1);
  }
}

void *hc_clEnqueueMapBuffer (cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, cl_map_flags map_flags, size_t offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err;

  void *buf = clEnqueueMapBuffer (command_queue, buffer, blocking_read, map_flags, offset, cb, num_events_in_wait_list, event_wait_list, event, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clEnqueueMapBuffer()", CL_err);

    exit (-1);
  }

  return buf;
}

void hc_clEnqueueUnmapMemObject (cl_command_queue command_queue, cl_mem memobj, void *mapped_ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = clEnqueueUnmapMemObject (command_queue, memobj, mapped_ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clEnqueueUnmapMemObject()", CL_err);

    exit (-1);
  }
}

void hc_clEnqueueFillBuffer (cl_command_queue command_queue, cl_mem buffer, const void *pattern, size_t pattern_size, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  cl_int CL_err = clEnqueueFillBuffer (command_queue, buffer, pattern, pattern_size, offset, size, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "clEnqueueFillBuffer()", CL_err);

    exit (-1);
  }
}
