/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#ifndef EXT_OPENCL_H
#define EXT_OPENCL_H

#include <common.h>

#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#define CL_USE_DEPRECATED_OPENCL_2_0_APIS

#ifdef DARWIN
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

#include <shared.h>

typedef cl_mem (CL_API_CALL *OCL_CLCREATEBUFFER)                 (cl_context, cl_mem_flags, size_t, void *, cl_int *);
typedef cl_command_queue (CL_API_CALL *OCL_CLCREATECOMMANDQUEUE) (cl_context, cl_device_id, cl_command_queue_properties, cl_int *);
typedef cl_context (CL_API_CALL *OCL_CLCREATECONTEXT)            (const cl_context_properties *, cl_uint, const cl_device_id *, void (CL_CALLBACK *)(const char *, const void *, size_t, void *), void *, cl_int *);
typedef cl_kernel (CL_API_CALL *OCL_CLCREATEKERNEL)              (cl_program, const char *, cl_int *);
typedef cl_program (CL_API_CALL *OCL_CLCREATEPROGRAMWITHSOURCE)  (cl_context, cl_uint, const char **, const size_t *, cl_int *);
typedef cl_program (CL_API_CALL *OCL_CLCREATEPROGRAMWITHBINARY)  (cl_context, cl_uint, const cl_device_id *, const size_t *, const unsigned char **, cl_int *, cl_int *);
typedef cl_int (CL_API_CALL *OCL_CLBUILDPROGRAM)                 (cl_program, cl_uint, const cl_device_id *, const char *, void (CL_CALLBACK *)(cl_program, void *), void *);
typedef cl_int (CL_API_CALL *OCL_CLENQUEUENDRANGEKERNEL)         (cl_command_queue, cl_kernel, cl_uint, const size_t *, const size_t *, const size_t *, cl_uint, const cl_event *, cl_event *);
typedef cl_int (CL_API_CALL *OCL_CLENQUEUEREADBUFFER)            (cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void *, cl_uint, const cl_event *, cl_event *);
typedef cl_int (CL_API_CALL *OCL_CLENQUEUEWRITEBUFFER)           (cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void *, cl_uint, const cl_event *, cl_event *);
typedef cl_int (CL_API_CALL *OCL_CLENQUEUECOPYBUFFER)            (cl_command_queue, cl_mem, cl_mem, size_t, size_t, size_t, cl_uint, const cl_event *, cl_event *);
typedef cl_int (CL_API_CALL *OCL_CLFLUSH)                        (cl_command_queue);
typedef cl_int (CL_API_CALL *OCL_CLFINISH)                       (cl_command_queue);
typedef cl_int (CL_API_CALL *OCL_CLGETDEVICEIDS)                 (cl_platform_id, cl_device_type, cl_uint, cl_device_id *, cl_uint *);
typedef cl_int (CL_API_CALL *OCL_CLGETDEVICEINFO)                (cl_device_id, cl_device_info, size_t, void *, size_t *);
typedef cl_int (CL_API_CALL *OCL_CLGETPLATFORMIDS)               (cl_uint, cl_platform_id *, cl_uint *);
typedef cl_int (CL_API_CALL *OCL_CLGETPLATFORMINFO)              (cl_platform_id, cl_platform_info, size_t, void *, size_t *);
typedef cl_int (CL_API_CALL *OCL_CLRELEASECOMMANDQUEUE)          (cl_command_queue);
typedef cl_int (CL_API_CALL *OCL_CLRELEASECONTEXT)               (cl_context);
typedef cl_int (CL_API_CALL *OCL_CLRELEASEKERNEL)                (cl_kernel);
typedef cl_int (CL_API_CALL *OCL_CLRELEASEMEMOBJECT)             (cl_mem);
typedef cl_int (CL_API_CALL *OCL_CLRELEASEPROGRAM)               (cl_program);
typedef cl_int (CL_API_CALL *OCL_CLSETKERNELARG)                 (cl_kernel, cl_uint, size_t, const void *);
typedef void * (CL_API_CALL *OCL_CLENQUEUEMAPBUFFER)             (cl_command_queue, cl_mem, cl_bool, cl_map_flags, size_t, size_t, cl_uint, const cl_event *, cl_event *, cl_int *);
typedef cl_int (CL_API_CALL *OCL_CLENQUEUEUNMAPMEMOBJECT)        (cl_command_queue, cl_mem, void *, cl_uint, const cl_event *, cl_event *);
typedef cl_int (CL_API_CALL *OCL_CLENQUEUEFILLBUFFER)            (cl_command_queue, cl_mem, const void *, size_t, size_t, size_t, cl_uint, const cl_event *, cl_event *);
typedef cl_int (CL_API_CALL *OCL_CLGETKERNELWORKGROUPINFO)       (cl_kernel, cl_device_id, cl_kernel_work_group_info, size_t, void *, size_t *);
typedef cl_int (CL_API_CALL *OCL_CLGETPROGRAMBUILDINFO)          (cl_program, cl_device_id, cl_program_build_info, size_t, void *, size_t *);
typedef cl_int (CL_API_CALL *OCL_CLGETPROGRAMINFO)               (cl_program, cl_program_info, size_t, void *, size_t *);
typedef cl_int (CL_API_CALL *OCL_CLGETEVENTINFO)                 (cl_event, cl_event_info, size_t, void *, size_t *);
typedef cl_int (CL_API_CALL *OCL_CLWAITFOREVENTS)                (cl_uint, const cl_event *);
typedef cl_int (CL_API_CALL *OCL_CLGETEVENTPROFILINGINFO)        (cl_event, cl_profiling_info, size_t, void *, size_t *);
typedef cl_int (CL_API_CALL *OCL_CLRELEASEEVENT)                 (cl_event);

typedef struct
{
  OCL_LIB lib;

  OCL_CLBUILDPROGRAM clBuildProgram;
  OCL_CLCREATEBUFFER clCreateBuffer;
  OCL_CLCREATECOMMANDQUEUE clCreateCommandQueue;
  OCL_CLCREATECONTEXT clCreateContext;
  OCL_CLCREATEKERNEL clCreateKernel;
  OCL_CLCREATEPROGRAMWITHBINARY clCreateProgramWithBinary;
  OCL_CLCREATEPROGRAMWITHSOURCE clCreateProgramWithSource;
  OCL_CLENQUEUECOPYBUFFER clEnqueueCopyBuffer;
  OCL_CLENQUEUEFILLBUFFER clEnqueueFillBuffer;
  OCL_CLENQUEUEMAPBUFFER clEnqueueMapBuffer;
  OCL_CLENQUEUENDRANGEKERNEL clEnqueueNDRangeKernel;
  OCL_CLENQUEUEREADBUFFER clEnqueueReadBuffer;
  OCL_CLENQUEUEUNMAPMEMOBJECT clEnqueueUnmapMemObject;
  OCL_CLENQUEUEWRITEBUFFER clEnqueueWriteBuffer;
  OCL_CLFINISH clFinish;
  OCL_CLFLUSH clFlush;
  OCL_CLGETDEVICEIDS clGetDeviceIDs;
  OCL_CLGETDEVICEINFO clGetDeviceInfo;
  OCL_CLGETEVENTINFO clGetEventInfo;
  OCL_CLGETKERNELWORKGROUPINFO clGetKernelWorkGroupInfo;
  OCL_CLGETPLATFORMIDS clGetPlatformIDs;
  OCL_CLGETPLATFORMINFO clGetPlatformInfo;
  OCL_CLGETPROGRAMBUILDINFO clGetProgramBuildInfo;
  OCL_CLGETPROGRAMINFO clGetProgramInfo;
  OCL_CLRELEASECOMMANDQUEUE clReleaseCommandQueue;
  OCL_CLRELEASECONTEXT clReleaseContext;
  OCL_CLRELEASEKERNEL clReleaseKernel;
  OCL_CLRELEASEMEMOBJECT clReleaseMemObject;
  OCL_CLRELEASEPROGRAM clReleaseProgram;
  OCL_CLSETKERNELARG clSetKernelArg;
  OCL_CLWAITFOREVENTS clWaitForEvents;
  OCL_CLGETEVENTPROFILINGINFO clGetEventProfilingInfo;
  OCL_CLRELEASEEVENT clReleaseEvent;

} hc_opencl_lib_t;

#define OCL_PTR hc_opencl_lib_t

int ocl_init (OCL_PTR *ocl);
void ocl_close (OCL_PTR *ocl);

cl_mem hc_clCreateBuffer (OCL_PTR *ocl, cl_context context, cl_mem_flags flags, size_t size, void *host_ptr);
cl_command_queue hc_clCreateCommandQueue (OCL_PTR *ocl, cl_context context, cl_device_id device, cl_command_queue_properties properties);
//cl_command_queue hc_clCreateCommandQueueWithProperties (cl_context context, cl_device_id device, const cl_queue_properties *properties);
cl_context hc_clCreateContext (OCL_PTR *ocl, cl_context_properties *properties, cl_uint num_devices, const cl_device_id *devices, void (CL_CALLBACK *pfn_notify) (const char *, const void *, size_t, void *), void *user_data);
cl_kernel hc_clCreateKernel (OCL_PTR *ocl, cl_program program, const char *kernel_name);
cl_program hc_clCreateProgramWithSource (OCL_PTR *ocl, cl_context context, cl_uint count, const char **strings, const size_t *lengths);
cl_program hc_clCreateProgramWithBinary (OCL_PTR *ocl, cl_context context, cl_uint num_devices, const cl_device_id *device_list, const size_t *lengths, const unsigned char **binaries, cl_int *binary_status);
cl_int hc_clBuildProgram (OCL_PTR *ocl, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data, bool exitOnFail);
void hc_clEnqueueNDRangeKernel (OCL_PTR *ocl, cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clEnqueueReadBuffer (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t cb, void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clEnqueueWriteBuffer (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t cb, const void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clEnqueueCopyBuffer (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clFlush (OCL_PTR *ocl, cl_command_queue command_queue);
void hc_clFinish (OCL_PTR *ocl, cl_command_queue command_queue);
void hc_clGetDeviceIDs (OCL_PTR *ocl, cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id *devices, cl_uint *num_devices);
void hc_clGetDeviceInfo (OCL_PTR *ocl, cl_device_id device, cl_device_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
void hc_clGetPlatformIDs (OCL_PTR *ocl, cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms);
void hc_clGetPlatformInfo (OCL_PTR *ocl, cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
void hc_clReleaseCommandQueue (OCL_PTR *ocl, cl_command_queue command_queue);
void hc_clReleaseContext (OCL_PTR *ocl, cl_context context);
void hc_clReleaseKernel (OCL_PTR *ocl, cl_kernel kernel);
void hc_clReleaseMemObject (OCL_PTR *ocl, cl_mem mem);
void hc_clReleaseProgram (OCL_PTR *ocl, cl_program program);
void hc_clSetKernelArg (OCL_PTR *ocl, cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void *arg_value);
void *hc_clEnqueueMapBuffer (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clEnqueueUnmapMemObject (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem memobj, void *mapped_ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
cl_int hc_clEnqueueFillBuffer (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, const void *pattern, size_t pattern_size, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
void hc_clGetKernelWorkGroupInfo (OCL_PTR *ocl, cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
cl_int hc_clGetProgramBuildInfo (OCL_PTR *ocl, cl_program program, cl_device_id device, cl_program_build_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
void hc_clGetProgramInfo (OCL_PTR *ocl, cl_program program, cl_program_info param_name, size_t param_value_size, void *param_value, size_t * param_value_size_ret);
void hc_clGetEventInfo (OCL_PTR *ocl, cl_event event, cl_event_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
void hc_clWaitForEvents (OCL_PTR *ocl, cl_uint num_events, const cl_event *event_list);
void hc_clGetEventProfilingInfo (OCL_PTR *ocl, cl_event event, cl_profiling_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
void hc_clReleaseEvent (OCL_PTR *ocl, cl_event event);

#endif
