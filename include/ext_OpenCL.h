/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_OPENCL_H
#define _EXT_OPENCL_H

#define CL_TARGET_OPENCL_VERSION 120

#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#define CL_USE_DEPRECATED_OPENCL_2_0_APIS

#if defined (__APPLE__)
#include <OpenCL/cl.h>
#else
#include <CL/cl.h>
#endif

// NVIDIA extras

#define CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV       0x4000
#define CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV       0x4001
#define CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV            0x4005
#define CL_DEVICE_PCI_BUS_ID_NV                     0x4008
#define CL_DEVICE_PCI_SLOT_ID_NV                    0x4009

// AMD extras

#define CL_DEVICE_TOPOLOGY_AMD                      0x4037

typedef union
{
    struct { cl_uint type; cl_uint data[5]; } raw;
    struct { cl_uint type; cl_char unused[17]; cl_char bus; cl_char device; cl_char function; } pcie;
} cl_device_topology_amd;

#define CL_PLATFORMS_MAX 16

typedef cl_int           (CL_API_CALL *OCL_CLBUILDPROGRAM)            (cl_program, cl_uint, const cl_device_id *, const char *, void (CL_CALLBACK *)(cl_program, void *), void *);
typedef cl_mem           (CL_API_CALL *OCL_CLCREATEBUFFER)            (cl_context, cl_mem_flags, size_t, void *, cl_int *);
typedef cl_command_queue (CL_API_CALL *OCL_CLCREATECOMMANDQUEUE)      (cl_context, cl_device_id, cl_command_queue_properties, cl_int *);
typedef cl_context       (CL_API_CALL *OCL_CLCREATECONTEXT)           (const cl_context_properties *, cl_uint, const cl_device_id *, void (CL_CALLBACK *)(const char *, const void *, size_t, void *), void *, cl_int *);
typedef cl_kernel        (CL_API_CALL *OCL_CLCREATEKERNEL)            (cl_program, const char *, cl_int *);
typedef cl_program       (CL_API_CALL *OCL_CLCREATEPROGRAMWITHBINARY) (cl_context, cl_uint, const cl_device_id *, const size_t *, const unsigned char **, cl_int *, cl_int *);
typedef cl_program       (CL_API_CALL *OCL_CLCREATEPROGRAMWITHSOURCE) (cl_context, cl_uint, const char **, const size_t *, cl_int *);
typedef cl_int           (CL_API_CALL *OCL_CLENQUEUECOPYBUFFER)       (cl_command_queue, cl_mem, cl_mem, size_t, size_t, size_t, cl_uint, const cl_event *, cl_event *);
typedef void *           (CL_API_CALL *OCL_CLENQUEUEMAPBUFFER)        (cl_command_queue, cl_mem, cl_bool, cl_map_flags, size_t, size_t, cl_uint, const cl_event *, cl_event *, cl_int *);
typedef cl_int           (CL_API_CALL *OCL_CLENQUEUENDRANGEKERNEL)    (cl_command_queue, cl_kernel, cl_uint, const size_t *, const size_t *, const size_t *, cl_uint, const cl_event *, cl_event *);
typedef cl_int           (CL_API_CALL *OCL_CLENQUEUEREADBUFFER)       (cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void *, cl_uint, const cl_event *, cl_event *);
typedef cl_int           (CL_API_CALL *OCL_CLENQUEUEUNMAPMEMOBJECT)   (cl_command_queue, cl_mem, void *, cl_uint, const cl_event *, cl_event *);
typedef cl_int           (CL_API_CALL *OCL_CLENQUEUEWRITEBUFFER)      (cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void *, cl_uint, const cl_event *, cl_event *);
typedef cl_int           (CL_API_CALL *OCL_CLFINISH)                  (cl_command_queue);
typedef cl_int           (CL_API_CALL *OCL_CLFLUSH)                   (cl_command_queue);
typedef cl_int           (CL_API_CALL *OCL_CLGETDEVICEIDS)            (cl_platform_id, cl_device_type, cl_uint, cl_device_id *, cl_uint *);
typedef cl_int           (CL_API_CALL *OCL_CLGETDEVICEINFO)           (cl_device_id, cl_device_info, size_t, void *, size_t *);
typedef cl_int           (CL_API_CALL *OCL_CLGETEVENTINFO)            (cl_event, cl_event_info, size_t, void *, size_t *);
typedef cl_int           (CL_API_CALL *OCL_CLGETEVENTPROFILINGINFO)   (cl_event, cl_profiling_info, size_t, void *, size_t *);
typedef cl_int           (CL_API_CALL *OCL_CLGETKERNELWORKGROUPINFO)  (cl_kernel, cl_device_id, cl_kernel_work_group_info, size_t, void *, size_t *);
typedef cl_int           (CL_API_CALL *OCL_CLGETPLATFORMIDS)          (cl_uint, cl_platform_id *, cl_uint *);
typedef cl_int           (CL_API_CALL *OCL_CLGETPLATFORMINFO)         (cl_platform_id, cl_platform_info, size_t, void *, size_t *);
typedef cl_int           (CL_API_CALL *OCL_CLGETPROGRAMBUILDINFO)     (cl_program, cl_device_id, cl_program_build_info, size_t, void *, size_t *);
typedef cl_int           (CL_API_CALL *OCL_CLGETPROGRAMINFO)          (cl_program, cl_program_info, size_t, void *, size_t *);
typedef cl_int           (CL_API_CALL *OCL_CLRELEASECOMMANDQUEUE)     (cl_command_queue);
typedef cl_int           (CL_API_CALL *OCL_CLRELEASECONTEXT)          (cl_context);
typedef cl_int           (CL_API_CALL *OCL_CLRELEASEEVENT)            (cl_event);
typedef cl_int           (CL_API_CALL *OCL_CLRELEASEKERNEL)           (cl_kernel);
typedef cl_int           (CL_API_CALL *OCL_CLRELEASEMEMOBJECT)        (cl_mem);
typedef cl_int           (CL_API_CALL *OCL_CLRELEASEPROGRAM)          (cl_program);
typedef cl_int           (CL_API_CALL *OCL_CLSETKERNELARG)            (cl_kernel, cl_uint, size_t, const void *);
typedef cl_int           (CL_API_CALL *OCL_CLWAITFOREVENTS)           (cl_uint, const cl_event *);

typedef struct hc_opencl_lib
{
  hc_dynlib_t lib;

  OCL_CLBUILDPROGRAM            clBuildProgram;
  OCL_CLCREATEBUFFER            clCreateBuffer;
  OCL_CLCREATECOMMANDQUEUE      clCreateCommandQueue;
  OCL_CLCREATECONTEXT           clCreateContext;
  OCL_CLCREATEKERNEL            clCreateKernel;
  OCL_CLCREATEPROGRAMWITHBINARY clCreateProgramWithBinary;
  OCL_CLCREATEPROGRAMWITHSOURCE clCreateProgramWithSource;
  OCL_CLENQUEUECOPYBUFFER       clEnqueueCopyBuffer;
  OCL_CLENQUEUEMAPBUFFER        clEnqueueMapBuffer;
  OCL_CLENQUEUENDRANGEKERNEL    clEnqueueNDRangeKernel;
  OCL_CLENQUEUEREADBUFFER       clEnqueueReadBuffer;
  OCL_CLENQUEUEUNMAPMEMOBJECT   clEnqueueUnmapMemObject;
  OCL_CLENQUEUEWRITEBUFFER      clEnqueueWriteBuffer;
  OCL_CLFINISH                  clFinish;
  OCL_CLFLUSH                   clFlush;
  OCL_CLGETDEVICEIDS            clGetDeviceIDs;
  OCL_CLGETDEVICEINFO           clGetDeviceInfo;
  OCL_CLGETEVENTINFO            clGetEventInfo;
  OCL_CLGETEVENTPROFILINGINFO   clGetEventProfilingInfo;
  OCL_CLGETKERNELWORKGROUPINFO  clGetKernelWorkGroupInfo;
  OCL_CLGETPLATFORMIDS          clGetPlatformIDs;
  OCL_CLGETPLATFORMINFO         clGetPlatformInfo;
  OCL_CLGETPROGRAMBUILDINFO     clGetProgramBuildInfo;
  OCL_CLGETPROGRAMINFO          clGetProgramInfo;
  OCL_CLRELEASECOMMANDQUEUE     clReleaseCommandQueue;
  OCL_CLRELEASECONTEXT          clReleaseContext;
  OCL_CLRELEASEEVENT            clReleaseEvent;
  OCL_CLRELEASEKERNEL           clReleaseKernel;
  OCL_CLRELEASEMEMOBJECT        clReleaseMemObject;
  OCL_CLRELEASEPROGRAM          clReleaseProgram;
  OCL_CLSETKERNELARG            clSetKernelArg;
  OCL_CLWAITFOREVENTS           clWaitForEvents;

} hc_opencl_lib_t;

typedef hc_opencl_lib_t OCL_PTR;

const char *val2cstr_cl (cl_int CL_err);

#endif // _EXT_OPENCL_H
