/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#ifndef _EXT_OPENCL_H
#define _EXT_OPENCL_H

#include <stdio.h>

#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#define CL_USE_DEPRECATED_OPENCL_2_0_APIS

#ifdef __APPLE__
#include <OpenCL/cl.h>
#endif

#ifdef WIN
#include <CL/cl.h>
#endif

#ifdef __linux__
#include <CL/cl.h>
#endif

#ifdef __FreeBSD__
#include <CL/cl.h>
#endif

#define CL_PLATFORMS_MAX 16

static const char CL_VENDOR_AMD[]           = "Advanced Micro Devices, Inc.";
static const char CL_VENDOR_AMD_USE_INTEL[] = "GenuineIntel";
static const char CL_VENDOR_APPLE[]         = "Apple";
static const char CL_VENDOR_INTEL_BEIGNET[] = "Intel";
static const char CL_VENDOR_INTEL_SDK[]     = "Intel(R) Corporation";
static const char CL_VENDOR_MESA[]          = "Mesa";
static const char CL_VENDOR_NV[]            = "NVIDIA Corporation";
static const char CL_VENDOR_POCL[]          = "The pocl project";

typedef enum vendor_id
{
  VENDOR_ID_AMD           = (1 << 0),
  VENDOR_ID_APPLE         = (1 << 1),
  VENDOR_ID_INTEL_BEIGNET = (1 << 2),
  VENDOR_ID_INTEL_SDK     = (1 << 3),
  VENDOR_ID_MESA          = (1 << 4),
  VENDOR_ID_NV            = (1 << 5),
  VENDOR_ID_POCL          = (1 << 6),
  VENDOR_ID_AMD_USE_INTEL = (1 << 7),
  VENDOR_ID_GENERIC       = (1 << 31)

} vendor_id_t;

typedef struct __hc_device_param hc_device_param_t;

struct __hc_device_param
{
  cl_device_id      device;
  cl_device_type    device_type;

  uint    device_id;
  uint    platform_devices_id;   // for mapping with hms devices

  bool    skipped;

  uint    sm_major;
  uint    sm_minor;
  uint    kernel_exec_timeout;

  uint    device_processors;
  u64     device_maxmem_alloc;
  u64     device_global_mem;
  u32     device_maxclock_frequency;
  size_t  device_maxworkgroup_size;

  uint    vector_width;

  uint    kernel_threads;
  uint    kernel_loops;
  uint    kernel_accel;
  uint    kernel_loops_min;
  uint    kernel_loops_max;
  uint    kernel_accel_min;
  uint    kernel_accel_max;
  uint    kernel_power;
  uint    hardware_power;

  size_t  size_pws;
  size_t  size_tmps;
  size_t  size_hooks;
  size_t  size_bfs;
  size_t  size_combs;
  size_t  size_rules;
  size_t  size_rules_c;
  size_t  size_root_css;
  size_t  size_markov_css;
  size_t  size_digests;
  size_t  size_salts;
  size_t  size_shown;
  size_t  size_results;
  size_t  size_plains;

  FILE   *combs_fp;
  comb_t *combs_buf;

  void   *hooks_buf;

  pw_t   *pws_buf;
  uint    pws_cnt;

  u64     words_off;
  u64     words_done;

  uint    outerloop_pos;
  uint    outerloop_left;

  uint    innerloop_pos;
  uint    innerloop_left;

  uint    exec_pos;
  double  exec_ms[EXEC_CACHE];

  // workaround cpu spinning

  double  exec_us_prev1[EXPECTED_ITERATIONS];
  double  exec_us_prev2[EXPECTED_ITERATIONS];
  double  exec_us_prev3[EXPECTED_ITERATIONS];

  // this is "current" speed

  uint    speed_pos;
  u64     speed_cnt[SPEED_CACHE];
  double  speed_ms[SPEED_CACHE];

  hc_timer_t timer_speed;

  // device specific attributes starting

  char   *device_name;
  char   *device_vendor;
  char   *device_name_chksum;
  char   *device_version;
  char   *driver_version;

  bool    opencl_v12;

  double  nvidia_spin_damp;

  cl_platform_id platform;

  cl_uint device_vendor_id;
  cl_uint platform_vendor_id;

  cl_kernel  kernel1;
  cl_kernel  kernel12;
  cl_kernel  kernel2;
  cl_kernel  kernel23;
  cl_kernel  kernel3;
  cl_kernel  kernel_mp;
  cl_kernel  kernel_mp_l;
  cl_kernel  kernel_mp_r;
  cl_kernel  kernel_amp;
  cl_kernel  kernel_tm;
  cl_kernel  kernel_weak;
  cl_kernel  kernel_memset;

  cl_context context;

  cl_program program;
  cl_program program_mp;
  cl_program program_amp;

  cl_command_queue command_queue;

  cl_mem  d_pws_buf;
  cl_mem  d_pws_amp_buf;
  cl_mem  d_words_buf_l;
  cl_mem  d_words_buf_r;
  cl_mem  d_rules;
  cl_mem  d_rules_c;
  cl_mem  d_combs;
  cl_mem  d_combs_c;
  cl_mem  d_bfs;
  cl_mem  d_bfs_c;
  cl_mem  d_tm_c;
  cl_mem  d_bitmap_s1_a;
  cl_mem  d_bitmap_s1_b;
  cl_mem  d_bitmap_s1_c;
  cl_mem  d_bitmap_s1_d;
  cl_mem  d_bitmap_s2_a;
  cl_mem  d_bitmap_s2_b;
  cl_mem  d_bitmap_s2_c;
  cl_mem  d_bitmap_s2_d;
  cl_mem  d_plain_bufs;
  cl_mem  d_digests_buf;
  cl_mem  d_digests_shown;
  cl_mem  d_salt_bufs;
  cl_mem  d_esalt_bufs;
  cl_mem  d_bcrypt_bufs;
  cl_mem  d_tmps;
  cl_mem  d_hooks;
  cl_mem  d_result;
  cl_mem  d_scryptV0_buf;
  cl_mem  d_scryptV1_buf;
  cl_mem  d_scryptV2_buf;
  cl_mem  d_scryptV3_buf;
  cl_mem  d_root_css_buf;
  cl_mem  d_markov_css_buf;

  void   *kernel_params[PARAMCNT];
  void   *kernel_params_mp[PARAMCNT];
  void   *kernel_params_mp_r[PARAMCNT];
  void   *kernel_params_mp_l[PARAMCNT];
  void   *kernel_params_amp[PARAMCNT];
  void   *kernel_params_tm[PARAMCNT];
  void   *kernel_params_memset[PARAMCNT];

  u32     kernel_params_buf32[PARAMCNT];

  u32     kernel_params_mp_buf32[PARAMCNT];
  u64     kernel_params_mp_buf64[PARAMCNT];

  u32     kernel_params_mp_r_buf32[PARAMCNT];
  u64     kernel_params_mp_r_buf64[PARAMCNT];

  u32     kernel_params_mp_l_buf32[PARAMCNT];
  u64     kernel_params_mp_l_buf64[PARAMCNT];

  u32     kernel_params_amp_buf32[PARAMCNT];
  u32     kernel_params_memset_buf32[PARAMCNT];
};

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

#ifdef _POSIX
typedef void *OCL_LIB;
#else
typedef HINSTANCE OCL_LIB;
#endif

typedef struct
{
  OCL_LIB lib;

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

int  ocl_init  (OCL_PTR *ocl);
void ocl_close (OCL_PTR *ocl);

cl_int hc_clBuildProgram            (OCL_PTR *ocl, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data);
cl_int hc_clCreateBuffer            (OCL_PTR *ocl, cl_context context, cl_mem_flags flags, size_t size, void *host_ptr, cl_mem *mem);
cl_int hc_clCreateCommandQueue      (OCL_PTR *ocl, cl_context context, cl_device_id device, cl_command_queue_properties properties, cl_command_queue *command_queue);
cl_int hc_clCreateContext           (OCL_PTR *ocl, cl_context_properties *properties, cl_uint num_devices, const cl_device_id *devices, void (CL_CALLBACK *pfn_notify) (const char *, const void *, size_t, void *), void *user_data, cl_context *context);
cl_int hc_clCreateKernel            (OCL_PTR *ocl, cl_program program, const char *kernel_name, cl_kernel *kernel);
cl_int hc_clCreateProgramWithBinary (OCL_PTR *ocl, cl_context context, cl_uint num_devices, const cl_device_id *device_list, const size_t *lengths, const unsigned char **binaries, cl_int *binary_status, cl_program *program);
cl_int hc_clCreateProgramWithSource (OCL_PTR *ocl, cl_context context, cl_uint count, const char **strings, const size_t *lengths, cl_program *program);
cl_int hc_clEnqueueCopyBuffer       (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
cl_int hc_clEnqueueMapBuffer        (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event, void **buf);
cl_int hc_clEnqueueNDRangeKernel    (OCL_PTR *ocl, cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
cl_int hc_clEnqueueReadBuffer       (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t cb, void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
cl_int hc_clEnqueueUnmapMemObject   (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem memobj, void *mapped_ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
cl_int hc_clEnqueueWriteBuffer      (OCL_PTR *ocl, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t cb, const void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
cl_int hc_clFinish                  (OCL_PTR *ocl, cl_command_queue command_queue);
cl_int hc_clFlush                   (OCL_PTR *ocl, cl_command_queue command_queue);
cl_int hc_clGetDeviceIDs            (OCL_PTR *ocl, cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id *devices, cl_uint *num_devices);
cl_int hc_clGetDeviceInfo           (OCL_PTR *ocl, cl_device_id device, cl_device_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
cl_int hc_clGetEventInfo            (OCL_PTR *ocl, cl_event event, cl_event_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
cl_int hc_clGetEventProfilingInfo   (OCL_PTR *ocl, cl_event event, cl_profiling_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
cl_int hc_clGetKernelWorkGroupInfo  (OCL_PTR *ocl, cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
cl_int hc_clGetPlatformIDs          (OCL_PTR *ocl, cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms);
cl_int hc_clGetPlatformInfo         (OCL_PTR *ocl, cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
cl_int hc_clGetProgramBuildInfo     (OCL_PTR *ocl, cl_program program, cl_device_id device, cl_program_build_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
cl_int hc_clGetProgramInfo          (OCL_PTR *ocl, cl_program program, cl_program_info param_name, size_t param_value_size, void *param_value, size_t * param_value_size_ret);
cl_int hc_clReleaseCommandQueue     (OCL_PTR *ocl, cl_command_queue command_queue);
cl_int hc_clReleaseContext          (OCL_PTR *ocl, cl_context context);
cl_int hc_clReleaseEvent            (OCL_PTR *ocl, cl_event event);
cl_int hc_clReleaseKernel           (OCL_PTR *ocl, cl_kernel kernel);
cl_int hc_clReleaseMemObject        (OCL_PTR *ocl, cl_mem mem);
cl_int hc_clReleaseProgram          (OCL_PTR *ocl, cl_program program);
cl_int hc_clSetKernelArg            (OCL_PTR *ocl, cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void *arg_value);
cl_int hc_clWaitForEvents           (OCL_PTR *ocl, cl_uint num_events, const cl_event *event_list);

#endif // _EXT_OPENCL_H
