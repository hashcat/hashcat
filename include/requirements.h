/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_REQUIREMENTS_H
#define HC_REQUIREMENTS_H

// Every runtime version hashcat refuses to work below, in one place, because they were spread across
// backend.c, ext_cuda.h and ext_OpenCL.h and nothing made them agree. A build that targets one API
// level while the runtime check enforces another is stating two different minimums, which is what
// __CUDA_API_VERSION and the CUDA gate used to do.
//
// docs/hashcat-requirements.md states these to users and to package maintainers. It has to be
// changed with them or it becomes wrong quietly.
//
// The floors are what a current distribution can install rather than what a vendor still lists as
// supported. Ubuntu 24.04 is the oldest release targeted: its archive carries nvidia-cuda-toolkit
// 12.0.140 and driver 535, which is CUDA 12.2, and pocl 5.0. It ships no ROCm, and AMD publishes
// 6.2.4 for it. PoCL stays at 5.0 for that reason and because no PoCL version has been good for
// hashcat, so asking for a newer one buys nothing.

#define HC_MIN_CUDA_VERSION       12000     // 12.0, both the driver and NVRTC
#define HC_MIN_HIP_VERSION        60200000  // 6.2.0, Linux and Windows alike

#define HC_MIN_OPENCL_MAJOR       1
#define HC_MIN_OPENCL_MINOR       2

// What the OpenCL headers are compiled against. It follows the pair above rather than being written
// out again, so the API this is built for and the API it insists on cannot drift apart.

#define HC_CL_TARGET_VERSION      ((HC_MIN_OPENCL_MAJOR * 100) + (HC_MIN_OPENCL_MINOR * 10))

#define HC_MIN_POCL_VERSION       500       // 5.0
#define HC_MIN_POCL_LLVM_VERSION  1000      // 10.0

#define HC_MIN_INTEL_CPU_DRIVER   2020
#define HC_MIN_AMD_OCL_DRIVER     3000
#define HC_MIN_NV_OCL_DRIVER      500

// macOS is asked with __builtin_available in C and @available in Objective-C, and both take the
// version as syntax rather than as a value, so this is the whole argument and not a number. The text
// form is for the message that names it.

#define HC_MIN_MACOS              macOS 13.0
#define HC_MIN_MACOS_TEXT         "13.0"

#endif // HC_REQUIREMENTS_H
