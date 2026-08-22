/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_VENDOR_H
#define INC_VENDOR_H

#if defined HC_CPU_OPENCL_EMU_H
#define IS_NATIVE
#elif defined __CUDACC__
#define IS_CUDA
#elif defined __HIPCC__
#define IS_HIP
#elif defined __METAL__ || defined __METAL_MACOS__
#define IS_METAL
#else
#define IS_OPENCL
#endif

#if defined IS_METAL
#include <metal_stdlib>

using namespace metal;
#endif

#if defined IS_NATIVE
#define CONSTANT_VK
#define CONSTANT_AS
#define GLOBAL_AS
#define LOCAL_VK
#define LOCAL_AS
#define PRIVATE_AS
#define KERNEL_FQ
#elif defined IS_CUDA
#define CONSTANT_VK __constant__
#define CONSTANT_AS
#define GLOBAL_AS
#define LOCAL_VK    __shared__
#define LOCAL_AS
#define PRIVATE_AS
#define KERNEL_FQ   extern "C" __global__
#elif defined IS_HIP
#define CONSTANT_VK __constant__
#define CONSTANT_AS
#define GLOBAL_AS
#define LOCAL_VK    __shared__
#define LOCAL_AS
#define PRIVATE_AS
#define KERNEL_FQ   extern "C" __global__
#elif defined IS_METAL
#define CONSTANT_VK constant
#define CONSTANT_AS constant
#define GLOBAL_AS   device
#define LOCAL_VK    threadgroup
#define LOCAL_AS    threadgroup
#define PRIVATE_AS  thread
#define KERNEL_FQ   kernel
#elif defined IS_OPENCL
#define CONSTANT_VK __constant
#define CONSTANT_AS __constant
#define GLOBAL_AS   __global
#define LOCAL_VK    __local
#define LOCAL_AS    __local
#define PRIVATE_AS
#define KERNEL_FQ   __kernel
#endif

#if defined FIXED_LOCAL_SIZE
#define KERNEL_FA FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE)
#else
#define KERNEL_FA
#endif

#ifndef MAYBE_UNUSED
#define MAYBE_UNUSED
#endif

/**
 * device type
 */

#define DEVICE_TYPE_CPU   2
#define DEVICE_TYPE_GPU   4
#define DEVICE_TYPE_ACCEL 8

#if   DEVICE_TYPE == DEVICE_TYPE_CPU
#define IS_CPU
#elif DEVICE_TYPE == DEVICE_TYPE_GPU
#define IS_GPU
#elif DEVICE_TYPE == DEVICE_TYPE_ACCEL
#define IS_ACCEL
#endif

/**
 * vendor specific
 */

#if   VENDOR_ID == (1 << 0)
//#define IS_AMD
// IS_AMD is off, so nothing can ask "is this an AMD GPU" any more. Some code still needs
// to, to reach an instruction only that hardware has, and the OpenCL backend is the one
// case IS_AMD_USE_HIP does not already name. This says the same thing without turning the
// disabled IS_AMD paths back on.
//
// The IS_GPU qualifier is load bearing. VENDOR_ID is the *platform* vendor, so a CPU device
// exposed by an AMD OpenCL platform arrives here too, and everything IS_AMD_USE_OPENCL
// selects is a __builtin_amdgcn_* that only exists when the target is amdgcn. Without the
// qualifier such a device tries to compile GPU builtins for x86 and no kernel builds at all.
#ifdef IS_GPU
#define IS_AMD_USE_OPENCL
#endif
#define IS_GENERIC
#elif VENDOR_ID == (1 << 1)
#define IS_APPLE
#define IS_GENERIC
#elif VENDOR_ID == (1 << 2)
#define IS_INTEL_BEIGNET
#define IS_GENERIC
#elif VENDOR_ID == (1 << 3)
#define IS_INTEL_SDK
#define IS_GENERIC
#elif VENDOR_ID == (1 << 4)
#define IS_MESA
#define IS_GENERIC
#elif VENDOR_ID == (1 << 5)
#define IS_NV
#elif VENDOR_ID == (1 << 6)
#define IS_POCL
#define IS_GENERIC
#elif VENDOR_ID == (1 << 8)
#define IS_AMD_USE_HIP
#else
#define IS_GENERIC
#endif

#define LOCAL_MEM_TYPE_LOCAL  1
#define LOCAL_MEM_TYPE_GLOBAL 2

#if LOCAL_MEM_TYPE == LOCAL_MEM_TYPE_LOCAL
#define REAL_SHM
#endif

// So far, only used by -m 22100 and only affects NVIDIA on OpenCL. CUDA seems to work fine.
#ifdef FORCE_DISABLE_SHM
#undef REAL_SHM
#endif

#ifdef REAL_SHM
#define SHM_TYPE LOCAL_AS
#else
#define SHM_TYPE CONSTANT_AS
#endif

/**
 * function declarations can have a large influence depending on the opencl runtime
 * fast but pure kernels on rocm is a good example
 */

#if defined NO_INLINE || defined FORCE_NO_INLINE
#define HC_INLINE
#else
#define HC_INLINE inline static
#endif

/**
 * NO_INLINE only drops the `inline static` hint. That is enough for some runtimes, but LLVM-based
 * OpenCL back-ends (AMD's "LC" / comgr stack) still inline every DECLSPEC helper at -O3 and merge a
 * kernel built from many large helpers into one huge function. Several LLVM back-end passes (greedy
 * register allocation, SelectionDAG scheduling) scale ~super-linearly per function, so that single
 * function can take minutes to compile. FORCE_NO_INLINE emits the hard noinline attribute, which
 * partitions the kernel back into many small functions.
 *
 * This is deliberately a separate switch from NO_INLINE: the two are not interchangeable, and
 * NO_INLINE already has a meaning that -m 33000 relies on. Out-of-line calls cost runtime
 * throughput, so FORCE_NO_INLINE stays opt-in per module/device and must never become a global
 * default. Note -cl-opt-disable is not an alternative: it fails to link the static/DECLSPEC helpers
 * (`ld.lld: undefined hidden symbol`).
 */

#ifdef FORCE_NO_INLINE
#define HC_NOINLINE __attribute__ ((noinline))
#else
#define HC_NOINLINE
#endif

// On a device DECLSPEC says how a function is compiled. On the host it says something else, because
// the host build of these files is compiled into the core and a plugin calls the result: every one
// of these functions is a host side hash, cipher or helper entry point, so DECLSPEC is where they
// are put into the plugin contract, once, instead of on a few hundred declarations. IS_NATIVE is
// set from the include guard of emu_general.h, and that is the header that brings HC_PLUGIN_API in,
// so the macro is always in hand by the time this is read.

// The `static` on the last branch is what lets a helper the kernel never calls be dropped
// before it reaches the back end. Without it these functions have external linkage and the
// compiler has to emit every one of them into every kernel. inc_common.cl alone is 174
// functions, so a kernel that calls twenty of them still pays for all 174, at whatever
// VECT_SIZE it was built with. Measured on gfx1100 with ROCm 7.0.1, a kernel body that
// calls nothing at all went from 2.97s and 99962 lines of ISA to 0.21s and 197 lines.
//
// This branch is where every OpenCL build lands, because the IS_AMD one above is dead.
// Plain `static` is deliberate. HC_INLINE would add an `inline` hint on top, which measures
// identically here and brings the whole-kernel inlining problem the FORCE_NO_INLINE comment
// above describes, so there is no reason to ask for it.

// The `static` on the last branch needs OpenCL C 1.2, which has file scope static. 1.1 does
// not, and a device reporting 1.0 or 1.1 is now skipped at device init in backend.c rather
// than compiled with -cl-std=CL1.1. That is not a new requirement: inc_rp_common.cl already
// declares its lookup tables as `CONSTANT_VK static` at file scope, so rule and wordlist
// attacks could never build on such a device anyway.

#if defined IS_AMD && defined IS_GPU
#define DECLSPEC HC_NOINLINE HC_INLINE
#elif defined IS_CUDA
#define DECLSPEC __device__ HC_NOINLINE
#elif defined IS_HIP
#define DECLSPEC __device__ HC_NOINLINE HC_INLINE
#elif defined IS_NATIVE
#define DECLSPEC HC_PLUGIN_API
#else
#define DECLSPEC static HC_NOINLINE
#endif

/**
 * AMD specific
 */

#ifdef IS_AMD
#if defined(cl_amd_media_ops)
#pragma OPENCL EXTENSION cl_amd_media_ops  : enable
#endif
#if defined(cl_amd_media_ops2)
#pragma OPENCL EXTENSION cl_amd_media_ops2 : enable
#endif
#endif

// Whitelist some OpenCL specific functions
// This could create more stable kernels on systems with bad OpenCL drivers

// USE_BITSELECT and USE_ROTATE each say "this backend has the OpenCL builtin of that name".
// CUDA and HIP have neither, so inc_platform.h supplies bitselect as a macro for both. It
// does not supply rotate: that macro is commented out at inc_platform.h:48 and :71. So
// USE_ROTATE must not be set here, or any code that believes it fails to compile with
// "use of undeclared identifier 'rotate'".
//
// Nothing hit that until now, because the two places that test USE_ROTATE without first
// returning on IS_CUDA or IS_HIP are the fallback arms of hc_swap32 and hc_swap64, and
// those were unreachable behind the V_PERM_B32 and prmt arms above them. The eight
// hc_rotl/hc_rotr functions are unaffected either way; each one returns on
// IS_CUDA || IS_HIP before it reaches its USE_ROTATE branch.

#ifdef IS_CUDA
#define USE_BITSELECT
#endif

#ifdef IS_HIP
#define USE_BITSELECT
#endif

#ifdef IS_OPENCL
#define USE_BITSELECT
#define USE_ROTATE
#define USE_SWIZZLE
#endif

#ifdef IS_METAL
#define USE_ROTATE
#ifndef IS_APPLE_SILICON
#define USE_BITSELECT
#define USE_SWIZZLE
#endif

// Metal support max VECT_SIZE = 4
#define s0 x
#define s1 y
#define s2 z
#define s3 w
#endif

#if HAS_SHFW == 1
#define USE_FUNNELSHIFT
#endif

// some algorithms do not like this, eg 150, 1100, ...

#ifdef NO_FUNNELSHIFT
#undef USE_FUNNELSHIFT
#endif

#endif // INC_VENDOR_H
