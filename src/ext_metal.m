/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "timer.h"
#include "ext_metal.h"

#include <sys/sysctl.h>
#include <objc/message.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <Metal/Metal.h>

typedef NS_ENUM(NSUInteger, hc_mtlLanguageVersion)
{
//MTL_LANGUAGEVERSION_1_0 = (1 << 16),
  MTL_LANGUAGEVERSION_1_1 = (1 << 16) + 1,
  MTL_LANGUAGEVERSION_1_2 = (1 << 16) + 2,
  MTL_LANGUAGEVERSION_2_0 = (2 << 16),
  MTL_LANGUAGEVERSION_2_1 = (2 << 16) + 1,
  MTL_LANGUAGEVERSION_2_2 = (2 << 16) + 2,
  MTL_LANGUAGEVERSION_2_3 = (2 << 16) + 3,
  MTL_LANGUAGEVERSION_2_4 = (2 << 16) + 4,
  MTL_LANGUAGEVERSION_3_0 = (3 << 16),
  MTL_LANGUAGEVERSION_3_1 = (3 << 16) + 1,
  MTL_LANGUAGEVERSION_3_2 = (3 << 16) + 2

} metalLanguageVersion_t;

static bool iokit_getGPUCore (void *hashcat_ctx, int *gpu_core)
{
  bool rc = false;

  CFDictionaryRef matching = IOServiceMatching ("IOAccelerator");

  if (!matching)
  {
    event_log_error (hashcat_ctx, "IOServiceMatching() failed");

    return rc;
  }


  io_service_t service = IOServiceGetMatchingService (hc_IOMasterPortDefault, matching);

  if (!service)
  {
    event_log_error (hashcat_ctx, "IOServiceGetMatchingService(): %08x", service);

    return rc;
  }

  // "gpu-core-count" is present only on Apple Silicon

  CFNumberRef num = IORegistryEntryCreateCFProperty (service, CFSTR ("gpu-core-count"), kCFAllocatorDefault, 0);

  int gc = 0;

  if (num == NULL || CFNumberGetValue (num, kCFNumberIntType, &gc) == false)
  {
    //event_log_error (hashcat_ctx, "IORegistryEntryCreateCFProperty(): 'gpu-core-count' entry not found");
  }
  else
  {
    *gpu_core = gc;

    rc = true;
  }

  if (num) CFRelease(num);

  IOObjectRelease (service);

  return rc;
}

static int hc_mtlInvocationHelper (id target, SEL selector, void *returnValue)
{
  if (target == nil) return -1;
  if (selector == nil) return -1;

  if ([target respondsToSelector: selector])
  {
    NSMethodSignature *signature = [object_getClass (target) instanceMethodSignatureForSelector: selector];

    if (signature == nil) return -1;

    NSInvocation *invocation = [NSInvocation invocationWithMethodSignature: signature];

    if (invocation == nil) return -1;

    [invocation setTarget: target];
    [invocation setSelector: selector];

    @try
    {
      [invocation invoke];
    }
    @catch (NSException *exception)
    {
      return -1;
    }

    [invocation getReturnValue: returnValue];

    return 0;
  }

  return -1;
}

static int hc_mtlBuildOptionsToDict (void *hashcat_ctx, const char *build_options_buf, const char *include_path, NSMutableDictionary *build_options_dict)
{
  if (build_options_buf == NULL)
  {
    event_log_error (hashcat_ctx, "%s(): build_options_buf is NULL", __func__);

    return -1;
  }

  if (build_options_dict == nil)
  {
    event_log_error (hashcat_ctx, "%s(): build_options_dict is NULL", __func__);

    return -1;
  }

  // NSString from build_options_buf

  NSString *options = [NSString stringWithCString: build_options_buf encoding: NSUTF8StringEncoding];

  if (options == nil)
  {
    event_log_error (hashcat_ctx, "%s(): stringWithCString failed", __func__);

    return -1;
  }

  // replace '-D ' to ''

  options = [options stringByReplacingOccurrencesOfString:@"-D " withString:@""];

  if (options == nil)
  {
    event_log_error (hashcat_ctx, "%s(): stringByReplacingOccurrencesOfString(-D) failed", __func__);

    return -1;
  }

  // replace '-I OpenCL ' to ''

  options = [options stringByReplacingOccurrencesOfString:@"-I OpenCL " withString:@""];

  if (options == nil)
  {
    event_log_error (hashcat_ctx, "%s(): stringByReplacingOccurrencesOfString(-I OpenCL) failed", __func__);

    return -1;
  }

  //NSLog(@"options: '%@'", options);

  // creating NSDictionary from options

  NSArray *lines = [options componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  for (NSString *aKeyValue in lines)
  {
    NSArray *components = [aKeyValue componentsSeparatedByString:@"="];

    NSString *key = [components[0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *value = nil;

    if ([components count] != 2)
    {
      // Every -D the rest of hashcat can emit without a value has to be named here, because a
      // preprocessor macro reaches Metal as a dictionary entry and a dictionary entry needs one.
      // A name missing from this list is dropped silently, so the kernel compiles as if the option
      // had never been given.

      if ([key isEqualToString:@"KERNEL_STATIC"] ||
          [key isEqualToString:@"IS_APPLE_SILICON"] ||
          [key isEqualToString:@"DYNAMIC_LOCAL"] ||
          [key isEqualToString:@"_unroll"] ||
          [key isEqualToString:@"NO_UNROLL"] ||
          [key isEqualToString:@"NO_INLINE"] ||
          [key isEqualToString:@"FORCE_NO_INLINE"] ||
          [key isEqualToString:@"NO_FUNNELSHIFT"] ||
          [key isEqualToString:@"FORCE_DISABLE_SHM"] ||
          [key isEqualToString:@"COOP_SBOX_LDS"] ||
          [key isEqualToString:@"COOP_X_REGS"] ||
          [key isEqualToString:@"COOP_X_GLOBAL"])
      {
        value = @"1";
      }
      else
      {
        #ifdef DEBUG
        const char *tmp = [key UTF8String];

        if (tmp != NULL && strlen (tmp) > 0)
        {
          event_log_warning (hashcat_ctx, "%s(): skipping malformed build option: '%s'", __func__, tmp);
        }
        #endif

        continue;
      }
    }
    else
    {
      value = [components[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    }

    [build_options_dict setObject: value forKey: key];
  }

  // if set, add INCLUDE_PATH to hack Apple kernel build from source limitation on -I usage

  if (include_path != NULL)
  {
    NSString *path_key = @"INCLUDE_PATH";
    NSString *path_value = [NSString stringWithCString: include_path encoding: NSUTF8StringEncoding];

    // Include path may contain spaces, escape them with a backslash

    path_value = [path_value stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];

    [build_options_dict setObject: path_value forKey: path_key];
  }

  //NSLog(@"Dict:\n%@", build_options_dict);

  return 0;
}

int mtl_init (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  memset (mtl, 0, sizeof (MTL_PTR));

  mtl->devices = nil;

  if (MTLCreateSystemDefaultDevice () == nil)
  {
    event_log_error (hashcat_ctx, "Metal is not supported on this computer");

    return -1;
  }

  return 0;
}

void mtl_close (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl)
  {
    if (mtl->devices)
    {
      int count = (int) CFArrayGetCount (mtl->devices);

      for (int i = 0; i < count; i++)
      {
        mtl_device_id device = (mtl_device_id) CFArrayGetValueAtIndex (mtl->devices, i);

        if (device != nil)
        {
          hc_mtlReleaseDevice (hashcat_ctx, &device);
        }
      }

      CFRelease (mtl->devices);

      mtl->devices = nil;
    }

    hcfree (backend_ctx->mtl);

    backend_ctx->mtl = NULL;
  }
}

int hc_mtlDeviceGetCount (void *hashcat_ctx, int *count)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == nil) return -1;

  CFArrayRef devices = (CFArrayRef) MTLCopyAllDevices ();

  if (devices == NULL)
  {
    event_log_error (hashcat_ctx, "metalDeviceGetCount(): empty device objects");

    if (mtl->devices)
    {
      CFRelease (mtl->devices);

      mtl->devices = nil;
    }

    *count = 0;

    return -1;
  }

  mtl->devices = devices;

  *count = (int) CFArrayGetCount (devices);

  return 0;
}

int hc_mtlDeviceGet (void *hashcat_ctx, mtl_device_id *metal_device, int ordinal)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == nil) return -1;

  if (mtl->devices == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid devices pointer", __func__);

    return -1;
  }

  mtl_device_id device = (mtl_device_id) CFArrayGetValueAtIndex (mtl->devices, ordinal);

  if (device == NULL)
  {
    event_log_error (hashcat_ctx, "metalDeviceGet(): invalid index");

    return -1;
  }

  /*
  // parallelize pipeline state object (PSO) compilation internally

  if ([device respondsToSelector:@selector(setShouldMaximizeConcurrentCompilation:)])
  {
    ((void (*)(id, SEL, BOOL))objc_msgSend)(device, @selector(setShouldMaximizeConcurrentCompilation:), YES);
  }
  */

  *metal_device = device;

  return 0;
}

int hc_mtlDeviceGetName (void *hashcat_ctx, char *name, size_t len, mtl_device_id metal_device)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device", __func__);

    return -1;
  }

  if (len <= 0)
  {
    event_log_error (hashcat_ctx, "%s(): buffer length", __func__);

    return -1;
  }

  id device_name_ptr = [metal_device name];

  if (device_name_ptr == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to get device name", __func__);

    return -1;
  }

  const char *device_name_str = [device_name_ptr UTF8String];

  if (device_name_str == NULL)
  {
    event_log_error (hashcat_ctx, "%s(): failed to get UTF8String from device name", __func__);

    return -1;
  }

  const size_t device_name_len = strlen (device_name_str);

  if (device_name_len <= 0)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device name length", __func__);

    return -1;
  }

  size_t copy_len = (device_name_len < len - 1) ? device_name_len : len - 1;

  memcpy(name, device_name_str, copy_len);

  name[copy_len] = '\0';

  return 0;
}

int hc_mtlDeviceGetAttribute (void *hashcat_ctx, int *pi, metalDeviceAttribute_t attrib, mtl_device_id metal_device)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device", __func__);

    return -1;
  }

  uint64_t val64 = 0;
  bool valBool = false;
  unsigned long valULong = 0;

  switch (attrib)
  {
    case MTL_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT:
      // works only with Apple Silicon
      if (iokit_getGPUCore (hashcat_ctx, pi) == false) *pi = 1;
      break;

    case MTL_DEVICE_ATTRIBUTE_UNIFIED_MEMORY:
      *pi = 0;

      SEL hasUnifiedMemorySelector = NSSelectorFromString (@"hasUnifiedMemory");

      hc_mtlInvocationHelper (metal_device, hasUnifiedMemorySelector, &valBool);

      *pi = (valBool == true) ? 1 : 0;

      break;

    case MTL_DEVICE_ATTRIBUTE_WARP_SIZE:
      // return a fake size of 32, it will be updated later
      *pi = 32;
      break;

    case MTL_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK:
      // M1 max is 1024
      // [MTLComputePipelineState maxTotalThreadsPerThreadgroup]
      *pi = 1024;
      break;

    case MTL_DEVICE_ATTRIBUTE_CLOCK_RATE:
      // unknown
      *pi = 1000000;
      break;

    case MTL_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK:
      // 32k
      *pi = 0;

      valULong = 0;

      SEL maxThreadgroupMemoryLengthSelector = NSSelectorFromString (@"maxThreadgroupMemoryLength");

      hc_mtlInvocationHelper (metal_device, maxThreadgroupMemoryLengthSelector, &valULong);

      *pi = valULong;

      break;

    case MTL_DEVICE_ATTRIBUTE_MAX_TRANSFER_RATE:
      *pi = 0;

      val64 = 0;

      SEL maxTransferRateSelector = NSSelectorFromString (@"maxTransferRate");

      hc_mtlInvocationHelper (metal_device, maxTransferRateSelector, &val64);

      *pi = (val64 == 0) ? 0 : val64 / 125; // kb/s

      break;

    case MTL_DEVICE_ATTRIBUTE_HEADLESS:
      valBool = [metal_device isHeadless];
      *pi = (valBool == true) ? 1 : 0;
      break;

    case MTL_DEVICE_ATTRIBUTE_LOW_POWER:
      valBool = [metal_device isLowPower];
      *pi = (valBool == true) ? 1 : 0;
      break;

    case MTL_DEVICE_ATTRIBUTE_REMOVABLE:
      valBool = [metal_device isRemovable];
      *pi = (valBool == true) ? 1 : 0;
      break;

    case MTL_DEVICE_ATTRIBUTE_REGISTRY_ID:
      *pi = (int) [metal_device registryID];
      break;

    case MTL_DEVICE_ATTRIBUTE_PHYSICAL_LOCATION:
      *pi = 0;

      valULong = 0;

      SEL locationSelector = NSSelectorFromString (@"location");

      hc_mtlInvocationHelper (metal_device, locationSelector, &valULong);

      *pi = valULong;

      break;

    case MTL_DEVICE_ATTRIBUTE_LOCATION_NUMBER:
      *pi = 0;

      valULong = 0;

      SEL locationNumberSelector = NSSelectorFromString (@"locationNumber");

      hc_mtlInvocationHelper (metal_device, locationNumberSelector, &valULong);

      *pi = valULong;

      break;

    default:
      event_log_error (hashcat_ctx, "%s(): unknown attribute (%d)", __func__, attrib);
      return -1;
  }

  return 0;
}

int hc_mtlMemGetInfo (void *hashcat_ctx, size_t *mem_free, size_t *mem_total)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  struct vm_statistics64 vm_stats = { 0 };

  vm_size_t page_size = 0;

  unsigned int count = HOST_VM_INFO64_COUNT;

  mach_port_t port = mach_host_self ();

  if (host_page_size (port, &page_size) != KERN_SUCCESS)
  {
    event_log_error (hashcat_ctx, "metalMemGetInfo(): cannot get page_size");

    mach_port_deallocate (mach_task_self(), port);

    return -1;
  }

  if (host_statistics64 (port, HOST_VM_INFO64, (host_info64_t) &vm_stats, &count) != KERN_SUCCESS)
  {
    event_log_error (hashcat_ctx, "metalMemGetInfo(): cannot get vm_stats");

    mach_port_deallocate (mach_task_self(), port);

    return -1;
  }

  mach_port_deallocate (mach_task_self(), port);

  uint64_t mem_free_tmp = (uint64_t) (vm_stats.free_count - vm_stats.speculative_count) * page_size;

  uint64_t mem_used_tmp = (uint64_t) (vm_stats.active_count + vm_stats.inactive_count + vm_stats.wire_count) * page_size;

  *mem_free  = (size_t) (mem_free_tmp);

  *mem_total = (size_t) (mem_free_tmp + mem_used_tmp);

  return 0;
}

int hc_mtlDeviceMaxMemAlloc (void *hashcat_ctx, size_t *bytes, mtl_device_id metal_device)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device", __func__);

    return -1;
  }

  uint64_t memsize = 0;

  SEL maxBufferLengthSelector = NSSelectorFromString (@"maxBufferLength");

  if (hc_mtlInvocationHelper (metal_device, maxBufferLengthSelector, &memsize) == -1) return -1;

  if (memsize == 0)
  {
    event_log_error (hashcat_ctx, "%s(): invalid maxBufferLength", __func__);

    return -1;
  }

  *bytes = (size_t) memsize;

  return 0;
}

int hc_mtlDeviceTotalMem (void *hashcat_ctx, size_t *bytes, mtl_device_id metal_device)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device", __func__);

    return -1;
  }

  uint64_t memsize = 0;

  if ([metal_device respondsToSelector:@selector(recommendedMaxWorkingSetSize)])
  {
    memsize = [metal_device recommendedMaxWorkingSetSize];
  }
  else
  {
    size_t len = sizeof (memsize);

    if (sysctlbyname ("hw.memsize", &memsize, &len, NULL, 0) != 0)
    {
      event_log_error (hashcat_ctx, "%s(): sysctlbyname(hw.memsize) failed", __func__);

      return -1;
    }
  }

  if (memsize == 0)
  {
    event_log_error (hashcat_ctx, "%s(): invalid memory size", __func__);

    return -1;
  }

  *bytes = (size_t) memsize;

  return 0;
}

int hc_mtlCreateCommandQueue (void *hashcat_ctx, mtl_device_id metal_device, mtl_command_queue *command_queue)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device", __func__);

    return -1;
  }

  mtl_command_queue queue = [metal_device newCommandQueue];

  if (queue == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create newCommandQueue", __func__);

    return -1;
  }

  *command_queue = queue;

  return 0;

}

int hc_mtlCreateKernel (void *hashcat_ctx, mtl_device_id metal_device, mtl_library metal_library, const char *func_name, mtl_function *metal_function, mtl_pipeline *metal_pipeline)
{
  backend_ctx_t  *backend_ctx  = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;
  user_options_t *user_options = ((hashcat_ctx_t *) hashcat_ctx)->user_options;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device", __func__);

    return -1;
  }

  if (metal_library == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid library", __func__);

    return -1;
  }

  if (func_name == NULL)
  {
    event_log_error (hashcat_ctx, "%s(): invalid function name", __func__);

    return -1;
  }

  __block NSError *error = nil;

  NSString *f_name = [NSString stringWithCString: func_name encoding: NSUTF8StringEncoding];

  if (f_name == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to convert function name to NSString", __func__);

    return -1;
  }

  mtl_function mtl_func = [metal_library newFunctionWithName: f_name];

  if (mtl_func == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create '%s' function", __func__, func_name);

    return -1;
  }

  // workaround for MTLCompilerService 'Infinite Loop' bug

  /*
  mtl_pipeline mtl_pipe = [metal_device newComputePipelineStateWithFunction: mtl_func error: &error];

  if (error != nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create '%s' pipeline, %s", __func__, func_name, [[error localizedDescription] UTF8String]);

    return -1;
  }
  */

  error = nil;

  __block mtl_pipeline mtl_pipe;

  dispatch_group_t group = dispatch_group_create ();
  dispatch_queue_t queue = dispatch_get_global_queue (DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

  // if no user-defined runtime, set to METAL_COMPILER_RUNTIME

  long timeout = (user_options->metal_compiler_runtime > 0) ? user_options->metal_compiler_runtime : METAL_COMPILER_RUNTIME;

  dispatch_time_t when = dispatch_time (DISPATCH_TIME_NOW,NSEC_PER_SEC * timeout);

  __block int rc_async_err = 0;

  dispatch_group_async (group, queue, ^(void)
  {
    mtl_pipe = [metal_device newComputePipelineStateWithFunction: mtl_func error: &error];

    if (error != nil)
    {
      event_log_error (hashcat_ctx, "%s(): failed to create '%s' pipeline, %s", __func__, func_name, [[error localizedDescription] UTF8String]);

      rc_async_err = -1;
    }
  });

  long rc_queue = dispatch_group_wait (group, when);

  dispatch_release (group);

  if (rc_async_err != 0) return -1;

  if (rc_queue != 0)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create '%s' pipeline, timeout reached (status %ld)", __func__, func_name, rc_queue);

    return -1;
  }

  if (mtl_pipe == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create '%s' pipeline", __func__, func_name);

    return -1;
  }

  *metal_function = mtl_func;
  *metal_pipeline = mtl_pipe;

  return 0;
}

int hc_mtlGetMaxTotalThreadsPerThreadgroup (void *hashcat_ctx, mtl_pipeline metal_pipeline, unsigned int *maxTotalThreadsPerThreadgroup)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_pipeline == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid pipeline", __func__);

    return -1;
  }

  *maxTotalThreadsPerThreadgroup = [metal_pipeline maxTotalThreadsPerThreadgroup];

  return 0;
}

int hc_mtlGetThreadExecutionWidth (void *hashcat_ctx, mtl_pipeline metal_pipeline, unsigned int *threadExecutionWidth)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_pipeline == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid pipeline", __func__);

    return -1;
  }

  *threadExecutionWidth = [metal_pipeline threadExecutionWidth];

  return 0;
}

int hc_mtlGetStaticThreadgroupMemoryLength (void *hashcat_ctx, mtl_pipeline metal_pipeline, unsigned int *staticThreadgroupMemoryLength)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_pipeline == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid pipeline", __func__);

    return -1;
  }

  *staticThreadgroupMemoryLength = [metal_pipeline staticThreadgroupMemoryLength];

  return 0;
}

int hc_mtlCreateBuffer (void *hashcat_ctx, mtl_device_id metal_device, size_t size, void *ptr, mtl_mem_t *mem, metalBufferStorageModeId_t metal_storage_mode)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device", __func__);

    return -1;
  }

//  MTLResourceOptions bufferOptions = MTLResourceStorageModeShared;

  MTLResourceOptions bufferOptions;

  metalResourceStorageMode_t storageMode = metalResourceStorageModes[metal_storage_mode];

  switch (storageMode)
  {
    case MTL_STORAGE_MODE_PRIVATE:
      bufferOptions = MTLResourceStorageModePrivate;
      break;

    case MTL_STORAGE_MODE_SHARED:
      bufferOptions = MTLResourceStorageModeShared;
      break;

    case MTL_STORAGE_MODE_MANAGED:
      bufferOptions = MTLResourceStorageModeManaged;
      break;

    default:
      event_log_error (hashcat_ctx, "%s(): invalid metal storage mode argument", __func__);
      return -1;
  }

  NSString *deviceName = [metal_device name];

  if ([deviceName containsString:@"AMD"])
  {
    if (bufferOptions == MTLResourceStorageModeShared)
    {
      // AMD discrete GPU perform best on MANAGED
      bufferOptions = MTLResourceStorageModeManaged;
    }
  }
  else if ([deviceName containsString:@"Intel"])
  {
    if (bufferOptions == MTLResourceStorageModeShared)
    {
      // for Intel integrated GPU we need more testing with stable HW
      // bufferOptions = MTLResourceStorageModeManaged;
    }
  }
  else
  {
    // we are on Apple Silicon, nothing to do ;)
  }

  if (ptr != NULL)
  {
    if (bufferOptions != MTLResourceStorageModeShared)
    {
      event_log_error (hashcat_ctx, "%s(): bufferOptions must be Shared when using unified memory", __func__);

      return -1;
    }

    // using unified memory

    mem->buf_ptr = [metal_device newBufferWithBytesNoCopy: ptr length: size options: bufferOptions deallocator: nil];
  }
  else
  {
    mem->buf_ptr = [metal_device newBufferWithLength: size options: bufferOptions];
  }

  if (mem->buf_ptr == nil)
  {
    event_log_error (hashcat_ctx, "%s(): %s failed (size: %zu)", __func__, (ptr == NULL) ? "newBufferWithLength" : "newBufferWithBytesNoCopy", size);

    return -1;
  }

  // now set buf_mode

  switch (bufferOptions)
  {
    case MTLResourceStorageModePrivate:
      mem->buf_mode = MTL_STORAGE_MODE_PRIVATE;
      break;

    case MTLResourceStorageModeShared:
      mem->buf_mode = MTL_STORAGE_MODE_SHARED;
      break;

    case MTLResourceStorageModeManaged:
      mem->buf_mode = MTL_STORAGE_MODE_MANAGED;
      break;

    default:
      event_log_error (hashcat_ctx, "%s(): invalid metal storage mode argument", __func__);
      return -1;
  }

  return 0;
}

int hc_mtlReleaseMemObject (void *hashcat_ctx, mtl_mem_t *mem)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (mem == NULL || mem->buf_ptr == nil) return -1;

  [mem->buf_ptr setPurgeableState: MTLPurgeableStateEmpty];

  #if !__has_feature(objc_arc)
  [mem->buf_ptr release];
  #endif

  mem->buf_ptr = nil;

  return 0;
}

int hc_mtlReleaseFunction (void *hashcat_ctx, mtl_function *metal_function)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_function == NULL || *metal_function == nil) return -1;

  #if !__has_feature(objc_arc)
  [*metal_function release];
  #endif

  *metal_function = nil;

  return 0;
}

int hc_mtlReleaseLibrary (void *hashcat_ctx, mtl_library *metal_library)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_library == NULL || *metal_library == nil) return -1;

  #if !__has_feature(objc_arc)
  [*metal_library release];
  #endif

  *metal_library = nil;

  return 0;
}

int hc_mtlReleaseCommandQueue (void *hashcat_ctx, mtl_command_queue *command_queue)
{
  if (command_queue == NULL || *command_queue == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal command queue", __func__);

    return -1;
  }

  #if !__has_feature(objc_arc)
  [*command_queue release];
  #endif

  *command_queue = nil;

  return 0;
}

int hc_mtlReleaseDevice (void *hashcat_ctx, mtl_device_id *metal_device)
{
  if (metal_device == NULL || *metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal device", __func__);

    return -1;
  }

  #if !__has_feature(objc_arc)
  [*metal_device release];
  #endif

  *metal_device = nil;

  return 0;
}

// device to device

int hc_mtlMemcpyDtoD (void *hashcat_ctx, mtl_command_queue command_queue, mtl_mem_t mem_dst, size_t mem_dst_off, mtl_mem_t mem_src, size_t mem_src_off, size_t size)
{
  if (command_queue == nil)
  {
    event_log_error (hashcat_ctx, "%s(): metal command queue is invalid", __func__);

    return -1;
  }

  if (mem_src.buf_ptr == nil)
  {
    event_log_error (hashcat_ctx, "%s(): metal src buffer is invalid", __func__);

    return -1;
  }

  if (mem_src_off < 0)
  {
    event_log_error (hashcat_ctx, "%s(): src buffer offset is invalid", __func__);

    return -1;
  }

  if (mem_dst.buf_ptr == nil)
  {
    event_log_error (hashcat_ctx, "%s(): metal dst buffer is invalid", __func__);

    return -1;
  }

  if (mem_dst_off < 0)
  {
    event_log_error (hashcat_ctx, "%s(): dst buffer offset is invalid", __func__);

    return -1;
  }

  if (size <= 0)
  {
    event_log_error (hashcat_ctx, "%s(): buffer size is invalid", __func__);

    return -1;
  }

  if (mem_src_off + size > [mem_src.buf_ptr length])
  {
    event_log_error (hashcat_ctx, "%s(): src buffer offset + size out of bounds", __func__);

    return -1;
  }

  if (mem_dst_off + size > [mem_dst.buf_ptr length])
  {
    event_log_error (hashcat_ctx, "%s(): dst buffer offset + size out of bounds", __func__);

    return -1;
  }

  if (mem_src.buf_mode != mem_dst.buf_mode)
  {
    event_log_error (hashcat_ctx, "%s(): src and dst buffers using different storage modes", __func__);

    return -1;
  }

  id<MTLCommandBuffer> command_buffer = [command_queue commandBuffer];

  if (command_buffer == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create a new command buffer", __func__);
    return -1;
  }

  id<MTLBlitCommandEncoder> blit_encoder = [command_buffer blitCommandEncoder];

  if (blit_encoder == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create a blit command encoder", __func__);

    return -1;
  }

  // copy

  [blit_encoder copyFromBuffer: mem_src.buf_ptr sourceOffset: mem_src_off toBuffer: mem_dst.buf_ptr destinationOffset: mem_dst_off size: size];

  if (mem_dst.buf_mode == MTL_STORAGE_MODE_MANAGED)
  {
    // synchronize needed with MANAGED only

    [blit_encoder synchronizeResource: mem_dst.buf_ptr];
  }

  // finish encoding and start the data transfer

  [blit_encoder endEncoding];

  [command_buffer commit];

  // Wait for complete

  [command_buffer waitUntilCompleted];

  return 0;
}

// host to device

int hc_mtlMemcpyHtoD (void *hashcat_ctx, mtl_device_id metal_device, mtl_command_queue command_queue, mtl_mem_t mem_dst, size_t mem_dst_off, const void *host_buf_src, size_t size)
{
  if (command_queue == nil)
  {
    event_log_error (hashcat_ctx, "%s(): metal command queue is invalid", __func__);

    return -1;
  }

  if (host_buf_src == NULL)
  {
    event_log_error (hashcat_ctx, "%s(): host src buffer is invalid", __func__);

    return -1;
  }

  if (mem_dst.buf_ptr == nil)
  {
    event_log_error (hashcat_ctx, "%s(): metal dst buffer is invalid", __func__);

    return -1;
  }

  if (size <= 0)
  {
    event_log_error (hashcat_ctx, "%s(): buffer size is invalid", __func__);

    return -1;
  }

  if (mem_dst_off < 0)
  {
    event_log_error (hashcat_ctx, "%s(): metal dst offset is invalid", __func__);

    return -1;
  }

  if (mem_dst_off + size > [mem_dst.buf_ptr length])
  {
    event_log_error (hashcat_ctx, "%s(): metal dst offset + size out of bounds", __func__);

    return -1;
  }

  if (mem_dst.buf_mode == MTL_STORAGE_MODE_PRIVATE)
  {
    id<MTLBuffer> staging_buf = [metal_device newBufferWithLength: size options: MTLResourceStorageModeShared];

    if (staging_buf == nil)
    {
      event_log_error (hashcat_ctx, "%s(): failed to create staging buffer", __func__);

      return -1;
    }

    void *staging_buf_ptr = [staging_buf contents];

    if (staging_buf_ptr == nil)
    {
      event_log_error (hashcat_ctx, "%s(): failed to get staging buffer ptr", __func__);

      return -1;
    }

    memcpy (staging_buf_ptr, host_buf_src, size);

    id<MTLCommandBuffer> command_buffer = [command_queue commandBuffer];

    if (command_buffer == nil)
    {
      event_log_error (hashcat_ctx, "%s(): failed to create a new command buffer", __func__);

      return -1;
    }

    id<MTLBlitCommandEncoder> blit_encoder = [command_buffer blitCommandEncoder];

    if (blit_encoder == nil)
    {
      event_log_error (hashcat_ctx, "%s(): failed to create a blit command encoder", __func__);

      return -1;
    }

    [blit_encoder copyFromBuffer: staging_buf sourceOffset: 0 toBuffer: mem_dst.buf_ptr destinationOffset: mem_dst_off size: size];

    [blit_encoder endEncoding];

    [command_buffer commit];

    [command_buffer waitUntilCompleted];

    #if !__has_feature(objc_arc)
    [staging_buf release];
    #endif

    return 0;
  }

  void *mem_dst_ptr = [mem_dst.buf_ptr contents];

  if (mem_dst_ptr == NULL)
  {
    event_log_error (hashcat_ctx, "%s(): failed to get metal dst ptr", __func__);

    return -1;
  }

  if (memcpy (mem_dst_ptr + mem_dst_off, host_buf_src, size) != mem_dst_ptr + mem_dst_off)
  {
    event_log_error (hashcat_ctx, "%s(): memcpy failed", __func__);

    return -1;
  }

  if (mem_dst.buf_mode == MTL_STORAGE_MODE_MANAGED)
  {
    [mem_dst.buf_ptr didModifyRange: NSMakeRange (mem_dst_off, size)];
  }

  return 0;
}

// device to host

int hc_mtlMemcpyDtoH (void *hashcat_ctx, mtl_device_id metal_device, mtl_command_queue command_queue, void *host_buf_dst, mtl_mem_t mem_src, size_t mem_src_off, size_t size)
{
  if (command_queue == nil)
  {
    event_log_error (hashcat_ctx, "%s(): metal command queue is invalid", __func__);

    return -1;
  }

  if (mem_src.buf_ptr == nil)
  {
    event_log_error (hashcat_ctx, "%s(): metal src buffer is invalid", __func__);

    return -1;
  }

  if (host_buf_dst == NULL)
  {
    event_log_error (hashcat_ctx, "%s(): host dst buffer is invalid", __func__);

    return -1;
  }

  if (size <= 0)
  {
    event_log_error (hashcat_ctx, "%s(): buffer size is invalid", __func__);

    return -1;
  }

  if (mem_src_off + size > [mem_src.buf_ptr length])
  {
    event_log_error (hashcat_ctx, "%s(): metal src offset + size out of bounds", __func__);

    return -1;
  }

  if (mem_src.buf_mode == MTL_STORAGE_MODE_SHARED)
  {
    // get src buf ptr

    void *mem_src_ptr = [mem_src.buf_ptr contents];

    if (mem_src_ptr == NULL)
    {
      event_log_error (hashcat_ctx, "%s(): failed to get metal src ptr", __func__);

      return -1;
    }

    if (memcpy (host_buf_dst, mem_src_ptr + mem_src_off, size) != host_buf_dst)
    {
      event_log_error (hashcat_ctx, "%s(): memcpy failed", __func__);

      return -1;
    }

    return 0;
  }

  id<MTLBuffer> staging_buf = nil;

  if (mem_src.buf_mode == MTL_STORAGE_MODE_PRIVATE)
  {
    staging_buf = [metal_device newBufferWithLength: size options: MTLResourceStorageModeShared];

    if (staging_buf == nil)
    {
      event_log_error (hashcat_ctx, "%s(): failed to create staging buffer", __func__);

      return -1;
    }
  }

  id<MTLCommandBuffer> command_buffer = [command_queue commandBuffer];

  if (command_buffer == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create a new command buffer", __func__);

    #if !__has_feature(objc_arc)
    if (staging_buf != nil)
    {
      [staging_buf release];
    }
    #endif

    return -1;
  }

  id<MTLBlitCommandEncoder> blit_encoder = [command_buffer blitCommandEncoder];

  if (blit_encoder == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create a blit command encoder", __func__);

    #if !__has_feature(objc_arc)
    if (staging_buf != nil)
    {
      [staging_buf release];
    }
    #endif

    return -1;
  }

  if (mem_src.buf_mode == MTL_STORAGE_MODE_MANAGED)
  {
    [blit_encoder synchronizeResource: mem_src.buf_ptr];
  }
  else
  {
    [blit_encoder copyFromBuffer: mem_src.buf_ptr sourceOffset: mem_src_off toBuffer: staging_buf destinationOffset: 0 size: size];
  }

  [blit_encoder endEncoding];

  [command_buffer commit];

  [command_buffer waitUntilCompleted];

  if (mem_src.buf_mode == MTL_STORAGE_MODE_MANAGED)
  {
    // get src buf ptr

    void *mem_src_ptr = [mem_src.buf_ptr contents];

    if (mem_src_ptr == NULL)
    {
      event_log_error (hashcat_ctx, "%s(): failed to get metal src ptr", __func__);

      return -1;
    }

    if (memcpy (host_buf_dst, mem_src_ptr + mem_src_off, size) != host_buf_dst)
    {
      event_log_error (hashcat_ctx, "%s(): memcpy failed", __func__);

      return -1;
    }

    return 0;
  }

  // PRIVATE

  void *staging_buf_ptr = [staging_buf contents];

  if (staging_buf_ptr == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to get staging buffer ptr", __func__);

    #if !__has_feature(objc_arc)
    [staging_buf release];
    #endif

    return -1;
  }

  if (memcpy (host_buf_dst, staging_buf_ptr, size) != host_buf_dst)
  {
    event_log_error (hashcat_ctx, "%s(): memcpy failed", __func__);

    #if !__has_feature(objc_arc)
    [staging_buf release];
    #endif

    return -1;
  }

  #if !__has_feature(objc_arc)
  [staging_buf release];
  #endif

  return 0;
}

int hc_mtlRuntimeGetVersionString (void *hashcat_ctx, char *runtimeVersion_str, size_t *size)
{
  CFURLRef plist_url = CFURLCreateWithFileSystemPath (kCFAllocatorDefault, CFSTR ("/System/Library/Frameworks/Metal.framework/Versions/Current/Resources/version.plist"), kCFURLPOSIXPathStyle, false);

  if (plist_url == NULL)
  {
    event_log_error (hashcat_ctx, "%s(): CFURLCreateWithFileSystemPath() failed\n", __func__);

    return -1;
  }

  CFReadStreamRef plist_stream = CFReadStreamCreateWithFile (NULL, plist_url);

  if (plist_stream == NULL)
  {
    event_log_error (hashcat_ctx, "%s(): CFReadStreamCreateWithFile() failed\n", __func__);

    CFRelease (plist_url);

    return -1;
  }

  if (CFReadStreamOpen (plist_stream) == false)
  {
    event_log_error (hashcat_ctx, "%s(): CFReadStreamOpen() failed\n", __func__);

    CFRelease (plist_stream);
    CFRelease (plist_url);

    return -1;
  }

  CFPropertyListRef plist_prop = CFPropertyListCreateWithStream (NULL, plist_stream, 0, kCFPropertyListImmutable, NULL, NULL);

  if (plist_prop == NULL)
  {
    event_log_error (hashcat_ctx, "%s(): CFPropertyListCreateWithStream() failed\n", __func__);

    CFReadStreamClose (plist_stream);
    CFRelease (plist_stream);
    CFRelease (plist_url);

    return -1;
  }

  CFStringRef runtime_version_cfstr = CFRetain (CFDictionaryGetValue (plist_prop, CFSTR ("CFBundleVersion")));

  if (runtime_version_cfstr != NULL)
  {
    CFRetain (runtime_version_cfstr);

    if (runtimeVersion_str == NULL)
    {
      CFIndex len = CFStringGetLength (runtime_version_cfstr);
      CFIndex maxSize = CFStringGetMaximumSizeForEncoding (len, kCFStringEncodingUTF8) + 1;

      *size = maxSize;

      CFRelease (runtime_version_cfstr);
      CFRelease (plist_prop);
      CFReadStreamClose (plist_stream);
      CFRelease (plist_stream);
      CFRelease (plist_url);

      return 0;
    }

    CFIndex maxSize = *size;

    if (CFStringGetCString (runtime_version_cfstr, runtimeVersion_str, maxSize, kCFStringEncodingUTF8) == false)
    {
      event_log_error (hashcat_ctx, "%s(): CFStringGetCString() failed\n", __func__);

      hcfree (runtimeVersion_str);

      CFRelease (runtime_version_cfstr);
      CFRelease (plist_prop);
      CFReadStreamClose (plist_stream);
      CFRelease (plist_stream);
      CFRelease (plist_url);

      return -1;
    }

    CFRelease (runtime_version_cfstr);
    CFRelease (plist_prop);
    CFReadStreamClose (plist_stream);
    CFRelease (plist_stream);
    CFRelease (plist_url);

    return 0;
  }

  CFRelease (plist_prop);
  CFReadStreamClose (plist_stream);
  CFRelease (plist_stream);
  CFRelease (plist_url);

  return -1;
}

int hc_mtlEncodeComputeCommand_pre (void *hashcat_ctx, mtl_pipeline metal_pipeline, mtl_command_queue metal_command_queue, mtl_command_buffer *metal_command_buffer, mtl_command_encoder *metal_command_encoder)
{
  if (metal_pipeline == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal_pipeline", __func__);

    return -1;
  }

  if (metal_command_queue == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal_command_queue", __func__);

    return -1;
  }

  id<MTLCommandBuffer> metal_commandBuffer = [metal_command_queue commandBuffer];

  if (metal_commandBuffer == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal_commandBuffer", __func__);

    return -1;
  }

  id<MTLComputeCommandEncoder> metal_commandEncoder = [metal_commandBuffer computeCommandEncoder];

  if (metal_commandEncoder == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal_commandBuffer", __func__);

    return -1;
  }

  [metal_commandEncoder setComputePipelineState: metal_pipeline];

  *metal_command_buffer  = metal_commandBuffer;

  *metal_command_encoder = metal_commandEncoder;

  return 0;
}

int hc_mtlSetCommandEncoderArg (void *hashcat_ctx, mtl_command_encoder metal_command_encoder, size_t off, size_t idx, id mem, void *host_data, size_t host_data_size)
{
  if (metal_command_encoder == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal_command_encoder", __func__);

    return -1;
  }

  // host_data can be objective-c object (so use nil) or C pointer (so use NULL)

  if (mem == nil && host_data == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid mem/host_data", __func__);

    return -1;
  }

  if (mem == nil)
  {
    if (host_data_size <= 0)
    {
      event_log_error (hashcat_ctx, "%s(): invalid host_data size", __func__);

      return -1;
    }
  }
  else
  {
    if (off < 0 || off > SIZE_MAX)
    {
      event_log_error (hashcat_ctx, "%s(): invalid buf off", __func__);

      return -1;
    }
  }

  if (idx < 0)
  {
    event_log_error (hashcat_ctx, "%s(): invalid mem/host_data idx", __func__);

    return -1;
  }

  // host_data can be objective-c object (so use nil) or C pointer (so use NULL)
  if (host_data == nil)
  {
    [metal_command_encoder setBuffer: mem offset: off atIndex: idx];
  }
  else
  {
    [metal_command_encoder setBytes: host_data length: host_data_size atIndex: idx];
  }

  return 0;
}

int hc_mtlEncodeComputeCommand (void *hashcat_ctx, mtl_command_encoder metal_command_encoder, mtl_command_buffer metal_command_buffer, const unsigned int work_dim, const size_t global_work_size[3], const size_t local_work_size[3], double *ms)
{
  if (metal_command_encoder == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal_command_encoder", __func__);

    return -1;
  }

  if (metal_command_buffer == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal_command_buffer", __func__);

    return -1;
  }

  MTLSize threadsPerThreadgroup =
  {
    local_work_size[0],
    local_work_size[1],
    local_work_size[2]
  };

  MTLSize threadgroupsPerGrid =
  {
    (global_work_size[0] + threadsPerThreadgroup.width - 1) / threadsPerThreadgroup.width,
    work_dim > 1 ? (global_work_size[1] + threadsPerThreadgroup.height - 1) / threadsPerThreadgroup.height : 1,
    work_dim > 2 ? (global_work_size[2] + threadsPerThreadgroup.depth - 1) / threadsPerThreadgroup.depth : 1
  };

  [metal_command_encoder dispatchThreadgroups: threadgroupsPerGrid threadsPerThreadgroup: threadsPerThreadgroup];

  [metal_command_encoder endEncoding];

  // using completition handler to get GPU timing

  __block CFTimeInterval elapsed = 0;

  [metal_command_buffer addCompletedHandler:^(id<MTLCommandBuffer> cb) {
    CFTimeInterval gpuStart = cb.GPUStartTime;
    CFTimeInterval gpuEnd = cb.GPUEndTime;
    elapsed = gpuEnd - gpuStart;

    *ms = elapsed * 1000.0;
  }];

  [metal_command_buffer commit];

  [metal_command_buffer waitUntilCompleted];

  return 0;
}

int hc_mtlCreateLibraryWithFile (void *hashcat_ctx, mtl_device_id metal_device, const char *cached_file, mtl_library *metal_library)
{
  NSError *error = nil;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal device", __func__);

    return -1;
  }

  if (cached_file == NULL)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metallib", __func__);

    return -1;
  }

  NSString *k_string = [NSString stringWithCString: cached_file encoding: NSUTF8StringEncoding];

  if (k_string != nil)
  {
    NSURL *libURL = [NSURL fileURLWithPath: k_string];

    if (libURL != nil)
    {
      id <MTLLibrary> metal_library_tmp = [metal_device newLibraryWithURL: libURL error: &error];

      if (error != nil)
      {
        event_log_error (hashcat_ctx, "%s(): failed to create metal library from metallib, %s", __func__, [[error localizedDescription] UTF8String]);

        return -1;
      }

      *metal_library = metal_library_tmp;

      return 0;
    }
  }

  return -1;
}

int hc_mtlCreateLibraryWithSource (void *hashcat_ctx, mtl_device_id metal_device, const char *kernel_sources, const char *build_options_buf, const char *cpath, mtl_library *metal_library)
{
  NSError *error = nil;

  NSString *k_string = [NSString stringWithCString: kernel_sources encoding: NSUTF8StringEncoding];

  if (k_string != nil)
  {
    MTLCompileOptions *compileOptions = [MTLCompileOptions new];

    NSMutableDictionary *build_options_dict = nil;

    if (build_options_buf != NULL)
    {
      //printf ("using build_opts from arg:\n%s\n", build_options_buf);

      build_options_dict = [NSMutableDictionary dictionary]; //[[NSMutableDictionary alloc] init];

      if (hc_mtlBuildOptionsToDict (hashcat_ctx, build_options_buf, cpath, build_options_dict) == -1)
      {
        event_log_error (hashcat_ctx, "%s(): failed to build options dictionary", __func__);

        [build_options_dict release];

        return -1;
      }

      compileOptions.preprocessorMacros = build_options_dict;

      /*
      compileOptions.optimizationLevel = MTLLibraryOptimizationLevelSize;
      compileOptions.mathMode = MTLMathModeSafe;
      // compileOptions.mathMode = MTLMathModeRelaxed;
      // compileOptions.enableLogging = true;
      */
    }

    // todo: detect current os version and choose the right
    // compileOptions.languageVersion = MTL_LANGUAGEVERSION_2_3;
/*
    if (@available(macOS 15.0, *))
    {
      compileOptions.languageVersion = MTL_LANGUAGEVERSION_3_2;
    }
    else if (@available(macOS 14.0, *))
    {
      compileOptions.languageVersion = MTL_LANGUAGEVERSION_3_1;
    }
    else if (@available(macOS 13.0, *))
    {
      compileOptions.languageVersion = MTL_LANGUAGEVERSION_3_0;
    }
    else if (@available(macOS 12.0, *))
    {
      compileOptions.languageVersion = MTL_LANGUAGEVERSION_2_4;
    }
    else if (@available(macOS 11.0, *))
    {
      compileOptions.languageVersion = MTL_LANGUAGEVERSION_2_3;
    }
    else if (@available(macOS 10.15, *))
    {
      compileOptions.languageVersion = MTL_LANGUAGEVERSION_2_2;
    }
    else if (@available(macOS 10.14, *))
    {
      compileOptions.languageVersion = MTL_LANGUAGEVERSION_2_1;
    }
    else if (@available(macOS 10.13, *))
    {
      compileOptions.languageVersion = MTL_LANGUAGEVERSION_2_0;
    }
    else if (@available(macOS 10.12, *))
    {
      compileOptions.languageVersion = MTL_LANGUAGEVERSION_1_2;
    }
    else if (@available(macOS 10.11, *))
    {
      compileOptions.languageVersion = MTL_LANGUAGEVERSION_1_1;
    }
*/
    id<MTLLibrary> metal_library_tmp = [metal_device newLibraryWithSource: k_string options: compileOptions error: &error];

    #if !__has_feature(objc_arc)
    [compileOptions release];
    #endif

    compileOptions = nil;

    if (build_options_dict != nil)
    {
      #if !__has_feature(objc_arc)
      [build_options_dict release];
      #endif

      build_options_dict = nil;
    }

    if (error != nil)
    {
      event_log_error (hashcat_ctx, "%s(): failed to create metal library, %s", __func__, [[error localizedDescription] UTF8String]);

      return -1;
    }

    *metal_library = metal_library_tmp;

    return 0;
  }

  return -1;
}

int hc_mtlFinish (void *hashcat_ctx, mtl_command_queue command_queue)
{
  if (command_queue == nil)
  {
    event_log_error (hashcat_ctx, "%s(): metal command queue is invalid", __func__);

    return -1;
  }

  id<MTLCommandBuffer> command_buffer = [command_queue commandBuffer];

  if (command_buffer == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create a new command buffer", __func__);

    return -1;
  }

  [command_buffer commit];

  [command_buffer waitUntilCompleted];

  return 0;
}
