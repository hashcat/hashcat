/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "timer.h"
#include "path.h"
#include "shared.h"
#include "system.h"
#include "ext_metal.h"
#include "requirements.h"

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

// Metal 4 arrived with macOS 26, and the backend still runs on macOS 13. Every Metal 4 class and
// selector is therefore reached by name, through the Objective-C runtime, so that one binary builds
// against any SDK and runs on every macOS the backend accepts. A device without it, or one the setup
// below turns down, keeps the Metal 3 path, which is unchanged.

static SEL mtl4_sel (const char *name)
{
  return sel_registerName (name);
}

static bool mtl4_responds (id obj, const char *name)
{
  if (obj == nil) return false;

  return ([obj respondsToSelector: mtl4_sel (name)] == YES);
}

static id mtl4_new (id obj, const char *name)
{
  return ((id (*) (id, SEL)) objc_msgSend) (obj, mtl4_sel (name));
}

static id mtl4_new_desc (id obj, const char *name, id desc, NSError **error)
{
  return ((id (*) (id, SEL, id, NSError **)) objc_msgSend) (obj, mtl4_sel (name), desc, error);
}

static void mtl4_call (id obj, const char *name)
{
  ((void (*) (id, SEL)) objc_msgSend) (obj, mtl4_sel (name));
}

static void mtl4_call_obj (id obj, const char *name, id arg)
{
  ((void (*) (id, SEL, id)) objc_msgSend) (obj, mtl4_sel (name), arg);
}

static void mtl4_call_uint (id obj, const char *name, NSUInteger arg)
{
  ((void (*) (id, SEL, NSUInteger)) objc_msgSend) (obj, mtl4_sel (name), arg);
}

static id   hc_mtl4_pipeline_desc (mtl_library metal_library, NSString *f_name);
static void hc_mtlArchiveStale    (void *hashcat_ctx, hc_device_param_t *device_param, const int program);
static void hc_mtlArchiveAbandon  (void *hashcat_ctx, hc_device_param_t *device_param, const int program, const char *func_name);

// Everything a device holds for Metal 4 beyond its queue. Released with the queue.

static void hc_mtl4_fini (hc_device_param_t *device_param)
{
  if (device_param->metal_sema != NULL)
  {
    dispatch_release (device_param->metal_sema);

    device_param->metal_sema = NULL;
  }

  #if !__has_feature(objc_arc)
  if (device_param->metal_scratch_buf       != nil) [device_param->metal_scratch_buf       release];
  if (device_param->metal_argument_table    != nil) [device_param->metal_argument_table    release];
  if (device_param->metal_command_buffer    != nil) [device_param->metal_command_buffer    release];
  if (device_param->metal_command_allocator != nil) [device_param->metal_command_allocator release];
  if (device_param->metal_residency_set     != nil) [device_param->metal_residency_set     release];
  if (device_param->metal_compiler          != nil) [device_param->metal_compiler          release];
  #endif

  device_param->metal_scratch_buf       = nil;
  device_param->metal_argument_table    = nil;
  device_param->metal_command_buffer    = nil;
  device_param->metal_command_allocator = nil;
  device_param->metal_residency_set     = nil;
  device_param->metal_compiler          = nil;

  device_param->metal_scratch_offset = 0;
}

static int hc_mtl4_init_failed (void *hashcat_ctx, hc_device_param_t *device_param, mtl_command_queue queue, const char *what, NSError *error)
{
  if (error != nil)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Metal 4 setup failed, %s: %s. Using Metal 3.", device_param->device_id + 1, what, [[error localizedDescription] UTF8String]);
  }
  else
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Metal 4 setup failed, %s is not available. Using Metal 3.", device_param->device_id + 1, what);
  }

  event_log_warning (hashcat_ctx, NULL);

  hc_mtl4_fini (device_param);

  #if !__has_feature(objc_arc)
  if (queue != nil) [queue release];
  #endif

  return -1;
}

// Set a device up for Metal 4: its queue, and around it the allocator, the one command buffer every
// launch and copy reuses, the argument table, the residency set the queue carries, the compiler, and
// the scratch buffer that stands in for setBytes:. Every object is asked for the selectors the
// launch and copy paths send, so a system with a different Metal 4 is turned down here rather than
// at the first launch.

static int hc_mtl4_init (void *hashcat_ctx, hc_device_param_t *device_param, mtl_command_queue *command_queue)
{
  mtl_device_id metal_device = device_param->metal_device;

  static const char *classes[] =
  {
    "MTL4CommandAllocatorDescriptor",
    "MTLResidencySetDescriptor",
    "MTL4ArgumentTableDescriptor",
    "MTL4CompilerDescriptor",
    "MTL4LibraryDescriptor",
    "MTL4LibraryFunctionDescriptor",
    "MTL4ComputePipelineDescriptor",
    "MTL4CommitOptions",
  };

  for (size_t i = 0; i < sizeof (classes) / sizeof (classes[0]); i++)
  {
    if (objc_getClass (classes[i]) == nil) return hc_mtl4_init_failed (hashcat_ctx, device_param, nil, classes[i], nil);
  }

  static const char *device_selectors[] =
  {
    "newMTL4CommandQueue",
    "newCommandAllocatorWithDescriptor:error:",
    "newResidencySetWithDescriptor:error:",
    "newArgumentTableWithDescriptor:error:",
    "newCommandBuffer",
    "newCompilerWithDescriptor:error:",
  };

  for (size_t i = 0; i < sizeof (device_selectors) / sizeof (device_selectors[0]); i++)
  {
    if (mtl4_responds (metal_device, device_selectors[i]) == false) return hc_mtl4_init_failed (hashcat_ctx, device_param, nil, device_selectors[i], nil);
  }

  NSError *error = nil;

  mtl_command_queue queue = mtl4_new (metal_device, "newMTL4CommandQueue");

  if (queue == nil) return hc_mtl4_init_failed (hashcat_ctx, device_param, nil, "newMTL4CommandQueue", nil);

  id desc = [objc_getClass ("MTL4CommandAllocatorDescriptor") new];

  device_param->metal_command_allocator = mtl4_new_desc (metal_device, "newCommandAllocatorWithDescriptor:error:", desc, &error);

  #if !__has_feature(objc_arc)
  [desc release];
  #endif

  if (device_param->metal_command_allocator == nil) return hc_mtl4_init_failed (hashcat_ctx, device_param, queue, "newCommandAllocatorWithDescriptor", error);

  desc = [objc_getClass ("MTLResidencySetDescriptor") new];

  mtl4_call_uint (desc, "setInitialCapacity:", 128);

  device_param->metal_residency_set = mtl4_new_desc (metal_device, "newResidencySetWithDescriptor:error:", desc, &error);

  #if !__has_feature(objc_arc)
  [desc release];
  #endif

  if (device_param->metal_residency_set == nil) return hc_mtl4_init_failed (hashcat_ctx, device_param, queue, "newResidencySetWithDescriptor", error);

  // the queue carries the set, so every command buffer committed to it runs with the same
  // allocations resident

  mtl4_call_obj (queue, "addResidencySet:", device_param->metal_residency_set);

  // 31 is the most an argument table takes, and the device engine binds that many

  desc = [objc_getClass ("MTL4ArgumentTableDescriptor") new];

  mtl4_call_uint (desc, "setMaxBufferBindCount:", 31);

  device_param->metal_argument_table = mtl4_new_desc (metal_device, "newArgumentTableWithDescriptor:error:", desc, &error);

  #if !__has_feature(objc_arc)
  [desc release];
  #endif

  if (device_param->metal_argument_table == nil) return hc_mtl4_init_failed (hashcat_ctx, device_param, queue, "newArgumentTableWithDescriptor", error);

  device_param->metal_command_buffer = mtl4_new (metal_device, "newCommandBuffer");

  if (device_param->metal_command_buffer == nil) return hc_mtl4_init_failed (hashcat_ctx, device_param, queue, "newCommandBuffer", nil);

  desc = [objc_getClass ("MTL4CompilerDescriptor") new];

  device_param->metal_compiler = mtl4_new_desc (metal_device, "newCompilerWithDescriptor:error:", desc, &error);

  #if !__has_feature(objc_arc)
  [desc release];
  #endif

  if (device_param->metal_compiler == nil) return hc_mtl4_init_failed (hashcat_ctx, device_param, queue, "newCompilerWithDescriptor", error);

  device_param->metal_scratch_buf = [metal_device newBufferWithLength: METAL4_SCRATCH_SIZE options: MTLResourceStorageModeShared];

  if (device_param->metal_scratch_buf == nil) return hc_mtl4_init_failed (hashcat_ctx, device_param, queue, "newBufferWithLength", nil);

  device_param->metal_scratch_offset = 0;

  mtl4_call_obj (device_param->metal_residency_set, "addAllocation:", device_param->metal_scratch_buf);
  mtl4_call     (device_param->metal_residency_set, "commit");
  mtl4_call     (device_param->metal_residency_set, "requestResidency");

  device_param->metal_sema = dispatch_semaphore_create (0);

  const struct { id obj; const char *name; } sends[] =
  {
    { queue,                                 "commit:count:options:" },
    { device_param->metal_command_allocator, "reset" },
    { device_param->metal_residency_set,     "removeAllocation:" },
    { device_param->metal_command_buffer,    "beginCommandBufferWithAllocator:" },
    { device_param->metal_command_buffer,    "endCommandBuffer" },
    { device_param->metal_command_buffer,    "useResidencySet:" },
    { device_param->metal_command_buffer,    "computeCommandEncoder" },
    { device_param->metal_argument_table,    "setAddress:atIndex:" },
    { device_param->metal_scratch_buf,       "gpuAddress" },
    { device_param->metal_compiler,          "newLibraryWithDescriptor:error:" },
    { device_param->metal_compiler,          "newComputePipelineStateWithDescriptor:compilerTaskOptions:error:" },
  };

  for (size_t i = 0; i < sizeof (sends) / sizeof (sends[0]); i++)
  {
    if (mtl4_responds (sends[i].obj, sends[i].name) == false) return hc_mtl4_init_failed (hashcat_ctx, device_param, queue, sends[i].name, nil);
  }

  *command_queue = queue;

  return 0;
}

// The one command buffer a device has, begun again for each launch or copy. Each is committed and
// waited for before the next begins, which is what the Metal 3 path does with a fresh command buffer
// every time, and the allocator is given back only once the GPU is done, as the API asks.

static id hc_mtl4_begin (void *hashcat_ctx, hc_device_param_t *device_param)
{
  id command_buffer = device_param->metal_command_buffer;

  if (command_buffer == nil)
  {
    event_log_error (hashcat_ctx, "%s(): Metal 4 command buffer is nil", __func__);

    return nil;
  }

  mtl4_call_obj (command_buffer, "beginCommandBufferWithAllocator:", device_param->metal_command_allocator);
  mtl4_call_obj (command_buffer, "useResidencySet:", device_param->metal_residency_set);

  return command_buffer;
}

static int hc_mtl4_commit_and_wait (void *hashcat_ctx, hc_device_param_t *device_param, id command_buffer, double *ms)
{
  mtl4_call (command_buffer, "endCommandBuffer");

  // Metal 4 has no waitUntilCompleted. The commit takes a feedback handler that runs once the GPU is
  // done, with the same start and end times the Metal 3 completion handler reported, and a semaphore
  // turns that into the wait.

  dispatch_semaphore_t sema = device_param->metal_sema;

  __block double   gpu_ms    = 0;
  __block NSError *gpu_error = nil;

  id options = [objc_getClass ("MTL4CommitOptions") new];

  ((void (*) (id, SEL, void (^) (id))) objc_msgSend) (options, mtl4_sel ("addFeedbackHandler:"), ^(id feedback)
  {
    double (*time_of) (id, SEL) = (double (*) (id, SEL)) objc_msgSend;

    gpu_ms = (time_of (feedback, mtl4_sel ("GPUEndTime")) - time_of (feedback, mtl4_sel ("GPUStartTime"))) * 1000.0;

    gpu_error = [mtl4_new (feedback, "error") retain];

    dispatch_semaphore_signal (sema);
  });

  id command_buffers[1] = { command_buffer };

  ((void (*) (id, SEL, id *, NSUInteger, id)) objc_msgSend) (device_param->metal_command_queue, mtl4_sel ("commit:count:options:"), command_buffers, 1, options);

  dispatch_semaphore_wait (sema, DISPATCH_TIME_FOREVER);

  mtl4_call (device_param->metal_command_allocator, "reset");

  device_param->metal_scratch_offset = 0;

  #if !__has_feature(objc_arc)
  [options release];
  #endif

  if (gpu_error != nil)
  {
    event_log_error (hashcat_ctx, "%s(): Metal 4 command buffer failed, %s", __func__, [[gpu_error localizedDescription] UTF8String]);

    #if !__has_feature(objc_arc)
    [gpu_error release];
    #endif

    return -1;
  }

  if (ms != NULL) *ms = gpu_ms;

  return 0;
}

// A copy between two buffers, which the Metal 4 compute encoder took over from the blit encoder. The
// two are made resident for it the way a launch makes its arguments resident.

static int hc_mtl4_copy (void *hashcat_ctx, hc_device_param_t *device_param, id dst, size_t dst_off, id src, size_t src_off, size_t size)
{
  mtl4_call_obj (device_param->metal_residency_set, "addAllocation:", src);
  mtl4_call_obj (device_param->metal_residency_set, "addAllocation:", dst);
  mtl4_call     (device_param->metal_residency_set, "commit");

  id command_buffer = hc_mtl4_begin (hashcat_ctx, device_param);

  if (command_buffer == nil) return -1;

  id command_encoder = mtl4_new (command_buffer, "computeCommandEncoder");

  if (command_encoder == nil)
  {
    event_log_error (hashcat_ctx, "%s(): Metal 4 compute command encoder is nil", __func__);

    return -1;
  }

  ((void (*) (id, SEL, id, NSUInteger, id, NSUInteger, NSUInteger)) objc_msgSend) (command_encoder, mtl4_sel ("copyFromBuffer:sourceOffset:toBuffer:destinationOffset:size:"), src, (NSUInteger) src_off, dst, (NSUInteger) dst_off, (NSUInteger) size);

  mtl4_call (command_encoder, "endEncoding");

  return hc_mtl4_commit_and_wait (hashcat_ctx, device_param, command_buffer, NULL);
}

static void hc_mtl4_forget (hc_device_param_t *device_param, id buffer)
{
  mtl4_call_obj (device_param->metal_residency_set, "removeAllocation:", buffer);
  mtl4_call     (device_param->metal_residency_set, "commit");
}

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

    case MTL_DEVICE_ATTRIBUTE_METAL_VERSION:
      // asked from the top down; the feature sets are the answer of a runtime without supportsFamily:

      *pi = 0;

      BOOL (*supports) (id, SEL, long) = (BOOL (*) (id, SEL, long)) objc_msgSend;

      if (mtl4_responds (metal_device, "supportsFamily:") == true)
      {
        if      (supports (metal_device, mtl4_sel ("supportsFamily:"), MTL_GPU_FAMILY_METAL4) == YES) *pi = 4;
        else if (supports (metal_device, mtl4_sel ("supportsFamily:"), MTL_GPU_FAMILY_METAL3) == YES) *pi = 3;
        else if (supports (metal_device, mtl4_sel ("supportsFamily:"), MTL_GPU_FAMILY_MAC2)   == YES) *pi = 2;
        else if (supports (metal_device, mtl4_sel ("supportsFamily:"), MTL_GPU_FAMILY_MAC1)   == YES) *pi = 1;
      }
      else if (mtl4_responds (metal_device, "supportsFeatureSet:") == true)
      {
        if      (supports (metal_device, mtl4_sel ("supportsFeatureSet:"), MTL_FEATURE_SET_MACOS_GPUFAMILY2_V1) == YES) *pi = 2;
        else if (supports (metal_device, mtl4_sel ("supportsFeatureSet:"), MTL_FEATURE_SET_MACOS_GPUFAMILY1_V1) == YES) *pi = 1;
      }

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

// The free memory of a device that shares the system's is the system's free memory, read the way
// the host side reads it, which is what cuMemGetInfo answers on the other backends. Metal has no
// such query of its own, and a discrete GPU is answered as unknown.

int hc_mtlDeviceMemFree (void *hashcat_ctx, size_t *bytes, mtl_device_id metal_device)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device", __func__);

    return -1;
  }

  if ([metal_device respondsToSelector: @selector (hasUnifiedMemory)] == NO) return -1;

  if ([metal_device hasUnifiedMemory] == NO) return -1;

  u64 free_mem = 0;

  if (get_free_memory (&free_mem) == false) return -1;

  *bytes = (size_t) free_mem;

  return 0;
}

int hc_mtlCreateCommandQueue (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, mtl_command_queue *command_queue)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device", __func__);

    return -1;
  }

  device_param->use_metal4 = false;

  // A device that reports the Metal 4 family and shares its memory with the host runs on Metal 4. A
  // discrete GPU stays on Metal 3: its buffers may come back Managed, and the Metal 4 compute encoder
  // has no synchronizeResource: to bring those back to the host.

  if ((device_param->metal_version >= 4) && (device_param->device_host_unified_memory == 1))
  {
    if (hc_mtl4_init (hashcat_ctx, device_param, command_queue) == 0)
    {
      device_param->use_metal4 = true;
    }
  }

  if (device_param->use_metal4 == false)
  {
    // Let the framework build pipeline states in parallel. Asked here, once per device being set up:
    // at enumeration, in hc_mtlDeviceGet, the same call crashes on macOS 26.

    SEL setShouldMaximizeConcurrentCompilationSel = NSSelectorFromString (@"setShouldMaximizeConcurrentCompilation:");

    if ([metal_device respondsToSelector: setShouldMaximizeConcurrentCompilationSel] == YES)
    {
      ((void (*) (id, SEL, BOOL)) objc_msgSend) (metal_device, setShouldMaximizeConcurrentCompilationSel, YES);
    }

    mtl_command_queue queue = [metal_device newCommandQueue];

    if (queue == nil)
    {
      event_log_error (hashcat_ctx, "%s(): failed to create newCommandQueue", __func__);

      return -1;
    }

    *command_queue = queue;
  }

  device_param->metal_fake_buf.buf_ptr = nil;

  if (hc_mtlCreateBuffer (hashcat_ctx, device_param, metal_device, sizeof (u8), NULL, &device_param->metal_fake_buf, MTL_STORAGE_MODE_PRIVATE) == -1) return -1;

  return 0;
}

// A pipeline that will not build is nearly always Apple's shader compiler running out of room on one
// of our larger kernels, not anything the user did. The error the framework hands back says only that
// the compiler service went away, so say what that means and name the way around it.

static void hc_mtlCompilerGaveUp (void *hashcat_ctx, const char *func_name)
{
  event_log_warning (hashcat_ctx, "* Apple's Metal shader compiler could not build kernel '%s'.", func_name);
  event_log_warning (hashcat_ctx, "  The kernel is too large for it. This is a limit of the compiler, not of the GPU.");
  event_log_warning (hashcat_ctx, "  The same GPU can run this hash mode through the OpenCL backend instead.");
  event_log_warning (hashcat_ctx, "  Use --backend-ignore-metal, or select the OpenCL device with -d.");
  event_log_warning (hashcat_ctx, NULL);
}

// One attempt at a pipeline, on a worker thread under the compiler timeout. The block touches
// nothing but what it captured, since it outlives the call when the timeout hits; what it found is
// applied to the device by the caller, once the wait has returned. With lookup the archive is asked
// and a miss is reported in place of a build; with add, Metal 3 puts the built pipeline into the
// archive.

static int hc_mtlBuildRound (void *hashcat_ctx, mtl_device_id metal_device, mtl_function mtl_func, id pipeline_desc, mtl_compiler compiler, mtl_archive archive, const bool lookup, const bool add, const char *func_name, mtl_pipeline *pipeline, bool *missed, bool *added)
{
  user_options_t *user_options = ((hashcat_ctx_t *) hashcat_ctx)->user_options;

  __block mtl_pipeline mtl_pipe   = nil;
  __block bool         was_missed = false;
  __block bool         was_added  = false;
  __block int          rc_async   = 0;

  dispatch_group_t group = dispatch_group_create ();
  dispatch_queue_t queue = dispatch_get_global_queue (DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

  // if no user-defined runtime, set to METAL_COMPILER_RUNTIME

  long timeout = (user_options->metal_compiler_runtime > 0) ? user_options->metal_compiler_runtime : METAL_COMPILER_RUNTIME;

  dispatch_time_t when = dispatch_time (DISPATCH_TIME_NOW, NSEC_PER_SEC * timeout);

  dispatch_group_async (group, queue, ^(void)
  {
    NSError *error = nil;

    if (pipeline_desc != nil)
    {
      if (lookup == true)
      {
        mtl_pipe = ((id (*) (id, SEL, id, NSError **)) objc_msgSend) (archive, mtl4_sel ("newComputePipelineStateWithDescriptor:error:"), pipeline_desc, &error);

        if (mtl_pipe == nil) was_missed = true;

        return;
      }

      id (*build) (id, SEL, id, id, NSError **) = (id (*) (id, SEL, id, id, NSError **)) objc_msgSend;

      mtl_pipe = build (compiler, mtl4_sel ("newComputePipelineStateWithDescriptor:compilerTaskOptions:error:"), pipeline_desc, nil, &error);
    }
    else
    {
      MTLComputePipelineDescriptor *desc = [MTLComputePipelineDescriptor new];

      desc.computeFunction = mtl_func;

      if (lookup == true)
      {
        desc.binaryArchives = @[archive];

        mtl_pipe = [metal_device newComputePipelineStateWithDescriptor: desc options: MTLPipelineOptionFailOnBinaryArchiveMiss reflection: nil error: &error];

        if (mtl_pipe == nil) was_missed = true;

        error = nil;
      }
      else
      {
        mtl_pipe = [metal_device newComputePipelineStateWithDescriptor: desc options: MTLPipelineOptionNone reflection: nil error: &error];

        if ((mtl_pipe != nil) && (add == true))
        {
          NSError *add_error = nil;

          was_added = ([(id <MTLBinaryArchive>) archive addComputePipelineFunctionsWithDescriptor: desc error: &add_error] == YES);
        }
      }

      #if !__has_feature(objc_arc)
      [desc release];
      #endif
    }

    if (error != nil)
    {
      event_log_error (hashcat_ctx, "%s(): failed to create '%s' pipeline, %s", __func__, func_name, [[error localizedDescription] UTF8String]);

      rc_async = -1;
    }
  });

  long rc_queue = dispatch_group_wait (group, when);

  dispatch_release (group);

  if (rc_queue != 0) return -2;

  if (rc_async != 0) return -1;

  *pipeline = mtl_pipe;
  *missed   = was_missed;
  *added    = was_added;

  return 0;
}

int hc_mtlCreateKernel (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, mtl_library metal_library, const int program, const int slot, const char *func_name, mtl_function *metal_function, mtl_pipeline *metal_pipeline)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

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

  // The slot is kept with its program so that the flush can tell which pipelines of the program
  // the archive to be written still lacks.

  device_param->metal_function_program[slot]  = program;
  device_param->metal_function_archived[slot] = false;

  // Metal 4 builds the pipeline from a descriptor naming the function; the MTLFunction is made all
  // the same, so the kernel slot holds the same thing on both paths.

  id pipeline_desc = (device_param->use_metal4 == true) ? hc_mtl4_pipeline_desc (metal_library, f_name) : nil;

  // An archive read from the cache is asked first, and answers nil for a pipeline it does not
  // hold, which an archive from another OS build does for every pipeline. The program then goes
  // back to a fresh archive, builds as a first run would, and the flush rewrites the file.

  bool lookup = (device_param->metal_archive[program] != nil) && (device_param->metal_archive_write[program] == false);

  mtl_pipeline mtl_pipe = nil;

  bool added = false;

  int rc = 0;

  for (int round = 0; round < 2; round++)
  {
    const bool add = (lookup == false) && (device_param->metal_archive_write[program] == true);

    mtl_compiler compiler = (device_param->metal_program_compiler[program] != nil) ? device_param->metal_program_compiler[program] : device_param->metal_compiler;

    bool missed = false;

    rc = hc_mtlBuildRound (hashcat_ctx, metal_device, mtl_func, pipeline_desc, compiler, device_param->metal_archive[program], lookup, add, func_name, &mtl_pipe, &missed, &added);

    if ((rc != 0) || (missed == false)) break;

    hc_mtlArchiveStale (hashcat_ctx, device_param, program);

    lookup = false;
  }

  #if !__has_feature(objc_arc)
  if (pipeline_desc != nil) [pipeline_desc release];
  #endif

  if (rc == -2)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create '%s' pipeline, timeout reached", __func__, func_name);

    hc_mtlCompilerGaveUp (hashcat_ctx, func_name);

    return -1;
  }

  if (rc == -1)
  {
    hc_mtlCompilerGaveUp (hashcat_ctx, func_name);

    return -1;
  }

  if (mtl_pipe == nil)
  {
    event_log_error (hashcat_ctx, "%s(): failed to create '%s' pipeline", __func__, func_name);

    return -1;
  }

  // A pipeline built through the program's compiler is in its serializer on Metal 4; on Metal 3 it
  // is in the archive only if the add went through, and a refusal ends the writing of the archive.

  if (device_param->metal_archive_write[program] == true)
  {
    if ((device_param->use_metal4 == true) || (added == true))
    {
      device_param->metal_function_archived[slot] = true;
    }
    else
    {
      hc_mtlArchiveAbandon (hashcat_ctx, device_param, program, func_name);
    }
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

int hc_mtlCreateBuffer (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, size_t size, void *ptr, mtl_mem_t *mem, metalResourceStorageMode_t metal_storage_mode)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_device == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid device", __func__);

    return -1;
  }

//  MTLResourceOptions bufferOptions = MTLResourceStorageModeShared;

  MTLResourceOptions bufferOptions;

  switch (metal_storage_mode)
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

  // newBufferWithBytesNoCopy () wants a Shared buffer, and the mode asked for above is not always the
  // mode given. A device that takes Managed instead gets a buffer of its own and the caller puts the
  // bytes there, rather than the call failing on it. buf_host says which of the two happened, so a
  // caller handing a pointer over reads the answer instead of predicting it.

  mem->buf_host = 0;

  if ((ptr != NULL) && (bufferOptions == MTLResourceStorageModeShared))
  {
    mem->buf_ptr  = [metal_device newBufferWithBytesNoCopy: ptr length: size options: bufferOptions deallocator: nil];
    mem->buf_host = 1;
  }
  else
  {
    mem->buf_ptr = [metal_device newBufferWithLength: size options: bufferOptions];
  }

  if (mem->buf_ptr == nil)
  {
    event_log_error (hashcat_ctx, "%s(): %s failed (size: %zu)", __func__, (mem->buf_host == 1) ? "newBufferWithBytesNoCopy" : "newBufferWithLength", size);

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

  // Metal 4 runs nothing against a buffer that is not resident, so every buffer joins the device's
  // residency set as it is made, and the set is committed at once rather than at the next launch.

  if (device_param->use_metal4 == true)
  {
    mtl4_call_obj (device_param->metal_residency_set, "addAllocation:", mem->buf_ptr);
    mtl4_call     (device_param->metal_residency_set, "commit");
    mtl4_call     (device_param->metal_residency_set, "requestResidency");
  }

  return 0;
}

int hc_mtlReleaseMemObject (void *hashcat_ctx, void *device_param_ptr, mtl_mem_t *mem)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (mem == NULL || mem->buf_ptr == nil) return -1;

  if (device_param->use_metal4 == true) hc_mtl4_forget (device_param, mem->buf_ptr);

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

int hc_mtlReleasePipeline (void *hashcat_ctx, mtl_pipeline *metal_pipeline)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  if (metal_pipeline == NULL || *metal_pipeline == nil) return -1;

  #if !__has_feature(objc_arc)
  [*metal_pipeline release];
  #endif

  *metal_pipeline = nil;

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

int hc_mtlReleaseCommandQueue (void *hashcat_ctx, void *device_param_ptr, mtl_command_queue *command_queue)
{
  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

  if (command_queue == NULL || *command_queue == nil)
  {
    event_log_error (hashcat_ctx, "%s(): invalid metal command queue", __func__);

    return -1;
  }

  if (device_param->metal_fake_buf.buf_ptr != nil) hc_mtlReleaseMemObject (hashcat_ctx, device_param, &device_param->metal_fake_buf);

  if (device_param->use_metal4 == true)
  {
    hc_mtl4_fini (device_param);

    device_param->use_metal4 = false;
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

int hc_mtlMemcpyDtoD (void *hashcat_ctx, void *device_param_ptr, mtl_command_queue command_queue, mtl_mem_t mem_dst, size_t mem_dst_off, mtl_mem_t mem_src, size_t mem_src_off, size_t size)
{
  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

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

  if (device_param->use_metal4 == true)
  {
    return hc_mtl4_copy (hashcat_ctx, device_param, mem_dst.buf_ptr, mem_dst_off, mem_src.buf_ptr, mem_src_off, size);
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

int hc_mtlMemcpyHtoD (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, mtl_command_queue command_queue, mtl_mem_t mem_dst, size_t mem_dst_off, const void *host_buf_src, size_t size)
{
  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

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

    if (device_param->use_metal4 == true)
    {
      const int rc = hc_mtl4_copy (hashcat_ctx, device_param, mem_dst.buf_ptr, mem_dst_off, staging_buf, 0, size);

      hc_mtl4_forget (device_param, staging_buf);

      #if !__has_feature(objc_arc)
      [staging_buf release];
      #endif

      return rc;
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

int hc_mtlMemcpyDtoH (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, mtl_command_queue command_queue, void *host_buf_dst, mtl_mem_t mem_src, size_t mem_src_off, size_t size)
{
  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

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

  if (device_param->use_metal4 == true)
  {
    // A Managed buffer cannot occur here: the Metal 4 path is only taken on unified memory, where
    // every buffer the backend makes is Shared, and Shared returned above.

    if (mem_src.buf_mode != MTL_STORAGE_MODE_PRIVATE)
    {
      event_log_error (hashcat_ctx, "%s(): unexpected storage mode %u on Metal 4", __func__, mem_src.buf_mode);

      return -1;
    }

    id<MTLBuffer> staging_buf4 = [metal_device newBufferWithLength: size options: MTLResourceStorageModeShared];

    if (staging_buf4 == nil)
    {
      event_log_error (hashcat_ctx, "%s(): failed to create staging buffer", __func__);

      return -1;
    }

    const int rc = hc_mtl4_copy (hashcat_ctx, device_param, staging_buf4, 0, mem_src.buf_ptr, mem_src_off, size);

    if (rc == 0) memcpy (host_buf_dst, [staging_buf4 contents], size);

    hc_mtl4_forget (device_param, staging_buf4);

    #if !__has_feature(objc_arc)
    [staging_buf4 release];
    #endif

    return rc;
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

int hc_mtlEncodeComputeCommand_pre (void *hashcat_ctx, void *device_param_ptr, mtl_pipeline metal_pipeline, mtl_command_queue metal_command_queue, mtl_command_buffer *metal_command_buffer, mtl_command_encoder *metal_command_encoder)
{
  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

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

  if (device_param->use_metal4 == true)
  {
    id command_buffer = hc_mtl4_begin (hashcat_ctx, device_param);

    if (command_buffer == nil) return -1;

    id command_encoder = mtl4_new (command_buffer, "computeCommandEncoder");

    if (command_encoder == nil)
    {
      event_log_error (hashcat_ctx, "%s(): Metal 4 compute command encoder is nil", __func__);

      return -1;
    }

    mtl4_call_obj (command_encoder, "setComputePipelineState:", metal_pipeline);

    device_param->metal_scratch_offset = 0;

    *metal_command_buffer  = command_buffer;
    *metal_command_encoder = command_encoder;

    return 0;
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

int hc_mtlSetCommandEncoderArg (void *hashcat_ctx, void *device_param_ptr, mtl_command_encoder metal_command_encoder, size_t off, size_t idx, id mem, void *host_data, size_t host_data_size)
{
  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

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

  if (device_param->use_metal4 == true)
  {
    // Metal 4 binds addresses through the device's argument table rather than objects through the
    // encoder, and a buffer handed to a kernel has to be in the residency set when it runs.

    uint64_t (*address_of) (id, SEL) = (uint64_t (*) (id, SEL)) objc_msgSend;

    uint64_t address = 0;

    if (host_data == nil)
    {
      address = address_of (mem, mtl4_sel ("gpuAddress")) + off;

      mtl4_call_obj (device_param->metal_residency_set, "addAllocation:", mem);
    }
    else
    {
      // setBytes: has no Metal 4 equivalent. The bytes go into the device's scratch buffer, each
      // argument on a 256 byte boundary, and the kernel is handed their address.

      const size_t scratch_off = (device_param->metal_scratch_offset + 255) & ~((size_t) 255);

      if ((scratch_off + host_data_size) > METAL4_SCRATCH_SIZE)
      {
        event_log_error (hashcat_ctx, "%s(): Metal 4 scratch buffer is full", __func__);

        return -1;
      }

      memcpy ((char *) [device_param->metal_scratch_buf contents] + scratch_off, host_data, host_data_size);

      address = address_of (device_param->metal_scratch_buf, mtl4_sel ("gpuAddress")) + scratch_off;

      device_param->metal_scratch_offset = scratch_off + host_data_size;
    }

    ((void (*) (id, SEL, uint64_t, NSUInteger)) objc_msgSend) (device_param->metal_argument_table, mtl4_sel ("setAddress:atIndex:"), address, (NSUInteger) idx);

    return 0;
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

int hc_mtlEncodeComputeCommand (void *hashcat_ctx, void *device_param_ptr, mtl_command_encoder metal_command_encoder, mtl_command_buffer metal_command_buffer, const unsigned int work_dim, const size_t global_work_size[3], const size_t local_work_size[3], double *ms)
{
  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

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

  if (device_param->use_metal4 == true)
  {
    mtl4_call     (device_param->metal_residency_set, "commit");
    mtl4_call_obj (metal_command_encoder, "setArgumentTable:", device_param->metal_argument_table);

    ((void (*) (id, SEL, MTLSize, MTLSize)) objc_msgSend) (metal_command_encoder, mtl4_sel ("dispatchThreadgroups:threadsPerThreadgroup:"), threadgroupsPerGrid, threadsPerThreadgroup);

    mtl4_call (metal_command_encoder, "endEncoding");

    return hc_mtl4_commit_and_wait (hashcat_ctx, device_param, metal_command_buffer, ms);
  }

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

int hc_mtlCreateLibraryWithSource (void *hashcat_ctx, void *device_param_ptr, mtl_device_id metal_device, const char *kernel_sources, const char *build_options_buf, const char *cpath, mtl_library *metal_library)
{
  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

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
      compileOptions.mathMode = MTLMathModeSafe;
      // compileOptions.mathMode = MTLMathModeRelaxed;
      // compileOptions.enableLogging = true;
      */
    }

    // Apple's shader compiler runs out of room on our larger kernels at the default optimization
    // level. Building a pipeline for one of those ends with the compiler service dying and the
    // framework reporting XPC_ERROR_CONNECTION_INTERRUPTED, which reaches the user as a kernel
    // create failure rather than as anything it could act on. The size level asks for less
    // aggressive inlining and unrolling of code we already unroll by hand, which is enough to bring
    // those kernels back under whatever the limit is, and it also cuts the time a kernel that did
    // build takes to compile.

    // optimizationLevel arrived in the macOS 13 SDK, so an older SDK has to build without it. That
    // is the same version the backend refuses to use Metal below, so it comes from the same place.

    #ifdef MAC_OS_VERSION_13_0
    if (@available (HC_MIN_MACOS, *))
    {
      compileOptions.optimizationLevel = MTLLibraryOptimizationLevelSize;
    }
    #endif

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
    id<MTLLibrary> metal_library_tmp = nil;

    if (device_param->use_metal4 == true)
    {
      id library_desc = [objc_getClass ("MTL4LibraryDescriptor") new];

      mtl4_call_obj (library_desc, "setSource:",  k_string);
      mtl4_call_obj (library_desc, "setOptions:", compileOptions);

      metal_library_tmp = mtl4_new_desc (device_param->metal_compiler, "newLibraryWithDescriptor:error:", library_desc, &error);

      #if !__has_feature(objc_arc)
      [library_desc release];
      #endif
    }
    else
    {
      metal_library_tmp = [metal_device newLibraryWithSource: k_string options: compileOptions error: &error];
    }

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

// The pipelines of a program are cached in the file the other backends cache their binary in: a
// MTLBinaryArchive on Metal 3, on Metal 4 the archive the data set serializer of a compiler made for
// the program writes. A file that exists is read and asked for every pipeline; otherwise, or once a
// pipeline is not in it, the program builds into a fresh archive and hc_mtlArchiveFlush writes the
// file once all of its pipelines are there.

static id hc_mtl4_pipeline_desc (mtl_library metal_library, NSString *f_name)
{
  id function_desc = [objc_getClass ("MTL4LibraryFunctionDescriptor") new];

  mtl4_call_obj (function_desc, "setName:",    f_name);
  mtl4_call_obj (function_desc, "setLibrary:", metal_library);

  id pipeline_desc = [objc_getClass ("MTL4ComputePipelineDescriptor") new];

  mtl4_call_obj (pipeline_desc, "setComputeFunctionDescriptor:", function_desc);

  #if !__has_feature(objc_arc)
  [function_desc release];
  #endif

  return pipeline_desc;
}

// The archive the program builds into. When it cannot be made the program runs without a cache,
// which is a warning and nothing more, as the other backends run without theirs.

static void hc_mtlArchiveFresh (void *hashcat_ctx, hc_device_param_t *device_param, const int program)
{
  mtl_device_id metal_device = device_param->metal_device;

  NSError *error = nil;

  if (device_param->use_metal4 == true)
  {
    id serializer_desc = [objc_getClass ("MTL4PipelineDataSetSerializerDescriptor") new];

    mtl4_call_uint (serializer_desc, "setConfiguration:", MTL4_PIPELINE_DATA_SET_SERIALIZER_CAPTURE_BINARIES);

    device_param->metal_serializer[program] = ((id (*) (id, SEL, id)) objc_msgSend) (metal_device, mtl4_sel ("newPipelineDataSetSerializerWithDescriptor:"), serializer_desc);

    #if !__has_feature(objc_arc)
    [serializer_desc release];
    #endif

    if (device_param->metal_serializer[program] != nil)
    {
      id compiler_desc = [objc_getClass ("MTL4CompilerDescriptor") new];

      mtl4_call_obj (compiler_desc, "setPipelineDataSetSerializer:", device_param->metal_serializer[program]);

      device_param->metal_program_compiler[program] = mtl4_new_desc (metal_device, "newCompilerWithDescriptor:error:", compiler_desc, &error);

      #if !__has_feature(objc_arc)
      [compiler_desc release];
      #endif
    }

    if (device_param->metal_program_compiler[program] == nil)
    {
      #if !__has_feature(objc_arc)
      if (device_param->metal_serializer[program] != nil) [device_param->metal_serializer[program] release];
      #endif

      device_param->metal_serializer[program] = nil;
    }
  }
  else
  {
    MTLBinaryArchiveDescriptor *desc = [MTLBinaryArchiveDescriptor new];

    device_param->metal_archive[program] = [metal_device newBinaryArchiveWithDescriptor: desc error: &error];

    #if !__has_feature(objc_arc)
    [desc release];
    #endif
  }

  const bool made = (device_param->use_metal4 == true) ? (device_param->metal_program_compiler[program] != nil) : (device_param->metal_archive[program] != nil);

  if (made == false)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s will not be cached, %s", device_param->device_id + 1, filename_from_filepath (device_param->metal_archive_file[program]), (error != nil) ? [[error localizedDescription] UTF8String] : "no archive");

    return;
  }

  device_param->metal_archive_write[program] = true;
}

static void hc_mtlArchiveStale (void *hashcat_ctx, hc_device_param_t *device_param, const int program)
{
  event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s does not hold its pipelines any more. Rebuilding it...", device_param->device_id + 1, filename_from_filepath (device_param->metal_archive_file[program]));

  #if !__has_feature(objc_arc)
  [device_param->metal_archive[program] release];
  #endif

  device_param->metal_archive[program] = nil;

  hc_mtlArchiveFresh (hashcat_ctx, device_param, program);
}

// Metal 3 refused to add a pipeline to the archive the program builds into: the archive is dropped,
// nothing is written, and the next run builds again.

static void hc_mtlArchiveAbandon (void *hashcat_ctx, hc_device_param_t *device_param, const int program, const char *func_name)
{
  event_log_warning (hashcat_ctx, "* Device #%u: Kernel '%s' was not added to the cache. Kernel %s will not be written.", device_param->device_id + 1, func_name, filename_from_filepath (device_param->metal_archive_file[program]));

  #if !__has_feature(objc_arc)
  if (device_param->metal_archive[program] != nil) [device_param->metal_archive[program] release];
  #endif

  device_param->metal_archive[program]       = nil;
  device_param->metal_archive_write[program] = false;
}

// A pipeline taken from the archive that turned out stale is put into the fresh one here: added
// from its function on Metal 3, built once more through the program's compiler on Metal 4, whose
// serializer captures it.

static bool hc_mtlArchiveRecord (void *hashcat_ctx, hc_device_param_t *device_param, const int program, const int slot)
{
  mtl_function mtl_func = device_param->metal_function[slot];

  const char *func_name = [[mtl_func name] UTF8String];

  if (device_param->use_metal4 == true)
  {
    NSError *error = nil;

    id pipeline_desc = hc_mtl4_pipeline_desc (device_param->metal_library[program], [mtl_func name]);

    id (*build) (id, SEL, id, id, NSError **) = (id (*) (id, SEL, id, id, NSError **)) objc_msgSend;

    mtl_pipeline mtl_pipe = build (device_param->metal_program_compiler[program], mtl4_sel ("newComputePipelineStateWithDescriptor:compilerTaskOptions:error:"), pipeline_desc, nil, &error);

    #if !__has_feature(objc_arc)
    [pipeline_desc release];

    if (mtl_pipe != nil) [mtl_pipe release];
    #endif

    if (mtl_pipe == nil)
    {
      hc_mtlArchiveAbandon (hashcat_ctx, device_param, program, func_name);

      return false;
    }

    return true;
  }

  MTLComputePipelineDescriptor *desc = [MTLComputePipelineDescriptor new];

  desc.computeFunction = mtl_func;

  NSError *error = nil;

  const bool added = ([(id <MTLBinaryArchive>) device_param->metal_archive[program] addComputePipelineFunctionsWithDescriptor: desc error: &error] == YES);

  #if !__has_feature(objc_arc)
  [desc release];
  #endif

  if (added == false) hc_mtlArchiveAbandon (hashcat_ctx, device_param, program, func_name);

  return added;
}

int hc_mtlArchiveOpen (void *hashcat_ctx, void *device_param_ptr, const int program, const char *cached_file, const bool cache_disable)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return -1;

  device_param->metal_archive[program]          = nil;
  device_param->metal_serializer[program]       = nil;
  device_param->metal_program_compiler[program] = nil;
  device_param->metal_archive_file[program]     = NULL;
  device_param->metal_archive_write[program]    = false;

  if (cache_disable == true) return 0;

  device_param->metal_archive_file[program] = hcstrdup (cached_file);

  if (hc_path_read (cached_file) == true)
  {
    mtl_device_id metal_device = device_param->metal_device;

    NSURL *url = [NSURL fileURLWithPath: [NSString stringWithCString: cached_file encoding: NSUTF8StringEncoding]];

    // The Metal 3 loader refuses a file that is not an archive, where the Metal 4 loader takes it and
    // fails later, so the file is opened as a Metal 3 archive first on both paths.

    MTLBinaryArchiveDescriptor *desc = [MTLBinaryArchiveDescriptor new];

    desc.url = url;

    id <MTLBinaryArchive> archive = [metal_device newBinaryArchiveWithDescriptor: desc error: nil];

    #if !__has_feature(objc_arc)
    [desc release];
    #endif

    if ((archive != nil) && (device_param->use_metal4 == true))
    {
      #if !__has_feature(objc_arc)
      [archive release];
      #endif

      archive = mtl4_new_desc (metal_device, "newArchiveWithURL:error:", url, NULL);
    }

    if (archive != nil)
    {
      device_param->metal_archive[program] = archive;

      return 0;
    }

    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s is not a usable archive. Rebuilding it...", device_param->device_id + 1, filename_from_filepath (device_param->metal_archive_file[program]));
  }

  hc_mtlArchiveFresh (hashcat_ctx, device_param, program);

  return 0;
}

// The file is written once every pipeline of the device exists. A write that fails is a warning,
// since the next run only builds again, as it does on the other backends without their cache.

void hc_mtlArchiveFlush (void *hashcat_ctx, void *device_param_ptr, const int program)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return;

  if (device_param->metal_archive_write[program] == false) return;

  // the pipelines of the program that were taken from the archive before it turned out stale

  for (int slot = 0; slot < HC_DEV_KERN_CNT; slot++)
  {
    if (device_param->metal_function[slot] == nil) continue;

    if (device_param->metal_function_program[slot] != program) continue;

    if (device_param->metal_function_archived[slot] == true) continue;

    if (hc_mtlArchiveRecord (hashcat_ctx, device_param, program, slot) == false) return;

    device_param->metal_function_archived[slot] = true;
  }

  device_param->metal_archive_write[program] = false;

  // The archive is written next to its final name and renamed over it, so that a run cut short in
  // the middle of the write never leaves a partial file under the name the next run looks for.

  char *tmp_file = NULL;

  hc_asprintf (&tmp_file, "%s.tmp", device_param->metal_archive_file[program]);

  unlink (tmp_file);

  NSError *error = nil;

  NSURL *url = [NSURL fileURLWithPath: [NSString stringWithCString: tmp_file encoding: NSUTF8StringEncoding]];

  BOOL written = NO;

  if (device_param->use_metal4 == true)
  {
    written = ((BOOL (*) (id, SEL, id, NSError **)) objc_msgSend) (device_param->metal_serializer[program], mtl4_sel ("serializeAsArchiveAndFlushToURL:error:"), url, &error);
  }
  else
  {
    written = [(id <MTLBinaryArchive>) device_param->metal_archive[program] serializeToURL: url error: &error];
  }

  if (written == NO)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s was not written, %s", device_param->device_id + 1, filename_from_filepath (device_param->metal_archive_file[program]), (error != nil) ? [[error localizedDescription] UTF8String] : "not written");

    unlink (tmp_file);
  }
  else if (rename (tmp_file, device_param->metal_archive_file[program]) == -1)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s was not written, %s", device_param->device_id + 1, filename_from_filepath (device_param->metal_archive_file[program]), strerror (errno));

    unlink (tmp_file);
  }

  hcfree (tmp_file);
}

void hc_mtlArchiveRelease (void *hashcat_ctx, void *device_param_ptr, const int program)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

  MTL_PTR *mtl = (MTL_PTR *) backend_ctx->mtl;

  if (mtl == NULL) return;

  #if !__has_feature(objc_arc)
  if (device_param->metal_program_compiler[program] != nil) [device_param->metal_program_compiler[program] release];
  if (device_param->metal_serializer[program]       != nil) [device_param->metal_serializer[program]       release];
  if (device_param->metal_archive[program]          != nil) [device_param->metal_archive[program]          release];
  #endif

  device_param->metal_program_compiler[program] = nil;
  device_param->metal_serializer[program]       = nil;
  device_param->metal_archive[program]          = nil;

  hcfree (device_param->metal_archive_file[program]);

  device_param->metal_archive_file[program]  = NULL;
  device_param->metal_archive_write[program] = false;
}

int hc_mtlFinish (void *hashcat_ctx, void *device_param_ptr, mtl_command_queue command_queue)
{
  hc_device_param_t *device_param = (hc_device_param_t *) device_param_ptr;

  if (command_queue == nil)
  {
    event_log_error (hashcat_ctx, "%s(): metal command queue is invalid", __func__);

    return -1;
  }

  // nothing is ever left pending on the Metal 4 queue: every commit above waits for the GPU

  if (device_param->use_metal4 == true) return 0;

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
