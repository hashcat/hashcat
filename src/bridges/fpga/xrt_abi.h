/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_XRT_ABI_H
#define HC_XRT_ABI_H

typedef void *xrtDeviceHandle;
typedef void *xrtKernelHandle;
typedef void *xrtRunHandle;
typedef void *xrtBufferHandle;

typedef unsigned long long xrtBufferFlags;
typedef unsigned int       xrtMemoryGroup;

typedef unsigned char hc_xrt_uuid_t[16];

typedef enum
{
  HC_XCL_BO_SYNC_BO_TO_DEVICE = 0,
  HC_XCL_BO_SYNC_BO_FROM_DEVICE = 1,

} hc_xclBOSyncDirection;

typedef enum
{
  HC_ERT_CMD_STATE_NEW = 1,
  HC_ERT_CMD_STATE_QUEUED = 2,
  HC_ERT_CMD_STATE_RUNNING = 3,
  HC_ERT_CMD_STATE_COMPLETED = 4,
  HC_ERT_CMD_STATE_ERROR = 5,
  HC_ERT_CMD_STATE_ABORT = 6,
  HC_ERT_CMD_STATE_SUBMITTED = 7,
  HC_ERT_CMD_STATE_TIMEOUT = 8,
  HC_ERT_CMD_STATE_NORESPONSE = 9,

} hc_ert_cmd_state;

typedef xrtDeviceHandle (*HC_XRT_DEVICE_OPEN)             (unsigned int);
typedef int             (*HC_XRT_DEVICE_CLOSE)            (xrtDeviceHandle);
typedef int             (*HC_XRT_DEVICE_LOAD_XCLBIN_FILE) (xrtDeviceHandle, const char *);
typedef int             (*HC_XRT_DEVICE_GET_XCLBIN_UUID)  (xrtDeviceHandle, hc_xrt_uuid_t);

typedef xrtKernelHandle (*HC_XRT_PL_KERNEL_OPEN)     (xrtDeviceHandle, const hc_xrt_uuid_t, const char *);

typedef xrtKernelHandle (*HC_XRT_PL_KERNEL_OPEN_EXCL) (xrtDeviceHandle, const hc_xrt_uuid_t, const char *);
typedef int             (*HC_XRT_KERNEL_CLOSE)       (xrtKernelHandle);
typedef int             (*HC_XRT_KERNEL_ARG_GROUP_ID)(xrtKernelHandle, int);
typedef xrtRunHandle    (*HC_XRT_RUN_OPEN)           (xrtKernelHandle);
typedef int             (*HC_XRT_RUN_START)          (xrtRunHandle);
typedef int             (*HC_XRT_RUN_STATE)          (xrtRunHandle);
typedef int             (*HC_XRT_RUN_CLOSE)          (xrtRunHandle);

typedef int (*HC_XRT_RUN_SET_ARG) (xrtRunHandle, int, ...);

typedef int (*HC_XRT_RUN_WAIT_FOR) (xrtRunHandle, unsigned int);

typedef int (*HC_XRT_KERNEL_READ_REGISTER) (xrtKernelHandle, unsigned int, unsigned int *);

typedef xrtBufferHandle (*HC_XRT_BO_ALLOC) (xrtDeviceHandle, size_t, xrtBufferFlags, xrtMemoryGroup);
typedef int             (*HC_XRT_BO_FREE)  (xrtBufferHandle);
typedef int             (*HC_XRT_BO_SYNC)  (xrtBufferHandle, int, size_t, size_t);
typedef void           *(*HC_XRT_BO_MAP)   (xrtBufferHandle);

typedef struct hc_xrt_lib
{
  hc_dynlib_t lib;

  HC_XRT_DEVICE_OPEN             xrtDeviceOpen;
  HC_XRT_DEVICE_CLOSE            xrtDeviceClose;
  HC_XRT_DEVICE_LOAD_XCLBIN_FILE xrtDeviceLoadXclbinFile;
  HC_XRT_DEVICE_GET_XCLBIN_UUID  xrtDeviceGetXclbinUUID;

  HC_XRT_PL_KERNEL_OPEN          xrtPLKernelOpen;

  HC_XRT_PL_KERNEL_OPEN_EXCL     xrtPLKernelOpenExclusive;
  HC_XRT_KERNEL_CLOSE            xrtKernelClose;
  HC_XRT_KERNEL_ARG_GROUP_ID     xrtKernelArgGroupId;

  HC_XRT_RUN_OPEN                xrtRunOpen;
  HC_XRT_RUN_SET_ARG             xrtRunSetArg;
  HC_XRT_RUN_START               xrtRunStart;
  HC_XRT_RUN_WAIT_FOR            xrtRunWaitFor;
  HC_XRT_RUN_STATE               xrtRunState;
  HC_XRT_RUN_CLOSE               xrtRunClose;

  HC_XRT_KERNEL_READ_REGISTER    xrtKernelReadRegister;

  HC_XRT_BO_ALLOC                xrtBOAlloc;
  HC_XRT_BO_FREE                 xrtBOFree;
  HC_XRT_BO_SYNC                 xrtBOSync;
  HC_XRT_BO_MAP                  xrtBOMap;

} hc_xrt_lib_t;

#endif
