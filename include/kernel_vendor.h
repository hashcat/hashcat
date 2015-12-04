/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

/**
 * vendor specific
 */

#ifdef __GPU__
#define IS_AMD
#endif

#ifdef __CUDACC__
#define IS_NV
#endif

/**
 * AMD specific
 */

/*
#ifdef IS_AMD
#ifdef __ATI_RV710__
#define VLIW1
#elif __ATI_RV730__
#define VLIW1
#elif __ATI_RV770__
#define VLIW4
#elif __Barts__
#define VLIW5
#elif __BeaverCreek__
#define VLIW5
#elif __Caicos__
#define VLIW5
#elif __Capeverde__
#define VLIW1
#elif __Cayman__
#define VLIW4
#elif __Cedar__
#define VLIW5
#elif __Cypress__
#define VLIW5
#elif __Devastator__
#define VLIW4
#elif __Juniper__
#define VLIW5
#elif __Loveland__
#define VLIW5
#elif __Pitcairn__
#define VLIW1
#elif __Redwood__
#define VLIW5
#elif __Tahiti__
#define VLIW1
#elif __Turks__
#define VLIW5
#elif __Scrapper__
#define VLIW4
#elif __WinterPark__
#define VLIW5
#endif
#endif
*/

#ifdef IS_AMD

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

#ifdef OSX

#else

#ifdef cl_amd_media_ops
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
#endif

#ifdef cl_amd_media_ops2
#pragma OPENCL EXTENSION cl_amd_media_ops2 : enable
#endif

#endif

#endif

#ifdef IS_NV
#ifdef sm_10
#define VLIW1
#elif sm_11
#define VLIW1
#elif sm_12
#define VLIW1
#elif sm_13
#define VLIW1
#elif sm_20
#define VLIW1
#elif sm_21
#define VLIW2
#elif sm_30
#define VLIW2
#elif sm_35
#define VLIW2
#elif sm_37
#define VLIW2
#elif sm_50
#define VLIW2
#elif sm_52
#define VLIW2
#endif
#endif
