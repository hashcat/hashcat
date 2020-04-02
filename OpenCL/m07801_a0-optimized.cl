/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible data-dependant code
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_rp_optimized.h"
#include "inc_rp_optimized.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"
#endif

CONSTANT_VK u32a theMagicArray[80][16] =
{
  { 0x91ac5114, 0x9f675443, 0x24e73be0, 0x28747bc2, 0x863313eb, 0x5a4fcb5c, 0x080a7337, 0x0e5d1c2f, 0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194 },
  { 0xac51149f, 0x67544324, 0xe73be028, 0x747bc286, 0x3313eb5a, 0x4fcb5c08, 0x0a73370e, 0x5d1c2f33, 0x8fe6e5f8, 0x9baedd16, 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f },
  { 0x51149f67, 0x544324e7, 0x3be02874, 0x7bc28633, 0x13eb5a4f, 0xcb5c080a, 0x73370e5d, 0x1c2f338f, 0xe6e5f89b, 0xaedd16f2, 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b },
  { 0x149f6754, 0x4324e73b, 0xe028747b, 0xc2863313, 0xeb5a4fcb, 0x5c080a73, 0x370e5d1c, 0x2f338fe6, 0xe5f89bae, 0xdd16f24b, 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1 },
  { 0x9f675443, 0x24e73be0, 0x28747bc2, 0x863313eb, 0x5a4fcb5c, 0x080a7337, 0x0e5d1c2f, 0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b },
  { 0x67544324, 0xe73be028, 0x747bc286, 0x3313eb5a, 0x4fcb5c08, 0x0a73370e, 0x5d1c2f33, 0x8fe6e5f8, 0x9baedd16, 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06 },
  { 0x544324e7, 0x3be02874, 0x7bc28633, 0x13eb5a4f, 0xcb5c080a, 0x73370e5d, 0x1c2f338f, 0xe6e5f89b, 0xaedd16f2, 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605 },
  { 0x4324e73b, 0xe028747b, 0xc2863313, 0xeb5a4fcb, 0x5c080a73, 0x370e5d1c, 0x2f338fe6, 0xe5f89bae, 0xdd16f24b, 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d },
  { 0x24e73be0, 0x28747bc2, 0x863313eb, 0x5a4fcb5c, 0x080a7337, 0x0e5d1c2f, 0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03 },
  { 0xe73be028, 0x747bc286, 0x3313eb5a, 0x4fcb5c08, 0x0a73370e, 0x5d1c2f33, 0x8fe6e5f8, 0x9baedd16, 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d },
  { 0x3be02874, 0x7bc28633, 0x13eb5a4f, 0xcb5c080a, 0x73370e5d, 0x1c2f338f, 0xe6e5f89b, 0xaedd16f2, 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e },
  { 0xe028747b, 0xc2863313, 0xeb5a4fcb, 0x5c080a73, 0x370e5d1c, 0x2f338fe6, 0xe5f89bae, 0xdd16f24b, 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13 },
  { 0x28747bc2, 0x863313eb, 0x5a4fcb5c, 0x080a7337, 0x0e5d1c2f, 0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a },
  { 0x747bc286, 0x3313eb5a, 0x4fcb5c08, 0x0a73370e, 0x5d1c2f33, 0x8fe6e5f8, 0x9baedd16, 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e },
  { 0x7bc28633, 0x13eb5a4f, 0xcb5c080a, 0x73370e5d, 0x1c2f338f, 0xe6e5f89b, 0xaedd16f2, 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a },
  { 0xc2863313, 0xeb5a4fcb, 0x5c080a73, 0x370e5d1c, 0x2f338fe6, 0xe5f89bae, 0xdd16f24b, 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a },
  { 0x863313eb, 0x5a4fcb5c, 0x080a7337, 0x0e5d1c2f, 0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8 },
  { 0x3313eb5a, 0x4fcb5c08, 0x0a73370e, 0x5d1c2f33, 0x8fe6e5f8, 0x9baedd16, 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9 },
  { 0x13eb5a4f, 0xcb5c080a, 0x73370e5d, 0x1c2f338f, 0xe6e5f89b, 0xaedd16f2, 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c },
  { 0xeb5a4fcb, 0x5c080a73, 0x370e5d1c, 0x2f338fe6, 0xe5f89bae, 0xdd16f24b, 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14 },
  { 0x5a4fcb5c, 0x080a7337, 0x0e5d1c2f, 0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417 },
  { 0x4fcb5c08, 0x0a73370e, 0x5d1c2f33, 0x8fe6e5f8, 0x9baedd16, 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758 },
  { 0xcb5c080a, 0x73370e5d, 0x1c2f338f, 0xe6e5f89b, 0xaedd16f2, 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7 },
  { 0x5c080a73, 0x370e5d1c, 0x2f338fe6, 0xe5f89bae, 0xdd16f24b, 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a },
  { 0x080a7337, 0x0e5d1c2f, 0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6 },
  { 0x0a73370e, 0x5d1c2f33, 0x8fe6e5f8, 0x9baedd16, 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1 },
  { 0x73370e5d, 0x1c2f338f, 0xe6e5f89b, 0xaedd16f2, 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199 },
  { 0x370e5d1c, 0x2f338fe6, 0xe5f89bae, 0xdd16f24b, 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963 },
  { 0x0e5d1c2f, 0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a },
  { 0x5d1c2f33, 0x8fe6e5f8, 0x9baedd16, 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7 },
  { 0x1c2f338f, 0xe6e5f89b, 0xaedd16f2, 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd },
  { 0x2f338fe6, 0xe5f89bae, 0xdd16f24b, 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70 },
  { 0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3 },
  { 0x8fe6e5f8, 0x9baedd16, 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6 },
  { 0xe6e5f89b, 0xaedd16f2, 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e },
  { 0xe5f89bae, 0xdd16f24b, 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74 },
  { 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413 },
  { 0x9baedd16, 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303 },
  { 0xaedd16f2, 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9 },
  { 0xdd16f24b, 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b },
  { 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413, 0x03c90b04 },
  { 0xf24b8d2c, 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303, 0xc90b0426 },
  { 0x4b8d2ce1, 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9, 0x0b042698 },
  { 0x8d2ce1d4, 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b, 0x042698f7 },
  { 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413, 0x03c90b04, 0x2698f726 },
  { 0xe1d4dcb0, 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303, 0xc90b0426, 0x98f7268a },
  { 0xd4dcb0cb, 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9, 0x0b042698, 0xf7268a92 },
  { 0xdcb0cbdf, 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b, 0x042698f7, 0x268a9293 },
  { 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413, 0x03c90b04, 0x2698f726, 0x8a929325 },
  { 0xcbdf9dd4, 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303, 0xc90b0426, 0x98f7268a, 0x929325b0 },
  { 0xdf9dd470, 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9, 0x0b042698, 0xf7268a92, 0x9325b0a2 },
  { 0x9dd4706d, 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b, 0x042698f7, 0x268a9293, 0x25b0a20d },
  { 0xd4706d17, 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413, 0x03c90b04, 0x2698f726, 0x8a929325, 0xb0a20d23 },
  { 0x706d17f9, 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303, 0xc90b0426, 0x98f7268a, 0x929325b0, 0xa20d23ed },
  { 0x6d17f94d, 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9, 0x0b042698, 0xf7268a92, 0x9325b0a2, 0x0d23ed63 },
  { 0x17f94d42, 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b, 0x042698f7, 0x268a9293, 0x25b0a20d, 0x23ed6379 },
  { 0xf94d423f, 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413, 0x03c90b04, 0x2698f726, 0x8a929325, 0xb0a20d23, 0xed63796d },
  { 0x4d423f9b, 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303, 0xc90b0426, 0x98f7268a, 0x929325b0, 0xa20d23ed, 0x63796d13 },
  { 0x423f9b1b, 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9, 0x0b042698, 0xf7268a92, 0x9325b0a2, 0x0d23ed63, 0x796d1332 },
  { 0x3f9b1b11, 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b, 0x042698f7, 0x268a9293, 0x25b0a20d, 0x23ed6379, 0x6d1332fa },
  { 0x9b1b1194, 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413, 0x03c90b04, 0x2698f726, 0x8a929325, 0xb0a20d23, 0xed63796d, 0x1332fa3c },
  { 0x1b11949f, 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303, 0xc90b0426, 0x98f7268a, 0x929325b0, 0xa20d23ed, 0x63796d13, 0x32fa3c35 },
  { 0x11949f5b, 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9, 0x0b042698, 0xf7268a92, 0x9325b0a2, 0x0d23ed63, 0x796d1332, 0xfa3c3502 },
  { 0x949f5bc1, 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b, 0x042698f7, 0x268a9293, 0x25b0a20d, 0x23ed6379, 0x6d1332fa, 0x3c35029a },
  { 0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413, 0x03c90b04, 0x2698f726, 0x8a929325, 0xb0a20d23, 0xed63796d, 0x1332fa3c, 0x35029aa3 },
  { 0x5bc19b06, 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303, 0xc90b0426, 0x98f7268a, 0x929325b0, 0xa20d23ed, 0x63796d13, 0x32fa3c35, 0x029aa3b3 },
  { 0xc19b0605, 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9, 0x0b042698, 0xf7268a92, 0x9325b0a2, 0x0d23ed63, 0x796d1332, 0xfa3c3502, 0x9aa3b3dd },
  { 0x9b06059d, 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b, 0x042698f7, 0x268a9293, 0x25b0a20d, 0x23ed6379, 0x6d1332fa, 0x3c35029a, 0xa3b3dd8e },
  { 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413, 0x03c90b04, 0x2698f726, 0x8a929325, 0xb0a20d23, 0xed63796d, 0x1332fa3c, 0x35029aa3, 0xb3dd8e0a },
  { 0x059d039d, 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303, 0xc90b0426, 0x98f7268a, 0x929325b0, 0xa20d23ed, 0x63796d13, 0x32fa3c35, 0x029aa3b3, 0xdd8e0a24 },
  { 0x9d039d5e, 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9, 0x0b042698, 0xf7268a92, 0x9325b0a2, 0x0d23ed63, 0x796d1332, 0xfa3c3502, 0x9aa3b3dd, 0x8e0a24bf },
  { 0x039d5e13, 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b, 0x042698f7, 0x268a9293, 0x25b0a20d, 0x23ed6379, 0x6d1332fa, 0x3c35029a, 0xa3b3dd8e, 0x0a24bf51 },
  { 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413, 0x03c90b04, 0x2698f726, 0x8a929325, 0xb0a20d23, 0xed63796d, 0x1332fa3c, 0x35029aa3, 0xb3dd8e0a, 0x24bf51c3 },
  { 0x5e138a1e, 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303, 0xc90b0426, 0x98f7268a, 0x929325b0, 0xa20d23ed, 0x63796d13, 0x32fa3c35, 0x029aa3b3, 0xdd8e0a24, 0xbf51c37c },
  { 0x138a1e9a, 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9, 0x0b042698, 0xf7268a92, 0x9325b0a2, 0x0d23ed63, 0x796d1332, 0xfa3c3502, 0x9aa3b3dd, 0x8e0a24bf, 0x51c37ccd },
  { 0x8a1e9a6a, 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b, 0x042698f7, 0x268a9293, 0x25b0a20d, 0x23ed6379, 0x6d1332fa, 0x3c35029a, 0xa3b3dd8e, 0x0a24bf51, 0xc37ccd55 },
  { 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3, 0xf65e7413, 0x03c90b04, 0x2698f726, 0x8a929325, 0xb0a20d23, 0xed63796d, 0x1332fa3c, 0x35029aa3, 0xb3dd8e0a, 0x24bf51c3, 0x7ccd559f },
  { 0x9a6ae8d9, 0x7c141758, 0xc72af6a1, 0x99630ad7, 0xfd70c3f6, 0x5e741303, 0xc90b0426, 0x98f7268a, 0x929325b0, 0xa20d23ed, 0x63796d13, 0x32fa3c35, 0x029aa3b3, 0xdd8e0a24, 0xbf51c37c, 0xcd559f37 },
  { 0x6ae8d97c, 0x141758c7, 0x2af6a199, 0x630ad7fd, 0x70c3f65e, 0x741303c9, 0x0b042698, 0xf7268a92, 0x9325b0a2, 0x0d23ed63, 0x796d1332, 0xfa3c3502, 0x9aa3b3dd, 0x8e0a24bf, 0x51c37ccd, 0x559f37af },
  { 0xe8d97c14, 0x1758c72a, 0xf6a19963, 0x0ad7fd70, 0xc3f65e74, 0x1303c90b, 0x042698f7, 0x268a9293, 0x25b0a20d, 0x23ed6379, 0x6d1332fa, 0x3c35029a, 0xa3b3dd8e, 0x0a24bf51, 0xc37ccd55, 0x9f37af94 },
};

DECLSPEC void SETSHIFTEDINT (u32 *a, const int n, const u32 v)
{
  const int d = n / 4;
  const int m = n & 3;

  u64 tmp = hl32_to_64_S (v, 0);

  tmp >>= m * 8;

  a[d + 0] |= h32_from_64_S (tmp);
  a[d + 1]  = l32_from_64_S (tmp);
}

KERNEL_FQ void m07801_m04 (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_theMagicArray[80][16];

  for (u32 i = lid; i < 80; i += lsz)
  {
    s_theMagicArray[i][ 0] = theMagicArray[i][ 0];
    s_theMagicArray[i][ 1] = theMagicArray[i][ 1];
    s_theMagicArray[i][ 2] = theMagicArray[i][ 2];
    s_theMagicArray[i][ 3] = theMagicArray[i][ 3];
    s_theMagicArray[i][ 4] = theMagicArray[i][ 4];
    s_theMagicArray[i][ 5] = theMagicArray[i][ 5];
    s_theMagicArray[i][ 6] = theMagicArray[i][ 6];
    s_theMagicArray[i][ 7] = theMagicArray[i][ 7];
    s_theMagicArray[i][ 8] = theMagicArray[i][ 8];
    s_theMagicArray[i][ 9] = theMagicArray[i][ 9];
    s_theMagicArray[i][10] = theMagicArray[i][10];
    s_theMagicArray[i][11] = theMagicArray[i][11];
    s_theMagicArray[i][12] = theMagicArray[i][12];
    s_theMagicArray[i][13] = theMagicArray[i][13];
    s_theMagicArray[i][14] = theMagicArray[i][14];
    s_theMagicArray[i][15] = theMagicArray[i][15];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_theMagicArray = theMagicArray;

  #endif

  if (gid >= gid_max) return;

  /**
   * modifier
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u32 salt_buf[8];

  salt_buf[0] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[0]);
  salt_buf[1] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[1]);
  salt_buf[2] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[2]);
  salt_buf[3] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[3]);
  salt_buf[4] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[4]);
  salt_buf[5] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[5]);
  salt_buf[6] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[6]);
  salt_buf[7] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[7]);

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);

    /**
     * SAP
     */

    u32 s0[4];
    u32 s1[4];
    u32 s2[4];
    u32 s3[4];

    s0[0] = salt_buf[0];
    s0[1] = salt_buf[1];
    s0[2] = salt_buf[2];
    s0[3] = salt_buf[3];
    s1[0] = salt_buf[4];
    s1[1] = salt_buf[5];
    s1[2] = salt_buf[6];
    s1[3] = salt_buf[7];
    s2[0] = 0;
    s2[1] = 0;
    s2[2] = 0;
    s2[3] = 0;
    s3[0] = 0;
    s3[1] = 0;
    s3[2] = 0;
    s3[3] = 0;

    switch_buffer_by_offset_be_S (s0, s1, s2, s3, out_len);

    const u32x pw_salt_len = out_len + salt_len;

    /**
     * sha1
     */

    u32 final[32];

    final[ 0] = w0[0] | s0[0];
    final[ 1] = w0[1] | s0[1];
    final[ 2] = w0[2] | s0[2];
    final[ 3] = w0[3] | s0[3];
    final[ 4] = w1[0] | s1[0];
    final[ 5] = w1[1] | s1[1];
    final[ 6] = w1[2] | s1[2];
    final[ 7] = w1[3] | s1[3];
    final[ 8] = w2[0] | s2[0];
    final[ 9] = w2[1] | s2[1];
    final[10] = w2[2] | s2[2];
    final[11] = w2[3] | s2[3];
    final[12] = w3[0] | s3[0];
    final[13] = w3[1] | s3[1];
    final[14] = 0;
    final[15] = pw_salt_len * 8;
    final[16] = 0;
    final[17] = 0;
    final[18] = 0;
    final[19] = 0;
    final[20] = 0;
    final[21] = 0;
    final[22] = 0;
    final[23] = 0;
    final[24] = 0;
    final[25] = 0;
    final[26] = 0;
    final[27] = 0;
    final[28] = 0;
    final[29] = 0;
    final[30] = 0;
    final[31] = 0;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (final +  0, final +  4, final +  8, final + 12, digest);

    // prepare magic array range

    u32 lengthMagicArray = 0x20;
    u32 offsetMagicArray = 0;

    lengthMagicArray += unpack_v8d_from_v32_S (digest[0]) % 6;
    lengthMagicArray += unpack_v8c_from_v32_S (digest[0]) % 6;
    lengthMagicArray += unpack_v8b_from_v32_S (digest[0]) % 6;
    lengthMagicArray += unpack_v8a_from_v32_S (digest[0]) % 6;
    lengthMagicArray += unpack_v8d_from_v32_S (digest[1]) % 6;
    lengthMagicArray += unpack_v8c_from_v32_S (digest[1]) % 6;
    lengthMagicArray += unpack_v8b_from_v32_S (digest[1]) % 6;
    lengthMagicArray += unpack_v8a_from_v32_S (digest[1]) % 6;
    lengthMagicArray += unpack_v8d_from_v32_S (digest[2]) % 6;
    lengthMagicArray += unpack_v8c_from_v32_S (digest[2]) % 6;
    offsetMagicArray += unpack_v8b_from_v32_S (digest[2]) & 7;
    offsetMagicArray += unpack_v8a_from_v32_S (digest[2]) & 7;
    offsetMagicArray += unpack_v8d_from_v32_S (digest[3]) & 7;
    offsetMagicArray += unpack_v8c_from_v32_S (digest[3]) & 7;
    offsetMagicArray += unpack_v8b_from_v32_S (digest[3]) & 7;
    offsetMagicArray += unpack_v8a_from_v32_S (digest[3]) & 7;
    offsetMagicArray += unpack_v8d_from_v32_S (digest[4]) & 7;
    offsetMagicArray += unpack_v8c_from_v32_S (digest[4]) & 7;
    offsetMagicArray += unpack_v8b_from_v32_S (digest[4]) & 7;
    offsetMagicArray += unpack_v8a_from_v32_S (digest[4]) & 7;

    // final

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    // append MagicArray

    final[ 0] = s_theMagicArray[offsetMagicArray][ 0];
    final[ 1] = s_theMagicArray[offsetMagicArray][ 1];
    final[ 2] = s_theMagicArray[offsetMagicArray][ 2];
    final[ 3] = s_theMagicArray[offsetMagicArray][ 3];
    final[ 4] = s_theMagicArray[offsetMagicArray][ 4];
    final[ 5] = s_theMagicArray[offsetMagicArray][ 5];
    final[ 6] = s_theMagicArray[offsetMagicArray][ 6];
    final[ 7] = s_theMagicArray[offsetMagicArray][ 7];
    final[ 8] = s_theMagicArray[offsetMagicArray][ 8];
    final[ 9] = s_theMagicArray[offsetMagicArray][ 9];
    final[10] = s_theMagicArray[offsetMagicArray][10];
    final[11] = s_theMagicArray[offsetMagicArray][11];
    final[12] = s_theMagicArray[offsetMagicArray][12];
    final[13] = s_theMagicArray[offsetMagicArray][13];
    final[14] = s_theMagicArray[offsetMagicArray][14];
    final[15] = s_theMagicArray[offsetMagicArray][15];
    final[16] = 0;
    final[17] = 0;
    final[18] = 0;
    final[19] = 0;
    final[20] = 0;
    final[21] = 0;
    final[22] = 0;
    final[23] = 0;
    final[24] = 0;
    final[25] = 0;
    final[26] = 0;
    final[27] = 0;
    final[28] = 0;
    final[29] = 0;
    final[30] = 0;
    final[31] = 0;

    truncate_block_16x4_be_S (final +  0, final +  4, final +  8, final + 12, lengthMagicArray);

    switch_buffer_by_offset_8x4_be_S (final +  0, final +  4, final +  8, final + 12, final + 16, final + 20, final + 24, final + 28, out_len);

    final[0] |= w0[0];
    final[1] |= w0[1];
    final[2] |= w0[2];
    final[3] |= w0[3];
    final[4] |= w1[0];
    final[5] |= w1[1];
    final[6] |= w1[2];
    final[7] |= w1[3];

    u32 final_len = out_len + lengthMagicArray;

    // append Salt

    for (int i = 0; i < salt_len + 1; i += 4) // +1 for the 0x80
    {
      const u32 tmp = salt_buf[i / 4]; // attention, int[] not char[]

      SETSHIFTEDINT (final, final_len + i, tmp);
    }

    final_len += salt_len;

    // calculate

    if (final_len >= 56)
    {
      final[30] = 0;
      final[31] = final_len * 8;

      sha1_transform (final +  0, final +  4, final +  8, final + 12, digest);
      sha1_transform (final + 16, final + 20, final + 24, final + 28, digest);
    }
    else
    {
      final[14] = 0;
      final[15] = final_len * 8;

      sha1_transform (final +  0, final +  4, final +  8, final + 12, digest);
    }

    COMPARE_M_SIMD (0, 0, digest[2] & 0xffff0000, digest[1]);
  }
}

KERNEL_FQ void m07801_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m07801_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m07801_s04 (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_theMagicArray[80][16];

  for (u32 i = lid; i < 80; i += lsz)
  {
    s_theMagicArray[i][ 0] = theMagicArray[i][ 0];
    s_theMagicArray[i][ 1] = theMagicArray[i][ 1];
    s_theMagicArray[i][ 2] = theMagicArray[i][ 2];
    s_theMagicArray[i][ 3] = theMagicArray[i][ 3];
    s_theMagicArray[i][ 4] = theMagicArray[i][ 4];
    s_theMagicArray[i][ 5] = theMagicArray[i][ 5];
    s_theMagicArray[i][ 6] = theMagicArray[i][ 6];
    s_theMagicArray[i][ 7] = theMagicArray[i][ 7];
    s_theMagicArray[i][ 8] = theMagicArray[i][ 8];
    s_theMagicArray[i][ 9] = theMagicArray[i][ 9];
    s_theMagicArray[i][10] = theMagicArray[i][10];
    s_theMagicArray[i][11] = theMagicArray[i][11];
    s_theMagicArray[i][12] = theMagicArray[i][12];
    s_theMagicArray[i][13] = theMagicArray[i][13];
    s_theMagicArray[i][14] = theMagicArray[i][14];
    s_theMagicArray[i][15] = theMagicArray[i][15];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_theMagicArray = theMagicArray;

  #endif

  if (gid >= gid_max) return;

  /**
   * modifier
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u32 salt_buf[8];

  salt_buf[0] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[0]);
  salt_buf[1] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[1]);
  salt_buf[2] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[2]);
  salt_buf[3] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[3]);
  salt_buf[4] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[4]);
  salt_buf[5] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[5]);
  salt_buf[6] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[6]);
  salt_buf[7] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[7]);

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);

    /**
     * SAP
     */

    u32 s0[4];
    u32 s1[4];
    u32 s2[4];
    u32 s3[4];

    s0[0] = salt_buf[0];
    s0[1] = salt_buf[1];
    s0[2] = salt_buf[2];
    s0[3] = salt_buf[3];
    s1[0] = salt_buf[4];
    s1[1] = salt_buf[5];
    s1[2] = salt_buf[6];
    s1[3] = salt_buf[7];
    s2[0] = 0;
    s2[1] = 0;
    s2[2] = 0;
    s2[3] = 0;
    s3[0] = 0;
    s3[1] = 0;
    s3[2] = 0;
    s3[3] = 0;

    switch_buffer_by_offset_be_S (s0, s1, s2, s3, out_len);

    const u32x pw_salt_len = out_len + salt_len;

    /**
     * sha1
     */

    u32 final[32];

    final[ 0] = w0[0] | s0[0];
    final[ 1] = w0[1] | s0[1];
    final[ 2] = w0[2] | s0[2];
    final[ 3] = w0[3] | s0[3];
    final[ 4] = w1[0] | s1[0];
    final[ 5] = w1[1] | s1[1];
    final[ 6] = w1[2] | s1[2];
    final[ 7] = w1[3] | s1[3];
    final[ 8] = w2[0] | s2[0];
    final[ 9] = w2[1] | s2[1];
    final[10] = w2[2] | s2[2];
    final[11] = w2[3] | s2[3];
    final[12] = w3[0] | s3[0];
    final[13] = w3[1] | s3[1];
    final[14] = 0;
    final[15] = pw_salt_len * 8;
    final[16] = 0;
    final[17] = 0;
    final[18] = 0;
    final[19] = 0;
    final[20] = 0;
    final[21] = 0;
    final[22] = 0;
    final[23] = 0;
    final[24] = 0;
    final[25] = 0;
    final[26] = 0;
    final[27] = 0;
    final[28] = 0;
    final[29] = 0;
    final[30] = 0;
    final[31] = 0;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (final +  0, final +  4, final +  8, final + 12, digest);

    // prepare magic array range

    u32 lengthMagicArray = 0x20;
    u32 offsetMagicArray = 0;

    lengthMagicArray += unpack_v8d_from_v32_S (digest[0]) % 6;
    lengthMagicArray += unpack_v8c_from_v32_S (digest[0]) % 6;
    lengthMagicArray += unpack_v8b_from_v32_S (digest[0]) % 6;
    lengthMagicArray += unpack_v8a_from_v32_S (digest[0]) % 6;
    lengthMagicArray += unpack_v8d_from_v32_S (digest[1]) % 6;
    lengthMagicArray += unpack_v8c_from_v32_S (digest[1]) % 6;
    lengthMagicArray += unpack_v8b_from_v32_S (digest[1]) % 6;
    lengthMagicArray += unpack_v8a_from_v32_S (digest[1]) % 6;
    lengthMagicArray += unpack_v8d_from_v32_S (digest[2]) % 6;
    lengthMagicArray += unpack_v8c_from_v32_S (digest[2]) % 6;
    offsetMagicArray += unpack_v8b_from_v32_S (digest[2]) & 7;
    offsetMagicArray += unpack_v8a_from_v32_S (digest[2]) & 7;
    offsetMagicArray += unpack_v8d_from_v32_S (digest[3]) & 7;
    offsetMagicArray += unpack_v8c_from_v32_S (digest[3]) & 7;
    offsetMagicArray += unpack_v8b_from_v32_S (digest[3]) & 7;
    offsetMagicArray += unpack_v8a_from_v32_S (digest[3]) & 7;
    offsetMagicArray += unpack_v8d_from_v32_S (digest[4]) & 7;
    offsetMagicArray += unpack_v8c_from_v32_S (digest[4]) & 7;
    offsetMagicArray += unpack_v8b_from_v32_S (digest[4]) & 7;
    offsetMagicArray += unpack_v8a_from_v32_S (digest[4]) & 7;

    // final

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    // append MagicArray

    final[ 0] = s_theMagicArray[offsetMagicArray][ 0];
    final[ 1] = s_theMagicArray[offsetMagicArray][ 1];
    final[ 2] = s_theMagicArray[offsetMagicArray][ 2];
    final[ 3] = s_theMagicArray[offsetMagicArray][ 3];
    final[ 4] = s_theMagicArray[offsetMagicArray][ 4];
    final[ 5] = s_theMagicArray[offsetMagicArray][ 5];
    final[ 6] = s_theMagicArray[offsetMagicArray][ 6];
    final[ 7] = s_theMagicArray[offsetMagicArray][ 7];
    final[ 8] = s_theMagicArray[offsetMagicArray][ 8];
    final[ 9] = s_theMagicArray[offsetMagicArray][ 9];
    final[10] = s_theMagicArray[offsetMagicArray][10];
    final[11] = s_theMagicArray[offsetMagicArray][11];
    final[12] = s_theMagicArray[offsetMagicArray][12];
    final[13] = s_theMagicArray[offsetMagicArray][13];
    final[14] = s_theMagicArray[offsetMagicArray][14];
    final[15] = s_theMagicArray[offsetMagicArray][15];
    final[16] = 0;
    final[17] = 0;
    final[18] = 0;
    final[19] = 0;
    final[20] = 0;
    final[21] = 0;
    final[22] = 0;
    final[23] = 0;
    final[24] = 0;
    final[25] = 0;
    final[26] = 0;
    final[27] = 0;
    final[28] = 0;
    final[29] = 0;
    final[30] = 0;
    final[31] = 0;

    truncate_block_16x4_be_S (final +  0, final +  4, final +  8, final + 12, lengthMagicArray);

    switch_buffer_by_offset_8x4_be_S (final +  0, final +  4, final +  8, final + 12, final + 16, final + 20, final + 24, final + 28, out_len);

    final[0] |= w0[0];
    final[1] |= w0[1];
    final[2] |= w0[2];
    final[3] |= w0[3];
    final[4] |= w1[0];
    final[5] |= w1[1];
    final[6] |= w1[2];
    final[7] |= w1[3];

    u32 final_len = out_len + lengthMagicArray;

    // append Salt

    for (int i = 0; i < salt_len + 1; i += 4) // +1 for the 0x80
    {
      const u32 tmp = salt_buf[i / 4]; // attention, int[] not char[]

      SETSHIFTEDINT (final, final_len + i, tmp);
    }

    final_len += salt_len;

    // calculate

    if (final_len >= 56)
    {
      final[30] = 0;
      final[31] = final_len * 8;

      sha1_transform (final +  0, final +  4, final +  8, final + 12, digest);
      sha1_transform (final + 16, final + 20, final + 24, final + 28, digest);
    }
    else
    {
      final[14] = 0;
      final[15] = final_len * 8;

      sha1_transform (final +  0, final +  4, final +  8, final + 12, digest);
    }

    COMPARE_S_SIMD (0, 0, digest[2] & 0xffff0000, digest[1]);
  }
}

KERNEL_FQ void m07801_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m07801_s16 (KERN_ATTR_RULES ())
{
}
