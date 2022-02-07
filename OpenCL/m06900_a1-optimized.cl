/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

CONSTANT_VK u32a c_tables[4][256] =
{
  {
    0x00072000, 0x00075000, 0x00074800, 0x00071000,
    0x00076800, 0x00074000, 0x00070000, 0x00077000,
    0x00073000, 0x00075800, 0x00070800, 0x00076000,
    0x00073800, 0x00077800, 0x00072800, 0x00071800,
    0x0005a000, 0x0005d000, 0x0005c800, 0x00059000,
    0x0005e800, 0x0005c000, 0x00058000, 0x0005f000,
    0x0005b000, 0x0005d800, 0x00058800, 0x0005e000,
    0x0005b800, 0x0005f800, 0x0005a800, 0x00059800,
    0x00022000, 0x00025000, 0x00024800, 0x00021000,
    0x00026800, 0x00024000, 0x00020000, 0x00027000,
    0x00023000, 0x00025800, 0x00020800, 0x00026000,
    0x00023800, 0x00027800, 0x00022800, 0x00021800,
    0x00062000, 0x00065000, 0x00064800, 0x00061000,
    0x00066800, 0x00064000, 0x00060000, 0x00067000,
    0x00063000, 0x00065800, 0x00060800, 0x00066000,
    0x00063800, 0x00067800, 0x00062800, 0x00061800,
    0x00032000, 0x00035000, 0x00034800, 0x00031000,
    0x00036800, 0x00034000, 0x00030000, 0x00037000,
    0x00033000, 0x00035800, 0x00030800, 0x00036000,
    0x00033800, 0x00037800, 0x00032800, 0x00031800,
    0x0006a000, 0x0006d000, 0x0006c800, 0x00069000,
    0x0006e800, 0x0006c000, 0x00068000, 0x0006f000,
    0x0006b000, 0x0006d800, 0x00068800, 0x0006e000,
    0x0006b800, 0x0006f800, 0x0006a800, 0x00069800,
    0x0007a000, 0x0007d000, 0x0007c800, 0x00079000,
    0x0007e800, 0x0007c000, 0x00078000, 0x0007f000,
    0x0007b000, 0x0007d800, 0x00078800, 0x0007e000,
    0x0007b800, 0x0007f800, 0x0007a800, 0x00079800,
    0x00052000, 0x00055000, 0x00054800, 0x00051000,
    0x00056800, 0x00054000, 0x00050000, 0x00057000,
    0x00053000, 0x00055800, 0x00050800, 0x00056000,
    0x00053800, 0x00057800, 0x00052800, 0x00051800,
    0x00012000, 0x00015000, 0x00014800, 0x00011000,
    0x00016800, 0x00014000, 0x00010000, 0x00017000,
    0x00013000, 0x00015800, 0x00010800, 0x00016000,
    0x00013800, 0x00017800, 0x00012800, 0x00011800,
    0x0001a000, 0x0001d000, 0x0001c800, 0x00019000,
    0x0001e800, 0x0001c000, 0x00018000, 0x0001f000,
    0x0001b000, 0x0001d800, 0x00018800, 0x0001e000,
    0x0001b800, 0x0001f800, 0x0001a800, 0x00019800,
    0x00042000, 0x00045000, 0x00044800, 0x00041000,
    0x00046800, 0x00044000, 0x00040000, 0x00047000,
    0x00043000, 0x00045800, 0x00040800, 0x00046000,
    0x00043800, 0x00047800, 0x00042800, 0x00041800,
    0x0000a000, 0x0000d000, 0x0000c800, 0x00009000,
    0x0000e800, 0x0000c000, 0x00008000, 0x0000f000,
    0x0000b000, 0x0000d800, 0x00008800, 0x0000e000,
    0x0000b800, 0x0000f800, 0x0000a800, 0x00009800,
    0x00002000, 0x00005000, 0x00004800, 0x00001000,
    0x00006800, 0x00004000, 0x00000000, 0x00007000,
    0x00003000, 0x00005800, 0x00000800, 0x00006000,
    0x00003800, 0x00007800, 0x00002800, 0x00001800,
    0x0003a000, 0x0003d000, 0x0003c800, 0x00039000,
    0x0003e800, 0x0003c000, 0x00038000, 0x0003f000,
    0x0003b000, 0x0003d800, 0x00038800, 0x0003e000,
    0x0003b800, 0x0003f800, 0x0003a800, 0x00039800,
    0x0002a000, 0x0002d000, 0x0002c800, 0x00029000,
    0x0002e800, 0x0002c000, 0x00028000, 0x0002f000,
    0x0002b000, 0x0002d800, 0x00028800, 0x0002e000,
    0x0002b800, 0x0002f800, 0x0002a800, 0x00029800,
    0x0004a000, 0x0004d000, 0x0004c800, 0x00049000,
    0x0004e800, 0x0004c000, 0x00048000, 0x0004f000,
    0x0004b000, 0x0004d800, 0x00048800, 0x0004e000,
    0x0004b800, 0x0004f800, 0x0004a800, 0x00049800,
  },
  {
    0x03a80000, 0x03c00000, 0x03880000, 0x03e80000,
    0x03d00000, 0x03980000, 0x03a00000, 0x03900000,
    0x03f00000, 0x03f80000, 0x03e00000, 0x03b80000,
    0x03b00000, 0x03800000, 0x03c80000, 0x03d80000,
    0x06a80000, 0x06c00000, 0x06880000, 0x06e80000,
    0x06d00000, 0x06980000, 0x06a00000, 0x06900000,
    0x06f00000, 0x06f80000, 0x06e00000, 0x06b80000,
    0x06b00000, 0x06800000, 0x06c80000, 0x06d80000,
    0x05280000, 0x05400000, 0x05080000, 0x05680000,
    0x05500000, 0x05180000, 0x05200000, 0x05100000,
    0x05700000, 0x05780000, 0x05600000, 0x05380000,
    0x05300000, 0x05000000, 0x05480000, 0x05580000,
    0x00a80000, 0x00c00000, 0x00880000, 0x00e80000,
    0x00d00000, 0x00980000, 0x00a00000, 0x00900000,
    0x00f00000, 0x00f80000, 0x00e00000, 0x00b80000,
    0x00b00000, 0x00800000, 0x00c80000, 0x00d80000,
    0x00280000, 0x00400000, 0x00080000, 0x00680000,
    0x00500000, 0x00180000, 0x00200000, 0x00100000,
    0x00700000, 0x00780000, 0x00600000, 0x00380000,
    0x00300000, 0x00000000, 0x00480000, 0x00580000,
    0x04280000, 0x04400000, 0x04080000, 0x04680000,
    0x04500000, 0x04180000, 0x04200000, 0x04100000,
    0x04700000, 0x04780000, 0x04600000, 0x04380000,
    0x04300000, 0x04000000, 0x04480000, 0x04580000,
    0x04a80000, 0x04c00000, 0x04880000, 0x04e80000,
    0x04d00000, 0x04980000, 0x04a00000, 0x04900000,
    0x04f00000, 0x04f80000, 0x04e00000, 0x04b80000,
    0x04b00000, 0x04800000, 0x04c80000, 0x04d80000,
    0x07a80000, 0x07c00000, 0x07880000, 0x07e80000,
    0x07d00000, 0x07980000, 0x07a00000, 0x07900000,
    0x07f00000, 0x07f80000, 0x07e00000, 0x07b80000,
    0x07b00000, 0x07800000, 0x07c80000, 0x07d80000,
    0x07280000, 0x07400000, 0x07080000, 0x07680000,
    0x07500000, 0x07180000, 0x07200000, 0x07100000,
    0x07700000, 0x07780000, 0x07600000, 0x07380000,
    0x07300000, 0x07000000, 0x07480000, 0x07580000,
    0x02280000, 0x02400000, 0x02080000, 0x02680000,
    0x02500000, 0x02180000, 0x02200000, 0x02100000,
    0x02700000, 0x02780000, 0x02600000, 0x02380000,
    0x02300000, 0x02000000, 0x02480000, 0x02580000,
    0x03280000, 0x03400000, 0x03080000, 0x03680000,
    0x03500000, 0x03180000, 0x03200000, 0x03100000,
    0x03700000, 0x03780000, 0x03600000, 0x03380000,
    0x03300000, 0x03000000, 0x03480000, 0x03580000,
    0x06280000, 0x06400000, 0x06080000, 0x06680000,
    0x06500000, 0x06180000, 0x06200000, 0x06100000,
    0x06700000, 0x06780000, 0x06600000, 0x06380000,
    0x06300000, 0x06000000, 0x06480000, 0x06580000,
    0x05a80000, 0x05c00000, 0x05880000, 0x05e80000,
    0x05d00000, 0x05980000, 0x05a00000, 0x05900000,
    0x05f00000, 0x05f80000, 0x05e00000, 0x05b80000,
    0x05b00000, 0x05800000, 0x05c80000, 0x05d80000,
    0x01280000, 0x01400000, 0x01080000, 0x01680000,
    0x01500000, 0x01180000, 0x01200000, 0x01100000,
    0x01700000, 0x01780000, 0x01600000, 0x01380000,
    0x01300000, 0x01000000, 0x01480000, 0x01580000,
    0x02a80000, 0x02c00000, 0x02880000, 0x02e80000,
    0x02d00000, 0x02980000, 0x02a00000, 0x02900000,
    0x02f00000, 0x02f80000, 0x02e00000, 0x02b80000,
    0x02b00000, 0x02800000, 0x02c80000, 0x02d80000,
    0x01a80000, 0x01c00000, 0x01880000, 0x01e80000,
    0x01d00000, 0x01980000, 0x01a00000, 0x01900000,
    0x01f00000, 0x01f80000, 0x01e00000, 0x01b80000,
    0x01b00000, 0x01800000, 0x01c80000, 0x01d80000,
  },
  {
    0x30000002, 0x60000002, 0x38000002, 0x08000002,
    0x28000002, 0x78000002, 0x68000002, 0x40000002,
    0x20000002, 0x50000002, 0x48000002, 0x70000002,
    0x00000002, 0x18000002, 0x58000002, 0x10000002,
    0xb0000005, 0xe0000005, 0xb8000005, 0x88000005,
    0xa8000005, 0xf8000005, 0xe8000005, 0xc0000005,
    0xa0000005, 0xd0000005, 0xc8000005, 0xf0000005,
    0x80000005, 0x98000005, 0xd8000005, 0x90000005,
    0x30000005, 0x60000005, 0x38000005, 0x08000005,
    0x28000005, 0x78000005, 0x68000005, 0x40000005,
    0x20000005, 0x50000005, 0x48000005, 0x70000005,
    0x00000005, 0x18000005, 0x58000005, 0x10000005,
    0x30000000, 0x60000000, 0x38000000, 0x08000000,
    0x28000000, 0x78000000, 0x68000000, 0x40000000,
    0x20000000, 0x50000000, 0x48000000, 0x70000000,
    0x00000000, 0x18000000, 0x58000000, 0x10000000,
    0xb0000003, 0xe0000003, 0xb8000003, 0x88000003,
    0xa8000003, 0xf8000003, 0xe8000003, 0xc0000003,
    0xa0000003, 0xd0000003, 0xc8000003, 0xf0000003,
    0x80000003, 0x98000003, 0xd8000003, 0x90000003,
    0x30000001, 0x60000001, 0x38000001, 0x08000001,
    0x28000001, 0x78000001, 0x68000001, 0x40000001,
    0x20000001, 0x50000001, 0x48000001, 0x70000001,
    0x00000001, 0x18000001, 0x58000001, 0x10000001,
    0xb0000000, 0xe0000000, 0xb8000000, 0x88000000,
    0xa8000000, 0xf8000000, 0xe8000000, 0xc0000000,
    0xa0000000, 0xd0000000, 0xc8000000, 0xf0000000,
    0x80000000, 0x98000000, 0xd8000000, 0x90000000,
    0xb0000006, 0xe0000006, 0xb8000006, 0x88000006,
    0xa8000006, 0xf8000006, 0xe8000006, 0xc0000006,
    0xa0000006, 0xd0000006, 0xc8000006, 0xf0000006,
    0x80000006, 0x98000006, 0xd8000006, 0x90000006,
    0xb0000001, 0xe0000001, 0xb8000001, 0x88000001,
    0xa8000001, 0xf8000001, 0xe8000001, 0xc0000001,
    0xa0000001, 0xd0000001, 0xc8000001, 0xf0000001,
    0x80000001, 0x98000001, 0xd8000001, 0x90000001,
    0x30000003, 0x60000003, 0x38000003, 0x08000003,
    0x28000003, 0x78000003, 0x68000003, 0x40000003,
    0x20000003, 0x50000003, 0x48000003, 0x70000003,
    0x00000003, 0x18000003, 0x58000003, 0x10000003,
    0x30000004, 0x60000004, 0x38000004, 0x08000004,
    0x28000004, 0x78000004, 0x68000004, 0x40000004,
    0x20000004, 0x50000004, 0x48000004, 0x70000004,
    0x00000004, 0x18000004, 0x58000004, 0x10000004,
    0xb0000002, 0xe0000002, 0xb8000002, 0x88000002,
    0xa8000002, 0xf8000002, 0xe8000002, 0xc0000002,
    0xa0000002, 0xd0000002, 0xc8000002, 0xf0000002,
    0x80000002, 0x98000002, 0xd8000002, 0x90000002,
    0xb0000004, 0xe0000004, 0xb8000004, 0x88000004,
    0xa8000004, 0xf8000004, 0xe8000004, 0xc0000004,
    0xa0000004, 0xd0000004, 0xc8000004, 0xf0000004,
    0x80000004, 0x98000004, 0xd8000004, 0x90000004,
    0x30000006, 0x60000006, 0x38000006, 0x08000006,
    0x28000006, 0x78000006, 0x68000006, 0x40000006,
    0x20000006, 0x50000006, 0x48000006, 0x70000006,
    0x00000006, 0x18000006, 0x58000006, 0x10000006,
    0xb0000007, 0xe0000007, 0xb8000007, 0x88000007,
    0xa8000007, 0xf8000007, 0xe8000007, 0xc0000007,
    0xa0000007, 0xd0000007, 0xc8000007, 0xf0000007,
    0x80000007, 0x98000007, 0xd8000007, 0x90000007,
    0x30000007, 0x60000007, 0x38000007, 0x08000007,
    0x28000007, 0x78000007, 0x68000007, 0x40000007,
    0x20000007, 0x50000007, 0x48000007, 0x70000007,
    0x00000007, 0x18000007, 0x58000007, 0x10000007,
  },
  {
    0x000000e8, 0x000000d8, 0x000000a0, 0x00000088,
    0x00000098, 0x000000f8, 0x000000a8, 0x000000c8,
    0x00000080, 0x000000d0, 0x000000f0, 0x000000b8,
    0x000000b0, 0x000000c0, 0x00000090, 0x000000e0,
    0x000007e8, 0x000007d8, 0x000007a0, 0x00000788,
    0x00000798, 0x000007f8, 0x000007a8, 0x000007c8,
    0x00000780, 0x000007d0, 0x000007f0, 0x000007b8,
    0x000007b0, 0x000007c0, 0x00000790, 0x000007e0,
    0x000006e8, 0x000006d8, 0x000006a0, 0x00000688,
    0x00000698, 0x000006f8, 0x000006a8, 0x000006c8,
    0x00000680, 0x000006d0, 0x000006f0, 0x000006b8,
    0x000006b0, 0x000006c0, 0x00000690, 0x000006e0,
    0x00000068, 0x00000058, 0x00000020, 0x00000008,
    0x00000018, 0x00000078, 0x00000028, 0x00000048,
    0x00000000, 0x00000050, 0x00000070, 0x00000038,
    0x00000030, 0x00000040, 0x00000010, 0x00000060,
    0x000002e8, 0x000002d8, 0x000002a0, 0x00000288,
    0x00000298, 0x000002f8, 0x000002a8, 0x000002c8,
    0x00000280, 0x000002d0, 0x000002f0, 0x000002b8,
    0x000002b0, 0x000002c0, 0x00000290, 0x000002e0,
    0x000003e8, 0x000003d8, 0x000003a0, 0x00000388,
    0x00000398, 0x000003f8, 0x000003a8, 0x000003c8,
    0x00000380, 0x000003d0, 0x000003f0, 0x000003b8,
    0x000003b0, 0x000003c0, 0x00000390, 0x000003e0,
    0x00000568, 0x00000558, 0x00000520, 0x00000508,
    0x00000518, 0x00000578, 0x00000528, 0x00000548,
    0x00000500, 0x00000550, 0x00000570, 0x00000538,
    0x00000530, 0x00000540, 0x00000510, 0x00000560,
    0x00000268, 0x00000258, 0x00000220, 0x00000208,
    0x00000218, 0x00000278, 0x00000228, 0x00000248,
    0x00000200, 0x00000250, 0x00000270, 0x00000238,
    0x00000230, 0x00000240, 0x00000210, 0x00000260,
    0x000004e8, 0x000004d8, 0x000004a0, 0x00000488,
    0x00000498, 0x000004f8, 0x000004a8, 0x000004c8,
    0x00000480, 0x000004d0, 0x000004f0, 0x000004b8,
    0x000004b0, 0x000004c0, 0x00000490, 0x000004e0,
    0x00000168, 0x00000158, 0x00000120, 0x00000108,
    0x00000118, 0x00000178, 0x00000128, 0x00000148,
    0x00000100, 0x00000150, 0x00000170, 0x00000138,
    0x00000130, 0x00000140, 0x00000110, 0x00000160,
    0x000001e8, 0x000001d8, 0x000001a0, 0x00000188,
    0x00000198, 0x000001f8, 0x000001a8, 0x000001c8,
    0x00000180, 0x000001d0, 0x000001f0, 0x000001b8,
    0x000001b0, 0x000001c0, 0x00000190, 0x000001e0,
    0x00000768, 0x00000758, 0x00000720, 0x00000708,
    0x00000718, 0x00000778, 0x00000728, 0x00000748,
    0x00000700, 0x00000750, 0x00000770, 0x00000738,
    0x00000730, 0x00000740, 0x00000710, 0x00000760,
    0x00000368, 0x00000358, 0x00000320, 0x00000308,
    0x00000318, 0x00000378, 0x00000328, 0x00000348,
    0x00000300, 0x00000350, 0x00000370, 0x00000338,
    0x00000330, 0x00000340, 0x00000310, 0x00000360,
    0x000005e8, 0x000005d8, 0x000005a0, 0x00000588,
    0x00000598, 0x000005f8, 0x000005a8, 0x000005c8,
    0x00000580, 0x000005d0, 0x000005f0, 0x000005b8,
    0x000005b0, 0x000005c0, 0x00000590, 0x000005e0,
    0x00000468, 0x00000458, 0x00000420, 0x00000408,
    0x00000418, 0x00000478, 0x00000428, 0x00000448,
    0x00000400, 0x00000450, 0x00000470, 0x00000438,
    0x00000430, 0x00000440, 0x00000410, 0x00000460,
    0x00000668, 0x00000658, 0x00000620, 0x00000608,
    0x00000618, 0x00000678, 0x00000628, 0x00000648,
    0x00000600, 0x00000650, 0x00000670, 0x00000638,
    0x00000630, 0x00000640, 0x00000610, 0x00000660,
  }
};

#if   VECT_SIZE == 1
#define BOX(i,n,S) (S)[(n)][(i)]
#elif VECT_SIZE == 2
#define BOX(i,n,S) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1])
#elif VECT_SIZE == 4
#define BOX(i,n,S) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1], (S)[(n)][(i).s2], (S)[(n)][(i).s3])
#elif VECT_SIZE == 8
#define BOX(i,n,S) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1], (S)[(n)][(i).s2], (S)[(n)][(i).s3], (S)[(n)][(i).s4], (S)[(n)][(i).s5], (S)[(n)][(i).s6], (S)[(n)][(i).s7])
#elif VECT_SIZE == 16
#define BOX(i,n,S) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1], (S)[(n)][(i).s2], (S)[(n)][(i).s3], (S)[(n)][(i).s4], (S)[(n)][(i).s5], (S)[(n)][(i).s6], (S)[(n)][(i).s7], (S)[(n)][(i).s8], (S)[(n)][(i).s9], (S)[(n)][(i).sa], (S)[(n)][(i).sb], (S)[(n)][(i).sc], (S)[(n)][(i).sd], (S)[(n)][(i).se], (S)[(n)][(i).sf])
#endif

#define _round(k1,k2,tbl)                 \
{                                         \
  u32x t;                                 \
  t = (k1) + r;                           \
  l ^= BOX (((t >>  0) & 0xff), 0, tbl) ^ \
       BOX (((t >>  8) & 0xff), 1, tbl) ^ \
       BOX (((t >> 16) & 0xff), 2, tbl) ^ \
       BOX (((t >> 24) & 0xff), 3, tbl);  \
  t = (k2) + l;                           \
  r ^= BOX (((t >>  0) & 0xff), 0, tbl) ^ \
       BOX (((t >>  8) & 0xff), 1, tbl) ^ \
       BOX (((t >> 16) & 0xff), 2, tbl) ^ \
       BOX (((t >> 24) & 0xff), 3, tbl);  \
}

#define R(k,h,s,i,t)      \
{                         \
  u32x r;                 \
  u32x l;                 \
  r = h[i + 0];           \
  l = h[i + 1];           \
  _round (k[0], k[1], t);  \
  _round (k[2], k[3], t);  \
  _round (k[4], k[5], t);  \
  _round (k[6], k[7], t);  \
  _round (k[0], k[1], t);  \
  _round (k[2], k[3], t);  \
  _round (k[4], k[5], t);  \
  _round (k[6], k[7], t);  \
  _round (k[0], k[1], t);  \
  _round (k[2], k[3], t);  \
  _round (k[4], k[5], t);  \
  _round (k[6], k[7], t);  \
  _round (k[7], k[6], t);  \
  _round (k[5], k[4], t);  \
  _round (k[3], k[2], t);  \
  _round (k[1], k[0], t);  \
  s[i + 0] = l;           \
  s[i + 1] = r;           \
}

#define X(w,u,v)      \
  w[0] = u[0] ^ v[0]; \
  w[1] = u[1] ^ v[1]; \
  w[2] = u[2] ^ v[2]; \
  w[3] = u[3] ^ v[3]; \
  w[4] = u[4] ^ v[4]; \
  w[5] = u[5] ^ v[5]; \
  w[6] = u[6] ^ v[6]; \
  w[7] = u[7] ^ v[7];

#define P(k,w)                        \
  k[0] = ((w[0] & 0x000000ff) <<  0)  \
       | ((w[2] & 0x000000ff) <<  8)  \
       | ((w[4] & 0x000000ff) << 16)  \
       | ((w[6] & 0x000000ff) << 24); \
  k[1] = ((w[0] & 0x0000ff00) >>  8)  \
       | ((w[2] & 0x0000ff00) >>  0)  \
       | ((w[4] & 0x0000ff00) <<  8)  \
       | ((w[6] & 0x0000ff00) << 16); \
  k[2] = ((w[0] & 0x00ff0000) >> 16)  \
       | ((w[2] & 0x00ff0000) >>  8)  \
       | ((w[4] & 0x00ff0000) <<  0)  \
       | ((w[6] & 0x00ff0000) <<  8); \
  k[3] = ((w[0] & 0xff000000) >> 24)  \
       | ((w[2] & 0xff000000) >> 16)  \
       | ((w[4] & 0xff000000) >>  8)  \
       | ((w[6] & 0xff000000) >>  0); \
  k[4] = ((w[1] & 0x000000ff) <<  0)  \
       | ((w[3] & 0x000000ff) <<  8)  \
       | ((w[5] & 0x000000ff) << 16)  \
       | ((w[7] & 0x000000ff) << 24); \
  k[5] = ((w[1] & 0x0000ff00) >>  8)  \
       | ((w[3] & 0x0000ff00) >>  0)  \
       | ((w[5] & 0x0000ff00) <<  8)  \
       | ((w[7] & 0x0000ff00) << 16); \
  k[6] = ((w[1] & 0x00ff0000) >> 16)  \
       | ((w[3] & 0x00ff0000) >>  8)  \
       | ((w[5] & 0x00ff0000) <<  0)  \
       | ((w[7] & 0x00ff0000) <<  8); \
  k[7] = ((w[1] & 0xff000000) >> 24)  \
       | ((w[3] & 0xff000000) >> 16)  \
       | ((w[5] & 0xff000000) >>  8)  \
       | ((w[7] & 0xff000000) >>  0);

#define A(x)        \
{                   \
  u32x l;           \
  u32x r;           \
  l = x[0] ^ x[2];  \
  r = x[1] ^ x[3];  \
  x[0] = x[2];      \
  x[1] = x[3];      \
  x[2] = x[4];      \
  x[3] = x[5];      \
  x[4] = x[6];      \
  x[5] = x[7];      \
  x[6] = l;         \
  x[7] = r;         \
}

#define AA(x)       \
{                   \
  u32x l;           \
  u32x r;           \
  l    = x[0];      \
  r    = x[2];      \
  x[0] = x[4];      \
  x[2] = x[6];      \
  x[4] = l ^ r;     \
  x[6] = x[0] ^ r;  \
  l    = x[1];      \
  r    = x[3];      \
  x[1] = x[5];      \
  x[3] = x[7];      \
  x[5] = l ^ r;     \
  x[7] = x[1] ^ r;  \
}

#define C(x)          \
  x[0] ^= 0xff00ff00; \
  x[1] ^= 0xff00ff00; \
  x[2] ^= 0x00ff00ff; \
  x[3] ^= 0x00ff00ff; \
  x[4] ^= 0x00ffff00; \
  x[5] ^= 0xff0000ff; \
  x[6] ^= 0x000000ff; \
  x[7] ^= 0xff00ffff;

#define SHIFT12(u,m,s)              \
  u[0] = m[0] ^ s[6];               \
  u[1] = m[1] ^ s[7];               \
  u[2] = m[2] ^ (s[0] << 16)        \
              ^ (s[0] >> 16)        \
              ^ (s[0] & 0x0000ffff) \
              ^ (s[1] & 0x0000ffff) \
              ^ (s[1] >> 16)        \
              ^ (s[2] << 16)        \
              ^ s[6]                \
              ^ (s[6] << 16)        \
              ^ (s[7] & 0xffff0000) \
              ^ (s[7] >> 16);       \
  u[3] = m[3] ^ (s[0] & 0x0000ffff) \
              ^ (s[0] << 16)        \
              ^ (s[1] & 0x0000ffff) \
              ^ (s[1] << 16)        \
              ^ (s[1] >> 16)        \
              ^ (s[2] << 16)        \
              ^ (s[2] >> 16)        \
              ^ (s[3] << 16)        \
              ^ s[6]                \
              ^ (s[6] << 16)        \
              ^ (s[6] >> 16)        \
              ^ (s[7] & 0x0000ffff) \
              ^ (s[7] << 16)        \
              ^ (s[7] >> 16);       \
  u[4] = m[4] ^ (s[0] & 0xffff0000) \
              ^ (s[0] << 16)        \
              ^ (s[0] >> 16)        \
              ^ (s[1] & 0xffff0000) \
              ^ (s[1] >> 16)        \
              ^ (s[2] << 16)        \
              ^ (s[2] >> 16)        \
              ^ (s[3] << 16)        \
              ^ (s[3] >> 16)        \
              ^ (s[4] << 16)        \
              ^ (s[6] << 16)        \
              ^ (s[6] >> 16)        \
              ^ (s[7] & 0x0000ffff) \
              ^ (s[7] << 16)        \
              ^ (s[7] >> 16);       \
  u[5] = m[5] ^ (s[0] << 16)        \
              ^ (s[0] >> 16)        \
              ^ (s[0] & 0xffff0000) \
              ^ (s[1] & 0x0000ffff) \
              ^ s[2]                \
              ^ (s[2] >> 16)        \
              ^ (s[3] << 16)        \
              ^ (s[3] >> 16)        \
              ^ (s[4] << 16)        \
              ^ (s[4] >> 16)        \
              ^ (s[5] << 16)        \
              ^ (s[6] << 16)        \
              ^ (s[6] >> 16)        \
              ^ (s[7] & 0xffff0000) \
              ^ (s[7] << 16)        \
              ^ (s[7] >> 16);       \
  u[6] = m[6] ^ s[0]                \
              ^ (s[1] >> 16)        \
              ^ (s[2] << 16)        \
              ^ s[3]                \
              ^ (s[3] >> 16)        \
              ^ (s[4] << 16)        \
              ^ (s[4] >> 16)        \
              ^ (s[5] << 16)        \
              ^ (s[5] >> 16)        \
              ^ s[6]                \
              ^ (s[6] << 16)        \
              ^ (s[6] >> 16)        \
              ^ (s[7] << 16);       \
  u[7] = m[7] ^ (s[0] & 0xffff0000) \
              ^ (s[0] << 16)        \
              ^ (s[1] & 0x0000ffff) \
              ^ (s[1] << 16)        \
              ^ (s[2] >> 16)        \
              ^ (s[3] << 16)        \
              ^ s[4]                \
              ^ (s[4] >> 16)        \
              ^ (s[5] << 16)        \
              ^ (s[5] >> 16)        \
              ^ (s[6] >> 16)        \
              ^ (s[7] & 0x0000ffff) \
              ^ (s[7] << 16)        \
              ^ (s[7] >> 16);

#define SHIFT16(h,v,u)              \
  v[0] = h[0] ^ (u[1] << 16)        \
              ^ (u[0] >> 16);       \
  v[1] = h[1] ^ (u[2] << 16)        \
              ^ (u[1] >> 16);       \
  v[2] = h[2] ^ (u[3] << 16)        \
              ^ (u[2] >> 16);       \
  v[3] = h[3] ^ (u[4] << 16)        \
              ^ (u[3] >> 16);       \
  v[4] = h[4] ^ (u[5] << 16)        \
              ^ (u[4] >> 16);       \
  v[5] = h[5] ^ (u[6] << 16)        \
              ^ (u[5] >> 16);       \
  v[6] = h[6] ^ (u[7] << 16)        \
              ^ (u[6] >> 16);       \
  v[7] = h[7] ^ (u[0] & 0xffff0000) \
              ^ (u[0] << 16)        \
              ^ (u[7] >> 16)        \
              ^ (u[1] & 0xffff0000) \
              ^ (u[1] << 16)        \
              ^ (u[6] << 16)        \
              ^ (u[7] & 0xffff0000);

#define SHIFT61(h,v)          \
  h[0] = (v[0] & 0xffff0000)  \
       ^ (v[0] << 16)         \
       ^ (v[0] >> 16)         \
       ^ (v[1] >> 16)         \
       ^ (v[1] & 0xffff0000)  \
       ^ (v[2] << 16)         \
       ^ (v[3] >> 16)         \
       ^ (v[4] << 16)         \
       ^ (v[5] >> 16)         \
       ^ v[5]                 \
       ^ (v[6] >> 16)         \
       ^ (v[7] << 16)         \
       ^ (v[7] >> 16)         \
       ^ (v[7] & 0x0000ffff); \
  h[1] = (v[0] << 16)         \
       ^ (v[0] >> 16)         \
       ^ (v[0] & 0xffff0000)  \
       ^ (v[1] & 0x0000ffff)  \
       ^ v[2]                 \
       ^ (v[2] >> 16)         \
       ^ (v[3] << 16)         \
       ^ (v[4] >> 16)         \
       ^ (v[5] << 16)         \
       ^ (v[6] << 16)         \
       ^ v[6]                 \
       ^ (v[7] & 0xffff0000)  \
       ^ (v[7] >> 16);        \
  h[2] = (v[0] & 0x0000ffff)  \
       ^ (v[0] << 16)         \
       ^ (v[1] << 16)         \
       ^ (v[1] >> 16)         \
       ^ (v[1] & 0xffff0000)  \
       ^ (v[2] << 16)         \
       ^ (v[3] >> 16)         \
       ^ v[3]                 \
       ^ (v[4] << 16)         \
       ^ (v[5] >> 16)         \
       ^ v[6]                 \
       ^ (v[6] >> 16)         \
       ^ (v[7] & 0x0000ffff)  \
       ^ (v[7] << 16)         \
       ^ (v[7] >> 16);        \
  h[3] = (v[0] << 16)         \
       ^ (v[0] >> 16)         \
       ^ (v[0] & 0xffff0000)  \
       ^ (v[1] & 0xffff0000)  \
       ^ (v[1] >> 16)         \
       ^ (v[2] << 16)         \
       ^ (v[2] >> 16)         \
       ^ v[2]                 \
       ^ (v[3] << 16)         \
       ^ (v[4] >> 16)         \
       ^ v[4]                 \
       ^ (v[5] << 16)         \
       ^ (v[6] << 16)         \
       ^ (v[7] & 0x0000ffff)  \
       ^ (v[7] >> 16);        \
  h[4] = (v[0] >> 16)         \
       ^ (v[1] << 16)         \
       ^ v[1]                 \
       ^ (v[2] >> 16)         \
       ^ v[2]                 \
       ^ (v[3] << 16)         \
       ^ (v[3] >> 16)         \
       ^ v[3]                 \
       ^ (v[4] << 16)         \
       ^ (v[5] >> 16)         \
       ^ v[5]                 \
       ^ (v[6] << 16)         \
       ^ (v[6] >> 16)         \
       ^ (v[7] << 16);        \
  h[5] = (v[0] << 16)         \
       ^ (v[0] & 0xffff0000)  \
       ^ (v[1] << 16)         \
       ^ (v[1] >> 16)         \
       ^ (v[1] & 0xffff0000)  \
       ^ (v[2] << 16)         \
       ^ v[2]                 \
       ^ (v[3] >> 16)         \
       ^ v[3]                 \
       ^ (v[4] << 16)         \
       ^ (v[4] >> 16)         \
       ^ v[4]                 \
       ^ (v[5] << 16)         \
       ^ (v[6] << 16)         \
       ^ (v[6] >> 16)         \
       ^ v[6]                 \
       ^ (v[7] << 16)         \
       ^ (v[7] >> 16)         \
       ^ (v[7] & 0xffff0000); \
  h[6] = v[0]                 \
       ^ v[2]                 \
       ^ (v[2] >> 16)         \
       ^ v[3]                 \
       ^ (v[3] << 16)         \
       ^ v[4]                 \
       ^ (v[4] >> 16)         \
       ^ (v[5] << 16)         \
       ^ (v[5] >> 16)         \
       ^ v[5]                 \
       ^ (v[6] << 16)         \
       ^ (v[6] >> 16)         \
       ^ v[6]                 \
       ^ (v[7] << 16)         \
       ^ v[7];                \
  h[7] = v[0]                 \
       ^ (v[0] >> 16)         \
       ^ (v[1] << 16)         \
       ^ (v[1] >> 16)         \
       ^ (v[2] << 16)         \
       ^ (v[3] >> 16)         \
       ^ v[3]                 \
       ^ (v[4] << 16)         \
       ^ v[4]                 \
       ^ (v[5] >> 16)         \
       ^ v[5]                 \
       ^ (v[6] << 16)         \
       ^ (v[6] >> 16)         \
       ^ (v[7] << 16)         \
       ^ v[7];

#define PASS0(h,s,u,v,t)  \
{                         \
  u32x k[8];              \
  u32x w[8];              \
  X (w, u, v);            \
  P (k, w);               \
  R (k, h, s, 0, t);      \
  A (u);                  \
  AA (v);                 \
}

#define PASS2(h,s,u,v,t)  \
{                         \
  u32x k[8];              \
  u32x w[8];              \
  X (w, u, v);            \
  P (k, w);               \
  R (k, h, s, 2, t);      \
  A (u);                  \
  C (u);                  \
  AA (v);                 \
}

#define PASS4(h,s,u,v,t)  \
{                         \
  u32x k[8];              \
  u32x w[8];              \
  X (w, u, v);            \
  P (k, w);               \
  R (k, h, s, 4, t);      \
  A (u);                  \
  AA (v);                 \
}

#define PASS6(h,s,u,v,t)  \
{                         \
  u32x k[8];              \
  u32x w[8];              \
  X (w, u, v);            \
  P (k, w);               \
  R (k, h, s, 6, t);      \
}

KERNEL_FQ void m06900_m04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  LOCAL_VK u32 s_tables[4][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_tables[0][i] = c_tables[0][i];
    s_tables[1][i] = c_tables[1][i];
    s_tables[2][i] = c_tables[2][i];
    s_tables[3][i] = c_tables[3][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
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

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    /**
     * GOST
     */

    u32x data[8];

    data[0] = w0[0];
    data[1] = w0[1];
    data[2] = w0[2];
    data[3] = w0[3];
    data[4] = w1[0];
    data[5] = w1[1];
    data[6] = w1[2];
    data[7] = w1[3];

    u32x state[16];

    state[ 0] = 0;
    state[ 1] = 0;
    state[ 2] = 0;
    state[ 3] = 0;
    state[ 4] = 0;
    state[ 5] = 0;
    state[ 6] = 0;
    state[ 7] = 0;
    state[ 8] = data[0];
    state[ 9] = data[1];
    state[10] = data[2];
    state[11] = data[3];
    state[12] = data[4];
    state[13] = data[5];
    state[14] = data[6];
    state[15] = data[7];

    u32x state_m[8];
    u32x data_m[8];

    /* gost1 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    u32x tmp[8];

    //if (pw_len > 0) // not really SIMD compatible
    {
      PASS0 (state, tmp, state_m, data_m, s_tables);
      PASS2 (state, tmp, state_m, data_m, s_tables);
      PASS4 (state, tmp, state_m, data_m, s_tables);
      PASS6 (state, tmp, state_m, data_m, s_tables);

      SHIFT12 (state_m, data, tmp);
      SHIFT16 (state, data_m, state_m);
      SHIFT61 (state, data_m);
    }

    data[0] = pw_len * 8;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;
    data[4] = 0;
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;

    /* gost2 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* gost3 */

    data[0] = state[ 8];
    data[1] = state[ 9];
    data[2] = state[10];
    data[3] = state[11];
    data[4] = state[12];
    data[5] = state[13];
    data[6] = state[14];
    data[7] = state[15];

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* store */

    COMPARE_M_SIMD (state[0], state[1], state[2], state[3]);
  }
}

KERNEL_FQ void m06900_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m06900_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m06900_s04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  LOCAL_VK u32 s_tables[4][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_tables[0][i] = c_tables[0][i];
    s_tables[1][i] = c_tables[1][i];
    s_tables[2][i] = c_tables[2][i];
    s_tables[3][i] = c_tables[3][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
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

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    /**
     * GOST
     */

    u32x data[8];

    data[0] = w0[0];
    data[1] = w0[1];
    data[2] = w0[2];
    data[3] = w0[3];
    data[4] = w1[0];
    data[5] = w1[1];
    data[6] = w1[2];
    data[7] = w1[3];

    u32x state[16];

    state[ 0] = 0;
    state[ 1] = 0;
    state[ 2] = 0;
    state[ 3] = 0;
    state[ 4] = 0;
    state[ 5] = 0;
    state[ 6] = 0;
    state[ 7] = 0;
    state[ 8] = data[0];
    state[ 9] = data[1];
    state[10] = data[2];
    state[11] = data[3];
    state[12] = data[4];
    state[13] = data[5];
    state[14] = data[6];
    state[15] = data[7];

    u32x state_m[8];
    u32x data_m[8];

    /* gost1 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    u32x tmp[8];

    //if (pw_len > 0) // not really SIMD compatible
    {
      PASS0 (state, tmp, state_m, data_m, s_tables);
      PASS2 (state, tmp, state_m, data_m, s_tables);
      PASS4 (state, tmp, state_m, data_m, s_tables);
      PASS6 (state, tmp, state_m, data_m, s_tables);

      SHIFT12 (state_m, data, tmp);
      SHIFT16 (state, data_m, state_m);
      SHIFT61 (state, data_m);
    }

    data[0] = pw_len * 8;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;
    data[4] = 0;
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;

    /* gost2 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* gost3 */

    data[0] = state[ 8];
    data[1] = state[ 9];
    data[2] = state[10];
    data[3] = state[11];
    data[4] = state[12];
    data[5] = state[13];
    data[6] = state[14];
    data[7] = state[15];

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* store */

    COMPARE_S_SIMD (state[0], state[1], state[2], state[3]);
  }
}

KERNEL_FQ void m06900_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m06900_s16 (KERN_ATTR_BASIC ())
{
}
