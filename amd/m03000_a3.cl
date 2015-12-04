/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 * NOTE........: sboxes were taken from JtR, license below
 */

#define _DES_
#define _SCALAR_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#ifdef  VLIW1
#define VECT_SIZE1
#endif

#ifdef  VLIW4
#define VECT_SIZE1
#endif

#ifdef  VLIW5
#define VECT_SIZE1
#endif

#define DGST_R0 0
#define DGST_R1 1
#define DGST_R2 2
#define DGST_R3 3

#include "include/kernel_functions.c"
#include "types_amd.c"
#include "common_amd.c"

#ifdef  VECT_SIZE1
#define VECT_COMPARE_S "check_single_vect1_comp4_warp_bs.c"
#define VECT_COMPARE_M "check_multi_vect1_comp4_warp_bs.c"
#endif

#ifdef  VECT_SIZE2
#define VECT_COMPARE_S "check_single_vect2_comp4_warp_bs.c"
#define VECT_COMPARE_M "check_multi_vect2_comp4_warp_bs.c"
#endif

#ifdef  VECT_SIZE4
#define VECT_COMPARE_S "check_single_vect4_comp4_warp_bs.c"
#define VECT_COMPARE_M "check_multi_vect4_comp4_warp_bs.c"
#endif

#define KXX_DECL

/*
 * Bitslice DES S-boxes making use of a vector conditional select operation
 * (e.g., vsel on PowerPC with AltiVec).
 *
 * Gate counts: 36 33 33 26 35 34 34 32
 * Average: 32.875
 *
 * Several same-gate-count expressions for each S-box are included (for use on
 * different CPUs/GPUs).
 *
 * These Boolean expressions corresponding to DES S-boxes have been generated
 * by Roman Rusakov <roman_rus at openwall.com> for use in Openwall's
 * John the Ripper password cracker: http://www.openwall.com/john/
 * Being mathematical formulas, they are not copyrighted and are free for reuse
 * by anyone.
 *
 * This file (a specific representation of the S-box expressions, surrounding
 * logic) is Copyright (c) 2011 by Solar Designer <solar at openwall.com>.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.  (This is a heavily cut-down "BSD license".)
 *
 * The effort has been sponsored by Rapid7: http://www.rapid7.com
 */

#define vnot(dst, a) 						(dst) = ~(a)
#define vand(dst, a, b) 				(dst) = (a) & (b)
#define vor(dst, a, b) 					(dst) = (a) | (b)
#define vandn(dst, a, b) 				(dst) = (a) & ~(b)
#define vxor(dst, a, b) 				(dst) = (a) ^ (b)
#define vsel(dst, a, b, c) 			(dst) = bitselect((a),(b),(c))

static void
s1(u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6,
    u32 * out1, u32 * out2, u32 * out3, u32 * out4)
{
	u32 x0F0F3333, x3C3C3C3C, x55FF55FF, x69C369C3, x0903B73F, x09FCB7C0,
	    x5CA9E295;
	u32 x55AFD1B7, x3C3C69C3, x6993B874;
	u32 x5CEDE59F, x09FCE295, x5D91A51E, x529E962D;
	u32 x29EEADC0, x4B8771A3, x428679F3, x6B68D433;
	u32 x5BA7E193, x026F12F3, x6B27C493, x94D83B6C;
	u32 x965E0B0F, x3327A113, x847F0A1F, xD6E19C32;
	u32 x0DBCE883, x3A25A215, x37994A96;
	u32 x8A487EA7, x8B480F07, xB96C2D16;
	u32 x0, x1, x2, x3;

	vsel(x0F0F3333, a3, a2, a5);
	vxor(x3C3C3C3C, a2, a3);
	vor(x55FF55FF, a1, a4);
	vxor(x69C369C3, x3C3C3C3C, x55FF55FF);
	vsel(x0903B73F, a5, x0F0F3333, x69C369C3);
	vxor(x09FCB7C0, a4, x0903B73F);
	vxor(x5CA9E295, a1, x09FCB7C0);

	vsel(x55AFD1B7, x5CA9E295, x55FF55FF, x0F0F3333);
	vsel(x3C3C69C3, x3C3C3C3C, x69C369C3, a5);
	vxor(x6993B874, x55AFD1B7, x3C3C69C3);

	vsel(x5CEDE59F, x55FF55FF, x5CA9E295, x6993B874);
	vsel(x09FCE295, x09FCB7C0, x5CA9E295, a5);
	vsel(x5D91A51E, x5CEDE59F, x6993B874, x09FCE295);
	vxor(x529E962D, x0F0F3333, x5D91A51E);

	vsel(x29EEADC0, x69C369C3, x09FCB7C0, x5CEDE59F);
	vsel(x4B8771A3, x0F0F3333, x69C369C3, x5CA9E295);
	vsel(x428679F3, a5, x4B8771A3, x529E962D);
	vxor(x6B68D433, x29EEADC0, x428679F3);

	vsel(x5BA7E193, x5CA9E295, x4B8771A3, a3);
	vsel(x026F12F3, a4, x0F0F3333, x529E962D);
	vsel(x6B27C493, x6B68D433, x5BA7E193, x026F12F3);
	vnot(x94D83B6C, x6B27C493);
	vsel(x0, x94D83B6C, x6B68D433, a6);
	vxor(*out1, *out1, x0);

	vsel(x965E0B0F, x94D83B6C, a3, x428679F3);
	vsel(x3327A113, x5BA7E193, a2, x69C369C3);
	vsel(x847F0A1F, x965E0B0F, a4, x3327A113);
	vxor(xD6E19C32, x529E962D, x847F0A1F);
	vsel(x1, xD6E19C32, x5CA9E295, a6);
	vxor(*out2, *out2, x1);

	vsel(x0DBCE883, x09FCE295, x3C3C69C3, x847F0A1F);
	vsel(x3A25A215, x3327A113, x5CA9E295, x0903B73F);
	vxor(x37994A96, x0DBCE883, x3A25A215);
	vsel(x3, x37994A96, x529E962D, a6);
	vxor(*out4, *out4, x3);

	vxor(x8A487EA7, x5CA9E295, xD6E19C32);
	vsel(x8B480F07, a3, x8A487EA7, x847F0A1F);
	vsel(xB96C2D16, x8B480F07, x3C3C3C3C, x3A25A215);
	vsel(x2, xB96C2D16, x6993B874, a6);
	vxor(*out3, *out3, x2);
}

static void
s2(u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6,
    u32 * out1, u32 * out2, u32 * out3, u32 * out4)
{
	u32 x55553333, x0055FF33, x33270F03, x66725A56, x00FFFF00, x668DA556;
	u32 x0F0F5A56, xF0F0A5A9, xA5A5969A, xA55A699A;
	u32 x0F5AF03C, x6600FF56, x87A5F09C;
	u32 xA55A963C, x3C69C30F, xB44BC32D;
	u32 x66D7CC56, x0F4B0F2D, x699CC37B, x996C66D2;
	u32 xB46C662D, x278DB412, xB66CB43B;
	u32 xD2DC4E52, x27993333, xD2994E33;
	u32 x278D0F2D, x2E0E547B, x09976748;
	u32 x0, x1, x2, x3;

	vsel(x55553333, a1, a3, a6);
	vsel(x0055FF33, a6, x55553333, a5);
	vsel(x33270F03, a3, a4, x0055FF33);
	vxor(x66725A56, a1, x33270F03);
	vxor(x00FFFF00, a5, a6);
	vxor(x668DA556, x66725A56, x00FFFF00);

	vsel(x0F0F5A56, a4, x66725A56, a6);
	vnot(xF0F0A5A9, x0F0F5A56);
	vxor(xA5A5969A, x55553333, xF0F0A5A9);
	vxor(xA55A699A, x00FFFF00, xA5A5969A);
	vsel(x1, xA55A699A, x668DA556, a2);
	vxor(*out2, *out2, x1);

	vxor(x0F5AF03C, a4, x0055FF33);
	vsel(x6600FF56, x66725A56, a6, x00FFFF00);
	vsel(x87A5F09C, xA5A5969A, x0F5AF03C, x6600FF56);

	vsel(xA55A963C, xA5A5969A, x0F5AF03C, a5);
	vxor(x3C69C30F, a3, x0F5AF03C);
	vsel(xB44BC32D, xA55A963C, x3C69C30F, a1);

	vsel(x66D7CC56, x66725A56, x668DA556, xA5A5969A);
	vsel(x0F4B0F2D, a4, xB44BC32D, a5);
	vxor(x699CC37B, x66D7CC56, x0F4B0F2D);
	vxor(x996C66D2, xF0F0A5A9, x699CC37B);
	vsel(x0, x996C66D2, xB44BC32D, a2);
	vxor(*out1, *out1, x0);

	vsel(xB46C662D, xB44BC32D, x996C66D2, x00FFFF00);
	vsel(x278DB412, x668DA556, xA5A5969A, a1);
	vsel(xB66CB43B, xB46C662D, x278DB412, x6600FF56);

	vsel(xD2DC4E52, x66D7CC56, x996C66D2, xB44BC32D);
	vsel(x27993333, x278DB412, a3, x0055FF33);
	vsel(xD2994E33, xD2DC4E52, x27993333, a5);
	vsel(x3, x87A5F09C, xD2994E33, a2);
	vxor(*out4, *out4, x3);

	vsel(x278D0F2D, x278DB412, x0F4B0F2D, a6);
	vsel(x2E0E547B, x0F0F5A56, xB66CB43B, x278D0F2D);
	vxor(x09976748, x27993333, x2E0E547B);
	vsel(x2, xB66CB43B, x09976748, a2);
	vxor(*out3, *out3, x2);
}

static void
s3(u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6,
    u32 * out1, u32 * out2, u32 * out3, u32 * out4)
{
	u32 x0F330F33, x0F33F0CC, x5A66A599;
	u32 x2111B7BB, x03FF3033, x05BB50EE, x074F201F, x265E97A4;
	u32 x556BA09E, x665A93AC, x99A56C53;
	u32 x25A1A797, x5713754C, x66559355, x47B135C6;
	u32 x9A5A5C60, xD07AF8F8, x87698DB4, xE13C1EE1;
	u32 x9E48CDE4, x655B905E, x00A55CFF, x9E49915E;
	u32 xD6599874, x05330022, xD2699876;
	u32 x665F9364, xD573F0F2, xB32C6396;
	u32 x0, x1, x2, x3;

	vsel(x0F330F33, a4, a3, a5);
	vxor(x0F33F0CC, a6, x0F330F33);
	vxor(x5A66A599, a2, x0F33F0CC);

	vsel(x2111B7BB, a3, a6, x5A66A599);
	vsel(x03FF3033, a5, a3, x0F33F0CC);
	vsel(x05BB50EE, a5, x0F33F0CC, a2);
	vsel(x074F201F, x03FF3033, a4, x05BB50EE);
	vxor(x265E97A4, x2111B7BB, x074F201F);

	vsel(x556BA09E, x5A66A599, x05BB50EE, a4);
	vsel(x665A93AC, x556BA09E, x265E97A4, a3);
	vnot(x99A56C53, x665A93AC);
	vsel(x1, x265E97A4, x99A56C53, a1);
	vxor(*out2, *out2, x1);

	vxor(x25A1A797, x03FF3033, x265E97A4);
	vsel(x5713754C, a2, x0F33F0CC, x074F201F);
	vsel(x66559355, x665A93AC, a2, a5);
	vsel(x47B135C6, x25A1A797, x5713754C, x66559355);

	vxor(x9A5A5C60, x03FF3033, x99A56C53);
	vsel(xD07AF8F8, x9A5A5C60, x556BA09E, x5A66A599);
	vxor(x87698DB4, x5713754C, xD07AF8F8);
	vxor(xE13C1EE1, x66559355, x87698DB4);

	vsel(x9E48CDE4, x9A5A5C60, x87698DB4, x265E97A4);
	vsel(x655B905E, x66559355, x05BB50EE, a4);
	vsel(x00A55CFF, a5, a6, x9A5A5C60);
	vsel(x9E49915E, x9E48CDE4, x655B905E, x00A55CFF);
	vsel(x0, x9E49915E, xE13C1EE1, a1);
	vxor(*out1, *out1, x0);

	vsel(xD6599874, xD07AF8F8, x66559355, x0F33F0CC);
	vand(x05330022, x0F330F33, x05BB50EE);
	vsel(xD2699876, xD6599874, x00A55CFF, x05330022);
	vsel(x3, x5A66A599, xD2699876, a1);
	vxor(*out4, *out4, x3);

	vsel(x665F9364, x265E97A4, x66559355, x47B135C6);
	vsel(xD573F0F2, xD07AF8F8, x05330022, a4);
	vxor(xB32C6396, x665F9364, xD573F0F2);
	vsel(x2, xB32C6396, x47B135C6, a1);
	vxor(*out3, *out3, x2);
}

static void
s4(u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6,
    u32 * out1, u32 * out2, u32 * out3, u32 * out4)
{
	u32 x0505AFAF, x0555AF55, x0A5AA05A, x46566456, x0A0A5F5F, x0AF55FA0,
	    x0AF50F0F, x4CA36B59;
	u32 xB35C94A6;
	u32 x01BB23BB, x5050FAFA, xA31C26BE, xA91679E1;
	u32 x56E9861E;
	u32 x50E9FA1E, x0AF55F00, x827D9784, xD2946D9A;
	u32 x31F720B3, x11FB21B3, x4712A7AD, x9586CA37;
	u32 x0, x1, x2, x3;

	vsel(x0505AFAF, a5, a3, a1);
	vsel(x0555AF55, x0505AFAF, a1, a4);
	vxor(x0A5AA05A, a3, x0555AF55);
	vsel(x46566456, a1, x0A5AA05A, a2);
	vsel(x0A0A5F5F, a3, a5, a1);
	vxor(x0AF55FA0, a4, x0A0A5F5F);
	vsel(x0AF50F0F, x0AF55FA0, a3, a5);
	vxor(x4CA36B59, x46566456, x0AF50F0F);

	vnot(xB35C94A6, x4CA36B59);

	vsel(x01BB23BB, a4, a2, x0555AF55);
	vxor(x5050FAFA, a1, x0505AFAF);
	vsel(xA31C26BE, xB35C94A6, x01BB23BB, x5050FAFA);
	vxor(xA91679E1, x0A0A5F5F, xA31C26BE);

	vnot(x56E9861E, xA91679E1);

	vsel(x50E9FA1E, x5050FAFA, x56E9861E, a4);
	vsel(x0AF55F00, x0AF50F0F, x0AF55FA0, x0A0A5F5F);
	vsel(x827D9784, xB35C94A6, x0AF55F00, a2);
	vxor(xD2946D9A, x50E9FA1E, x827D9784);
	vsel(x2, xD2946D9A, x4CA36B59, a6);
	vxor(*out3, *out3, x2);
	vsel(x3, xB35C94A6, xD2946D9A, a6);
	vxor(*out4, *out4, x3);

	vsel(x31F720B3, a2, a4, x0AF55FA0);
	vsel(x11FB21B3, x01BB23BB, x31F720B3, x5050FAFA);
	vxor(x4712A7AD, x56E9861E, x11FB21B3);
	vxor(x9586CA37, xD2946D9A, x4712A7AD);
	vsel(x0, x56E9861E, x9586CA37, a6);
	vxor(*out1, *out1, x0);
	vsel(x1, x9586CA37, xA91679E1, a6);
	vxor(*out2, *out2, x1);
}

static void
s5(u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6,
    u32 * out1, u32 * out2, u32 * out3, u32 * out4)
{
	u32 x550F550F, xAAF0AAF0, xA5F5A5F5, x96C696C6, x00FFFF00, x963969C6;
	u32 x2E3C2E3C, xB73121F7, x1501DF0F, x00558A5F, x2E69A463;
	u32 x0679ED42, x045157FD, xB32077FF, x9D49D39C;
	u32 xAC81CFB2, xF72577AF, x5BA4B81D;
	u32 x5BA477AF, x4895469F, x3A35273A, x1A35669A;
	u32 x12E6283D, x9E47D3D4, x1A676AB4;
	u32 x891556DF, xE5E77F82, x6CF2295D;
	u32 x2E3CA5F5, x9697C1C6, x369CC1D6;
	u32 x0, x1, x2, x3;

	vsel(x550F550F, a1, a3, a5);
	vnot(xAAF0AAF0, x550F550F);
	vsel(xA5F5A5F5, xAAF0AAF0, a1, a3);
	vxor(x96C696C6, a2, xA5F5A5F5);
	vxor(x00FFFF00, a5, a6);
	vxor(x963969C6, x96C696C6, x00FFFF00);

	vsel(x2E3C2E3C, a3, xAAF0AAF0, a2);
	vsel(xB73121F7, a2, x963969C6, x96C696C6);
	vsel(x1501DF0F, a6, x550F550F, xB73121F7);
	vsel(x00558A5F, x1501DF0F, a5, a1);
	vxor(x2E69A463, x2E3C2E3C, x00558A5F);

	vsel(x0679ED42, x00FFFF00, x2E69A463, x96C696C6);
	vsel(x045157FD, a6, a1, x0679ED42);
	vsel(xB32077FF, xB73121F7, a6, x045157FD);
	vxor(x9D49D39C, x2E69A463, xB32077FF);
	vsel(x2, x9D49D39C, x2E69A463, a4);
	vxor(*out3, *out3, x2);

	vsel(xAC81CFB2, xAAF0AAF0, x1501DF0F, x0679ED42);
	vsel(xF72577AF, xB32077FF, x550F550F, a1);
	vxor(x5BA4B81D, xAC81CFB2, xF72577AF);
	vsel(x1, x5BA4B81D, x963969C6, a4);
	vxor(*out2, *out2, x1);

	vsel(x5BA477AF, x5BA4B81D, xF72577AF, a6);
	vsel(x4895469F, x5BA477AF, x00558A5F, a2);
	vsel(x3A35273A, x2E3C2E3C, a2, x963969C6);
	vsel(x1A35669A, x4895469F, x3A35273A, x5BA4B81D);

	vsel(x12E6283D, a5, x5BA4B81D, x963969C6);
	vsel(x9E47D3D4, x96C696C6, x9D49D39C, xAC81CFB2);
	vsel(x1A676AB4, x12E6283D, x9E47D3D4, x4895469F);

	vsel(x891556DF, xB32077FF, x4895469F, x3A35273A);
	vsel(xE5E77F82, xF72577AF, x00FFFF00, x12E6283D);
	vxor(x6CF2295D, x891556DF, xE5E77F82);
	vsel(x3, x1A35669A, x6CF2295D, a4);
	vxor(*out4, *out4, x3);

	vsel(x2E3CA5F5, x2E3C2E3C, xA5F5A5F5, a6);
	vsel(x9697C1C6, x96C696C6, x963969C6, x045157FD);
	vsel(x369CC1D6, x2E3CA5F5, x9697C1C6, x5BA477AF);
	vsel(x0, x369CC1D6, x1A676AB4, a4);
	vxor(*out1, *out1, x0);
}

static void
s6(u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6,
    u32 * out1, u32 * out2, u32 * out3, u32 * out4)
{
	u32 x555500FF, x666633CC, x606F30CF, x353A659A, x353A9A65, xCAC5659A;
	u32 x353A6565, x0A3F0A6F, x6C5939A3, x5963A3C6;
	u32 x35FF659A, x3AF06A95, x05CF0A9F, x16E94A97;
	u32 x86CD4C9B, x12E0FFFD, x942D9A67;
	u32 x142956AB, x455D45DF, x1C3EE619;
	u32 x2AEA70D5, x20CF7A9F, x3CF19C86, x69A49C79;
	u32 x840DBB67, x6DA19C1E, x925E63E1;
	u32 x9C3CA761, x257A75D5, xB946D2B4;
	u32 x0, x1, x2, x3;

	vsel(x555500FF, a1, a4, a5);
	vxor(x666633CC, a2, x555500FF);
	vsel(x606F30CF, x666633CC, a4, a3);
	vxor(x353A659A, a1, x606F30CF);
	vxor(x353A9A65, a5, x353A659A);
	vnot(xCAC5659A, x353A9A65);

	vsel(x353A6565, x353A659A, x353A9A65, a4);
	vsel(x0A3F0A6F, a3, a4, x353A6565);
	vxor(x6C5939A3, x666633CC, x0A3F0A6F);
	vxor(x5963A3C6, x353A9A65, x6C5939A3);

	vsel(x35FF659A, a4, x353A659A, x353A6565);
	vxor(x3AF06A95, a3, x35FF659A);
	vsel(x05CF0A9F, a4, a3, x353A9A65);
	vsel(x16E94A97, x3AF06A95, x05CF0A9F, x6C5939A3);

	vsel(x86CD4C9B, xCAC5659A, x05CF0A9F, x6C5939A3);
	vsel(x12E0FFFD, a5, x3AF06A95, x16E94A97);
	vsel(x942D9A67, x86CD4C9B, x353A9A65, x12E0FFFD);
	vsel(x0, xCAC5659A, x942D9A67, a6);
	vxor(*out1, *out1, x0);

	vsel(x142956AB, x353A659A, x942D9A67, a2);
	vsel(x455D45DF, a1, x86CD4C9B, x142956AB);
	vxor(x1C3EE619, x5963A3C6, x455D45DF);
	vsel(x3, x5963A3C6, x1C3EE619, a6);
	vxor(*out4, *out4, x3);

	vsel(x2AEA70D5, x3AF06A95, x606F30CF, x353A9A65);
	vsel(x20CF7A9F, x2AEA70D5, x05CF0A9F, x0A3F0A6F);
	vxor(x3CF19C86, x1C3EE619, x20CF7A9F);
	vxor(x69A49C79, x555500FF, x3CF19C86);

	vsel(x840DBB67, a5, x942D9A67, x86CD4C9B);
	vsel(x6DA19C1E, x69A49C79, x3CF19C86, x840DBB67);
	vnot(x925E63E1, x6DA19C1E);
	vsel(x1, x925E63E1, x69A49C79, a6);
	vxor(*out2, *out2, x1);

	vsel(x9C3CA761, x840DBB67, x1C3EE619, x3CF19C86);
	vsel(x257A75D5, x455D45DF, x2AEA70D5, x606F30CF);
	vxor(xB946D2B4, x9C3CA761, x257A75D5);
	vsel(x2, x16E94A97, xB946D2B4, a6);
	vxor(*out3, *out3, x2);
}

static void
s7(u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6,
    u32 * out1, u32 * out2, u32 * out3, u32 * out4)
{
	u32 x44447777, x4B4B7878, x22772277, x0505F5F5, x220522F5, x694E5A8D;
	u32 x00FFFF00, x66666666, x32353235, x26253636, x26DAC936;
	u32 x738F9C63, x11EF9867, x26DA9867;
	u32 x4B4B9C63, x4B666663, x4E639396;
	u32 x4E4B393C, xFF00FF00, xFF05DD21, xB14EE41D;
	u32 xD728827B, x6698807B, x699C585B;
	u32 x738C847B, xA4A71E18, x74878E78;
	u32 x333D9639, x74879639, x8B7869C6;
	u32 x0, x1, x2, x3;

	vsel(x44447777, a2, a6, a3);
	vxor(x4B4B7878, a4, x44447777);
	vsel(x22772277, a3, a5, a2);
	vsel(x0505F5F5, a6, a2, a4);
	vsel(x220522F5, x22772277, x0505F5F5, a5);
	vxor(x694E5A8D, x4B4B7878, x220522F5);

	vxor(x00FFFF00, a5, a6);
	vxor(x66666666, a2, a3);
	vsel(x32353235, a3, x220522F5, a4);
	vsel(x26253636, x66666666, x32353235, x4B4B7878);
	vxor(x26DAC936, x00FFFF00, x26253636);
	vsel(x0, x26DAC936, x694E5A8D, a1);
	vxor(*out1, *out1, x0);

	vxor(x738F9C63, a2, x26DAC936);
	vsel(x11EF9867, x738F9C63, a5, x66666666);
	vsel(x26DA9867, x26DAC936, x11EF9867, a6);

	vsel(x4B4B9C63, x4B4B7878, x738F9C63, a6);
	vsel(x4B666663, x4B4B9C63, x66666666, x00FFFF00);
	vxor(x4E639396, x0505F5F5, x4B666663);

	vsel(x4E4B393C, x4B4B7878, x4E639396, a2);
	vnot(xFF00FF00, a5);
	vsel(xFF05DD21, xFF00FF00, x738F9C63, x32353235);
	vxor(xB14EE41D, x4E4B393C, xFF05DD21);
	vsel(x1, xB14EE41D, x26DA9867, a1);
	vxor(*out2, *out2, x1);

	vxor(xD728827B, x66666666, xB14EE41D);
	vsel(x6698807B, x26DA9867, xD728827B, x4E4B393C);
	vsel(x699C585B, x6698807B, x694E5A8D, xFF05DD21);
	vsel(x2, x699C585B, x4E639396, a1);
	vxor(*out3, *out3, x2);

	vsel(x738C847B, x738F9C63, xD728827B, x4B4B7878);
	vxor(xA4A71E18, x738F9C63, xD728827B);
	vsel(x74878E78, x738C847B, xA4A71E18, a4);

	vsel(x333D9639, x32353235, x738C847B, xB14EE41D);
	vsel(x74879639, x74878E78, x333D9639, a6);
	vnot(x8B7869C6, x74879639);
	vsel(x3, x74878E78, x8B7869C6, a1);
	vxor(*out4, *out4, x3);
}

static void
s8(u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6,
    u32 * out1, u32 * out2, u32 * out3, u32 * out4)
{
	u32 x0505F5F5, x05FAF50A, x0F0F00FF, x22227777, x07DA807F, x34E9B34C;
	u32 x00FFF00F, x0033FCCF, x5565B15C, x0C0C3F3F, x59698E63;
	u32 x3001F74E, x30555745, x693CD926;
	u32 x0C0CD926, x0C3F25E9, x38D696A5;
	u32 xC729695A;
	u32 x03D2117B, xC778395B, xCB471CB2;
	u32 x5425B13F, x56B3803F, x919AE965;
	u32 x17B3023F, x75555755, x62E6556A, xA59E6C31;
	u32 x0, x1, x2, x3;

	vsel(x0505F5F5, a5, a1, a3);
	vxor(x05FAF50A, a4, x0505F5F5);
	vsel(x0F0F00FF, a3, a4, a5);
	vsel(x22227777, a2, a5, a1);
	vsel(x07DA807F, x05FAF50A, x0F0F00FF, x22227777);
	vxor(x34E9B34C, a2, x07DA807F);

	vsel(x00FFF00F, x05FAF50A, a4, a3);
	vsel(x0033FCCF, a5, x00FFF00F, a2);
	vsel(x5565B15C, a1, x34E9B34C, x0033FCCF);
	vsel(x0C0C3F3F, a3, a5, a2);
	vxor(x59698E63, x5565B15C, x0C0C3F3F);

	vsel(x3001F74E, x34E9B34C, a5, x05FAF50A);
	vsel(x30555745, x3001F74E, a1, x00FFF00F);
	vxor(x693CD926, x59698E63, x30555745);
	vsel(x2, x693CD926, x59698E63, a6);
	vxor(*out3, *out3, x2);

	vsel(x0C0CD926, x0C0C3F3F, x693CD926, a5);
	vxor(x0C3F25E9, x0033FCCF, x0C0CD926);
	vxor(x38D696A5, x34E9B34C, x0C3F25E9);

	vnot(xC729695A, x38D696A5);

	vsel(x03D2117B, x07DA807F, a2, x0C0CD926);
	vsel(xC778395B, xC729695A, x03D2117B, x30555745);
	vxor(xCB471CB2, x0C3F25E9, xC778395B);
	vsel(x1, xCB471CB2, x34E9B34C, a6);
	vxor(*out2, *out2, x1);

	vsel(x5425B13F, x5565B15C, x0C0C3F3F, x03D2117B);
	vsel(x56B3803F, x07DA807F, x5425B13F, x59698E63);
	vxor(x919AE965, xC729695A, x56B3803F);
	vsel(x3, xC729695A, x919AE965, a6);
	vxor(*out4, *out4, x3);

	vsel(x17B3023F, x07DA807F, a2, x59698E63);
	vor(x75555755, a1, x30555745);
	vxor(x62E6556A, x17B3023F, x75555755);
	vxor(xA59E6C31, xC778395B, x62E6556A);
	vsel(x0, xA59E6C31, x38D696A5, a6);
	vxor(*out1, *out1, x0);
}

#define SWAP(a, b) { u32 tmp=a;a=b;b=tmp; }

#define DATASWAP  \
  SWAP(D00, D32); \
  SWAP(D01, D33); \
  SWAP(D02, D34); \
  SWAP(D03, D35); \
  SWAP(D04, D36); \
  SWAP(D05, D37); \
  SWAP(D06, D38); \
  SWAP(D07, D39); \
  SWAP(D08, D40); \
  SWAP(D09, D41); \
  SWAP(D10, D42); \
  SWAP(D11, D43); \
  SWAP(D12, D44); \
  SWAP(D13, D45); \
  SWAP(D14, D46); \
  SWAP(D15, D47); \
  SWAP(D16, D48); \
  SWAP(D17, D49); \
  SWAP(D18, D50); \
  SWAP(D19, D51); \
  SWAP(D20, D52); \
  SWAP(D21, D53); \
  SWAP(D22, D54); \
  SWAP(D23, D55); \
  SWAP(D24, D56); \
  SWAP(D25, D57); \
  SWAP(D26, D58); \
  SWAP(D27, D59); \
  SWAP(D28, D60); \
  SWAP(D29, D61); \
  SWAP(D30, D62); \
  SWAP(D31, D63);

#define KEYSET00 { k00 = K08; k01 = K44; k02 = K29; k03 = K52; k04 = K42; k05 = K14; k06 = K28; k07 = K49; k08 = K01; k09 = K07; k10 = K16; k11 = K36; k12 = K02; k13 = K30; k14 = K22; k15 = K21; k16 = K38; k17 = K50; k18 = K51; k19 = K00; k20 = K31; k21 = K23; k22 = K15; k23 = K35; k24 = K19; k25 = K24; k26 = K34; k27 = K47; k28 = K32; k29 = K03; k30 = K41; k31 = K26; k32 = K04; k33 = K46; k34 = K20; k35 = K25; k36 = K53; k37 = K18; k38 = K33; k39 = K55; k40 = K13; k41 = K17; k42 = K39; k43 = K12; k44 = K11; k45 = K54; k46 = K48; k47 = K27; }
#define KEYSET10 { k00 = K49; k01 = K28; k02 = K45; k03 = K36; k04 = K01; k05 = K30; k06 = K44; k07 = K08; k08 = K42; k09 = K23; k10 = K00; k11 = K52; k12 = K43; k13 = K14; k14 = K38; k15 = K37; k16 = K22; k17 = K09; k18 = K35; k19 = K16; k20 = K15; k21 = K07; k22 = K31; k23 = K51; k24 = K03; k25 = K40; k26 = K46; k27 = K04; k28 = K20; k29 = K19; k30 = K53; k31 = K10; k32 = K47; k33 = K34; k34 = K32; k35 = K13; k36 = K41; k37 = K06; k38 = K17; k39 = K12; k40 = K25; k41 = K33; k42 = K27; k43 = K55; k44 = K54; k45 = K11; k46 = K05; k47 = K39; }
#define KEYSET01 { k00 = K01; k01 = K37; k02 = K22; k03 = K45; k04 = K35; k05 = K07; k06 = K21; k07 = K42; k08 = K51; k09 = K00; k10 = K09; k11 = K29; k12 = K52; k13 = K23; k14 = K15; k15 = K14; k16 = K31; k17 = K43; k18 = K44; k19 = K50; k20 = K49; k21 = K16; k22 = K08; k23 = K28; k24 = K12; k25 = K17; k26 = K27; k27 = K40; k28 = K25; k29 = K55; k30 = K34; k31 = K19; k32 = K24; k33 = K39; k34 = K13; k35 = K18; k36 = K46; k37 = K11; k38 = K26; k39 = K48; k40 = K06; k41 = K10; k42 = K32; k43 = K05; k44 = K04; k45 = K47; k46 = K41; k47 = K20; }
#define KEYSET11 { k00 = K35; k01 = K14; k02 = K31; k03 = K22; k04 = K44; k05 = K16; k06 = K30; k07 = K51; k08 = K28; k09 = K09; k10 = K43; k11 = K38; k12 = K29; k13 = K00; k14 = K49; k15 = K23; k16 = K08; k17 = K52; k18 = K21; k19 = K02; k20 = K01; k21 = K50; k22 = K42; k23 = K37; k24 = K48; k25 = K26; k26 = K32; k27 = K17; k28 = K06; k29 = K05; k30 = K39; k31 = K55; k32 = K33; k33 = K20; k34 = K18; k35 = K54; k36 = K27; k37 = K47; k38 = K03; k39 = K53; k40 = K11; k41 = K19; k42 = K13; k43 = K41; k44 = K40; k45 = K24; k46 = K46; k47 = K25; }
#define KEYSET02 { k00 = K44; k01 = K23; k02 = K08; k03 = K31; k04 = K21; k05 = K50; k06 = K07; k07 = K28; k08 = K37; k09 = K43; k10 = K52; k11 = K15; k12 = K38; k13 = K09; k14 = K01; k15 = K00; k16 = K42; k17 = K29; k18 = K30; k19 = K36; k20 = K35; k21 = K02; k22 = K51; k23 = K14; k24 = K53; k25 = K03; k26 = K13; k27 = K26; k28 = K11; k29 = K41; k30 = K20; k31 = K05; k32 = K10; k33 = K25; k34 = K54; k35 = K04; k36 = K32; k37 = K24; k38 = K12; k39 = K34; k40 = K47; k41 = K55; k42 = K18; k43 = K46; k44 = K17; k45 = K33; k46 = K27; k47 = K06; }
#define KEYSET12 { k00 = K21; k01 = K00; k02 = K42; k03 = K08; k04 = K30; k05 = K02; k06 = K16; k07 = K37; k08 = K14; k09 = K52; k10 = K29; k11 = K49; k12 = K15; k13 = K43; k14 = K35; k15 = K09; k16 = K51; k17 = K38; k18 = K07; k19 = K45; k20 = K44; k21 = K36; k22 = K28; k23 = K23; k24 = K34; k25 = K12; k26 = K18; k27 = K03; k28 = K47; k29 = K46; k30 = K25; k31 = K41; k32 = K19; k33 = K06; k34 = K04; k35 = K40; k36 = K13; k37 = K33; k38 = K48; k39 = K39; k40 = K24; k41 = K05; k42 = K54; k43 = K27; k44 = K26; k45 = K10; k46 = K32; k47 = K11; }
#define KEYSET03 { k00 = K30; k01 = K09; k02 = K51; k03 = K42; k04 = K07; k05 = K36; k06 = K50; k07 = K14; k08 = K23; k09 = K29; k10 = K38; k11 = K01; k12 = K49; k13 = K52; k14 = K44; k15 = K43; k16 = K28; k17 = K15; k18 = K16; k19 = K22; k20 = K21; k21 = K45; k22 = K37; k23 = K00; k24 = K39; k25 = K48; k26 = K54; k27 = K12; k28 = K24; k29 = K27; k30 = K06; k31 = K46; k32 = K55; k33 = K11; k34 = K40; k35 = K17; k36 = K18; k37 = K10; k38 = K53; k39 = K20; k40 = K33; k41 = K41; k42 = K04; k43 = K32; k44 = K03; k45 = K19; k46 = K13; k47 = K47; }
#define KEYSET13 { k00 = K07; k01 = K43; k02 = K28; k03 = K51; k04 = K16; k05 = K45; k06 = K02; k07 = K23; k08 = K00; k09 = K38; k10 = K15; k11 = K35; k12 = K01; k13 = K29; k14 = K21; k15 = K52; k16 = K37; k17 = K49; k18 = K50; k19 = K31; k20 = K30; k21 = K22; k22 = K14; k23 = K09; k24 = K20; k25 = K53; k26 = K04; k27 = K48; k28 = K33; k29 = K32; k30 = K11; k31 = K27; k32 = K05; k33 = K47; k34 = K17; k35 = K26; k36 = K54; k37 = K19; k38 = K34; k39 = K25; k40 = K10; k41 = K46; k42 = K40; k43 = K13; k44 = K12; k45 = K55; k46 = K18; k47 = K24; }
#define KEYSET04 { k00 = K16; k01 = K52; k02 = K37; k03 = K28; k04 = K50; k05 = K22; k06 = K36; k07 = K00; k08 = K09; k09 = K15; k10 = K49; k11 = K44; k12 = K35; k13 = K38; k14 = K30; k15 = K29; k16 = K14; k17 = K01; k18 = K02; k19 = K08; k20 = K07; k21 = K31; k22 = K23; k23 = K43; k24 = K25; k25 = K34; k26 = K40; k27 = K53; k28 = K10; k29 = K13; k30 = K47; k31 = K32; k32 = K41; k33 = K24; k34 = K26; k35 = K03; k36 = K04; k37 = K55; k38 = K39; k39 = K06; k40 = K19; k41 = K27; k42 = K17; k43 = K18; k44 = K48; k45 = K05; k46 = K54; k47 = K33; }
#define KEYSET14 { k00 = K50; k01 = K29; k02 = K14; k03 = K37; k04 = K02; k05 = K31; k06 = K45; k07 = K09; k08 = K43; k09 = K49; k10 = K01; k11 = K21; k12 = K44; k13 = K15; k14 = K07; k15 = K38; k16 = K23; k17 = K35; k18 = K36; k19 = K42; k20 = K16; k21 = K08; k22 = K00; k23 = K52; k24 = K06; k25 = K39; k26 = K17; k27 = K34; k28 = K19; k29 = K18; k30 = K24; k31 = K13; k32 = K46; k33 = K33; k34 = K03; k35 = K12; k36 = K40; k37 = K05; k38 = K20; k39 = K11; k40 = K55; k41 = K32; k42 = K26; k43 = K54; k44 = K53; k45 = K41; k46 = K04; k47 = K10; }
#define KEYSET05 { k00 = K02; k01 = K38; k02 = K23; k03 = K14; k04 = K36; k05 = K08; k06 = K22; k07 = K43; k08 = K52; k09 = K01; k10 = K35; k11 = K30; k12 = K21; k13 = K49; k14 = K16; k15 = K15; k16 = K00; k17 = K44; k18 = K45; k19 = K51; k20 = K50; k21 = K42; k22 = K09; k23 = K29; k24 = K11; k25 = K20; k26 = K26; k27 = K39; k28 = K55; k29 = K54; k30 = K33; k31 = K18; k32 = K27; k33 = K10; k34 = K12; k35 = K48; k36 = K17; k37 = K41; k38 = K25; k39 = K47; k40 = K05; k41 = K13; k42 = K03; k43 = K04; k44 = K34; k45 = K46; k46 = K40; k47 = K19; }
#define KEYSET15 { k00 = K36; k01 = K15; k02 = K00; k03 = K23; k04 = K45; k05 = K42; k06 = K31; k07 = K52; k08 = K29; k09 = K35; k10 = K44; k11 = K07; k12 = K30; k13 = K01; k14 = K50; k15 = K49; k16 = K09; k17 = K21; k18 = K22; k19 = K28; k20 = K02; k21 = K51; k22 = K43; k23 = K38; k24 = K47; k25 = K25; k26 = K03; k27 = K20; k28 = K05; k29 = K04; k30 = K10; k31 = K54; k32 = K32; k33 = K19; k34 = K48; k35 = K53; k36 = K26; k37 = K46; k38 = K06; k39 = K24; k40 = K41; k41 = K18; k42 = K12; k43 = K40; k44 = K39; k45 = K27; k46 = K17; k47 = K55; }
#define KEYSET06 { k00 = K45; k01 = K49; k02 = K09; k03 = K00; k04 = K22; k05 = K51; k06 = K08; k07 = K29; k08 = K38; k09 = K44; k10 = K21; k11 = K16; k12 = K07; k13 = K35; k14 = K02; k15 = K01; k16 = K43; k17 = K30; k18 = K31; k19 = K37; k20 = K36; k21 = K28; k22 = K52; k23 = K15; k24 = K24; k25 = K06; k26 = K12; k27 = K25; k28 = K41; k29 = K40; k30 = K19; k31 = K04; k32 = K13; k33 = K55; k34 = K53; k35 = K34; k36 = K03; k37 = K27; k38 = K11; k39 = K33; k40 = K46; k41 = K54; k42 = K48; k43 = K17; k44 = K20; k45 = K32; k46 = K26; k47 = K05; }
#define KEYSET16 { k00 = K22; k01 = K01; k02 = K43; k03 = K09; k04 = K31; k05 = K28; k06 = K42; k07 = K38; k08 = K15; k09 = K21; k10 = K30; k11 = K50; k12 = K16; k13 = K44; k14 = K36; k15 = K35; k16 = K52; k17 = K07; k18 = K08; k19 = K14; k20 = K45; k21 = K37; k22 = K29; k23 = K49; k24 = K33; k25 = K11; k26 = K48; k27 = K06; k28 = K46; k29 = K17; k30 = K55; k31 = K40; k32 = K18; k33 = K05; k34 = K34; k35 = K39; k36 = K12; k37 = K32; k38 = K47; k39 = K10; k40 = K27; k41 = K04; k42 = K53; k43 = K26; k44 = K25; k45 = K13; k46 = K03; k47 = K41; }
#define KEYSET07 { k00 = K31; k01 = K35; k02 = K52; k03 = K43; k04 = K08; k05 = K37; k06 = K51; k07 = K15; k08 = K49; k09 = K30; k10 = K07; k11 = K02; k12 = K50; k13 = K21; k14 = K45; k15 = K44; k16 = K29; k17 = K16; k18 = K42; k19 = K23; k20 = K22; k21 = K14; k22 = K38; k23 = K01; k24 = K10; k25 = K47; k26 = K53; k27 = K11; k28 = K27; k29 = K26; k30 = K05; k31 = K17; k32 = K54; k33 = K41; k34 = K39; k35 = K20; k36 = K48; k37 = K13; k38 = K24; k39 = K19; k40 = K32; k41 = K40; k42 = K34; k43 = K03; k44 = K06; k45 = K18; k46 = K12; k47 = K46; }
#define KEYSET17 { k00 = K15; k01 = K51; k02 = K36; k03 = K02; k04 = K49; k05 = K21; k06 = K35; k07 = K31; k08 = K08; k09 = K14; k10 = K23; k11 = K43; k12 = K09; k13 = K37; k14 = K29; k15 = K28; k16 = K45; k17 = K00; k18 = K01; k19 = K07; k20 = K38; k21 = K30; k22 = K22; k23 = K42; k24 = K26; k25 = K04; k26 = K41; k27 = K54; k28 = K39; k29 = K10; k30 = K48; k31 = K33; k32 = K11; k33 = K53; k34 = K27; k35 = K32; k36 = K05; k37 = K25; k38 = K40; k39 = K03; k40 = K20; k41 = K24; k42 = K46; k43 = K19; k44 = K18; k45 = K06; k46 = K55; k47 = K34; }

static void DES (const u32 K00, const u32 K01, const u32 K02, const u32 K03, const u32 K04, const u32 K05, const u32 K06, const u32 K07, const u32 K08, const u32 K09, const u32 K10, const u32 K11, const u32 K12, const u32 K13, const u32 K14, const u32 K15, const u32 K16, const u32 K17, const u32 K18, const u32 K19, const u32 K20, const u32 K21, const u32 K22, const u32 K23, const u32 K24, const u32 K25, const u32 K26, const u32 K27, const u32 K28, const u32 K29, const u32 K30, const u32 K31, const u32 K32, const u32 K33, const u32 K34, const u32 K35, const u32 K36, const u32 K37, const u32 K38, const u32 K39, const u32 K40, const u32 K41, const u32 K42, const u32 K43, const u32 K44, const u32 K45, const u32 K46, const u32 K47, const u32 K48, const u32 K49, const u32 K50, const u32 K51, const u32 K52, const u32 K53, const u32 K54, const u32 K55, u32 &D00, u32 &D01, u32 &D02, u32 &D03, u32 &D04, u32 &D05, u32 &D06, u32 &D07, u32 &D08, u32 &D09, u32 &D10, u32 &D11, u32 &D12, u32 &D13, u32 &D14, u32 &D15, u32 &D16, u32 &D17, u32 &D18, u32 &D19, u32 &D20, u32 &D21, u32 &D22, u32 &D23, u32 &D24, u32 &D25, u32 &D26, u32 &D27, u32 &D28, u32 &D29, u32 &D30, u32 &D31, u32 &D32, u32 &D33, u32 &D34, u32 &D35, u32 &D36, u32 &D37, u32 &D38, u32 &D39, u32 &D40, u32 &D41, u32 &D42, u32 &D43, u32 &D44, u32 &D45, u32 &D46, u32 &D47, u32 &D48, u32 &D49, u32 &D50, u32 &D51, u32 &D52, u32 &D53, u32 &D54, u32 &D55, u32 &D56, u32 &D57, u32 &D58, u32 &D59, u32 &D60, u32 &D61, u32 &D62, u32 &D63)
{
  KXX_DECL u32 k00, k01, k02, k03, k04, k05;
  KXX_DECL u32 k06, k07, k08, k09, k10, k11;
  KXX_DECL u32 k12, k13, k14, k15, k16, k17;
  KXX_DECL u32 k18, k19, k20, k21, k22, k23;
  KXX_DECL u32 k24, k25, k26, k27, k28, k29;
  KXX_DECL u32 k30, k31, k32, k33, k34, k35;
  KXX_DECL u32 k36, k37, k38, k39, k40, k41;
  KXX_DECL u32 k42, k43, k44, k45, k46, k47;

  #pragma unroll
  for (u32 i = 0; i < 16; i++)
  {
    switch (i)
    {
      case  0: KEYSET00; break;
      case  1: KEYSET01; break;
      case  2: KEYSET02; break;
      case  3: KEYSET03; break;
      case  4: KEYSET04; break;
      case  5: KEYSET05; break;
      case  6: KEYSET06; break;
      case  7: KEYSET07; break;
      case  8: KEYSET10; break;
      case  9: KEYSET11; break;
      case 10: KEYSET12; break;
      case 11: KEYSET13; break;
      case 12: KEYSET14; break;
      case 13: KEYSET15; break;
      case 14: KEYSET16; break;
      case 15: KEYSET17; break;
    }

    s1(D63 ^ k00, D32 ^ k01, D33 ^ k02, D34 ^ k03, D35 ^ k04, D36 ^ k05, &D08, &D16, &D22, &D30);
    s2(D35 ^ k06, D36 ^ k07, D37 ^ k08, D38 ^ k09, D39 ^ k10, D40 ^ k11, &D12, &D27, &D01, &D17);
    s3(D39 ^ k12, D40 ^ k13, D41 ^ k14, D42 ^ k15, D43 ^ k16, D44 ^ k17, &D23, &D15, &D29, &D05);
    s4(D43 ^ k18, D44 ^ k19, D45 ^ k20, D46 ^ k21, D47 ^ k22, D48 ^ k23, &D25, &D19, &D09, &D00);
    s5(D47 ^ k24, D48 ^ k25, D49 ^ k26, D50 ^ k27, D51 ^ k28, D52 ^ k29, &D07, &D13, &D24, &D02);
    s6(D51 ^ k30, D52 ^ k31, D53 ^ k32, D54 ^ k33, D55 ^ k34, D56 ^ k35, &D03, &D28, &D10, &D18);
    s7(D55 ^ k36, D56 ^ k37, D57 ^ k38, D58 ^ k39, D59 ^ k40, D60 ^ k41, &D31, &D11, &D21, &D06);
    s8(D59 ^ k42, D60 ^ k43, D61 ^ k44, D62 ^ k45, D63 ^ k46, D32 ^ k47, &D04, &D26, &D14, &D20);

    DATASWAP;
  }
}

static void transpose32c (u32 data[32])
{
  #define swap(x,y,j,m)               \
     t  = ((x) ^ ((y) >> (j))) & (m); \
    (x) = (x) ^ t;                    \
    (y) = (y) ^ (t << (j));

  u32 t;

  swap (data[ 0], data[16], 16, 0x0000ffff);
  swap (data[ 1], data[17], 16, 0x0000ffff);
  swap (data[ 2], data[18], 16, 0x0000ffff);
  swap (data[ 3], data[19], 16, 0x0000ffff);
  swap (data[ 4], data[20], 16, 0x0000ffff);
  swap (data[ 5], data[21], 16, 0x0000ffff);
  swap (data[ 6], data[22], 16, 0x0000ffff);
  swap (data[ 7], data[23], 16, 0x0000ffff);
  swap (data[ 8], data[24], 16, 0x0000ffff);
  swap (data[ 9], data[25], 16, 0x0000ffff);
  swap (data[10], data[26], 16, 0x0000ffff);
  swap (data[11], data[27], 16, 0x0000ffff);
  swap (data[12], data[28], 16, 0x0000ffff);
  swap (data[13], data[29], 16, 0x0000ffff);
  swap (data[14], data[30], 16, 0x0000ffff);
  swap (data[15], data[31], 16, 0x0000ffff);
  swap (data[ 0], data[ 8],  8, 0x00ff00ff);
  swap (data[ 1], data[ 9],  8, 0x00ff00ff);
  swap (data[ 2], data[10],  8, 0x00ff00ff);
  swap (data[ 3], data[11],  8, 0x00ff00ff);
  swap (data[ 4], data[12],  8, 0x00ff00ff);
  swap (data[ 5], data[13],  8, 0x00ff00ff);
  swap (data[ 6], data[14],  8, 0x00ff00ff);
  swap (data[ 7], data[15],  8, 0x00ff00ff);
  swap (data[ 0], data[ 4],  4, 0x0f0f0f0f);
  swap (data[ 1], data[ 5],  4, 0x0f0f0f0f);
  swap (data[ 2], data[ 6],  4, 0x0f0f0f0f);
  swap (data[ 3], data[ 7],  4, 0x0f0f0f0f);
  swap (data[ 0], data[ 2],  2, 0x33333333);
  swap (data[ 1], data[ 3],  2, 0x33333333);
  swap (data[ 0], data[ 1],  1, 0x55555555);
  swap (data[ 2], data[ 3],  1, 0x55555555);
  swap (data[ 4], data[ 6],  2, 0x33333333);
  swap (data[ 5], data[ 7],  2, 0x33333333);
  swap (data[ 4], data[ 5],  1, 0x55555555);
  swap (data[ 6], data[ 7],  1, 0x55555555);
  swap (data[ 8], data[12],  4, 0x0f0f0f0f);
  swap (data[ 9], data[13],  4, 0x0f0f0f0f);
  swap (data[10], data[14],  4, 0x0f0f0f0f);
  swap (data[11], data[15],  4, 0x0f0f0f0f);
  swap (data[ 8], data[10],  2, 0x33333333);
  swap (data[ 9], data[11],  2, 0x33333333);
  swap (data[ 8], data[ 9],  1, 0x55555555);
  swap (data[10], data[11],  1, 0x55555555);
  swap (data[12], data[14],  2, 0x33333333);
  swap (data[13], data[15],  2, 0x33333333);
  swap (data[12], data[13],  1, 0x55555555);
  swap (data[14], data[15],  1, 0x55555555);
  swap (data[16], data[24],  8, 0x00ff00ff);
  swap (data[17], data[25],  8, 0x00ff00ff);
  swap (data[18], data[26],  8, 0x00ff00ff);
  swap (data[19], data[27],  8, 0x00ff00ff);
  swap (data[20], data[28],  8, 0x00ff00ff);
  swap (data[21], data[29],  8, 0x00ff00ff);
  swap (data[22], data[30],  8, 0x00ff00ff);
  swap (data[23], data[31],  8, 0x00ff00ff);
  swap (data[16], data[20],  4, 0x0f0f0f0f);
  swap (data[17], data[21],  4, 0x0f0f0f0f);
  swap (data[18], data[22],  4, 0x0f0f0f0f);
  swap (data[19], data[23],  4, 0x0f0f0f0f);
  swap (data[16], data[18],  2, 0x33333333);
  swap (data[17], data[19],  2, 0x33333333);
  swap (data[16], data[17],  1, 0x55555555);
  swap (data[18], data[19],  1, 0x55555555);
  swap (data[20], data[22],  2, 0x33333333);
  swap (data[21], data[23],  2, 0x33333333);
  swap (data[20], data[21],  1, 0x55555555);
  swap (data[22], data[23],  1, 0x55555555);
  swap (data[24], data[28],  4, 0x0f0f0f0f);
  swap (data[25], data[29],  4, 0x0f0f0f0f);
  swap (data[26], data[30],  4, 0x0f0f0f0f);
  swap (data[27], data[31],  4, 0x0f0f0f0f);
  swap (data[24], data[26],  2, 0x33333333);
  swap (data[25], data[27],  2, 0x33333333);
  swap (data[24], data[25],  1, 0x55555555);
  swap (data[26], data[27],  1, 0x55555555);
  swap (data[28], data[30],  2, 0x33333333);
  swap (data[29], data[31],  2, 0x33333333);
  swap (data[28], data[29],  1, 0x55555555);
  swap (data[30], data[31],  1, 0x55555555);
}

static void m03000m (__local u32 *s_S, __global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bs_word_t * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  /**
   * keys
   */

  const u32 K00 = pws[gid].i[ 0];
  const u32 K01 = pws[gid].i[ 1];
  const u32 K02 = pws[gid].i[ 2];
  const u32 K03 = pws[gid].i[ 3];
  const u32 K04 = pws[gid].i[ 4];
  const u32 K05 = pws[gid].i[ 5];
  const u32 K06 = pws[gid].i[ 6];
  const u32 K07 = pws[gid].i[ 7];
  const u32 K08 = pws[gid].i[ 8];
  const u32 K09 = pws[gid].i[ 9];
  const u32 K10 = pws[gid].i[10];
  const u32 K11 = pws[gid].i[11];
  const u32 K12 = pws[gid].i[12];
  const u32 K13 = pws[gid].i[13];
  const u32 K14 = pws[gid].i[14];
  const u32 K15 = pws[gid].i[15];
  const u32 K16 = pws[gid].i[16];
  const u32 K17 = pws[gid].i[17];
  const u32 K18 = pws[gid].i[18];
  const u32 K19 = pws[gid].i[19];
  const u32 K20 = pws[gid].i[20];
  const u32 K21 = pws[gid].i[21];
  const u32 K22 = pws[gid].i[22];
  const u32 K23 = pws[gid].i[23];
  const u32 K24 = pws[gid].i[24];
  const u32 K25 = pws[gid].i[25];
  const u32 K26 = pws[gid].i[26];
  const u32 K27 = pws[gid].i[27];
  const u32 K28 = pws[gid].i[28];
  const u32 K29 = pws[gid].i[29];
  const u32 K30 = pws[gid].i[30];
  const u32 K31 = pws[gid].i[31];
  const u32 K32 = pws[gid].i[32];
  const u32 K33 = pws[gid].i[33];
  const u32 K34 = pws[gid].i[34];
  const u32 K35 = pws[gid].i[35];
  const u32 K36 = pws[gid].i[36];
  const u32 K37 = pws[gid].i[37];
  const u32 K38 = pws[gid].i[38];
  const u32 K39 = pws[gid].i[39];
  const u32 K40 = pws[gid].i[40];
  const u32 K41 = pws[gid].i[41];
  const u32 K42 = pws[gid].i[42];
  const u32 K43 = pws[gid].i[43];
  const u32 K44 = pws[gid].i[44];
  const u32 K45 = pws[gid].i[45];
  const u32 K46 = pws[gid].i[46];
  const u32 K47 = pws[gid].i[47];
  const u32 K48 = pws[gid].i[48];
  const u32 K49 = pws[gid].i[49];
  const u32 K50 = pws[gid].i[50];
  const u32 K51 = pws[gid].i[51];
  const u32 K52 = pws[gid].i[52];
  const u32 K53 = pws[gid].i[53];
  const u32 K54 = pws[gid].i[54];
  const u32 K55 = pws[gid].i[55];

  const u32 bf_loops = bfs_cnt;

  const u32 pc_pos = get_local_id (1);

  const u32 il_pos = pc_pos * 32;

  u32 k00 = K00;
  u32 k01 = K01;
  u32 k02 = K02;
  u32 k03 = K03;
  u32 k04 = K04;
  u32 k05 = K05;
  u32 k06 = K06;
  u32 k07 = K07;
  u32 k08 = K08;
  u32 k09 = K09;
  u32 k10 = K10;
  u32 k11 = K11;
  u32 k12 = K12;
  u32 k13 = K13;
  u32 k14 = K14;
  u32 k15 = K15;
  u32 k16 = K16;
  u32 k17 = K17;
  u32 k18 = K18;
  u32 k19 = K19;
  u32 k20 = K20;
  u32 k21 = K21;
  u32 k22 = K22;
  u32 k23 = K23;
  u32 k24 = K24;
  u32 k25 = K25;
  u32 k26 = K26;
  u32 k27 = K27;
  u32 k28 = K28;
  u32 k29 = K29;
  u32 k30 = K30;
  u32 k31 = K31;

  k00 |= words_buf_r[pc_pos].b[ 0];
  k01 |= words_buf_r[pc_pos].b[ 1];
  k02 |= words_buf_r[pc_pos].b[ 2];
  k03 |= words_buf_r[pc_pos].b[ 3];
  k04 |= words_buf_r[pc_pos].b[ 4];
  k05 |= words_buf_r[pc_pos].b[ 5];
  k06 |= words_buf_r[pc_pos].b[ 6];
  k07 |= words_buf_r[pc_pos].b[ 7];
  k08 |= words_buf_r[pc_pos].b[ 8];
  k09 |= words_buf_r[pc_pos].b[ 9];
  k10 |= words_buf_r[pc_pos].b[10];
  k11 |= words_buf_r[pc_pos].b[11];
  k12 |= words_buf_r[pc_pos].b[12];
  k13 |= words_buf_r[pc_pos].b[13];
  k14 |= words_buf_r[pc_pos].b[14];
  k15 |= words_buf_r[pc_pos].b[15];
  k16 |= words_buf_r[pc_pos].b[16];
  k17 |= words_buf_r[pc_pos].b[17];
  k18 |= words_buf_r[pc_pos].b[18];
  k19 |= words_buf_r[pc_pos].b[19];
  k20 |= words_buf_r[pc_pos].b[20];
  k21 |= words_buf_r[pc_pos].b[21];
  k22 |= words_buf_r[pc_pos].b[22];
  k23 |= words_buf_r[pc_pos].b[23];
  k24 |= words_buf_r[pc_pos].b[24];
  k25 |= words_buf_r[pc_pos].b[25];
  k26 |= words_buf_r[pc_pos].b[26];
  k27 |= words_buf_r[pc_pos].b[27];
  k28 |= words_buf_r[pc_pos].b[28];
  k29 |= words_buf_r[pc_pos].b[29];
  k30 |= words_buf_r[pc_pos].b[30];
  k31 |= words_buf_r[pc_pos].b[31];

  // KGS!@#$% including IP

  u32 D00 = 0;
  u32 D01 = 0;
  u32 D02 = 0;
  u32 D03 = 0xffffffff;
  u32 D04 = 0;
  u32 D05 = 0xffffffff;
  u32 D06 = 0xffffffff;
  u32 D07 = 0xffffffff;
  u32 D08 = 0;
  u32 D09 = 0;
  u32 D10 = 0;
  u32 D11 = 0;
  u32 D12 = 0;
  u32 D13 = 0xffffffff;
  u32 D14 = 0;
  u32 D15 = 0;
  u32 D16 = 0xffffffff;
  u32 D17 = 0xffffffff;
  u32 D18 = 0;
  u32 D19 = 0;
  u32 D20 = 0;
  u32 D21 = 0;
  u32 D22 = 0xffffffff;
  u32 D23 = 0;
  u32 D24 = 0xffffffff;
  u32 D25 = 0;
  u32 D26 = 0xffffffff;
  u32 D27 = 0;
  u32 D28 = 0xffffffff;
  u32 D29 = 0xffffffff;
  u32 D30 = 0xffffffff;
  u32 D31 = 0xffffffff;
  u32 D32 = 0;
  u32 D33 = 0;
  u32 D34 = 0;
  u32 D35 = 0;
  u32 D36 = 0;
  u32 D37 = 0;
  u32 D38 = 0;
  u32 D39 = 0;
  u32 D40 = 0xffffffff;
  u32 D41 = 0xffffffff;
  u32 D42 = 0xffffffff;
  u32 D43 = 0;
  u32 D44 = 0xffffffff;
  u32 D45 = 0;
  u32 D46 = 0;
  u32 D47 = 0;
  u32 D48 = 0;
  u32 D49 = 0;
  u32 D50 = 0;
  u32 D51 = 0;
  u32 D52 = 0;
  u32 D53 = 0;
  u32 D54 = 0;
  u32 D55 = 0xffffffff;
  u32 D56 = 0;
  u32 D57 = 0;
  u32 D58 = 0xffffffff;
  u32 D59 = 0;
  u32 D60 = 0;
  u32 D61 = 0xffffffff;
  u32 D62 = 0xffffffff;
  u32 D63 = 0xffffffff;

  DES
  (
    k00, k01, k02, k03, k04, k05, k06,
    k07, k08, k09, k10, k11, k12, k13,
    k14, k15, k16, k17, k18, k19, k20,
    k21, k22, k23, k24, k25, k26, k27,
    k28, k29, k30, k31, K32, K33, K34,
    K35, K36, K37, K38, K39, K40, K41,
    K42, K43, K44, K45, K46, K47, K48,
    K49, K50, K51, K52, K53, K54, K55,
    D00, D01, D02, D03, D04, D05, D06, D07,
    D08, D09, D10, D11, D12, D13, D14, D15,
    D16, D17, D18, D19, D20, D21, D22, D23,
    D24, D25, D26, D27, D28, D29, D30, D31,
    D32, D33, D34, D35, D36, D37, D38, D39,
    D40, D41, D42, D43, D44, D45, D46, D47,
    D48, D49, D50, D51, D52, D53, D54, D55,
    D56, D57, D58, D59, D60, D61, D62, D63
  );

  u32 out[64];

  out[ 0] = D00;
  out[ 1] = D01;
  out[ 2] = D02;
  out[ 3] = D03;
  out[ 4] = D04;
  out[ 5] = D05;
  out[ 6] = D06;
  out[ 7] = D07;
  out[ 8] = D08;
  out[ 9] = D09;
  out[10] = D10;
  out[11] = D11;
  out[12] = D12;
  out[13] = D13;
  out[14] = D14;
  out[15] = D15;
  out[16] = D16;
  out[17] = D17;
  out[18] = D18;
  out[19] = D19;
  out[20] = D20;
  out[21] = D21;
  out[22] = D22;
  out[23] = D23;
  out[24] = D24;
  out[25] = D25;
  out[26] = D26;
  out[27] = D27;
  out[28] = D28;
  out[29] = D29;
  out[30] = D30;
  out[31] = D31;
  out[32] = D32;
  out[33] = D33;
  out[34] = D34;
  out[35] = D35;
  out[36] = D36;
  out[37] = D37;
  out[38] = D38;
  out[39] = D39;
  out[40] = D40;
  out[41] = D41;
  out[42] = D42;
  out[43] = D43;
  out[44] = D44;
  out[45] = D45;
  out[46] = D46;
  out[47] = D47;
  out[48] = D48;
  out[49] = D49;
  out[50] = D50;
  out[51] = D51;
  out[52] = D52;
  out[53] = D53;
  out[54] = D54;
  out[55] = D55;
  out[56] = D56;
  out[57] = D57;
  out[58] = D58;
  out[59] = D59;
  out[60] = D60;
  out[61] = D61;
  out[62] = D62;
  out[63] = D63;

  if (digests_cnt < 16)
  {
    for (u32 d = 0; d < digests_cnt; d++)
    {
      const u32 final_hash_pos = digests_offset + d;

      if (hashes_shown[final_hash_pos]) continue;

      u32 search[2];

      search[0] = digests_buf[final_hash_pos].digest_buf[DGST_R0];
      search[1] = digests_buf[final_hash_pos].digest_buf[DGST_R1];

      u32 tmpResult = 0;

      #pragma unroll
      for (int i = 0; i < 32; i++)
      {
        const u32 b0 = -((search[0] >> i) & 1);
        const u32 b1 = -((search[1] >> i) & 1);

        tmpResult |= out[ 0 + i] ^ b0;
        tmpResult |= out[32 + i] ^ b1;
      }

      if (tmpResult == 0xffffffff) continue;

      const u32 slice = 31 - clz (~tmpResult);

      const u32x r0 = search[0];
      const u32x r1 = search[1];
      const u32x r2 = 0;
      const u32x r3 = 0;

      #include VECT_COMPARE_M
    }
  }
  else
  {
    u32 out0[32];
    u32 out1[32];

    #pragma unroll
    for (int i = 0; i < 32; i++)
    {
      out0[i] = out[ 0 + 31 - i];
      out1[i] = out[32 + 31 - i];
    }

    transpose32c (out0);
    transpose32c (out1);

    #pragma unroll
    for (int slice = 0; slice < 32; slice++)
    {
      const u32x r0 = out0[31 - slice];
      const u32x r1 = out1[31 - slice];
      const u32x r2 = 0;
      const u32x r3 = 0;

      #include VECT_COMPARE_M
    }
  }
}

static void m03000s (__local u32 *s_S, __global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bs_word_t * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  /**
   * digest
   */

  #define S00 s_S[ 0]
  #define S01 s_S[ 1]
  #define S02 s_S[ 2]
  #define S03 s_S[ 3]
  #define S04 s_S[ 4]
  #define S05 s_S[ 5]
  #define S06 s_S[ 6]
  #define S07 s_S[ 7]
  #define S08 s_S[ 8]
  #define S09 s_S[ 9]
  #define S10 s_S[10]
  #define S11 s_S[11]
  #define S12 s_S[12]
  #define S13 s_S[13]
  #define S14 s_S[14]
  #define S15 s_S[15]
  #define S16 s_S[16]
  #define S17 s_S[17]
  #define S18 s_S[18]
  #define S19 s_S[19]
  #define S20 s_S[20]
  #define S21 s_S[21]
  #define S22 s_S[22]
  #define S23 s_S[23]
  #define S24 s_S[24]
  #define S25 s_S[25]
  #define S26 s_S[26]
  #define S27 s_S[27]
  #define S28 s_S[28]
  #define S29 s_S[29]
  #define S30 s_S[30]
  #define S31 s_S[31]
  #define S32 s_S[32]
  #define S33 s_S[33]
  #define S34 s_S[34]
  #define S35 s_S[35]
  #define S36 s_S[36]
  #define S37 s_S[37]
  #define S38 s_S[38]
  #define S39 s_S[39]
  #define S40 s_S[40]
  #define S41 s_S[41]
  #define S42 s_S[42]
  #define S43 s_S[43]
  #define S44 s_S[44]
  #define S45 s_S[45]
  #define S46 s_S[46]
  #define S47 s_S[47]
  #define S48 s_S[48]
  #define S49 s_S[49]
  #define S50 s_S[50]
  #define S51 s_S[51]
  #define S52 s_S[52]
  #define S53 s_S[53]
  #define S54 s_S[54]
  #define S55 s_S[55]
  #define S56 s_S[56]
  #define S57 s_S[57]
  #define S58 s_S[58]
  #define S59 s_S[59]
  #define S60 s_S[60]
  #define S61 s_S[61]
  #define S62 s_S[62]
  #define S63 s_S[63]

  /**
   * keys
   */

  const u32 K00 = pws[gid].i[ 0];
  const u32 K01 = pws[gid].i[ 1];
  const u32 K02 = pws[gid].i[ 2];
  const u32 K03 = pws[gid].i[ 3];
  const u32 K04 = pws[gid].i[ 4];
  const u32 K05 = pws[gid].i[ 5];
  const u32 K06 = pws[gid].i[ 6];
  const u32 K07 = pws[gid].i[ 7];
  const u32 K08 = pws[gid].i[ 8];
  const u32 K09 = pws[gid].i[ 9];
  const u32 K10 = pws[gid].i[10];
  const u32 K11 = pws[gid].i[11];
  const u32 K12 = pws[gid].i[12];
  const u32 K13 = pws[gid].i[13];
  const u32 K14 = pws[gid].i[14];
  const u32 K15 = pws[gid].i[15];
  const u32 K16 = pws[gid].i[16];
  const u32 K17 = pws[gid].i[17];
  const u32 K18 = pws[gid].i[18];
  const u32 K19 = pws[gid].i[19];
  const u32 K20 = pws[gid].i[20];
  const u32 K21 = pws[gid].i[21];
  const u32 K22 = pws[gid].i[22];
  const u32 K23 = pws[gid].i[23];
  const u32 K24 = pws[gid].i[24];
  const u32 K25 = pws[gid].i[25];
  const u32 K26 = pws[gid].i[26];
  const u32 K27 = pws[gid].i[27];
  const u32 K28 = pws[gid].i[28];
  const u32 K29 = pws[gid].i[29];
  const u32 K30 = pws[gid].i[30];
  const u32 K31 = pws[gid].i[31];
  const u32 K32 = pws[gid].i[32];
  const u32 K33 = pws[gid].i[33];
  const u32 K34 = pws[gid].i[34];
  const u32 K35 = pws[gid].i[35];
  const u32 K36 = pws[gid].i[36];
  const u32 K37 = pws[gid].i[37];
  const u32 K38 = pws[gid].i[38];
  const u32 K39 = pws[gid].i[39];
  const u32 K40 = pws[gid].i[40];
  const u32 K41 = pws[gid].i[41];
  const u32 K42 = pws[gid].i[42];
  const u32 K43 = pws[gid].i[43];
  const u32 K44 = pws[gid].i[44];
  const u32 K45 = pws[gid].i[45];
  const u32 K46 = pws[gid].i[46];
  const u32 K47 = pws[gid].i[47];
  const u32 K48 = pws[gid].i[48];
  const u32 K49 = pws[gid].i[49];
  const u32 K50 = pws[gid].i[50];
  const u32 K51 = pws[gid].i[51];
  const u32 K52 = pws[gid].i[52];
  const u32 K53 = pws[gid].i[53];
  const u32 K54 = pws[gid].i[54];
  const u32 K55 = pws[gid].i[55];

  const u32 pc_pos = get_local_id (1);

  const u32 il_pos = pc_pos * 32;

  u32 k00 = K00;
  u32 k01 = K01;
  u32 k02 = K02;
  u32 k03 = K03;
  u32 k04 = K04;
  u32 k05 = K05;
  u32 k06 = K06;
  u32 k07 = K07;
  u32 k08 = K08;
  u32 k09 = K09;
  u32 k10 = K10;
  u32 k11 = K11;
  u32 k12 = K12;
  u32 k13 = K13;
  u32 k14 = K14;
  u32 k15 = K15;
  u32 k16 = K16;
  u32 k17 = K17;
  u32 k18 = K18;
  u32 k19 = K19;
  u32 k20 = K20;
  u32 k21 = K21;
  u32 k22 = K22;
  u32 k23 = K23;
  u32 k24 = K24;
  u32 k25 = K25;
  u32 k26 = K26;
  u32 k27 = K27;
  u32 k28 = K28;
  u32 k29 = K29;
  u32 k30 = K30;
  u32 k31 = K31;

  k00 |= words_buf_r[pc_pos].b[ 0];
  k01 |= words_buf_r[pc_pos].b[ 1];
  k02 |= words_buf_r[pc_pos].b[ 2];
  k03 |= words_buf_r[pc_pos].b[ 3];
  k04 |= words_buf_r[pc_pos].b[ 4];
  k05 |= words_buf_r[pc_pos].b[ 5];
  k06 |= words_buf_r[pc_pos].b[ 6];
  k07 |= words_buf_r[pc_pos].b[ 7];
  k08 |= words_buf_r[pc_pos].b[ 8];
  k09 |= words_buf_r[pc_pos].b[ 9];
  k10 |= words_buf_r[pc_pos].b[10];
  k11 |= words_buf_r[pc_pos].b[11];
  k12 |= words_buf_r[pc_pos].b[12];
  k13 |= words_buf_r[pc_pos].b[13];
  k14 |= words_buf_r[pc_pos].b[14];
  k15 |= words_buf_r[pc_pos].b[15];
  k16 |= words_buf_r[pc_pos].b[16];
  k17 |= words_buf_r[pc_pos].b[17];
  k18 |= words_buf_r[pc_pos].b[18];
  k19 |= words_buf_r[pc_pos].b[19];
  k20 |= words_buf_r[pc_pos].b[20];
  k21 |= words_buf_r[pc_pos].b[21];
  k22 |= words_buf_r[pc_pos].b[22];
  k23 |= words_buf_r[pc_pos].b[23];
  k24 |= words_buf_r[pc_pos].b[24];
  k25 |= words_buf_r[pc_pos].b[25];
  k26 |= words_buf_r[pc_pos].b[26];
  k27 |= words_buf_r[pc_pos].b[27];
  k28 |= words_buf_r[pc_pos].b[28];
  k29 |= words_buf_r[pc_pos].b[29];
  k30 |= words_buf_r[pc_pos].b[30];
  k31 |= words_buf_r[pc_pos].b[31];

  // KGS!@#$% including IP

  u32 D00 = 0;
  u32 D01 = 0;
  u32 D02 = 0;
  u32 D03 = 0xffffffff;
  u32 D04 = 0;
  u32 D05 = 0xffffffff;
  u32 D06 = 0xffffffff;
  u32 D07 = 0xffffffff;
  u32 D08 = 0;
  u32 D09 = 0;
  u32 D10 = 0;
  u32 D11 = 0;
  u32 D12 = 0;
  u32 D13 = 0xffffffff;
  u32 D14 = 0;
  u32 D15 = 0;
  u32 D16 = 0xffffffff;
  u32 D17 = 0xffffffff;
  u32 D18 = 0;
  u32 D19 = 0;
  u32 D20 = 0;
  u32 D21 = 0;
  u32 D22 = 0xffffffff;
  u32 D23 = 0;
  u32 D24 = 0xffffffff;
  u32 D25 = 0;
  u32 D26 = 0xffffffff;
  u32 D27 = 0;
  u32 D28 = 0xffffffff;
  u32 D29 = 0xffffffff;
  u32 D30 = 0xffffffff;
  u32 D31 = 0xffffffff;
  u32 D32 = 0;
  u32 D33 = 0;
  u32 D34 = 0;
  u32 D35 = 0;
  u32 D36 = 0;
  u32 D37 = 0;
  u32 D38 = 0;
  u32 D39 = 0;
  u32 D40 = 0xffffffff;
  u32 D41 = 0xffffffff;
  u32 D42 = 0xffffffff;
  u32 D43 = 0;
  u32 D44 = 0xffffffff;
  u32 D45 = 0;
  u32 D46 = 0;
  u32 D47 = 0;
  u32 D48 = 0;
  u32 D49 = 0;
  u32 D50 = 0;
  u32 D51 = 0;
  u32 D52 = 0;
  u32 D53 = 0;
  u32 D54 = 0;
  u32 D55 = 0xffffffff;
  u32 D56 = 0;
  u32 D57 = 0;
  u32 D58 = 0xffffffff;
  u32 D59 = 0;
  u32 D60 = 0;
  u32 D61 = 0xffffffff;
  u32 D62 = 0xffffffff;
  u32 D63 = 0xffffffff;

  DES
  (
    k00, k01, k02, k03, k04, k05, k06,
    k07, k08, k09, k10, k11, k12, k13,
    k14, k15, k16, k17, k18, k19, k20,
    k21, k22, k23, k24, k25, k26, k27,
    k28, k29, k30, k31, K32, K33, K34,
    K35, K36, K37, K38, K39, K40, K41,
    K42, K43, K44, K45, K46, K47, K48,
    K49, K50, K51, K52, K53, K54, K55,
    D00, D01, D02, D03, D04, D05, D06, D07,
    D08, D09, D10, D11, D12, D13, D14, D15,
    D16, D17, D18, D19, D20, D21, D22, D23,
    D24, D25, D26, D27, D28, D29, D30, D31,
    D32, D33, D34, D35, D36, D37, D38, D39,
    D40, D41, D42, D43, D44, D45, D46, D47,
    D48, D49, D50, D51, D52, D53, D54, D55,
    D56, D57, D58, D59, D60, D61, D62, D63
  );

  u32 tmpResult = 0;

  tmpResult |= D00 ^ S00;
  tmpResult |= D01 ^ S01;
  tmpResult |= D02 ^ S02;
  tmpResult |= D03 ^ S03;
  tmpResult |= D04 ^ S04;
  tmpResult |= D05 ^ S05;
  tmpResult |= D06 ^ S06;
  tmpResult |= D07 ^ S07;
  tmpResult |= D08 ^ S08;
  tmpResult |= D09 ^ S09;
  tmpResult |= D10 ^ S10;
  tmpResult |= D11 ^ S11;
  tmpResult |= D12 ^ S12;
  tmpResult |= D13 ^ S13;
  tmpResult |= D14 ^ S14;
  tmpResult |= D15 ^ S15;

  if (tmpResult == 0xffffffff) return;

  tmpResult |= D16 ^ S16;
  tmpResult |= D17 ^ S17;
  tmpResult |= D18 ^ S18;
  tmpResult |= D19 ^ S19;
  tmpResult |= D20 ^ S20;
  tmpResult |= D21 ^ S21;
  tmpResult |= D22 ^ S22;
  tmpResult |= D23 ^ S23;
  tmpResult |= D24 ^ S24;
  tmpResult |= D25 ^ S25;
  tmpResult |= D26 ^ S26;
  tmpResult |= D27 ^ S27;
  tmpResult |= D28 ^ S28;
  tmpResult |= D29 ^ S29;
  tmpResult |= D30 ^ S30;
  tmpResult |= D31 ^ S31;

  if (tmpResult == 0xffffffff) return;

  tmpResult |= D32 ^ S32;
  tmpResult |= D33 ^ S33;
  tmpResult |= D34 ^ S34;
  tmpResult |= D35 ^ S35;
  tmpResult |= D36 ^ S36;
  tmpResult |= D37 ^ S37;
  tmpResult |= D38 ^ S38;
  tmpResult |= D39 ^ S39;
  tmpResult |= D40 ^ S40;
  tmpResult |= D41 ^ S41;
  tmpResult |= D42 ^ S42;
  tmpResult |= D43 ^ S43;
  tmpResult |= D44 ^ S44;
  tmpResult |= D45 ^ S45;
  tmpResult |= D46 ^ S46;
  tmpResult |= D47 ^ S47;

  if (tmpResult == 0xffffffff) return;

  tmpResult |= D48 ^ S48;
  tmpResult |= D49 ^ S49;
  tmpResult |= D50 ^ S50;
  tmpResult |= D51 ^ S51;
  tmpResult |= D52 ^ S52;
  tmpResult |= D53 ^ S53;
  tmpResult |= D54 ^ S54;
  tmpResult |= D55 ^ S55;
  tmpResult |= D56 ^ S56;
  tmpResult |= D57 ^ S57;
  tmpResult |= D58 ^ S58;
  tmpResult |= D59 ^ S59;
  tmpResult |= D60 ^ S60;
  tmpResult |= D61 ^ S61;
  tmpResult |= D62 ^ S62;
  tmpResult |= D63 ^ S63;

  if (tmpResult == 0xffffffff) return;

  const u32 slice = 31 - clz (~tmpResult);

  #include VECT_COMPARE_S
}

//
// transpose bitslice base : easy because no overlapping buffers
//                    mod  : attention race conditions, need different buffers for *in and *out
//

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m03000_tb (__global pw_t *pws)
{
  const u32 gid = get_global_id (0);

  const u32 w0s = pws[gid].i[0];
  const u32 w1s = pws[gid].i[1];

  #pragma unroll
  for (int i = 0; i < 32; i += 8)
  {
    pws[gid].i[i +  0 + 0] = -((w0s >> (i + 7)) & 1);
    pws[gid].i[i +  0 + 1] = -((w0s >> (i + 6)) & 1);
    pws[gid].i[i +  0 + 2] = -((w0s >> (i + 5)) & 1);
    pws[gid].i[i +  0 + 3] = -((w0s >> (i + 4)) & 1);
    pws[gid].i[i +  0 + 4] = -((w0s >> (i + 3)) & 1);
    pws[gid].i[i +  0 + 5] = -((w0s >> (i + 2)) & 1);
    pws[gid].i[i +  0 + 6] = -((w0s >> (i + 1)) & 1);
    pws[gid].i[i +  0 + 7] = -((w0s >> (i + 0)) & 1);
  }

  #pragma unroll
  for (int i = 0; i < 24; i += 8)
  {
    pws[gid].i[i + 32 + 0] = -((w1s >> (i + 7)) & 1);
    pws[gid].i[i + 32 + 1] = -((w1s >> (i + 6)) & 1);
    pws[gid].i[i + 32 + 2] = -((w1s >> (i + 5)) & 1);
    pws[gid].i[i + 32 + 3] = -((w1s >> (i + 4)) & 1);
    pws[gid].i[i + 32 + 4] = -((w1s >> (i + 3)) & 1);
    pws[gid].i[i + 32 + 5] = -((w1s >> (i + 2)) & 1);
    pws[gid].i[i + 32 + 6] = -((w1s >> (i + 1)) & 1);
    pws[gid].i[i + 32 + 7] = -((w1s >> (i + 0)) & 1);
  }
}

__kernel void __attribute__((reqd_work_group_size (32, 1, 1))) m03000_tm (__global u32 *mod, __global bs_word_t *words_buf_r)
{
  const u32 gid = get_global_id (0);

  const u32 block = gid / 32;
  const u32 slice = gid % 32;

  const u32 w0 = mod[gid];

  #pragma unroll
  for (int i = 0; i < 32; i += 8)
  {
    atomic_or (&words_buf_r[block].b[i + 0], (((w0 >> (i + 7)) & 1) << slice));
    atomic_or (&words_buf_r[block].b[i + 1], (((w0 >> (i + 6)) & 1) << slice));
    atomic_or (&words_buf_r[block].b[i + 2], (((w0 >> (i + 5)) & 1) << slice));
    atomic_or (&words_buf_r[block].b[i + 3], (((w0 >> (i + 4)) & 1) << slice));
    atomic_or (&words_buf_r[block].b[i + 4], (((w0 >> (i + 3)) & 1) << slice));
    atomic_or (&words_buf_r[block].b[i + 5], (((w0 >> (i + 2)) & 1) << slice));
    atomic_or (&words_buf_r[block].b[i + 6], (((w0 >> (i + 1)) & 1) << slice));
    atomic_or (&words_buf_r[block].b[i + 7], (((w0 >> (i + 0)) & 1) << slice));
  }
}

__kernel void __attribute__((reqd_work_group_size (2, 32, 1))) m03000_m04 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bs_word_t * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 vid = get_local_id (1);

  const u32 s0 = digests_buf[digests_offset].digest_buf[0];
  const u32 s1 = digests_buf[digests_offset].digest_buf[1];

  __local u32 s_S[64];

  if (lid == 0)
  {
    s_S[ 0 + vid] = -((s0 >> vid) & 1);
  }
  else if (lid == 1)
  {
    s_S[32 + vid] = -((s1 >> vid) & 1);
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  m03000m (s_S, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset);
}

__kernel void __attribute__((reqd_work_group_size (2, 32, 1))) m03000_m08 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bs_word_t * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (2, 32, 1))) m03000_m16 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bs_word_t * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (2, 32, 1))) m03000_s04 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bs_word_t * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 vid = get_local_id (1);

  const u32 s0 = digests_buf[digests_offset].digest_buf[0];
  const u32 s1 = digests_buf[digests_offset].digest_buf[1];

  __local u32 s_S[64];

  if (lid == 0)
  {
    s_S[ 0 + vid] = -((s0 >> vid) & 1);
  }
  else if (lid == 1)
  {
    s_S[32 + vid] = -((s1 >> vid) & 1);
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  m03000s (s_S, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset);
}

__kernel void __attribute__((reqd_work_group_size (2, 32, 1))) m03000_s08 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bs_word_t * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (2, 32, 1))) m03000_s16 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bs_word_t * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
