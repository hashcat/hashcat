/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_fugue.h"

// The 4 tables of SMIX, which combine the AES S-box with the column mix of the reference
// implementation. Each is the one before it rotated right by 8 bits.

CONSTANT_VK u32a fugue_mixtab[4][256] =
{
  {
    0x63633297, 0x7c7c6feb, 0x77775ec7, 0x7b7b7af7, 0xf2f2e8e5, 0x6b6b0ab7, 0x6f6f16a7, 0xc5c56d39,
    0x303090c0, 0x01010704, 0x67672e87, 0x2b2bd1ac, 0xfefeccd5, 0xd7d71371, 0xabab7c9a, 0x767659c3,
    0xcaca4005, 0x8282a33e, 0xc9c94909, 0x7d7d68ef, 0xfafad0c5, 0x5959947f, 0x4747ce07, 0xf0f0e6ed,
    0xadad6e82, 0xd4d41a7d, 0xa2a243be, 0xafaf608a, 0x9c9cf946, 0xa4a451a6, 0x727245d3, 0xc0c0762d,
    0xb7b728ea, 0xfdfdc5d9, 0x9393d47a, 0x2626f298, 0x363682d8, 0x3f3fbdfc, 0xf7f7f3f1, 0xcccc521d,
    0x34348cd0, 0xa5a556a2, 0xe5e58db9, 0xf1f1e1e9, 0x71714cdf, 0xd8d83e4d, 0x313197c4, 0x15156b54,
    0x04041c10, 0xc7c76331, 0x2323e98c, 0xc3c37f21, 0x18184860, 0x9696cf6e, 0x05051b14, 0x9a9aeb5e,
    0x0707151c, 0x12127e48, 0x8080ad36, 0xe2e298a5, 0xebeba781, 0x2727f59c, 0xb2b233fe, 0x757550cf,
    0x09093f24, 0x8383a43a, 0x2c2cc4b0, 0x1a1a4668, 0x1b1b416c, 0x6e6e11a3, 0x5a5a9d73, 0xa0a04db6,
    0x5252a553, 0x3b3ba1ec, 0xd6d61475, 0xb3b334fa, 0x2929dfa4, 0xe3e39fa1, 0x2f2fcdbc, 0x8484b126,
    0x5353a257, 0xd1d10169, 0x00000000, 0xededb599, 0x2020e080, 0xfcfcc2dd, 0xb1b13af2, 0x5b5b9a77,
    0x6a6a0db3, 0xcbcb4701, 0xbebe17ce, 0x3939afe4, 0x4a4aed33, 0x4c4cff2b, 0x5858937b, 0xcfcf5b11,
    0xd0d0066d, 0xefefbb91, 0xaaaa7b9e, 0xfbfbd7c1, 0x4343d217, 0x4d4df82f, 0x333399cc, 0x8585b622,
    0x4545c00f, 0xf9f9d9c9, 0x02020e08, 0x7f7f66e7, 0x5050ab5b, 0x3c3cb4f0, 0x9f9ff04a, 0xa8a87596,
    0x5151ac5f, 0xa3a344ba, 0x4040db1b, 0x8f8f800a, 0x9292d37e, 0x9d9dfe42, 0x3838a8e0, 0xf5f5fdf9,
    0xbcbc19c6, 0xb6b62fee, 0xdada3045, 0x2121e784, 0x10107040, 0xffffcbd1, 0xf3f3efe1, 0xd2d20865,
    0xcdcd5519, 0x0c0c2430, 0x1313794c, 0xececb29d, 0x5f5f8667, 0x9797c86a, 0x4444c70b, 0x1717655c,
    0xc4c46a3d, 0xa7a758aa, 0x7e7e61e3, 0x3d3db3f4, 0x6464278b, 0x5d5d886f, 0x19194f64, 0x737342d7,
    0x60603b9b, 0x8181aa32, 0x4f4ff627, 0xdcdc225d, 0x2222ee88, 0x2a2ad6a8, 0x9090dd76, 0x88889516,
    0x4646c903, 0xeeeebc95, 0xb8b805d6, 0x14146c50, 0xdede2c55, 0x5e5e8163, 0x0b0b312c, 0xdbdb3741,
    0xe0e096ad, 0x32329ec8, 0x3a3aa6e8, 0x0a0a3628, 0x4949e43f, 0x06061218, 0x2424fc90, 0x5c5c8f6b,
    0xc2c27825, 0xd3d30f61, 0xacac6986, 0x62623593, 0x9191da72, 0x9595c662, 0xe4e48abd, 0x797974ff,
    0xe7e783b1, 0xc8c84e0d, 0x373785dc, 0x6d6d18af, 0x8d8d8e02, 0xd5d51d79, 0x4e4ef123, 0xa9a97292,
    0x6c6c1fab, 0x5656b943, 0xf4f4fafd, 0xeaeaa085, 0x6565208f, 0x7a7a7df3, 0xaeae678e, 0x08083820,
    0xbaba0bde, 0x787873fb, 0x2525fb94, 0x2e2ecab8, 0x1c1c5470, 0xa6a65fae, 0xb4b421e6, 0xc6c66435,
    0xe8e8ae8d, 0xdddd2559, 0x747457cb, 0x1f1f5d7c, 0x4b4bea37, 0xbdbd1ec2, 0x8b8b9c1a, 0x8a8a9b1e,
    0x70704bdb, 0x3e3ebaf8, 0xb5b526e2, 0x66662983, 0x4848e33b, 0x0303090c, 0xf6f6f4f5, 0x0e0e2a38,
    0x61613c9f, 0x35358bd4, 0x5757be47, 0xb9b902d2, 0x8686bf2e, 0xc1c17129, 0x1d1d5374, 0x9e9ef74e,
    0xe1e191a9, 0xf8f8decd, 0x9898e556, 0x11117744, 0x696904bf, 0xd9d93949, 0x8e8e870e, 0x9494c166,
    0x9b9bec5a, 0x1e1e5a78, 0x8787b82a, 0xe9e9a989, 0xcece5c15, 0x5555b04f, 0x2828d8a0, 0xdfdf2b51,
    0x8c8c8906, 0xa1a14ab2, 0x89899212, 0x0d0d2334, 0xbfbf10ca, 0xe6e684b5, 0x4242d513, 0x686803bb,
    0x4141dc1f, 0x9999e252, 0x2d2dc3b4, 0x0f0f2d3c, 0xb0b03df6, 0x5454b74b, 0xbbbb0cda, 0x16166258
  },
  {
    0x97636332, 0xeb7c7c6f, 0xc777775e, 0xf77b7b7a, 0xe5f2f2e8, 0xb76b6b0a, 0xa76f6f16, 0x39c5c56d,
    0xc0303090, 0x04010107, 0x8767672e, 0xac2b2bd1, 0xd5fefecc, 0x71d7d713, 0x9aabab7c, 0xc3767659,
    0x05caca40, 0x3e8282a3, 0x09c9c949, 0xef7d7d68, 0xc5fafad0, 0x7f595994, 0x074747ce, 0xedf0f0e6,
    0x82adad6e, 0x7dd4d41a, 0xbea2a243, 0x8aafaf60, 0x469c9cf9, 0xa6a4a451, 0xd3727245, 0x2dc0c076,
    0xeab7b728, 0xd9fdfdc5, 0x7a9393d4, 0x982626f2, 0xd8363682, 0xfc3f3fbd, 0xf1f7f7f3, 0x1dcccc52,
    0xd034348c, 0xa2a5a556, 0xb9e5e58d, 0xe9f1f1e1, 0xdf71714c, 0x4dd8d83e, 0xc4313197, 0x5415156b,
    0x1004041c, 0x31c7c763, 0x8c2323e9, 0x21c3c37f, 0x60181848, 0x6e9696cf, 0x1405051b, 0x5e9a9aeb,
    0x1c070715, 0x4812127e, 0x368080ad, 0xa5e2e298, 0x81ebeba7, 0x9c2727f5, 0xfeb2b233, 0xcf757550,
    0x2409093f, 0x3a8383a4, 0xb02c2cc4, 0x681a1a46, 0x6c1b1b41, 0xa36e6e11, 0x735a5a9d, 0xb6a0a04d,
    0x535252a5, 0xec3b3ba1, 0x75d6d614, 0xfab3b334, 0xa42929df, 0xa1e3e39f, 0xbc2f2fcd, 0x268484b1,
    0x575353a2, 0x69d1d101, 0x00000000, 0x99ededb5, 0x802020e0, 0xddfcfcc2, 0xf2b1b13a, 0x775b5b9a,
    0xb36a6a0d, 0x01cbcb47, 0xcebebe17, 0xe43939af, 0x334a4aed, 0x2b4c4cff, 0x7b585893, 0x11cfcf5b,
    0x6dd0d006, 0x91efefbb, 0x9eaaaa7b, 0xc1fbfbd7, 0x174343d2, 0x2f4d4df8, 0xcc333399, 0x228585b6,
    0x0f4545c0, 0xc9f9f9d9, 0x0802020e, 0xe77f7f66, 0x5b5050ab, 0xf03c3cb4, 0x4a9f9ff0, 0x96a8a875,
    0x5f5151ac, 0xbaa3a344, 0x1b4040db, 0x0a8f8f80, 0x7e9292d3, 0x429d9dfe, 0xe03838a8, 0xf9f5f5fd,
    0xc6bcbc19, 0xeeb6b62f, 0x45dada30, 0x842121e7, 0x40101070, 0xd1ffffcb, 0xe1f3f3ef, 0x65d2d208,
    0x19cdcd55, 0x300c0c24, 0x4c131379, 0x9dececb2, 0x675f5f86, 0x6a9797c8, 0x0b4444c7, 0x5c171765,
    0x3dc4c46a, 0xaaa7a758, 0xe37e7e61, 0xf43d3db3, 0x8b646427, 0x6f5d5d88, 0x6419194f, 0xd7737342,
    0x9b60603b, 0x328181aa, 0x274f4ff6, 0x5ddcdc22, 0x882222ee, 0xa82a2ad6, 0x769090dd, 0x16888895,
    0x034646c9, 0x95eeeebc, 0xd6b8b805, 0x5014146c, 0x55dede2c, 0x635e5e81, 0x2c0b0b31, 0x41dbdb37,
    0xade0e096, 0xc832329e, 0xe83a3aa6, 0x280a0a36, 0x3f4949e4, 0x18060612, 0x902424fc, 0x6b5c5c8f,
    0x25c2c278, 0x61d3d30f, 0x86acac69, 0x93626235, 0x729191da, 0x629595c6, 0xbde4e48a, 0xff797974,
    0xb1e7e783, 0x0dc8c84e, 0xdc373785, 0xaf6d6d18, 0x028d8d8e, 0x79d5d51d, 0x234e4ef1, 0x92a9a972,
    0xab6c6c1f, 0x435656b9, 0xfdf4f4fa, 0x85eaeaa0, 0x8f656520, 0xf37a7a7d, 0x8eaeae67, 0x20080838,
    0xdebaba0b, 0xfb787873, 0x942525fb, 0xb82e2eca, 0x701c1c54, 0xaea6a65f, 0xe6b4b421, 0x35c6c664,
    0x8de8e8ae, 0x59dddd25, 0xcb747457, 0x7c1f1f5d, 0x374b4bea, 0xc2bdbd1e, 0x1a8b8b9c, 0x1e8a8a9b,
    0xdb70704b, 0xf83e3eba, 0xe2b5b526, 0x83666629, 0x3b4848e3, 0x0c030309, 0xf5f6f6f4, 0x380e0e2a,
    0x9f61613c, 0xd435358b, 0x475757be, 0xd2b9b902, 0x2e8686bf, 0x29c1c171, 0x741d1d53, 0x4e9e9ef7,
    0xa9e1e191, 0xcdf8f8de, 0x569898e5, 0x44111177, 0xbf696904, 0x49d9d939, 0x0e8e8e87, 0x669494c1,
    0x5a9b9bec, 0x781e1e5a, 0x2a8787b8, 0x89e9e9a9, 0x15cece5c, 0x4f5555b0, 0xa02828d8, 0x51dfdf2b,
    0x068c8c89, 0xb2a1a14a, 0x12898992, 0x340d0d23, 0xcabfbf10, 0xb5e6e684, 0x134242d5, 0xbb686803,
    0x1f4141dc, 0x529999e2, 0xb42d2dc3, 0x3c0f0f2d, 0xf6b0b03d, 0x4b5454b7, 0xdabbbb0c, 0x58161662
  },
  {
    0x32976363, 0x6feb7c7c, 0x5ec77777, 0x7af77b7b, 0xe8e5f2f2, 0x0ab76b6b, 0x16a76f6f, 0x6d39c5c5,
    0x90c03030, 0x07040101, 0x2e876767, 0xd1ac2b2b, 0xccd5fefe, 0x1371d7d7, 0x7c9aabab, 0x59c37676,
    0x4005caca, 0xa33e8282, 0x4909c9c9, 0x68ef7d7d, 0xd0c5fafa, 0x947f5959, 0xce074747, 0xe6edf0f0,
    0x6e82adad, 0x1a7dd4d4, 0x43bea2a2, 0x608aafaf, 0xf9469c9c, 0x51a6a4a4, 0x45d37272, 0x762dc0c0,
    0x28eab7b7, 0xc5d9fdfd, 0xd47a9393, 0xf2982626, 0x82d83636, 0xbdfc3f3f, 0xf3f1f7f7, 0x521dcccc,
    0x8cd03434, 0x56a2a5a5, 0x8db9e5e5, 0xe1e9f1f1, 0x4cdf7171, 0x3e4dd8d8, 0x97c43131, 0x6b541515,
    0x1c100404, 0x6331c7c7, 0xe98c2323, 0x7f21c3c3, 0x48601818, 0xcf6e9696, 0x1b140505, 0xeb5e9a9a,
    0x151c0707, 0x7e481212, 0xad368080, 0x98a5e2e2, 0xa781ebeb, 0xf59c2727, 0x33feb2b2, 0x50cf7575,
    0x3f240909, 0xa43a8383, 0xc4b02c2c, 0x46681a1a, 0x416c1b1b, 0x11a36e6e, 0x9d735a5a, 0x4db6a0a0,
    0xa5535252, 0xa1ec3b3b, 0x1475d6d6, 0x34fab3b3, 0xdfa42929, 0x9fa1e3e3, 0xcdbc2f2f, 0xb1268484,
    0xa2575353, 0x0169d1d1, 0x00000000, 0xb599eded, 0xe0802020, 0xc2ddfcfc, 0x3af2b1b1, 0x9a775b5b,
    0x0db36a6a, 0x4701cbcb, 0x17cebebe, 0xafe43939, 0xed334a4a, 0xff2b4c4c, 0x937b5858, 0x5b11cfcf,
    0x066dd0d0, 0xbb91efef, 0x7b9eaaaa, 0xd7c1fbfb, 0xd2174343, 0xf82f4d4d, 0x99cc3333, 0xb6228585,
    0xc00f4545, 0xd9c9f9f9, 0x0e080202, 0x66e77f7f, 0xab5b5050, 0xb4f03c3c, 0xf04a9f9f, 0x7596a8a8,
    0xac5f5151, 0x44baa3a3, 0xdb1b4040, 0x800a8f8f, 0xd37e9292, 0xfe429d9d, 0xa8e03838, 0xfdf9f5f5,
    0x19c6bcbc, 0x2feeb6b6, 0x3045dada, 0xe7842121, 0x70401010, 0xcbd1ffff, 0xefe1f3f3, 0x0865d2d2,
    0x5519cdcd, 0x24300c0c, 0x794c1313, 0xb29decec, 0x86675f5f, 0xc86a9797, 0xc70b4444, 0x655c1717,
    0x6a3dc4c4, 0x58aaa7a7, 0x61e37e7e, 0xb3f43d3d, 0x278b6464, 0x886f5d5d, 0x4f641919, 0x42d77373,
    0x3b9b6060, 0xaa328181, 0xf6274f4f, 0x225ddcdc, 0xee882222, 0xd6a82a2a, 0xdd769090, 0x95168888,
    0xc9034646, 0xbc95eeee, 0x05d6b8b8, 0x6c501414, 0x2c55dede, 0x81635e5e, 0x312c0b0b, 0x3741dbdb,
    0x96ade0e0, 0x9ec83232, 0xa6e83a3a, 0x36280a0a, 0xe43f4949, 0x12180606, 0xfc902424, 0x8f6b5c5c,
    0x7825c2c2, 0x0f61d3d3, 0x6986acac, 0x35936262, 0xda729191, 0xc6629595, 0x8abde4e4, 0x74ff7979,
    0x83b1e7e7, 0x4e0dc8c8, 0x85dc3737, 0x18af6d6d, 0x8e028d8d, 0x1d79d5d5, 0xf1234e4e, 0x7292a9a9,
    0x1fab6c6c, 0xb9435656, 0xfafdf4f4, 0xa085eaea, 0x208f6565, 0x7df37a7a, 0x678eaeae, 0x38200808,
    0x0bdebaba, 0x73fb7878, 0xfb942525, 0xcab82e2e, 0x54701c1c, 0x5faea6a6, 0x21e6b4b4, 0x6435c6c6,
    0xae8de8e8, 0x2559dddd, 0x57cb7474, 0x5d7c1f1f, 0xea374b4b, 0x1ec2bdbd, 0x9c1a8b8b, 0x9b1e8a8a,
    0x4bdb7070, 0xbaf83e3e, 0x26e2b5b5, 0x29836666, 0xe33b4848, 0x090c0303, 0xf4f5f6f6, 0x2a380e0e,
    0x3c9f6161, 0x8bd43535, 0xbe475757, 0x02d2b9b9, 0xbf2e8686, 0x7129c1c1, 0x53741d1d, 0xf74e9e9e,
    0x91a9e1e1, 0xdecdf8f8, 0xe5569898, 0x77441111, 0x04bf6969, 0x3949d9d9, 0x870e8e8e, 0xc1669494,
    0xec5a9b9b, 0x5a781e1e, 0xb82a8787, 0xa989e9e9, 0x5c15cece, 0xb04f5555, 0xd8a02828, 0x2b51dfdf,
    0x89068c8c, 0x4ab2a1a1, 0x92128989, 0x23340d0d, 0x10cabfbf, 0x84b5e6e6, 0xd5134242, 0x03bb6868,
    0xdc1f4141, 0xe2529999, 0xc3b42d2d, 0x2d3c0f0f, 0x3df6b0b0, 0xb74b5454, 0x0cdabbbb, 0x62581616
  },
  {
    0x63329763, 0x7c6feb7c, 0x775ec777, 0x7b7af77b, 0xf2e8e5f2, 0x6b0ab76b, 0x6f16a76f, 0xc56d39c5,
    0x3090c030, 0x01070401, 0x672e8767, 0x2bd1ac2b, 0xfeccd5fe, 0xd71371d7, 0xab7c9aab, 0x7659c376,
    0xca4005ca, 0x82a33e82, 0xc94909c9, 0x7d68ef7d, 0xfad0c5fa, 0x59947f59, 0x47ce0747, 0xf0e6edf0,
    0xad6e82ad, 0xd41a7dd4, 0xa243bea2, 0xaf608aaf, 0x9cf9469c, 0xa451a6a4, 0x7245d372, 0xc0762dc0,
    0xb728eab7, 0xfdc5d9fd, 0x93d47a93, 0x26f29826, 0x3682d836, 0x3fbdfc3f, 0xf7f3f1f7, 0xcc521dcc,
    0x348cd034, 0xa556a2a5, 0xe58db9e5, 0xf1e1e9f1, 0x714cdf71, 0xd83e4dd8, 0x3197c431, 0x156b5415,
    0x041c1004, 0xc76331c7, 0x23e98c23, 0xc37f21c3, 0x18486018, 0x96cf6e96, 0x051b1405, 0x9aeb5e9a,
    0x07151c07, 0x127e4812, 0x80ad3680, 0xe298a5e2, 0xeba781eb, 0x27f59c27, 0xb233feb2, 0x7550cf75,
    0x093f2409, 0x83a43a83, 0x2cc4b02c, 0x1a46681a, 0x1b416c1b, 0x6e11a36e, 0x5a9d735a, 0xa04db6a0,
    0x52a55352, 0x3ba1ec3b, 0xd61475d6, 0xb334fab3, 0x29dfa429, 0xe39fa1e3, 0x2fcdbc2f, 0x84b12684,
    0x53a25753, 0xd10169d1, 0x00000000, 0xedb599ed, 0x20e08020, 0xfcc2ddfc, 0xb13af2b1, 0x5b9a775b,
    0x6a0db36a, 0xcb4701cb, 0xbe17cebe, 0x39afe439, 0x4aed334a, 0x4cff2b4c, 0x58937b58, 0xcf5b11cf,
    0xd0066dd0, 0xefbb91ef, 0xaa7b9eaa, 0xfbd7c1fb, 0x43d21743, 0x4df82f4d, 0x3399cc33, 0x85b62285,
    0x45c00f45, 0xf9d9c9f9, 0x020e0802, 0x7f66e77f, 0x50ab5b50, 0x3cb4f03c, 0x9ff04a9f, 0xa87596a8,
    0x51ac5f51, 0xa344baa3, 0x40db1b40, 0x8f800a8f, 0x92d37e92, 0x9dfe429d, 0x38a8e038, 0xf5fdf9f5,
    0xbc19c6bc, 0xb62feeb6, 0xda3045da, 0x21e78421, 0x10704010, 0xffcbd1ff, 0xf3efe1f3, 0xd20865d2,
    0xcd5519cd, 0x0c24300c, 0x13794c13, 0xecb29dec, 0x5f86675f, 0x97c86a97, 0x44c70b44, 0x17655c17,
    0xc46a3dc4, 0xa758aaa7, 0x7e61e37e, 0x3db3f43d, 0x64278b64, 0x5d886f5d, 0x194f6419, 0x7342d773,
    0x603b9b60, 0x81aa3281, 0x4ff6274f, 0xdc225ddc, 0x22ee8822, 0x2ad6a82a, 0x90dd7690, 0x88951688,
    0x46c90346, 0xeebc95ee, 0xb805d6b8, 0x146c5014, 0xde2c55de, 0x5e81635e, 0x0b312c0b, 0xdb3741db,
    0xe096ade0, 0x329ec832, 0x3aa6e83a, 0x0a36280a, 0x49e43f49, 0x06121806, 0x24fc9024, 0x5c8f6b5c,
    0xc27825c2, 0xd30f61d3, 0xac6986ac, 0x62359362, 0x91da7291, 0x95c66295, 0xe48abde4, 0x7974ff79,
    0xe783b1e7, 0xc84e0dc8, 0x3785dc37, 0x6d18af6d, 0x8d8e028d, 0xd51d79d5, 0x4ef1234e, 0xa97292a9,
    0x6c1fab6c, 0x56b94356, 0xf4fafdf4, 0xeaa085ea, 0x65208f65, 0x7a7df37a, 0xae678eae, 0x08382008,
    0xba0bdeba, 0x7873fb78, 0x25fb9425, 0x2ecab82e, 0x1c54701c, 0xa65faea6, 0xb421e6b4, 0xc66435c6,
    0xe8ae8de8, 0xdd2559dd, 0x7457cb74, 0x1f5d7c1f, 0x4bea374b, 0xbd1ec2bd, 0x8b9c1a8b, 0x8a9b1e8a,
    0x704bdb70, 0x3ebaf83e, 0xb526e2b5, 0x66298366, 0x48e33b48, 0x03090c03, 0xf6f4f5f6, 0x0e2a380e,
    0x613c9f61, 0x358bd435, 0x57be4757, 0xb902d2b9, 0x86bf2e86, 0xc17129c1, 0x1d53741d, 0x9ef74e9e,
    0xe191a9e1, 0xf8decdf8, 0x98e55698, 0x11774411, 0x6904bf69, 0xd93949d9, 0x8e870e8e, 0x94c16694,
    0x9bec5a9b, 0x1e5a781e, 0x87b82a87, 0xe9a989e9, 0xce5c15ce, 0x55b04f55, 0x28d8a028, 0xdf2b51df,
    0x8c89068c, 0xa14ab2a1, 0x89921289, 0x0d23340d, 0xbf10cabf, 0xe684b5e6, 0x42d51342, 0x6803bb68,
    0x41dc1f41, 0x99e25299, 0x2dc3b42d, 0x0f2d3c0f, 0xb03df6b0, 0x54b74b54, 0xbb0cdabb, 0x16625816
  }
};

#if   VECT_SIZE == 1
#define FUGUE_BOX(T,n,i) ((T)[(n)][(i)])
#elif VECT_SIZE == 2
#define FUGUE_BOX(T,n,i) make_u32x ((T)[(n)][(i).s0], (T)[(n)][(i).s1])
#elif VECT_SIZE == 4
#define FUGUE_BOX(T,n,i) make_u32x ((T)[(n)][(i).s0], (T)[(n)][(i).s1], (T)[(n)][(i).s2], (T)[(n)][(i).s3])
#elif VECT_SIZE == 8
#define FUGUE_BOX(T,n,i) make_u32x ((T)[(n)][(i).s0], (T)[(n)][(i).s1], (T)[(n)][(i).s2], (T)[(n)][(i).s3], (T)[(n)][(i).s4], (T)[(n)][(i).s5], (T)[(n)][(i).s6], (T)[(n)][(i).s7])
#elif VECT_SIZE == 16
#define FUGUE_BOX(T,n,i) make_u32x ((T)[(n)][(i).s0], (T)[(n)][(i).s1], (T)[(n)][(i).s2], (T)[(n)][(i).s3], (T)[(n)][(i).s4], (T)[(n)][(i).s5], (T)[(n)][(i).s6], (T)[(n)][(i).s7], (T)[(n)][(i).s8], (T)[(n)][(i).s9], (T)[(n)][(i).sa], (T)[(n)][(i).sb], (T)[(n)][(i).sc], (T)[(n)][(i).sd], (T)[(n)][(i).se], (T)[(n)][(i).sf])
#endif

#define FUGUE_BOX_S(T,n,i) ((T)[(n)][(i)])

// SMIX on the 4 columns x0 to x3: the AES S-box on each of their 16 bytes and the super-mix, both
// done by the table lookups. c holds the lookups of each column, r those of each byte position.

#define FUGUE_SMIX(BOX,TY,TB,x0,x1,x2,x3)                                                       \
{                                                                                             \
  const TY a00 = BOX (TB, 0, ((x0) >> 24));                                                   \
  const TY a01 = BOX (TB, 1, ((x0) >> 16) & 0xff);                                            \
  const TY a02 = BOX (TB, 2, ((x0) >>  8) & 0xff);                                            \
  const TY a03 = BOX (TB, 3, ((x0) >>  0) & 0xff);                                            \
  const TY a10 = BOX (TB, 0, ((x1) >> 24));                                                   \
  const TY a11 = BOX (TB, 1, ((x1) >> 16) & 0xff);                                            \
  const TY a12 = BOX (TB, 2, ((x1) >>  8) & 0xff);                                            \
  const TY a13 = BOX (TB, 3, ((x1) >>  0) & 0xff);                                            \
  const TY a20 = BOX (TB, 0, ((x2) >> 24));                                                   \
  const TY a21 = BOX (TB, 1, ((x2) >> 16) & 0xff);                                            \
  const TY a22 = BOX (TB, 2, ((x2) >>  8) & 0xff);                                            \
  const TY a23 = BOX (TB, 3, ((x2) >>  0) & 0xff);                                            \
  const TY a30 = BOX (TB, 0, ((x3) >> 24));                                                   \
  const TY a31 = BOX (TB, 1, ((x3) >> 16) & 0xff);                                            \
  const TY a32 = BOX (TB, 2, ((x3) >>  8) & 0xff);                                            \
  const TY a33 = BOX (TB, 3, ((x3) >>  0) & 0xff);                                            \
                                                                                              \
  const TY c0 = a00 ^ a01 ^ a02 ^ a03;                                                        \
  const TY c1 = a10 ^ a11 ^ a12 ^ a13;                                                        \
  const TY c2 = a20 ^ a21 ^ a22 ^ a23;                                                        \
  const TY c3 = a30 ^ a31 ^ a32 ^ a33;                                                        \
                                                                                              \
  const TY r0 = a10 ^ a20 ^ a30;                                                              \
  const TY r1 = a01 ^ a21 ^ a31;                                                              \
  const TY r2 = a02 ^ a12 ^ a32;                                                              \
  const TY r3 = a03 ^ a13 ^ a23;                                                              \
                                                                                              \
  x0 = ((c0 ^ (r0 <<  0)) & 0xff000000) | ((c1 ^ (r1 <<  0)) & 0x00ff0000)                    \
     | ((c2 ^ (r2 <<  0)) & 0x0000ff00) | ((c3 ^ (r3 <<  0)) & 0x000000ff);                   \
  x1 = ((c1 ^ (r0 <<  8)) & 0xff000000) | ((c2 ^ (r1 <<  8)) & 0x00ff0000)                    \
     | ((c3 ^ (r2 <<  8)) & 0x0000ff00) | ((c0 ^ (r3 >> 24)) & 0x000000ff);                   \
  x2 = ((c2 ^ (r0 << 16)) & 0xff000000) | ((c3 ^ (r1 << 16)) & 0x00ff0000)                    \
     | ((c0 ^ (r2 >> 16)) & 0x0000ff00) | ((c1 ^ (r3 >> 16)) & 0x000000ff);                   \
  x3 = ((c3 ^ (r0 << 24)) & 0xff000000) | ((c0 ^ (r1 >>  8)) & 0x00ff0000)                    \
     | ((c1 ^ (r2 >>  8)) & 0x0000ff00) | ((c2 ^ (r3 >>  8)) & 0x000000ff);                   \
}

// Fugue rotates its state of N columns right by a few columns many times per word. Instead of
// moving the words, the code below finds column j of the rotated state at word FUGUE_IX (N, f, j),
// where f is the word that holds column 0. Every f is a constant, so the state stays in registers.
// A block of words ends with column 0 back at word 0.

#define FUGUE_IX(N,f,j) (((f) + (j)) % (N))

#define FUGUE_CMIX(x00,x01,x02,x04,x05,x06,y0,y1,y2) \
{                                                    \
  x00 ^= x04;                                        \
  x01 ^= x05;                                        \
  x02 ^= x06;                                        \
  y0  ^= x04;                                        \
  y1  ^= x05;                                        \
  y2  ^= x06;                                        \
}

// A rotation by 3 columns, CMIX and SMIX. f is where column 0 is after the rotation.

#define FUGUE_SUB(BOX,TY,TB,S,N,f)                                                              \
{                                                                                             \
  FUGUE_CMIX (S[FUGUE_IX (N, f, 0)], S[FUGUE_IX (N, f, 1)], S[FUGUE_IX (N, f, 2)],            \
              S[FUGUE_IX (N, f, 4)], S[FUGUE_IX (N, f, 5)], S[FUGUE_IX (N, f, 6)],            \
              S[FUGUE_IX (N, f, ((N) / 2) + 0)],                                              \
              S[FUGUE_IX (N, f, ((N) / 2) + 1)],                                              \
              S[FUGUE_IX (N, f, ((N) / 2) + 2)]);                                             \
                                                                                              \
  FUGUE_SMIX (BOX, TY, TB, S[FUGUE_IX (N, f, 0)], S[FUGUE_IX (N, f, 1)],                      \
                           S[FUGUE_IX (N, f, 2)], S[FUGUE_IX (N, f, 3)]);                     \
}

// One input word q, absorbed at f. TIX puts it into the state, then 2, 3 or 4 sub rounds follow,
// which move the state by 6, 9 or 12 columns.

#define FUGUE2_WORD(BOX,TY,TB,S,q,f)                                                            \
{                                                                                             \
  S[FUGUE_IX (30, f, 10)] ^= S[FUGUE_IX (30, f,  0)];                                         \
  S[FUGUE_IX (30, f,  0)]  = (q);                                                             \
  S[FUGUE_IX (30, f,  8)] ^= S[FUGUE_IX (30, f,  0)];                                         \
  S[FUGUE_IX (30, f,  1)] ^= S[FUGUE_IX (30, f, 24)];                                         \
                                                                                              \
  FUGUE_SUB (BOX, TY, TB, S, 30, (f) + 27);                                                   \
  FUGUE_SUB (BOX, TY, TB, S, 30, (f) + 24);                                                   \
}

#define FUGUE3_WORD(BOX,TY,TB,S,q,f)                                                            \
{                                                                                             \
  S[FUGUE_IX (36, f, 16)] ^= S[FUGUE_IX (36, f,  0)];                                         \
  S[FUGUE_IX (36, f,  0)]  = (q);                                                             \
  S[FUGUE_IX (36, f,  8)] ^= S[FUGUE_IX (36, f,  0)];                                         \
  S[FUGUE_IX (36, f,  1)] ^= S[FUGUE_IX (36, f, 27)];                                         \
  S[FUGUE_IX (36, f,  4)] ^= S[FUGUE_IX (36, f, 30)];                                         \
                                                                                              \
  FUGUE_SUB (BOX, TY, TB, S, 36, (f) + 33);                                                   \
  FUGUE_SUB (BOX, TY, TB, S, 36, (f) + 30);                                                   \
  FUGUE_SUB (BOX, TY, TB, S, 36, (f) + 27);                                                   \
}

#define FUGUE4_WORD(BOX,TY,TB,S,q,f)                                                            \
{                                                                                             \
  S[FUGUE_IX (36, f, 22)] ^= S[FUGUE_IX (36, f,  0)];                                         \
  S[FUGUE_IX (36, f,  0)]  = (q);                                                             \
  S[FUGUE_IX (36, f,  8)] ^= S[FUGUE_IX (36, f,  0)];                                         \
  S[FUGUE_IX (36, f,  1)] ^= S[FUGUE_IX (36, f, 24)];                                         \
  S[FUGUE_IX (36, f,  4)] ^= S[FUGUE_IX (36, f, 27)];                                         \
  S[FUGUE_IX (36, f,  7)] ^= S[FUGUE_IX (36, f, 30)];                                         \
                                                                                              \
  FUGUE_SUB (BOX, TY, TB, S, 36, (f) + 33);                                                   \
  FUGUE_SUB (BOX, TY, TB, S, 36, (f) + 30);                                                   \
  FUGUE_SUB (BOX, TY, TB, S, 36, (f) + 27);                                                   \
  FUGUE_SUB (BOX, TY, TB, S, 36, (f) + 24);                                                   \
}

#define FUGUE2_BLOCK(BOX,TY,TB,S,M,SWAP)                                                        \
{                                                                                             \
  FUGUE2_WORD (BOX, TY, TB, S, SWAP (M[0]),  0);                                              \
  FUGUE2_WORD (BOX, TY, TB, S, SWAP (M[1]), 24);                                              \
  FUGUE2_WORD (BOX, TY, TB, S, SWAP (M[2]), 18);                                              \
  FUGUE2_WORD (BOX, TY, TB, S, SWAP (M[3]), 12);                                              \
  FUGUE2_WORD (BOX, TY, TB, S, SWAP (M[4]),  6);                                              \
}

#define FUGUE3_BLOCK(BOX,TY,TB,S,M,SWAP)                                                        \
{                                                                                             \
  FUGUE3_WORD (BOX, TY, TB, S, SWAP (M[0]),  0);                                              \
  FUGUE3_WORD (BOX, TY, TB, S, SWAP (M[1]), 27);                                              \
  FUGUE3_WORD (BOX, TY, TB, S, SWAP (M[2]), 18);                                              \
  FUGUE3_WORD (BOX, TY, TB, S, SWAP (M[3]),  9);                                              \
}

#define FUGUE4_BLOCK(BOX,TY,TB,S,M,SWAP)                                                        \
{                                                                                             \
  FUGUE4_WORD (BOX, TY, TB, S, SWAP (M[0]),  0);                                              \
  FUGUE4_WORD (BOX, TY, TB, S, SWAP (M[1]), 24);                                              \
  FUGUE4_WORD (BOX, TY, TB, S, SWAP (M[2]), 12);                                              \
}

// Move the words of the state so that word f becomes word 0. Only the words left over after the
// last block need this, which are at most 4.

#define FUGUE_ROT(TY,S,N,f)                                                                     \
{                                                                                             \
  TY t[N];                                                                                    \
                                                                                              \
  for (u32 i = 0; i < (N); i++) t[i] = S[((f) + i) % (N)];                                    \
  for (u32 i = 0; i < (N); i++) S[i] = t[i];                                                  \
}

// The final rounds are 10, 18 or 32 sub rounds, then 13 rounds of 2, 3 or 4 SMIX. Before each of
// these SMIX, column 0 is xored into other columns and the state rotates. Each of the 13 rounds
// rotates the state left by one column in total.

#define FUGUE_SMIX_AT(BOX,TY,TB,S,N,f)                                                          \
{                                                                                             \
  FUGUE_SMIX (BOX, TY, TB, S[FUGUE_IX (N, f, 0)], S[FUGUE_IX (N, f, 1)],                      \
                           S[FUGUE_IX (N, f, 2)], S[FUGUE_IX (N, f, 3)]);                     \
}

#define FUGUE_X2(S,N,f,a,b)                                                                     \
{                                                                                             \
  S[FUGUE_IX (N, f, a)] ^= S[FUGUE_IX (N, f, 0)];                                             \
  S[FUGUE_IX (N, f, b)] ^= S[FUGUE_IX (N, f, 0)];                                             \
}

#define FUGUE_X3(S,N,f,a,b,c)                                                                   \
{                                                                                             \
  S[FUGUE_IX (N, f, a)] ^= S[FUGUE_IX (N, f, 0)];                                             \
  S[FUGUE_IX (N, f, b)] ^= S[FUGUE_IX (N, f, 0)];                                             \
  S[FUGUE_IX (N, f, c)] ^= S[FUGUE_IX (N, f, 0)];                                             \
}

#define FUGUE_X4(S,N,f,a,b,c,d)                                                                 \
{                                                                                             \
  S[FUGUE_IX (N, f, a)] ^= S[FUGUE_IX (N, f, 0)];                                             \
  S[FUGUE_IX (N, f, b)] ^= S[FUGUE_IX (N, f, 0)];                                             \
  S[FUGUE_IX (N, f, c)] ^= S[FUGUE_IX (N, f, 0)];                                             \
  S[FUGUE_IX (N, f, d)] ^= S[FUGUE_IX (N, f, 0)];                                             \
}

// One of the 13 rounds, which starts at f and ends at f + 1

#define FUGUE2_G(BOX,TY,TB,S,f)                                                                 \
{                                                                                             \
  FUGUE_X2 (S, 30, (f) +  0, 4, 15); FUGUE_SMIX_AT (BOX, TY, TB, S, 30, (f) + 15);            \
  FUGUE_X2 (S, 30, (f) + 15, 4, 16); FUGUE_SMIX_AT (BOX, TY, TB, S, 30, (f) +  1);            \
}

#define FUGUE3_G(BOX,TY,TB,S,f)                                                                 \
{                                                                                             \
  FUGUE_X3 (S, 36, (f) +  0, 4, 12, 24); FUGUE_SMIX_AT (BOX, TY, TB, S, 36, (f) + 24);        \
  FUGUE_X3 (S, 36, (f) + 24, 4, 13, 24); FUGUE_SMIX_AT (BOX, TY, TB, S, 36, (f) + 12);        \
  FUGUE_X3 (S, 36, (f) + 12, 4, 13, 25); FUGUE_SMIX_AT (BOX, TY, TB, S, 36, (f) +  1);        \
}

#define FUGUE4_G(BOX,TY,TB,S,f)                                                                 \
{                                                                                             \
  FUGUE_X4 (S, 36, (f) +  0, 4,  9, 18, 27); FUGUE_SMIX_AT (BOX, TY, TB, S, 36, (f) + 27);    \
  FUGUE_X4 (S, 36, (f) + 27, 4, 10, 18, 27); FUGUE_SMIX_AT (BOX, TY, TB, S, 36, (f) + 18);    \
  FUGUE_X4 (S, 36, (f) + 18, 4, 10, 19, 27); FUGUE_SMIX_AT (BOX, TY, TB, S, 36, (f) +  9);    \
  FUGUE_X4 (S, 36, (f) +  9, 4, 10, 19, 28); FUGUE_SMIX_AT (BOX, TY, TB, S, 36, (f) +  1);    \
}

// The sub rounds of one full rotation, after which column 0 is at word 0 again

#define FUGUE2_TURN(BOX,TY,TB,S)                                                                \
{                                                                                             \
  FUGUE_SUB (BOX, TY, TB, S, 30, 27); FUGUE_SUB (BOX, TY, TB, S, 30, 24);                     \
  FUGUE_SUB (BOX, TY, TB, S, 30, 21); FUGUE_SUB (BOX, TY, TB, S, 30, 18);                     \
  FUGUE_SUB (BOX, TY, TB, S, 30, 15); FUGUE_SUB (BOX, TY, TB, S, 30, 12);                     \
  FUGUE_SUB (BOX, TY, TB, S, 30,  9); FUGUE_SUB (BOX, TY, TB, S, 30,  6);                     \
  FUGUE_SUB (BOX, TY, TB, S, 30,  3); FUGUE_SUB (BOX, TY, TB, S, 30,  0);                     \
}

#define FUGUE36_TURN(BOX,TY,TB,S)                                                               \
{                                                                                             \
  FUGUE_SUB (BOX, TY, TB, S, 36, 33); FUGUE_SUB (BOX, TY, TB, S, 36, 30);                     \
  FUGUE_SUB (BOX, TY, TB, S, 36, 27); FUGUE_SUB (BOX, TY, TB, S, 36, 24);                     \
  FUGUE_SUB (BOX, TY, TB, S, 36, 21); FUGUE_SUB (BOX, TY, TB, S, 36, 18);                     \
  FUGUE_SUB (BOX, TY, TB, S, 36, 15); FUGUE_SUB (BOX, TY, TB, S, 36, 12);                     \
  FUGUE_SUB (BOX, TY, TB, S, 36,  9); FUGUE_SUB (BOX, TY, TB, S, 36,  6);                     \
  FUGUE_SUB (BOX, TY, TB, S, 36,  3); FUGUE_SUB (BOX, TY, TB, S, 36,  0);                     \
}

// The digest is 2, 3 or 4 groups of 4 columns, each column a big endian word

#define FUGUE2_CLOSE(BOX,TY,TB,S,H,SWAP)                                                        \
{                                                                                             \
  FUGUE2_TURN (BOX, TY, TB, S);                                                               \
                                                                                              \
  FUGUE2_G (BOX, TY, TB, S,  0); FUGUE2_G (BOX, TY, TB, S,  1);                               \
  FUGUE2_G (BOX, TY, TB, S,  2); FUGUE2_G (BOX, TY, TB, S,  3);                               \
  FUGUE2_G (BOX, TY, TB, S,  4); FUGUE2_G (BOX, TY, TB, S,  5);                               \
  FUGUE2_G (BOX, TY, TB, S,  6); FUGUE2_G (BOX, TY, TB, S,  7);                               \
  FUGUE2_G (BOX, TY, TB, S,  8); FUGUE2_G (BOX, TY, TB, S,  9);                               \
  FUGUE2_G (BOX, TY, TB, S, 10); FUGUE2_G (BOX, TY, TB, S, 11);                               \
  FUGUE2_G (BOX, TY, TB, S, 12);                                                              \
                                                                                              \
  FUGUE_X2 (S, 30, 13, 4, 15);                                                                \
                                                                                              \
  H[0] = SWAP (S[FUGUE_IX (30, 13,  1)]);                                                     \
  H[1] = SWAP (S[FUGUE_IX (30, 13,  2)]);                                                     \
  H[2] = SWAP (S[FUGUE_IX (30, 13,  3)]);                                                     \
  H[3] = SWAP (S[FUGUE_IX (30, 13,  4)]);                                                     \
  H[4] = SWAP (S[FUGUE_IX (30, 13, 15)]);                                                     \
  H[5] = SWAP (S[FUGUE_IX (30, 13, 16)]);                                                     \
  H[6] = SWAP (S[FUGUE_IX (30, 13, 17)]);                                                     \
  H[7] = SWAP (S[FUGUE_IX (30, 13, 18)]);                                                     \
}

#define FUGUE3_CLOSE(BOX,TY,TB,S,H,SWAP)                                                        \
{                                                                                             \
  FUGUE36_TURN (BOX, TY, TB, S);                                                              \
                                                                                              \
  FUGUE_SUB (BOX, TY, TB, S, 36, 33); FUGUE_SUB (BOX, TY, TB, S, 36, 30);                     \
  FUGUE_SUB (BOX, TY, TB, S, 36, 27); FUGUE_SUB (BOX, TY, TB, S, 36, 24);                     \
  FUGUE_SUB (BOX, TY, TB, S, 36, 21); FUGUE_SUB (BOX, TY, TB, S, 36, 18);                     \
                                                                                              \
  FUGUE3_G (BOX, TY, TB, S, 18); FUGUE3_G (BOX, TY, TB, S, 19);                               \
  FUGUE3_G (BOX, TY, TB, S, 20); FUGUE3_G (BOX, TY, TB, S, 21);                               \
  FUGUE3_G (BOX, TY, TB, S, 22); FUGUE3_G (BOX, TY, TB, S, 23);                               \
  FUGUE3_G (BOX, TY, TB, S, 24); FUGUE3_G (BOX, TY, TB, S, 25);                               \
  FUGUE3_G (BOX, TY, TB, S, 26); FUGUE3_G (BOX, TY, TB, S, 27);                               \
  FUGUE3_G (BOX, TY, TB, S, 28); FUGUE3_G (BOX, TY, TB, S, 29);                               \
  FUGUE3_G (BOX, TY, TB, S, 30);                                                              \
                                                                                              \
  FUGUE_X3 (S, 36, 31, 4, 12, 24);                                                            \
                                                                                              \
  H[ 0] = SWAP (S[FUGUE_IX (36, 31,  1)]);                                                    \
  H[ 1] = SWAP (S[FUGUE_IX (36, 31,  2)]);                                                    \
  H[ 2] = SWAP (S[FUGUE_IX (36, 31,  3)]);                                                    \
  H[ 3] = SWAP (S[FUGUE_IX (36, 31,  4)]);                                                    \
  H[ 4] = SWAP (S[FUGUE_IX (36, 31, 12)]);                                                    \
  H[ 5] = SWAP (S[FUGUE_IX (36, 31, 13)]);                                                    \
  H[ 6] = SWAP (S[FUGUE_IX (36, 31, 14)]);                                                    \
  H[ 7] = SWAP (S[FUGUE_IX (36, 31, 15)]);                                                    \
  H[ 8] = SWAP (S[FUGUE_IX (36, 31, 24)]);                                                    \
  H[ 9] = SWAP (S[FUGUE_IX (36, 31, 25)]);                                                    \
  H[10] = SWAP (S[FUGUE_IX (36, 31, 26)]);                                                    \
  H[11] = SWAP (S[FUGUE_IX (36, 31, 27)]);                                                    \
}

#define FUGUE4_CLOSE(BOX,TY,TB,S,H,SWAP)                                                        \
{                                                                                             \
  for (u32 i = 0; i < 2; i++) FUGUE36_TURN (BOX, TY, TB, S);                                  \
                                                                                              \
  FUGUE_SUB (BOX, TY, TB, S, 36, 33); FUGUE_SUB (BOX, TY, TB, S, 36, 30);                     \
  FUGUE_SUB (BOX, TY, TB, S, 36, 27); FUGUE_SUB (BOX, TY, TB, S, 36, 24);                     \
  FUGUE_SUB (BOX, TY, TB, S, 36, 21); FUGUE_SUB (BOX, TY, TB, S, 36, 18);                     \
  FUGUE_SUB (BOX, TY, TB, S, 36, 15); FUGUE_SUB (BOX, TY, TB, S, 36, 12);                     \
                                                                                              \
  FUGUE4_G (BOX, TY, TB, S, 12); FUGUE4_G (BOX, TY, TB, S, 13);                               \
  FUGUE4_G (BOX, TY, TB, S, 14); FUGUE4_G (BOX, TY, TB, S, 15);                               \
  FUGUE4_G (BOX, TY, TB, S, 16); FUGUE4_G (BOX, TY, TB, S, 17);                               \
  FUGUE4_G (BOX, TY, TB, S, 18); FUGUE4_G (BOX, TY, TB, S, 19);                               \
  FUGUE4_G (BOX, TY, TB, S, 20); FUGUE4_G (BOX, TY, TB, S, 21);                               \
  FUGUE4_G (BOX, TY, TB, S, 22); FUGUE4_G (BOX, TY, TB, S, 23);                               \
  FUGUE4_G (BOX, TY, TB, S, 24);                                                              \
                                                                                              \
  FUGUE_X4 (S, 36, 25, 4, 9, 18, 27);                                                         \
                                                                                              \
  H[ 0] = SWAP (S[FUGUE_IX (36, 25,  1)]);                                                    \
  H[ 1] = SWAP (S[FUGUE_IX (36, 25,  2)]);                                                    \
  H[ 2] = SWAP (S[FUGUE_IX (36, 25,  3)]);                                                    \
  H[ 3] = SWAP (S[FUGUE_IX (36, 25,  4)]);                                                    \
  H[ 4] = SWAP (S[FUGUE_IX (36, 25,  9)]);                                                    \
  H[ 5] = SWAP (S[FUGUE_IX (36, 25, 10)]);                                                    \
  H[ 6] = SWAP (S[FUGUE_IX (36, 25, 11)]);                                                    \
  H[ 7] = SWAP (S[FUGUE_IX (36, 25, 12)]);                                                    \
  H[ 8] = SWAP (S[FUGUE_IX (36, 25, 18)]);                                                    \
  H[ 9] = SWAP (S[FUGUE_IX (36, 25, 19)]);                                                    \
  H[10] = SWAP (S[FUGUE_IX (36, 25, 20)]);                                                    \
  H[11] = SWAP (S[FUGUE_IX (36, 25, 21)]);                                                    \
  H[12] = SWAP (S[FUGUE_IX (36, 25, 27)]);                                                    \
  H[13] = SWAP (S[FUGUE_IX (36, 25, 28)]);                                                    \
  H[14] = SWAP (S[FUGUE_IX (36, 25, 29)]);                                                    \
  H[15] = SWAP (S[FUGUE_IX (36, 25, 30)]);                                                    \
}

// The initial state is zero, with the IV of the digest size in its last columns

#define FUGUE_IV(S,dlen)                                                                        \
{                                                                                             \
  for (u32 i = 0; i < 36; i++) S[i] = 0;                                                      \
                                                                                              \
  if ((dlen) == 28)                                                                           \
  {                                                                                           \
    S[23] = 0xf4c9120d; S[24] = 0x6286f757; S[25] = 0xee39e01c; S[26] = 0xe074e3cb;           \
    S[27] = 0xa1127c62; S[28] = 0x9a43d215; S[29] = 0xbd8d679a;                               \
  }                                                                                           \
  else if ((dlen) == 32)                                                                      \
  {                                                                                           \
    S[22] = 0xe952bdde; S[23] = 0x6671135f; S[24] = 0xe0d4f668; S[25] = 0xd2b0b594;           \
    S[26] = 0xf96c621d; S[27] = 0xfbf929de; S[28] = 0x9149e899; S[29] = 0x34f8c248;           \
  }                                                                                           \
  else if ((dlen) == 48)                                                                      \
  {                                                                                           \
    S[24] = 0xaa61ec0d; S[25] = 0x31252e1f; S[26] = 0xa01db4c7; S[27] = 0x00600985;           \
    S[28] = 0x215ef44a; S[29] = 0x741b5e9c; S[30] = 0xfa693e9a; S[31] = 0x473eb040;           \
    S[32] = 0xe502ae8a; S[33] = 0xa99c25e0; S[34] = 0xbc95517c; S[35] = 0x5c1095a1;           \
  }                                                                                           \
  else                                                                                        \
  {                                                                                           \
    S[20] = 0x8807a57e; S[21] = 0xe616af75; S[22] = 0xc5d3e4db; S[23] = 0xac9ab027;           \
    S[24] = 0xd915f117; S[25] = 0xb6eecc54; S[26] = 0x06e8020b; S[27] = 0x4a92efd1;           \
    S[28] = 0xaac6e2c9; S[29] = 0xddb21398; S[30] = 0xcae65838; S[31] = 0x437f203f;           \
    S[32] = 0x25ea78e7; S[33] = 0x951fddd6; S[34] = 0xda6ed11d; S[35] = 0xe13e3567;           \
  }                                                                                           \
}

DECLSPEC void fugue_init (PRIVATE_AS fugue_ctx_t *ctx, const int dlen, SHM_TYPE u32a (*s_mixtab)[256])
{
  FUGUE_IV (ctx->S, dlen);

  for (u32 i = 0; i <  5; i++) ctx->m[i] = 0;
  for (u32 i = 0; i < 16; i++) ctx->h[i] = 0;

  ctx->pos = 0;
  ctx->bs  = (dlen == 64) ? 12 : (dlen == 48) ? 16 : 20;
  ctx->len = 0;

  ctx->dlen = dlen;

  ctx->s_mixtab = s_mixtab;
}

DECLSPEC void fugue_block (PRIVATE_AS fugue_ctx_t *ctx)
{
  SHM_TYPE u32a (*s_mixtab)[256] = ctx->s_mixtab;

  if (ctx->dlen == 64)
  {
    FUGUE4_BLOCK (FUGUE_BOX_S, u32, s_mixtab, ctx->S, ctx->m, hc_swap32_S);
  }
  else if (ctx->dlen == 48)
  {
    FUGUE3_BLOCK (FUGUE_BOX_S, u32, s_mixtab, ctx->S, ctx->m, hc_swap32_S);
  }
  else
  {
    FUGUE2_BLOCK (FUGUE_BOX_S, u32, s_mixtab, ctx->S, ctx->m, hc_swap32_S);
  }

  for (u32 i = 0; i < 5; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

// One big endian word outside a block. The words of the state then move so that column 0 is at
// word 0 again.

DECLSPEC void fugue_step (PRIVATE_AS fugue_ctx_t *ctx, const u32 q)
{
  SHM_TYPE u32a (*s_mixtab)[256] = ctx->s_mixtab;

  if (ctx->dlen == 64)
  {
    FUGUE4_WORD (FUGUE_BOX_S, u32, s_mixtab, ctx->S, q, 0);

    FUGUE_ROT (u32, ctx->S, 36, 24);
  }
  else if (ctx->dlen == 48)
  {
    FUGUE3_WORD (FUGUE_BOX_S, u32, s_mixtab, ctx->S, q, 0);

    FUGUE_ROT (u32, ctx->S, 36, 27);
  }
  else
  {
    FUGUE2_WORD (FUGUE_BOX_S, u32, s_mixtab, ctx->S, q, 0);

    FUGUE_ROT (u32, ctx->S, 30, 24);
  }
}

DECLSPEC void fugue_close (PRIVATE_AS fugue_ctx_t *ctx)
{
  SHM_TYPE u32a (*s_mixtab)[256] = ctx->s_mixtab;

  if (ctx->dlen == 64)
  {
    FUGUE4_CLOSE (FUGUE_BOX_S, u32, s_mixtab, ctx->S, ctx->h, hc_swap32_S);
  }
  else if (ctx->dlen == 48)
  {
    FUGUE3_CLOSE (FUGUE_BOX_S, u32, s_mixtab, ctx->S, ctx->h, hc_swap32_S);
  }
  else
  {
    FUGUE2_CLOSE (FUGUE_BOX_S, u32, s_mixtab, ctx->S, ctx->h, hc_swap32_S);
  }
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, absorb it and use any remaining
// bytes to start the next block.

DECLSPEC void fugue_absorb (PRIVATE_AS fugue_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = ctx->bs - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32 x = v & mask;

  const u32 idx = pos / 4;
  const int off = pos & 3;

  // The block is written at constant indices only, which keeps the context in registers

  const u32 lo = x << (off * 8);

  u32 hi = 0;

  if ((off + fit) > 4) hi = x >> ((4 - off) * 8);

  for (u32 k = 0; k < 5; k++)
  {
    if (k == (idx + 0)) ctx->m[k] |= lo;
    if (k == (idx + 1)) ctx->m[k] |= hi;
  }

  if (fit == room)
  {
    fugue_block (ctx);

    if (n > fit)
    {
      ctx->m[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void fugue_update (PRIVATE_AS fugue_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    fugue_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void fugue_absorb_utf16le (PRIVATE_AS fugue_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  fugue_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) fugue_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void fugue_update_utf16le (PRIVATE_AS fugue_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (hc_enc_scan (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      fugue_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    fugue_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void fugue_update_global (PRIVATE_AS fugue_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    fugue_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void fugue_update_global_utf16le (PRIVATE_AS fugue_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (hc_enc_scan_global (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next_global (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      fugue_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    fugue_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Zero bytes complete the last word, and the block already holds them. The message length in bits
// follows as a 64 bit big endian number. The words left over after the last block go through
// fugue_step, so that the final rounds always start with column 0 at word 0. A context with
// invalid UTF-8 input produces a digest with every bit flipped, so that no candidate matches it by
// chance.

DECLSPEC void fugue_final (PRIVATE_AS fugue_ctx_t *ctx)
{
  const u32 len = (u32) ctx->len;

  ctx->pos = (ctx->pos + 3) & ~3;

  if (ctx->pos == ctx->bs) fugue_block (ctx);

  fugue_absorb (ctx, hc_swap32_S (len >> 29), 4);
  fugue_absorb (ctx, hc_swap32_S (len <<  3), 4);

  const int words = ctx->pos / 4;

  for (int i = 0; i < words; i++)
  {
    fugue_step (ctx, hc_swap32_S (ctx->m[0]));

    for (u32 k = 0; k < 4; k++) ctx->m[k] = ctx->m[k + 1];
  }

  fugue_close (ctx);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 16; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void fugue_init_vector (PRIVATE_AS fugue_ctx_vector_t *ctx, const int dlen, SHM_TYPE u32a (*s_mixtab)[256])
{
  FUGUE_IV (ctx->S, dlen);

  for (u32 i = 0; i <  5; i++) ctx->m[i] = 0;
  for (u32 i = 0; i < 16; i++) ctx->h[i] = 0;

  ctx->pos = 0;
  ctx->bs  = (dlen == 64) ? 12 : (dlen == 48) ? 16 : 20;
  ctx->len = 0;

  ctx->dlen = dlen;

  ctx->s_mixtab = s_mixtab;
}

DECLSPEC void fugue_block_vector (PRIVATE_AS fugue_ctx_vector_t *ctx)
{
  SHM_TYPE u32a (*s_mixtab)[256] = ctx->s_mixtab;

  if (ctx->dlen == 64)
  {
    FUGUE4_BLOCK (FUGUE_BOX, u32x, s_mixtab, ctx->S, ctx->m, hc_swap32);
  }
  else if (ctx->dlen == 48)
  {
    FUGUE3_BLOCK (FUGUE_BOX, u32x, s_mixtab, ctx->S, ctx->m, hc_swap32);
  }
  else
  {
    FUGUE2_BLOCK (FUGUE_BOX, u32x, s_mixtab, ctx->S, ctx->m, hc_swap32);
  }

  for (u32 i = 0; i < 5; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void fugue_step_vector (PRIVATE_AS fugue_ctx_vector_t *ctx, const u32x q)
{
  SHM_TYPE u32a (*s_mixtab)[256] = ctx->s_mixtab;

  if (ctx->dlen == 64)
  {
    FUGUE4_WORD (FUGUE_BOX, u32x, s_mixtab, ctx->S, q, 0);

    FUGUE_ROT (u32x, ctx->S, 36, 24);
  }
  else if (ctx->dlen == 48)
  {
    FUGUE3_WORD (FUGUE_BOX, u32x, s_mixtab, ctx->S, q, 0);

    FUGUE_ROT (u32x, ctx->S, 36, 27);
  }
  else
  {
    FUGUE2_WORD (FUGUE_BOX, u32x, s_mixtab, ctx->S, q, 0);

    FUGUE_ROT (u32x, ctx->S, 30, 24);
  }
}

DECLSPEC void fugue_close_vector (PRIVATE_AS fugue_ctx_vector_t *ctx)
{
  SHM_TYPE u32a (*s_mixtab)[256] = ctx->s_mixtab;

  if (ctx->dlen == 64)
  {
    FUGUE4_CLOSE (FUGUE_BOX, u32x, s_mixtab, ctx->S, ctx->h, hc_swap32);
  }
  else if (ctx->dlen == 48)
  {
    FUGUE3_CLOSE (FUGUE_BOX, u32x, s_mixtab, ctx->S, ctx->h, hc_swap32);
  }
  else
  {
    FUGUE2_CLOSE (FUGUE_BOX, u32x, s_mixtab, ctx->S, ctx->h, hc_swap32);
  }
}

DECLSPEC void fugue_absorb_vector (PRIVATE_AS fugue_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = ctx->bs - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const u32 idx = pos / 4;
  const int off = pos & 3;

  const u32x lo = x << (off * 8);

  u32x hi = 0;

  if ((off + fit) > 4) hi = x >> ((4 - off) * 8);

  for (u32 k = 0; k < 5; k++)
  {
    if (k == (idx + 0)) ctx->m[k] |= lo;
    if (k == (idx + 1)) ctx->m[k] |= hi;
  }

  if (fit == room)
  {
    fugue_block_vector (ctx);

    if (n > fit)
    {
      ctx->m[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void fugue_update_vector (PRIVATE_AS fugue_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    fugue_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void fugue_update_vector_utf16le (PRIVATE_AS fugue_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    fugue_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) fugue_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void fugue_final_vector (PRIVATE_AS fugue_ctx_vector_t *ctx)
{
  const u32 len = (u32) ctx->len;

  ctx->pos = (ctx->pos + 3) & ~3;

  if (ctx->pos == ctx->bs) fugue_block_vector (ctx);

  fugue_absorb_vector (ctx, make_u32x (hc_swap32_S (len >> 29)), 4);
  fugue_absorb_vector (ctx, make_u32x (hc_swap32_S (len <<  3)), 4);

  const int words = ctx->pos / 4;

  for (int i = 0; i < words; i++)
  {
    fugue_step_vector (ctx, hc_swap32 (ctx->m[0]));

    for (u32 k = 0; k < 4; k++) ctx->m[k] = ctx->m[k + 1];
  }

  fugue_close_vector (ctx);
}
