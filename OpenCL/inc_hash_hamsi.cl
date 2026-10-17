/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_hamsi.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off. Hamsi reads its blocks as bytes, so the words go in unswapped. Its
// chaining value and its length field are big endian, which the final functions take care of.

CONSTANT_VK u32a hamsi256_iv[2][8] =
{
  { 0xc3967a67, 0xc3bc6c20, 0x4bc3bcc3, 0xa7c3bc6b, 0x2c204b61, 0x74686f6c, 0x69656b65, 0x20556e69 },
  { 0x76657273, 0x69746569, 0x74204c65, 0x7576656e, 0x2c204465, 0x70617274, 0x656d656e, 0x7420456c },
};

CONSTANT_VK u32a hamsi512_iv[2][16] =
{
  { 0x656b7472, 0x6f746563, 0x686e6965, 0x6b2c2043, 0x6f6d7075, 0x74657220, 0x53656375, 0x72697479,
    0x20616e64, 0x20496e64, 0x75737472, 0x69616c20, 0x43727970, 0x746f6772, 0x61706879, 0x2c204b61 },
  { 0x73746565, 0x6c706172, 0x6b204172, 0x656e6265, 0x72672031, 0x302c2062, 0x75732032, 0x3434362c,
    0x20422d33, 0x30303120, 0x4c657576, 0x656e2d48, 0x65766572, 0x6c65652c, 0x2042656c, 0x6769756d },
};

// The constants of the permutation P and of the final permutation Pf

CONSTANT_VK u32a hamsi_alpha[2][32] =
{
  { 0xff00f0f0, 0xccccaaaa, 0xf0f0cccc, 0xff00aaaa, 0xccccaaaa, 0xf0f0ff00, 0xaaaacccc, 0xf0f0ff00,
    0xf0f0cccc, 0xaaaaff00, 0xccccff00, 0xaaaaf0f0, 0xaaaaf0f0, 0xff00cccc, 0xccccf0f0, 0xff00aaaa,
    0xccccaaaa, 0xff00f0f0, 0xff00aaaa, 0xf0f0cccc, 0xf0f0ff00, 0xccccaaaa, 0xf0f0ff00, 0xaaaacccc,
    0xaaaaff00, 0xf0f0cccc, 0xaaaaf0f0, 0xccccff00, 0xff00cccc, 0xaaaaf0f0, 0xff00aaaa, 0xccccf0f0 },
  { 0xcaf9639c, 0x0ff0f9c0, 0x639c0ff0, 0xcaf9f9c0, 0x0ff0f9c0, 0x639ccaf9, 0xf9c00ff0, 0x639ccaf9,
    0x639c0ff0, 0xf9c0caf9, 0x0ff0caf9, 0xf9c0639c, 0xf9c0639c, 0xcaf90ff0, 0x0ff0639c, 0xcaf9f9c0,
    0x0ff0f9c0, 0xcaf9639c, 0xcaf9f9c0, 0x639c0ff0, 0x639ccaf9, 0x0ff0f9c0, 0x639ccaf9, 0xf9c00ff0,
    0xf9c0caf9, 0x639c0ff0, 0xf9c0639c, 0x0ff0caf9, 0xcaf90ff0, 0xf9c0639c, 0xcaf9f9c0, 0x0ff0639c },
};

// The message expansion is linear, so every set bit of a block adds one row of the generator
// matrix to the expanded words. Row i belongs to bit i of the block, counted from the low bit of
// its first byte, which in little endian words is bit i % 32 of word i / 32. These are sphlib's
// tables for one bit per lookup. Which row is read never depends on the data, so every work item
// reads the same row at the same time and the tables need no copy in shared memory.

CONSTANT_VK u32a hamsi256_expand[32][8] =
{
  { 0x74951000, 0x5a2b467e, 0x88fd1d2b, 0x1ee68292, 0xcba90000, 0x90273769, 0xbbdcf407, 0xd0f4af61 },
  { 0xcba90000, 0x90273769, 0xbbdcf407, 0xd0f4af61, 0xbf3c1000, 0xca0c7117, 0x3321e92c, 0xce122df3 },
  { 0xe92a2000, 0xb4578cfc, 0x11fa3a57, 0x3dc90524, 0x97530000, 0x204f6ed3, 0x77b9e80f, 0xa1ec5ec1 },
  { 0x97530000, 0x204f6ed3, 0x77b9e80f, 0xa1ec5ec1, 0x7e792000, 0x9418e22f, 0x6643d258, 0x9c255be5 },
  { 0x121b4000, 0x5b17d9e8, 0x8dfacfab, 0xce36cc72, 0xe6570000, 0x4bb33a25, 0x848598ba, 0x1041003e },
  { 0xe6570000, 0x4bb33a25, 0x848598ba, 0x1041003e, 0xf44c4000, 0x10a4e3cd, 0x097f5711, 0xde77cc4c },
  { 0xe4788000, 0x859673c1, 0xb5fb2452, 0x29cc5edf, 0x045f0000, 0x9c4a93c9, 0x62fc79d0, 0x731ebdc2 },
  { 0x045f0000, 0x9c4a93c9, 0x62fc79d0, 0x731ebdc2, 0xe0278000, 0x19dce008, 0xd7075d82, 0x5ad2e31d },
  { 0xb7a40100, 0x8a1f31d8, 0x8589d8ab, 0xe6c46464, 0x734c0000, 0x956fa7d6, 0xa29d1297, 0x6ee56854 },
  { 0x734c0000, 0x956fa7d6, 0xa29d1297, 0x6ee56854, 0xc4e80100, 0x1f70960e, 0x2714ca3c, 0x88210c30 },
  { 0xa7b80200, 0x1f128433, 0x60e5f9f2, 0x9e147576, 0xee260000, 0x124b683e, 0x80c2d68f, 0x3bf3ab2c },
  { 0xee260000, 0x124b683e, 0x80c2d68f, 0x3bf3ab2c, 0x499e0200, 0x0d59ec0d, 0xe0272f7d, 0xa5e7de5a },
  { 0x8f3e0400, 0x0d9dc877, 0x6fc548e1, 0x898d2cd6, 0x14bd0000, 0x2fba37ff, 0x6a72e5bb, 0x247febe6 },
  { 0x14bd0000, 0x2fba37ff, 0x6a72e5bb, 0x247febe6, 0x9b830400, 0x2227ff88, 0x05b7ad5a, 0xadf2c730 },
  { 0xde320800, 0x288350fe, 0x71852ac7, 0xa6bf9f96, 0xe18b0000, 0x5459887d, 0xbf1283d3, 0x1b666a73 },
  { 0xe18b0000, 0x5459887d, 0xbf1283d3, 0x1b666a73, 0x3fb90800, 0x7cdad883, 0xce97a914, 0xbdd9f5e5 },
  { 0x515c0010, 0x40f372fb, 0xfce72602, 0x71575061, 0x2e390000, 0x64dd6689, 0x3cd406fc, 0xb1f490bc },
  { 0x2e390000, 0x64dd6689, 0x3cd406fc, 0xb1f490bc, 0x7f650010, 0x242e1472, 0xc03320fe, 0xc0a3c0dd },
  { 0xa2b80020, 0x81e7e5f6, 0xf9ce4c04, 0xe2afa0c0, 0x5c720000, 0xc9bacd12, 0x79a90df9, 0x63e92178 },
  { 0x5c720000, 0xc9bacd12, 0x79a90df9, 0x63e92178, 0xfeca0020, 0x485d28e4, 0x806741fd, 0x814681b8 },
  { 0x4dce0040, 0x3b5bec7e, 0x36656ba8, 0x23633a05, 0x78ab0000, 0xa0cd5a34, 0x5d5ca0f7, 0x727784cb },
  { 0x78ab0000, 0xa0cd5a34, 0x5d5ca0f7, 0x727784cb, 0x35650040, 0x9b96b64a, 0x6b39cb5f, 0x5114bece },
  { 0x5bd20080, 0x450f18ec, 0xc2c46c55, 0xf362b233, 0x39a60000, 0x4ab753eb, 0xd14e094b, 0xb772b42b },
  { 0x39a60000, 0x4ab753eb, 0xd14e094b, 0xb772b42b, 0x62740080, 0x0fb84b07, 0x138a651e, 0x44100618 },
  { 0xc04e0001, 0x33b9c010, 0xae0ebb05, 0xb5a4c63b, 0xc8f10000, 0x0b2de782, 0x6bf648a4, 0x539cbdbf },
  { 0xc8f10000, 0x0b2de782, 0x6bf648a4, 0x539cbdbf, 0x08bf0001, 0x38942792, 0xc5f8f3a1, 0xe6387b84 },
  { 0x88230002, 0x5fe7a7b3, 0x99e585aa, 0x8d75f7f1, 0x51ac0000, 0x25e30f14, 0x79e22a4c, 0x1298bd46 },
  { 0x51ac0000, 0x25e30f14, 0x79e22a4c, 0x1298bd46, 0xd98f0002, 0x7a04a8a7, 0xe007afe6, 0x9fed4ab7 },
  { 0xd0080004, 0x8c768f77, 0x9dc5b050, 0xaf4a29da, 0x6ba90000, 0x40ebf9aa, 0x98321c3d, 0x76acc733 },
  { 0x6ba90000, 0x40ebf9aa, 0x98321c3d, 0x76acc733, 0xbba10004, 0xcc9d76dd, 0x05f7ac6d, 0xd9e6eee9 },
  { 0xa8ae0008, 0x2079397d, 0xfe739301, 0xb8a92831, 0x171c0000, 0xb26e3344, 0x9e6a837e, 0x58f8485f },
  { 0x171c0000, 0xb26e3344, 0x9e6a837e, 0x58f8485f, 0xbfb20008, 0x92170a39, 0x6019107f, 0xe051606e },
};

CONSTANT_VK u32a hamsi512_expand[64][16] =
{
  { 0xef0b0270, 0x3afd0000, 0x5dae0000, 0x69490000, 0x9b0f3c06, 0x4405b5f9, 0x66140a51, 0x924f5d0a,
    0xc96b0030, 0xe7250000, 0x2f840000, 0x264f0000, 0x08695bf9, 0x6dfcf137, 0x509f6984, 0x9e69af68 },
  { 0xc96b0030, 0xe7250000, 0x2f840000, 0x264f0000, 0x08695bf9, 0x6dfcf137, 0x509f6984, 0x9e69af68,
    0x26600240, 0xddd80000, 0x722a0000, 0x4f060000, 0x936667ff, 0x29f944ce, 0x368b63d5, 0x0c26f262 },
  { 0x145a3c00, 0xb9e90000, 0x61270000, 0xf1610000, 0xce613d6c, 0xb0493d78, 0x47a96720, 0xe18e24c5,
    0x23671400, 0xc8b90000, 0xf4c70000, 0xfb750000, 0x73cd2465, 0xf8a6a549, 0x02c40a3f, 0xdc24e61f },
  { 0x23671400, 0xc8b90000, 0xf4c70000, 0xfb750000, 0x73cd2465, 0xf8a6a549, 0x02c40a3f, 0xdc24e61f,
    0x373d2800, 0x71500000, 0x95e00000, 0x0a140000, 0xbdac1909, 0x48ef9831, 0x456d6d1f, 0x3daac2da },
  { 0x54285c00, 0xeaed0000, 0xc5d60000, 0xa1c50000, 0xb3a26770, 0x94a5c4e1, 0x6bb0419d, 0x551b3782,
    0x9cbb1800, 0xb0d30000, 0x92510000, 0xed930000, 0x593a4345, 0xe114d5f4, 0x430633da, 0x78cace29 },
  { 0x9cbb1800, 0xb0d30000, 0x92510000, 0xed930000, 0x593a4345, 0xe114d5f4, 0x430633da, 0x78cace29,
    0xc8934400, 0x5a3e0000, 0x57870000, 0x4c560000, 0xea982435, 0x75b11115, 0x28b67247, 0x2dd1f9ab },
  { 0x29449c00, 0x64e70000, 0xf24b0000, 0xc2f30000, 0x0ede4e8f, 0x56c23745, 0xf3e04259, 0x8d0d9ec4,
    0x466d0c00, 0x08620000, 0xdd5d0000, 0xbadd0000, 0x6a927942, 0x441f2b93, 0x218ace6f, 0xbf2c0be2 },
  { 0x466d0c00, 0x08620000, 0xdd5d0000, 0xbadd0000, 0x6a927942, 0x441f2b93, 0x218ace6f, 0xbf2c0be2,
    0x6f299000, 0x6c850000, 0x2f160000, 0x782e0000, 0x644c37cd, 0x12dd1cd6, 0xd26a8c36, 0x32219526 },
  { 0xf6800005, 0x3443c000, 0x24070000, 0x8f3d0000, 0x21373bfb, 0x0ab8d5ae, 0xcdc58b19, 0xd795ba31,
    0xa67f0001, 0x71378000, 0x19fc0000, 0x96db0000, 0x3a8b6dfd, 0xebcaaef3, 0x2c6d478f, 0xac8e6c88 },
  { 0xa67f0001, 0x71378000, 0x19fc0000, 0x96db0000, 0x3a8b6dfd, 0xebcaaef3, 0x2c6d478f, 0xac8e6c88,
    0x50ff0004, 0x45744000, 0x3dfb0000, 0x19e60000, 0x1bbc5606, 0xe1727b5d, 0xe1a8cc96, 0x7b1bd6b9 },
  { 0xf7750009, 0xcf3cc000, 0xc3d60000, 0x04920000, 0x029519a9, 0xf8e836ba, 0x7a87f14e, 0x9e16981a,
    0xd46a0000, 0x8dc8c000, 0xa5af0000, 0x4a290000, 0xfc4e427a, 0xc9b4866c, 0x98369604, 0xf746c320 },
  { 0xd46a0000, 0x8dc8c000, 0xa5af0000, 0x4a290000, 0xfc4e427a, 0xc9b4866c, 0x98369604, 0xf746c320,
    0x231f0009, 0x42f40000, 0x66790000, 0x4ebb0000, 0xfedb5bd3, 0x315cb0d6, 0xe2b1674a, 0x69505b3a },
  { 0x774400f0, 0xf15a0000, 0xf5b20000, 0x34140000, 0x89377e8c, 0x5a8bec25, 0x0bc3cd1e, 0xcf3775cb,
    0xf46c0050, 0x96180000, 0x14a50000, 0x031f0000, 0x42947eb8, 0x66bf7e19, 0x9ca470d2, 0x8a341574 },
  { 0xf46c0050, 0x96180000, 0x14a50000, 0x031f0000, 0x42947eb8, 0x66bf7e19, 0x9ca470d2, 0x8a341574,
    0x832800a0, 0x67420000, 0xe1170000, 0x370b0000, 0xcba30034, 0x3c34923c, 0x9767bdcc, 0x450360bf },
  { 0xe8870170, 0x9d720000, 0x12db0000, 0xd4220000, 0xf2886b27, 0xa921e543, 0x4ef8b518, 0x618813b1,
    0xb4370060, 0x0c4c0000, 0x56c20000, 0x5cae0000, 0x94541f3f, 0x3b3ef825, 0x1b365f3d, 0xf3d45758 },
  { 0xb4370060, 0x0c4c0000, 0x56c20000, 0x5cae0000, 0x94541f3f, 0x3b3ef825, 0x1b365f3d, 0xf3d45758,
    0x5cb00110, 0x913e0000, 0x44190000, 0x888c0000, 0x66dc7418, 0x921f1d66, 0x55ceea25, 0x925c44e9 },
  { 0x0c720000, 0x49e50f00, 0x42790000, 0x5cea0000, 0x33aa301a, 0x15822514, 0x95a34b7b, 0xb44b0090,
    0xfe220000, 0xa7580500, 0x25d10000, 0xf7600000, 0x893178da, 0x1fd4f860, 0x4ed0a315, 0xa123ff9f },
  { 0xfe220000, 0xa7580500, 0x25d10000, 0xf7600000, 0x893178da, 0x1fd4f860, 0x4ed0a315, 0xa123ff9f,
    0xf2500000, 0xeebd0a00, 0x67a80000, 0xab8a0000, 0xba9b48c0, 0x0a56dd74, 0xdb73e86e, 0x1568ff0f },
  { 0x45180000, 0xa5b51700, 0xf96a0000, 0x3b480000, 0x1ecc142c, 0x231395d6, 0x16bca6b0, 0xdf33f4df,
    0xb83d0000, 0x16710600, 0x379a0000, 0xf5b10000, 0x228161ac, 0xae48f145, 0x66241616, 0xc5c1eb3e },
  { 0xb83d0000, 0x16710600, 0x379a0000, 0xf5b10000, 0x228161ac, 0xae48f145, 0x66241616, 0xc5c1eb3e,
    0xfd250000, 0xb3c41100, 0xcef00000, 0xcef90000, 0x3c4d7580, 0x8d5b6493, 0x7098b0a6, 0x1af21fe1 },
  { 0x75a40000, 0xc28b2700, 0x94a40000, 0x90f50000, 0xfb7857e0, 0x49ce0bae, 0x1767c483, 0xaedf667e,
    0xd1660000, 0x1bbc0300, 0x9eec0000, 0xf6940000, 0x03024527, 0xcf70fcf2, 0xb4431b17, 0x857f3c2b },
  { 0xd1660000, 0x1bbc0300, 0x9eec0000, 0xf6940000, 0x03024527, 0xcf70fcf2, 0xb4431b17, 0x857f3c2b,
    0xa4c20000, 0xd9372400, 0x0a480000, 0x66610000, 0xf87a12c7, 0x86bef75c, 0xa324df94, 0x2ba05a55 },
  { 0x75c90003, 0x0e10c000, 0xd1200000, 0xbaea0000, 0x8bc42f3e, 0x8758b757, 0xbb28761d, 0x00b72e2b,
    0xeecf0001, 0x6f564000, 0xf33e0000, 0xa79e0000, 0xbdb57219, 0xb711ebc5, 0x4a3b40ba, 0xfeabf254 },
  { 0xeecf0001, 0x6f564000, 0xf33e0000, 0xa79e0000, 0xbdb57219, 0xb711ebc5, 0x4a3b40ba, 0xfeabf254,
    0x9b060002, 0x61468000, 0x221e0000, 0x1d740000, 0x36715d27, 0x30495c92, 0xf11336a7, 0xfe1cdc7f },
  { 0x86790000, 0x3f390002, 0xe19ae000, 0x98560000, 0x9565670e, 0x4e88c8ea, 0xd3dd4944, 0x161ddab9,
    0x30b70000, 0xe5d00000, 0xf4f46000, 0x42c40000, 0x63b83d6a, 0x78ba9460, 0x21afa1ea, 0xb0a51834 },
  { 0x30b70000, 0xe5d00000, 0xf4f46000, 0x42c40000, 0x63b83d6a, 0x78ba9460, 0x21afa1ea, 0xb0a51834,
    0xb6ce0000, 0xdae90002, 0x156e8000, 0xda920000, 0xf6dd5a64, 0x36325c8a, 0xf272e8ae, 0xa6b8c28d },
  { 0x14190000, 0x23ca003c, 0x50df0000, 0x44b60000, 0x1b6c67b0, 0x3cf3ac75, 0x61e610b0, 0xdbcadb80,
    0xe3430000, 0x3a4e0014, 0xf2c60000, 0xaa4e0000, 0xdb1e42a6, 0x256bbe15, 0x123db156, 0x3a4e99d7 },
  { 0xe3430000, 0x3a4e0014, 0xf2c60000, 0xaa4e0000, 0xdb1e42a6, 0x256bbe15, 0x123db156, 0x3a4e99d7,
    0xf75a0000, 0x19840028, 0xa2190000, 0xeef80000, 0xc0722516, 0x19981260, 0x73dba1e6, 0xe1844257 },
  { 0x54500000, 0x0671005c, 0x25ae0000, 0x6a1e0000, 0x2ea54edf, 0x664e8512, 0xbfba18c3, 0x7e715d17,
    0xbc8d0000, 0xfc3b0018, 0x19830000, 0xd10b0000, 0xae1878c4, 0x42a69856, 0x0012da37, 0x2c3b504e },
  { 0xbc8d0000, 0xfc3b0018, 0x19830000, 0xd10b0000, 0xae1878c4, 0x42a69856, 0x0012da37, 0x2c3b504e,
    0xe8dd0000, 0xfa4a0044, 0x3c2d0000, 0xbb150000, 0x80bd361b, 0x24e81d44, 0xbfa8c2f4, 0x524a0d59 },
  { 0x69510000, 0xd4e1009c, 0xc3230000, 0xac2f0000, 0xe4950bae, 0xcea415dc, 0x87ec287c, 0xbce1a3ce,
    0xc6730000, 0xaf8d000c, 0xa4c10000, 0x218d0000, 0x23111587, 0x7913512f, 0x1d28ac88, 0x378dd173 },
  { 0xc6730000, 0xaf8d000c, 0xa4c10000, 0x218d0000, 0x23111587, 0x7913512f, 0x1d28ac88, 0x378dd173,
    0xaf220000, 0x7b6c0090, 0x67e20000, 0x8da20000, 0xc7841e29, 0xb7b744f3, 0x9ac484f4, 0x8b6c72bd },
  { 0xcc140000, 0xa5630000, 0x5ab90780, 0x3b500000, 0x4bd013ff, 0x879b3418, 0x694348c1, 0xca5a87fe,
    0x819e0000, 0xec570000, 0x66320280, 0x95f30000, 0x5da92802, 0x48f43cbc, 0xe65aa22d, 0x8e67b7fa },
  { 0x819e0000, 0xec570000, 0x66320280, 0x95f30000, 0x5da92802, 0x48f43cbc, 0xe65aa22d, 0x8e67b7fa,
    0x4d8a0000, 0x49340000, 0x3c8b0500, 0xaea30000, 0x16793bfd, 0xcf6f08a4, 0x8f19eaec, 0x443d3004 },
  { 0x78230000, 0x12fc0000, 0xa93a0b80, 0x90a50000, 0x713e2879, 0x7ee98924, 0xf08ca062, 0x636f8bab,
    0x02af0000, 0xb7280000, 0xba1c0300, 0x56980000, 0xba8d45d3, 0x8048c667, 0xa95c149a, 0xf4f6ea7b },
  { 0x02af0000, 0xb7280000, 0xba1c0300, 0x56980000, 0xba8d45d3, 0x8048c667, 0xa95c149a, 0xf4f6ea7b,
    0x7a8c0000, 0xa5d40000, 0x13260880, 0xc63d0000, 0xcbb36daa, 0xfea14f43, 0x59d0b4f8, 0x979961d0 },
  { 0xac480000, 0x1ba60000, 0x45fb1380, 0x03430000, 0x5a85316a, 0x1fb250b6, 0xfe72c7fe, 0x91e478f6,
    0x1e4e0000, 0xdecf0000, 0x6df80180, 0x77240000, 0xec47079e, 0xf4a0694e, 0xcda31812, 0x98aa496e },
  { 0x1e4e0000, 0xdecf0000, 0x6df80180, 0x77240000, 0xec47079e, 0xf4a0694e, 0xcda31812, 0x98aa496e,
    0xb2060000, 0xc5690000, 0x28031200, 0x74670000, 0xb6c236f4, 0xeb1239f8, 0x33d1dfec, 0x094e3198 },
  { 0xaec30000, 0x9c4f0001, 0x79d1e000, 0x2c150000, 0x45cc75b3, 0x6650b736, 0xab92f78f, 0xa312567b,
    0xdb250000, 0x09290000, 0x49aac000, 0x81e10000, 0xcafe6b59, 0x42793431, 0x43566b76, 0xe86cba2e },
  { 0xdb250000, 0x09290000, 0x49aac000, 0x81e10000, 0xcafe6b59, 0x42793431, 0x43566b76, 0xe86cba2e,
    0x75e60000, 0x95660001, 0x307b2000, 0xadf40000, 0x8f321eea, 0x24298307, 0xe8c49cf9, 0x4b7eec55 },
  { 0x58430000, 0x807e0000, 0x78330001, 0xc66b3800, 0xe7375cdc, 0x79ad3fdd, 0xac73fe6f, 0x3a4479b1,
    0x1d5a0000, 0x2b720000, 0x488d0000, 0xaf611800, 0x25cb2ec5, 0xc879bfd0, 0x81a20429, 0x1e7536a6 },
  { 0x1d5a0000, 0x2b720000, 0x488d0000, 0xaf611800, 0x25cb2ec5, 0xc879bfd0, 0x81a20429, 0x1e7536a6,
    0x45190000, 0xab0c0000, 0x30be0001, 0x690a2000, 0xc2fc7219, 0xb1d4800d, 0x2dd1fa46, 0x24314f17 },
  { 0xa53b0000, 0x14260000, 0x4e30001e, 0x7cae0000, 0x8f9e0dd5, 0x78dfaa3d, 0xf73168d8, 0x0b1b4946,
    0x07ed0000, 0xb2500000, 0x8774000a, 0x970d0000, 0x437223ae, 0x48c76ea4, 0xf4786222, 0x9075b1ce },
  { 0x07ed0000, 0xb2500000, 0x8774000a, 0x970d0000, 0x437223ae, 0x48c76ea4, 0xf4786222, 0x9075b1ce,
    0xa2d60000, 0xa6760000, 0xc9440014, 0xeba30000, 0xccec2e7b, 0x3018c499, 0x03490afa, 0x9b6ef888 },
  { 0x88980000, 0x1f940000, 0x7fcf002e, 0xfb4e0000, 0xf158079a, 0x61ae9167, 0xa895706c, 0xe6107494,
    0x0bc20000, 0xdb630000, 0x7e88000c, 0x15860000, 0x91fd48f3, 0x7581bb43, 0xf460449e, 0xd8b61463 },
  { 0x0bc20000, 0xdb630000, 0x7e88000c, 0x15860000, 0x91fd48f3, 0x7581bb43, 0xf460449e, 0xd8b61463,
    0x835a0000, 0xc4f70000, 0x01470022, 0xeec80000, 0x60a54f69, 0x142f2a24, 0x5cf534f2, 0x3ea660f7 },
  { 0x52500000, 0x29540000, 0x6a61004e, 0xf0ff0000, 0x9a317eec, 0x452341ce, 0xcf568fe5, 0x5303130f,
    0x538d0000, 0xa9fc0000, 0x9ef70006, 0x56ff0000, 0x0ae4004e, 0x92c5cdf9, 0xa9444018, 0x7f975691 },
  { 0x538d0000, 0xa9fc0000, 0x9ef70006, 0x56ff0000, 0x0ae4004e, 0x92c5cdf9, 0xa9444018, 0x7f975691,
    0x01dd0000, 0x80a80000, 0xf4960048, 0xa6000000, 0x90d57ea2, 0xd7e68c37, 0x6612cffd, 0x2c94459e },
  { 0xe6280000, 0x4c4b0000, 0xa8550000, 0xd3d002e0, 0xd86130b8, 0x98a7b0da, 0x289506b4, 0xd75a4897,
    0xf0c50000, 0x59230000, 0x45820000, 0xe18d00c0, 0x3b6d0631, 0xc2ed5699, 0xcbe0fe1c, 0x56a7b19f },
  { 0xf0c50000, 0x59230000, 0x45820000, 0xe18d00c0, 0x3b6d0631, 0xc2ed5699, 0xcbe0fe1c, 0x56a7b19f,
    0x16ed0000, 0x15680000, 0xedd70000, 0x325d0220, 0xe30c3689, 0x5a4ae643, 0xe375f8a8, 0x81fdf908 },
  { 0xb4310000, 0x77330000, 0xb15d0000, 0x7fd004e0, 0x78a26138, 0xd116c35d, 0xd256d489, 0x4e6f74de,
    0xe3060000, 0xbdc10000, 0x87130000, 0xbff20060, 0x2eba0a1a, 0x8db53751, 0x73c5ab06, 0x5bd61539 },
  { 0xe3060000, 0xbdc10000, 0x87130000, 0xbff20060, 0x2eba0a1a, 0x8db53751, 0x73c5ab06, 0x5bd61539,
    0x57370000, 0xcaf20000, 0x364e0000, 0xc0220480, 0x56186b22, 0x5ca3f40c, 0xa1937f8f, 0x15b961e7 },
  { 0x02f20000, 0xa2810000, 0x873f0000, 0xe36c7800, 0x1e1d74ef, 0x073d2bd6, 0xc4c23237, 0x7f32259e,
    0xbadd0000, 0x13ad0000, 0xb7e70000, 0xf7282800, 0xdf45144d, 0x361ac33a, 0xea5a8d14, 0x2a2c18f0 },
  { 0xbadd0000, 0x13ad0000, 0xb7e70000, 0xf7282800, 0xdf45144d, 0x361ac33a, 0xea5a8d14, 0x2a2c18f0,
    0xb82f0000, 0xb12c0000, 0x30d80000, 0x14445000, 0xc15860a2, 0x3127e8ec, 0x2e98bf23, 0x551e3d6e },
  { 0x1e6c0000, 0xc4420000, 0x8a2e0000, 0xbcb6b800, 0x2c4413b6, 0x8bfdd3da, 0x6a0c1bc8, 0xb99dc2eb,
    0x92560000, 0x1eda0000, 0xea510000, 0xe8b13000, 0xa93556a5, 0xebfb6199, 0xb15c2254, 0x33c5244f },
  { 0x92560000, 0x1eda0000, 0xea510000, 0xe8b13000, 0xa93556a5, 0xebfb6199, 0xb15c2254, 0x33c5244f,
    0x8c3a0000, 0xda980000, 0x607f0000, 0x54078800, 0x85714513, 0x6006b243, 0xdb50399c, 0x8a58e6a4 },
  { 0x033d0000, 0x08b30000, 0xf33a0000, 0x3ac20007, 0x51298a50, 0x6b6e661f, 0x0ea5cfe3, 0xe6da7ffe,
    0xa8da0000, 0x96be0000, 0x5c1d0000, 0x07da0002, 0x7d669583, 0x1f98708a, 0xbb668808, 0xda878000 },
  { 0xa8da0000, 0x96be0000, 0x5c1d0000, 0x07da0002, 0x7d669583, 0x1f98708a, 0xbb668808, 0xda878000,
    0xabe70000, 0x9e0d0000, 0xaf270000, 0x3d180005, 0x2c4f1fd3, 0x74f61695, 0xb5c347eb, 0x3c5dfffe },
  { 0x01930000, 0xe7820000, 0xedfb0000, 0xcf0c000b, 0x8dd08d58, 0xbca3b42e, 0x063661e1, 0x536f9e7b,
    0x92280000, 0xdc850000, 0x57fa0000, 0x56dc0003, 0xbae92316, 0x5aefa30c, 0x90cef752, 0x7b1675d7 },
  { 0x92280000, 0xdc850000, 0x57fa0000, 0x56dc0003, 0xbae92316, 0x5aefa30c, 0x90cef752, 0x7b1675d7,
    0x93bb0000, 0x3b070000, 0xba010000, 0x99d00008, 0x3739ae4e, 0xe64c1722, 0x96f896b3, 0x2879ebac },
  { 0x5fa80000, 0x56030000, 0x43ae0000, 0x64f30013, 0x257e86bf, 0x1311944e, 0x541e95bf, 0x8ea4db69,
    0x00440000, 0x7f480000, 0xda7c0000, 0x2a230001, 0x3badc9cc, 0xa9b69c87, 0x030a9e60, 0xbe0a679e },
  { 0x00440000, 0x7f480000, 0xda7c0000, 0x2a230001, 0x3badc9cc, 0xa9b69c87, 0x030a9e60, 0xbe0a679e,
    0x5fec0000, 0x294b0000, 0x99d20000, 0x4ed00012, 0x1ed34f73, 0xbaa708c9, 0x57140bdf, 0x30aebcf7 },
  { 0xee930000, 0xd6070000, 0x92c10000, 0x2b9801e0, 0x9451287c, 0x3b6cfb57, 0x45312374, 0x201f6a64,
    0x7b280000, 0x57420000, 0xa9e50000, 0x634300a0, 0x9edb442f, 0x6d9995bb, 0x27f83b03, 0xc7ff60f0 },
  { 0x7b280000, 0x57420000, 0xa9e50000, 0x634300a0, 0x9edb442f, 0x6d9995bb, 0x27f83b03, 0xc7ff60f0,
    0x95bb0000, 0x81450000, 0x3b240000, 0x48db0140, 0x0a8a6c53, 0x56f56eec, 0x62c91877, 0xe7e00a94 },
};

#define HAMSI_SBOX(T,A,B,C,D)                                                   \
{                                                                               \
  T sb = (A);                                                                   \
                                                                                \
  (A) &= (C);                                                                   \
  (A) ^= (D);                                                                   \
  (C) ^= (B);                                                                   \
  (C) ^= (A);                                                                   \
  (D) |= sb;                                                                    \
  (D) ^= (B);                                                                   \
  sb  ^= (C);                                                                   \
  (B)  = (D);                                                                   \
  (D) |= sb;                                                                    \
  (D) ^= (A);                                                                   \
  (A) &= (B);                                                                   \
  sb  ^= (A);                                                                   \
  (B) ^= (D);                                                                   \
  (B) ^= sb;                                                                    \
  (A)  = (C);                                                                   \
  (C)  = (B);                                                                   \
  (B)  = (D);                                                                   \
  (D)  = ~sb;                                                                   \
}

#define HAMSI_L(ROTL,A,B,C,D)                                                   \
{                                                                               \
  (A)  = ROTL ((A), 13);                                                        \
  (C)  = ROTL ((C),  3);                                                        \
  (B) ^= (A) ^ (C);                                                             \
  (D) ^= (C) ^ ((A) << 3);                                                      \
  (B)  = ROTL ((B),  1);                                                        \
  (D)  = ROTL ((D),  7);                                                        \
  (A) ^= (B) ^ (D);                                                             \
  (C) ^= (D) ^ ((B) << 7);                                                      \
  (A)  = ROTL ((A),  5);                                                        \
  (C)  = ROTL ((C), 22);                                                        \
}

// One block of Hamsi-224 or Hamsi-256. The 32 bits of X expand to 8 words, which are interleaved
// with the 8 chaining words. R rounds follow with the constants of row A of hamsi_alpha, then half
// of the state is fed forward into H.

#define HAMSI256_TRANSFORM(T,ROTL,H,X,R,A)                                      \
{                                                                               \
  T m[8];                                                                       \
                                                                                \
  for (u32 j = 0; j < 8; j++) m[j] = 0;                                         \
                                                                                \
  for (u32 i = 0; i < 32; i++)                                                  \
  {                                                                             \
    const T d = (((X) >> i) & 1) * 0xffffffff;                                  \
                                                                                \
    for (u32 j = 0; j < 8; j++) m[j] ^= d & hamsi256_expand[i][j];              \
  }                                                                             \
                                                                                \
  T s[16];                                                                      \
                                                                                \
  s[ 0] = m[0];                                                                 \
  s[ 1] = m[1];                                                                 \
  s[ 2] = H[0];                                                                 \
  s[ 3] = H[1];                                                                 \
  s[ 4] = H[2];                                                                 \
  s[ 5] = H[3];                                                                 \
  s[ 6] = m[2];                                                                 \
  s[ 7] = m[3];                                                                 \
  s[ 8] = m[4];                                                                 \
  s[ 9] = m[5];                                                                 \
  s[10] = H[4];                                                                 \
  s[11] = H[5];                                                                 \
  s[12] = H[6];                                                                 \
  s[13] = H[7];                                                                 \
  s[14] = m[6];                                                                 \
  s[15] = m[7];                                                                 \
                                                                                \
  for (u32 r = 0; r < (R); r++)                                                 \
  {                                                                             \
    for (u32 i = 0; i < 4; i++)                                                 \
    {                                                                           \
      s[ 0 + i] ^= hamsi_alpha[A][ 0 + i];                                      \
      s[ 4 + i] ^= hamsi_alpha[A][ 8 + i];                                      \
      s[ 8 + i] ^= hamsi_alpha[A][16 + i];                                      \
      s[12 + i] ^= hamsi_alpha[A][24 + i];                                      \
    }                                                                           \
                                                                                \
    s[1] ^= r;                                                                  \
                                                                                \
    for (u32 i = 0; i < 4; i++)                                                 \
    {                                                                           \
      HAMSI_SBOX (T, s[i], s[4 + i], s[8 + i], s[12 + i]);                      \
    }                                                                           \
                                                                                \
    HAMSI_L (ROTL, s[0], s[5], s[10], s[15]);                                   \
    HAMSI_L (ROTL, s[1], s[6], s[11], s[12]);                                   \
    HAMSI_L (ROTL, s[2], s[7], s[ 8], s[13]);                                   \
    HAMSI_L (ROTL, s[3], s[4], s[ 9], s[14]);                                   \
  }                                                                             \
                                                                                \
  H[0] ^= s[ 0];                                                                \
  H[1] ^= s[ 1];                                                                \
  H[2] ^= s[ 2];                                                                \
  H[3] ^= s[ 3];                                                                \
  H[4] ^= s[ 8];                                                                \
  H[5] ^= s[ 9];                                                                \
  H[6] ^= s[10];                                                                \
  H[7] ^= s[11];                                                                \
}

// One block of Hamsi-384 or Hamsi-512, the same way with 64 bits in X0 and X1, 16 expanded words
// and 16 chaining words.

#define HAMSI512_TRANSFORM(T,ROTL,H,X0,X1,R,A)                                  \
{                                                                               \
  T m[16];                                                                      \
                                                                                \
  for (u32 j = 0; j < 16; j++) m[j] = 0;                                        \
                                                                                \
  for (u32 i = 0; i < 32; i++)                                                  \
  {                                                                             \
    const T d0 = (((X0) >> i) & 1) * 0xffffffff;                                \
    const T d1 = (((X1) >> i) & 1) * 0xffffffff;                                \
                                                                                \
    for (u32 j = 0; j < 16; j++)                                                \
    {                                                                           \
      m[j] ^= (d0 & hamsi512_expand[i][j]) ^ (d1 & hamsi512_expand[32 + i][j]); \
    }                                                                           \
  }                                                                             \
                                                                                \
  T s[32];                                                                      \
                                                                                \
  s[ 0] = m[ 0];                                                                \
  s[ 1] = m[ 1];                                                                \
  s[ 2] = H[ 0];                                                                \
  s[ 3] = H[ 1];                                                                \
  s[ 4] = m[ 2];                                                                \
  s[ 5] = m[ 3];                                                                \
  s[ 6] = H[ 2];                                                                \
  s[ 7] = H[ 3];                                                                \
  s[ 8] = H[ 4];                                                                \
  s[ 9] = H[ 5];                                                                \
  s[10] = m[ 4];                                                                \
  s[11] = m[ 5];                                                                \
  s[12] = H[ 6];                                                                \
  s[13] = H[ 7];                                                                \
  s[14] = m[ 6];                                                                \
  s[15] = m[ 7];                                                                \
  s[16] = m[ 8];                                                                \
  s[17] = m[ 9];                                                                \
  s[18] = H[ 8];                                                                \
  s[19] = H[ 9];                                                                \
  s[20] = m[10];                                                                \
  s[21] = m[11];                                                                \
  s[22] = H[10];                                                                \
  s[23] = H[11];                                                                \
  s[24] = H[12];                                                                \
  s[25] = H[13];                                                                \
  s[26] = m[12];                                                                \
  s[27] = m[13];                                                                \
  s[28] = H[14];                                                                \
  s[29] = H[15];                                                                \
  s[30] = m[14];                                                                \
  s[31] = m[15];                                                                \
                                                                                \
  for (u32 r = 0; r < (R); r++)                                                 \
  {                                                                             \
    for (u32 i = 0; i < 32; i++) s[i] ^= hamsi_alpha[A][i];                     \
                                                                                \
    s[1] ^= r;                                                                  \
                                                                                \
    for (u32 i = 0; i < 8; i++)                                                 \
    {                                                                           \
      HAMSI_SBOX (T, s[i], s[8 + i], s[16 + i], s[24 + i]);                     \
    }                                                                           \
                                                                                \
    HAMSI_L (ROTL, s[ 0], s[ 9], s[18], s[27]);                                 \
    HAMSI_L (ROTL, s[ 1], s[10], s[19], s[28]);                                 \
    HAMSI_L (ROTL, s[ 2], s[11], s[20], s[29]);                                 \
    HAMSI_L (ROTL, s[ 3], s[12], s[21], s[30]);                                 \
    HAMSI_L (ROTL, s[ 4], s[13], s[22], s[31]);                                 \
    HAMSI_L (ROTL, s[ 5], s[14], s[23], s[24]);                                 \
    HAMSI_L (ROTL, s[ 6], s[15], s[16], s[25]);                                 \
    HAMSI_L (ROTL, s[ 7], s[ 8], s[17], s[26]);                                 \
                                                                                \
    HAMSI_L (ROTL, s[ 0], s[ 2], s[ 5], s[ 7]);                                 \
    HAMSI_L (ROTL, s[16], s[19], s[21], s[22]);                                 \
    HAMSI_L (ROTL, s[ 9], s[11], s[12], s[14]);                                 \
    HAMSI_L (ROTL, s[25], s[26], s[28], s[31]);                                 \
  }                                                                             \
                                                                                \
  for (u32 i = 0; i < 8; i++)                                                   \
  {                                                                             \
    H[0 + i] ^= s[ 0 + i];                                                      \
    H[8 + i] ^= s[16 + i];                                                      \
  }                                                                             \
}

DECLSPEC void hamsi256_transform (PRIVATE_AS u32 *h, const u32 x)
{
  HAMSI256_TRANSFORM (u32, hc_rotl32_S, h, x, 3, 0);
}

DECLSPEC void hamsi256_transform_final (PRIVATE_AS u32 *h, const u32 x)
{
  HAMSI256_TRANSFORM (u32, hc_rotl32_S, h, x, 6, 1);
}

DECLSPEC void hamsi256_init (PRIVATE_AS hamsi256_ctx_t *ctx, const int dlen)
{
  const int iv = (dlen == 28) ? 0 : 1;

  for (u32 i = 0; i < 8; i++) ctx->h[i] = hamsi256_iv[iv][i];

  ctx->m    = 0;
  ctx->pos  = 0;
  ctx->cnt  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, process it and use any remaining
// bytes to start the next block. A block ends on a word boundary, so the bytes that do not fit are
// shifted out of the word and need no mask.

DECLSPEC void hamsi256_absorb (PRIVATE_AS hamsi256_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 4 - pos;

  const int fit = (n > room) ? room : n;

  ctx->m |= v << (pos * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  hamsi256_transform (ctx->h, ctx->m);

  ctx->cnt += 4;

  ctx->m   = 0;
  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m   = v >> (fit * 8);
    ctx->pos = n - fit;
  }
}

DECLSPEC void hamsi256_update (PRIVATE_AS hamsi256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    hamsi256_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void hamsi256_absorb_utf16le (PRIVATE_AS hamsi256_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  hamsi256_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) hamsi256_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void hamsi256_update_utf16le (PRIVATE_AS hamsi256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      hamsi256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    hamsi256_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void hamsi256_update_global (PRIVATE_AS hamsi256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    hamsi256_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void hamsi256_update_global_utf16le (PRIVATE_AS hamsi256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      hamsi256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    hamsi256_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding is a 0x80 byte and zeros up to the end of the block, which is processed even when it
// holds no message byte. The message length in bits follows as a 64 bit big endian number, which
// fills 2 more blocks, and only the last of them goes through Pf. A context with invalid UTF-8
// input produces a digest with every bit flipped, so that no candidate matches it by chance.

DECLSPEC void hamsi256_final (PRIVATE_AS hamsi256_ctx_t *ctx)
{
  const u64 bits = (ctx->cnt + (u64) ctx->pos) * 8;

  hamsi256_transform (ctx->h, ctx->m | (0x80u << (ctx->pos * 8)));

  hamsi256_transform       (ctx->h, hc_swap32_S (h32_from_64_S (bits)));
  hamsi256_transform_final (ctx->h, hc_swap32_S (l32_from_64_S (bits)));

  for (u32 i = 0; i < 8; i++) ctx->h[i] = hc_swap32_S (ctx->h[i]);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 8; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void hamsi256_transform_vector (PRIVATE_AS u32x *h, const u32x x)
{
  HAMSI256_TRANSFORM (u32x, hc_rotl32, h, x, 3, 0);
}

DECLSPEC void hamsi256_transform_final_vector (PRIVATE_AS u32x *h, const u32x x)
{
  HAMSI256_TRANSFORM (u32x, hc_rotl32, h, x, 6, 1);
}

DECLSPEC void hamsi256_init_vector (PRIVATE_AS hamsi256_ctx_vector_t *ctx, const int dlen)
{
  const int iv = (dlen == 28) ? 0 : 1;

  for (u32 i = 0; i < 8; i++) ctx->h[i] = make_u32x (hamsi256_iv[iv][i]);

  ctx->m    = 0;
  ctx->pos  = 0;
  ctx->cnt  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void hamsi256_absorb_vector (PRIVATE_AS hamsi256_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 4 - pos;

  const int fit = (n > room) ? room : n;

  ctx->m |= v << (pos * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  hamsi256_transform_vector (ctx->h, ctx->m);

  ctx->cnt += 4;

  ctx->m   = 0;
  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m   = v >> (fit * 8);
    ctx->pos = n - fit;
  }
}

DECLSPEC void hamsi256_update_vector (PRIVATE_AS hamsi256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    hamsi256_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void hamsi256_update_vector_utf16le (PRIVATE_AS hamsi256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    hamsi256_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) hamsi256_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void hamsi256_final_vector (PRIVATE_AS hamsi256_ctx_vector_t *ctx)
{
  const u64 bits = (ctx->cnt + (u64) ctx->pos) * 8;

  hamsi256_transform_vector (ctx->h, ctx->m | (0x80u << (ctx->pos * 8)));

  hamsi256_transform_vector       (ctx->h, make_u32x (hc_swap32_S (h32_from_64_S (bits))));
  hamsi256_transform_final_vector (ctx->h, make_u32x (hc_swap32_S (l32_from_64_S (bits))));

  for (u32 i = 0; i < 8; i++) ctx->h[i] = hc_swap32 (ctx->h[i]);
}

DECLSPEC void hamsi512_transform (PRIVATE_AS u32 *h, const u32 x0, const u32 x1)
{
  HAMSI512_TRANSFORM (u32, hc_rotl32_S, h, x0, x1, 6, 0);
}

DECLSPEC void hamsi512_transform_final (PRIVATE_AS u32 *h, const u32 x0, const u32 x1)
{
  HAMSI512_TRANSFORM (u32, hc_rotl32_S, h, x0, x1, 12, 1);
}

DECLSPEC void hamsi512_init (PRIVATE_AS hamsi512_ctx_t *ctx, const int dlen)
{
  const int iv = (dlen == 48) ? 0 : 1;

  for (u32 i = 0; i < 16; i++) ctx->h[i] = hamsi512_iv[iv][i];

  ctx->m[0] = 0;
  ctx->m[1] = 0;

  ctx->pos  = 0;
  ctx->cnt  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

// The same as hamsi256_absorb (), for a block of 2 words. Both are addressed by constant indices
// only, because a variable index keeps the whole context in scratch memory on a GPU.

DECLSPEC void hamsi512_absorb (PRIVATE_AS hamsi512_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 8 - pos;

  const int fit = (n > room) ? room : n;

  if (pos >= 4)
  {
    ctx->m[1] |= v << ((pos - 4) * 8);
  }
  else
  {
    ctx->m[0] |= v << (pos * 8);

    if ((pos + fit) > 4) ctx->m[1] |= v >> ((4 - pos) * 8);
  }

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  hamsi512_transform (ctx->h, ctx->m[0], ctx->m[1]);

  ctx->cnt += 8;

  ctx->m[0] = 0;
  ctx->m[1] = 0;

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void hamsi512_update (PRIVATE_AS hamsi512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    hamsi512_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void hamsi512_absorb_utf16le (PRIVATE_AS hamsi512_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  hamsi512_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) hamsi512_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void hamsi512_update_utf16le (PRIVATE_AS hamsi512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      hamsi512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    hamsi512_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void hamsi512_update_global (PRIVATE_AS hamsi512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    hamsi512_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void hamsi512_update_global_utf16le (PRIVATE_AS hamsi512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      hamsi512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    hamsi512_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding is a 0x80 byte and zeros up to the end of the block, which is processed even when it
// holds no message byte. The message length in bits fills the last block, as a 64 bit big endian
// number, and goes through Pf. Hamsi-384 keeps 12 of the 16 chaining words, which move to the
// front of h. A context with invalid UTF-8 input produces a digest with every bit flipped.

DECLSPEC void hamsi512_final (PRIVATE_AS hamsi512_ctx_t *ctx)
{
  const u64 bits = (ctx->cnt + (u64) ctx->pos) * 8;

  const int pos = ctx->pos;

  const u32 pad = 0x80u << ((pos & 3) * 8);

  if (pos >= 4)
  {
    ctx->m[1] |= pad;
  }
  else
  {
    ctx->m[0] |= pad;
  }

  hamsi512_transform (ctx->h, ctx->m[0], ctx->m[1]);

  hamsi512_transform_final (ctx->h, hc_swap32_S (h32_from_64_S (bits)), hc_swap32_S (l32_from_64_S (bits)));

  if (ctx->dlen == 48)
  {
    ctx->h[ 2] = ctx->h[ 3];
    ctx->h[ 3] = ctx->h[ 4];
    ctx->h[ 4] = ctx->h[ 5];
    ctx->h[ 5] = ctx->h[ 6];
    ctx->h[ 6] = ctx->h[ 8];
    ctx->h[ 7] = ctx->h[ 9];
    ctx->h[ 8] = ctx->h[10];
    ctx->h[ 9] = ctx->h[12];
    ctx->h[10] = ctx->h[13];
    ctx->h[11] = ctx->h[15];
  }

  for (u32 i = 0; i < 16; i++) ctx->h[i] = hc_swap32_S (ctx->h[i]);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 16; i++) ctx->h[i] = ~ctx->h[i];
  }
}

DECLSPEC void hamsi512_transform_vector (PRIVATE_AS u32x *h, const u32x x0, const u32x x1)
{
  HAMSI512_TRANSFORM (u32x, hc_rotl32, h, x0, x1, 6, 0);
}

DECLSPEC void hamsi512_transform_final_vector (PRIVATE_AS u32x *h, const u32x x0, const u32x x1)
{
  HAMSI512_TRANSFORM (u32x, hc_rotl32, h, x0, x1, 12, 1);
}

DECLSPEC void hamsi512_init_vector (PRIVATE_AS hamsi512_ctx_vector_t *ctx, const int dlen)
{
  const int iv = (dlen == 48) ? 0 : 1;

  for (u32 i = 0; i < 16; i++) ctx->h[i] = make_u32x (hamsi512_iv[iv][i]);

  ctx->m[0] = 0;
  ctx->m[1] = 0;

  ctx->pos  = 0;
  ctx->cnt  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void hamsi512_absorb_vector (PRIVATE_AS hamsi512_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 8 - pos;

  const int fit = (n > room) ? room : n;

  if (pos >= 4)
  {
    ctx->m[1] |= v << ((pos - 4) * 8);
  }
  else
  {
    ctx->m[0] |= v << (pos * 8);

    if ((pos + fit) > 4) ctx->m[1] |= v >> ((4 - pos) * 8);
  }

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  hamsi512_transform_vector (ctx->h, ctx->m[0], ctx->m[1]);

  ctx->cnt += 8;

  ctx->m[0] = 0;
  ctx->m[1] = 0;

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void hamsi512_update_vector (PRIVATE_AS hamsi512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    hamsi512_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void hamsi512_update_vector_utf16le (PRIVATE_AS hamsi512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    hamsi512_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) hamsi512_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void hamsi512_final_vector (PRIVATE_AS hamsi512_ctx_vector_t *ctx)
{
  const u64 bits = (ctx->cnt + (u64) ctx->pos) * 8;

  const int pos = ctx->pos;

  const u32 pad = 0x80u << ((pos & 3) * 8);

  if (pos >= 4)
  {
    ctx->m[1] |= pad;
  }
  else
  {
    ctx->m[0] |= pad;
  }

  hamsi512_transform_vector (ctx->h, ctx->m[0], ctx->m[1]);

  hamsi512_transform_final_vector (ctx->h, make_u32x (hc_swap32_S (h32_from_64_S (bits))), make_u32x (hc_swap32_S (l32_from_64_S (bits))));

  if (ctx->dlen == 48)
  {
    ctx->h[ 2] = ctx->h[ 3];
    ctx->h[ 3] = ctx->h[ 4];
    ctx->h[ 4] = ctx->h[ 5];
    ctx->h[ 5] = ctx->h[ 6];
    ctx->h[ 6] = ctx->h[ 8];
    ctx->h[ 7] = ctx->h[ 9];
    ctx->h[ 8] = ctx->h[10];
    ctx->h[ 9] = ctx->h[12];
    ctx->h[10] = ctx->h[13];
    ctx->h[11] = ctx->h[15];
  }

  for (u32 i = 0; i < 16; i++) ctx->h[i] = hc_swap32 (ctx->h[i]);
}
