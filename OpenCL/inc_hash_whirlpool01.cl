/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_whirlpool01.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off. State word i holds bytes 8i to 8i+7 of the Whirlpool state, the
// first one in the low bits, so 2 input words make one state word and the input needs no swap.

// The table T0 of each variant in that byte order: Whirlpool-0 first, then Whirlpool-T. Each entry
// is an S-box output multiplied by the 8 coefficients of the circulant diffusion matrix, so its low
// byte is the S-box output itself. The tables T1 to T7 of the reference are T0 rotated left by 8
// to 56 bits, and the rounds rotate rather than read 7 more tables, which keeps both variants at
// 4 KiB of shared memory.

CONSTANT_VK u64a whirlpool01_t0[2][256] =
{
  {
    0xd50f67d568b86868, 0xb71eceb7d06dd0d0, 0x60e00b60eb20ebeb, 0x876e45872b7d2b2b,
    0x75327a7548d84848, 0xd3019cd39dba9d9d, 0xdf1d77df6abe6a6a, 0x53977353e431e4e4,
    0x48a84b48e338e3e3, 0x15d27115a3f8a3a3, 0x13dc8a1356fa5656, 0xbffd7cbf819e8181,
    0x94b2cf947d877d7d, 0x122adb12f10ef1f1, 0xabd95cab85928585, 0xdc1a84dc9ebf9e9e,
    0x9c517d9c2c742c2c, 0x8c8a048c8e8f8e8e, 0x859fe78578887878, 0xc5d41ec5ca43caca,
    0x4bafb84b17391717, 0x37882137a9e6a9a9, 0xf84e2ff861a36161, 0xa633e6a6d562d5d5,
    0x348fd2345de75d5d, 0x275358270b1d0b0b, 0x869814868c898c8c, 0xccc1fdcc3c443c3c,
    0xb6e89fb677997777, 0x08e3b20851f35151, 0xaa2f0daa22662222, 0x57682a5742c64242,
    0xc3dae5c33f413f3f, 0x19ce9a1954fc5454, 0x5873325841c34141, 0xbaf474ba809d8080,
    0xdbe22edbcc49cccc, 0xa4c244a486978686, 0x4542f145b3c8b3b3, 0x78d8c07818281818,
    0x96436d962e722e2e, 0x16d5821657f95757, 0x1e36301e060a0606, 0xf75537f762a66262,
    0x0307f303f401f4f4, 0xee9badee365a3636, 0xb217c6b2d16ed1d1, 0xda147fda6bbd6b6b,
    0x77c3d8771b2d1b1b, 0xec6a0fec65af6565, 0xbcfa8fbc759f7575, 0x5090805010301010,
    0x95449e95da73dada, 0x703b727049db4949, 0xbe0b2dbe266a2626, 0x3a629b3af916f9f9,
    0xc0dd16c0cb40cbcb, 0xe37117e366aa6666, 0x5c8c6b5ce734e7e7, 0x6803b968bad3baba,
    0x2cb7192caeefaeae, 0x0deaba0d50f05050, 0x07f8aa0752f65252, 0x3d9a313dabe0abab,
    0x112d2811050f0505, 0x1723d317f00df0f0, 0x396568390d170d0d, 0xa2ccbfa273957373,
    0xd7fec5d73b4d3b3b, 0x14242014040c0404, 0xa03d1da020602020, 0x215da321fe1ffefe,
    0x8e7ba68edd7adddd, 0x060efb06f502f5f5, 0x5e7dc95eb4c1b4b4, 0x3e9dc23e5fe15f5f,
    0x225a50220a1e0a0a, 0x5b74c15bb5c2b5b5, 0xe78e4ee7c05dc0c0, 0x1ac9691aa0fda0a0,
    0xa8deafa871937171, 0x0be4410ba5f2a5a5, 0x995875992d772d2d, 0xfd4727fd60a06060,
    0xa7c5b7a772967272, 0xe57fece593a89393, 0xddecd5dd394b3939, 0x2848402808180808,
    0xb5ef6cb583988383, 0xa53415a521632121, 0x3186da315ce45c5c, 0xa1cb4ca187948787,
    0x4f50e14fb1ceb1b1, 0x47b35347e03de0e0, 0x0000000000000000, 0xe89556e8c358c3c3,
    0x5a82905a12361212, 0xef6dfcef91ae9191, 0x98ae24988a838a8a, 0x0a12100a02060202,
    0x6cfce06c1c241c1c, 0x59856359e637e6e6, 0x4c57124c45cf4545, 0xed9c5eedc25bc2c2,
    0xf3aa6ef3c451c4c4, 0x2e46bb2efd1afdfd, 0x792e9179bfdcbfbf, 0x495e1a4944cc4444,
    0x1fc0611fa1fea1a1, 0x61165a614cd44c4c, 0xffb685ff33553333, 0xf6a366f6c552c5c5,
    0xaed054ae84918484, 0xaf2605af23652323, 0x91bbc7917c847c7c, 0x4a59e94ab0cdb0b0,
    0xb11035b1256f2525, 0x41bda841153f1515, 0xe180b5e1355f3535, 0xd0066fd069bb6969,
    0x2454ab24ff1cffff, 0xfe40d4fe94a19494, 0x641f52644dd74d4d, 0xadd7a7ad70907070,
    0x10db7910a2fba2a2, 0x29be1129afecafaf, 0xdeeb26decd4acdcd, 0xa928fea9d667d6d6,
    0xc12b47c16cb46c6c, 0x5166d151b7c4b7b7, 0x3f6b933ff815f8f8, 0x2d41482d091b0909,
    0x1838cb18f308f3f3, 0xe6781fe667a96767, 0x0eed490ea4f1a4a4, 0x65e90365ea23eaea,
    0x7bdf337bec29ecec, 0x546fd954b6c7b6b6, 0xa33aeea3d461d4d4, 0xbd0cdebdd26bd2d2,
    0x44b4a044143c1414, 0x66eef0661e221e1e, 0x42ba5b42e13ee1e1, 0xb4193db4246c2424,
    0xd8e5ddd838483838, 0xf9b87ef9c657c6c6, 0x904d9690db70dbdb, 0x7a29627a4bdd4b4b,
    0x8f8df78f7a8e7a7a, 0xd2f7cdd23a4e3a3a, 0x8160be81de7fdede, 0x3b94ca3b5ee25e5e,
    0x8469b684df7cdfdf, 0xfb49dcfb95a29595, 0x2b4fb32bfc19fcfc, 0x38933938aae3aaaa,
    0xac21f6acd764d7d7, 0xd1f03ed1ce4fcece, 0x1b3f381b07090707, 0x337778330f110f0f,
    0xc9c8f5c93d473d3d, 0x25a2fa2558e85858, 0xc83ea4c89ab39a9a, 0xc22cb4c298b59898,
    0xd60894d69cb99c9c, 0x1d31c31df20bf2f2, 0x01f65101a7f4a7a7, 0x5599885511331111,
    0x9ba9d79b7e827e7e, 0x9da72c9d8b808b8b, 0x5261225243c54343, 0x0f1b180f03050303,
    0x4da1434de23be2e2, 0x8b72ae8bdc79dcdc, 0x569e7b56e532e5e5, 0x404bf940b2cbb2b2,
    0x6b044a6b4ed24e4e, 0xfcb176fcc754c7c7, 0xc4224fc46db76d6d, 0x6af21b6ae926e9e9,
    0xbb0225bb27692727, 0x5d7a3a5d40c04040, 0x9f568e9fd875d8d8, 0xeb92a5eb37593737,
    0xe076e4e092ab9292, 0x89830c898f8c8f8f, 0x0509080501030101, 0x69f5e8691d271d1d,
    0x02f1a20253f55353, 0xc6d3edc63e423e3e, 0x20abf22059eb5959, 0xe28746e2c15ec1c1,
    0x6e0d426e4fd14f4f, 0xfabf8dfa32563232, 0x4ea6b04e163a1616, 0x35798335fa13fafa,
    0xb9f387b9749c7474, 0x30708b30fb10fbfb, 0xf25c3ff263a56363, 0xd9138cd99fbc9f9f,
    0xe489bde4345c3434, 0x72cad0721a2e1a1a, 0x82674d822a7e2a2a, 0x2fb0ea2f5aee5a5a,
    0x83911c838d8a8d8d, 0xcacf06cac946c9c9, 0xd4f936d4cf4ccfcf, 0x0915e309f607f6f6,
    0xea64f4ea90ad9090, 0x88755d8828782828, 0x92bc349288858888, 0xcd37accd9bb09b9b,
    0xf5a495f531533131, 0x367e70360e120e0e, 0x733c8173bddabdbd, 0x7f206a7f4ade4a4a,
    0x6ffb136fe825e8e8, 0xf452c4f496a79696, 0x04ff5904a6f7a6a6, 0x3c6c603c0c140c0c,
    0xcfc60ecfc845c8c8, 0x8096ef80798b7979, 0x76358976bcd9bcbc, 0x7c27997cbedfbebe,
    0x74c42b74ef2cefef, 0xcb3957cb6eb26e6e, 0x434c0a4346ca4646, 0xf15bccf197a49797,
    0x2ab9e22a5bed5b5b, 0x7ed63b7eed2aeded, 0x7dd1c87d192b1919, 0x9a5f869ad976d9d9,
    0x26a50926ace9acac, 0xc725bcc799b69999, 0x32812932a8e5a8a8, 0x8d7c558d297b2929,
    0xe96307e964ac6464, 0x63e7f8631f211f1f, 0x23ac0123adeaadad, 0x1cc7921c55ff5555,
    0x5f8b985f13351313, 0x6d0ab16dbbd0bbbb, 0x0c1ceb0cf704f7f7, 0xce305fce6fb16f6f,
    0x6718a167b9d6b9b9, 0x4645024647c94747, 0x934a65932f712f2f, 0x71cd2371ee2feeee,
    0x6211a962b8d5b8b8, 0x8a84ff8a7b8d7b7b, 0x97b53c9789868989, 0xf0ad9df030503030,
    0xb805d6b8d368d3d3, 0x9ea0df9e7f817f7f, 0xb3e197b3769a7676, 0xb0e664b0829b8282
  },
  {
    0x78d8c07818281818, 0xaf2605af23652323, 0xf9b87ef9c657c6c6, 0x6ffb136fe825e8e8,
    0xa1cb4ca187948787, 0x6211a962b8d5b8b8, 0x0509080501030101, 0x6e0d426e4fd14f4f,
    0xee9badee365a3636, 0x04ff5904a6f7a6a6, 0xbd0cdebdd26bd2d2, 0x060efb06f502f5f5,
    0x8096ef80798b7979, 0xce305fce6fb16f6f, 0xef6dfcef91ae9191, 0x07f8aa0752f65252,
    0xfd4727fd60a06060, 0x76358976bcd9bcbc, 0xcd37accd9bb09b9b, 0x8c8a048c8e8f8e8e,
    0x15d27115a3f8a3a3, 0x3c6c603c0c140c0c, 0x8a84ff8a7b8d7b7b, 0xe180b5e1355f3535,
    0x69f5e8691d271d1d, 0x47b35347e03de0e0, 0xac21f6acd764d7d7, 0xed9c5eedc25bc2c2,
    0x96436d962e722e2e, 0x7a29627a4bdd4b4b, 0x215da321fe1ffefe, 0x16d5821657f95757,
    0x41bda841153f1515, 0xb6e89fb677997777, 0xeb92a5eb37593737, 0x569e7b56e532e5e5,
    0xd9138cd99fbc9f9f, 0x1723d317f00df0f0, 0x7f206a7f4ade4a4a, 0x95449e95da73dada,
    0x25a2fa2558e85858, 0xcacf06cac946c9c9, 0x8d7c558d297b2929, 0x225a50220a1e0a0a,
    0x4f50e14fb1ceb1b1, 0x1ac9691aa0fda0a0, 0xda147fda6bbd6b6b, 0xabd95cab85928585,
    0x733c8173bddabdbd, 0x348fd2345de75d5d, 0x5090805010301010, 0x0307f303f401f4f4,
    0xc0dd16c0cb40cbcb, 0xc6d3edc63e423e3e, 0x112d2811050f0505, 0xe6781fe667a96767,
    0x53977353e431e4e4, 0xbb0225bb27692727, 0x5873325841c34141, 0x9da72c9d8b808b8b,
    0x01f65101a7f4a7a7, 0x94b2cf947d877d7d, 0xfb49dcfb95a29595, 0x9f568e9fd875d8d8,
    0x30708b30fb10fbfb, 0x71cd2371ee2feeee, 0x91bbc7917c847c7c, 0xe37117e366aa6666,
    0x8e7ba68edd7adddd, 0x4bafb84b17391717, 0x4645024647c94747, 0xdc1a84dc9ebf9e9e,
    0xc5d41ec5ca43caca, 0x995875992d772d2d, 0x792e9179bfdcbfbf, 0x1b3f381b07090707,
    0x23ac0123adeaadad, 0x2fb0ea2f5aee5a5a, 0xb5ef6cb583988383, 0xffb685ff33553333,
    0xf25c3ff263a56363, 0x0a12100a02060202, 0x38933938aae3aaaa, 0xa8deafa871937171,
    0xcfc60ecfc845c8c8, 0x7dd1c87d192b1919, 0x703b727049db4949, 0x9a5f869ad976d9d9,
    0x1d31c31df20bf2f2, 0x48a84b48e338e3e3, 0x2ab9e22a5bed5b5b, 0x92bc349288858888,
    0xc83ea4c89ab39a9a, 0xbe0b2dbe266a2626, 0xfabf8dfa32563232, 0x4a59e94ab0cdb0b0,
    0x6af21b6ae926e9e9, 0x337778330f110f0f, 0xa633e6a6d562d5d5, 0xbaf474ba809d8080,
    0x7c27997cbedfbebe, 0xdeeb26decd4acdcd, 0xe489bde4345c3434, 0x75327a7548d84848,
    0x2454ab24ff1cffff, 0x8f8df78f7a8e7a7a, 0xea64f4ea90ad9090, 0x3e9dc23e5fe15f5f,
    0xa03d1da020602020, 0xd50f67d568b86868, 0x72cad0721a2e1a1a, 0x2cb7192caeefaeae,
    0x5e7dc95eb4c1b4b4, 0x19ce9a1954fc5454, 0xe57fece593a89393, 0xaa2f0daa22662222,
    0xe96307e964ac6464, 0x122adb12f10ef1f1, 0xa2ccbfa273957373, 0x5a82905a12361212,
    0x5d7a3a5d40c04040, 0x2848402808180808, 0xe89556e8c358c3c3, 0x7bdf337bec29ecec,
    0x904d9690db70dbdb, 0x1fc0611fa1fea1a1, 0x83911c838d8a8d8d, 0xc9c8f5c93d473d3d,
    0xf15bccf197a49797, 0x0000000000000000, 0xd4f936d4cf4ccfcf, 0x876e45872b7d2b2b,
    0xb3e197b3769a7676, 0xb0e664b0829b8282, 0xa928fea9d667d6d6, 0x77c3d8771b2d1b1b,
    0x5b74c15bb5c2b5b5, 0x29be1129afecafaf, 0xdf1d77df6abe6a6a, 0x0deaba0d50f05050,
    0x4c57124c45cf4545, 0x1838cb18f308f3f3, 0xf0ad9df030503030, 0x74c42b74ef2cefef,
    0xc3dae5c33f413f3f, 0x1cc7921c55ff5555, 0x10db7910a2fba2a2, 0x65e90365ea23eaea,
    0xec6a0fec65af6565, 0x6803b968bad3baba, 0x934a65932f712f2f, 0xe78e4ee7c05dc0c0,
    0x8160be81de7fdede, 0x6cfce06c1c241c1c, 0x2e46bb2efd1afdfd, 0x641f52644dd74d4d,
    0xe076e4e092ab9292, 0xbcfa8fbc759f7575, 0x1e36301e060a0606, 0x98ae24988a838a8a,
    0x404bf940b2cbb2b2, 0x59856359e637e6e6, 0x367e70360e120e0e, 0x63e7f8631f211f1f,
    0xf75537f762a66262, 0xa33aeea3d461d4d4, 0x32812932a8e5a8a8, 0xf452c4f496a79696,
    0x3a629b3af916f9f9, 0xf6a366f6c552c5c5, 0xb11035b1256f2525, 0x20abf22059eb5959,
    0xaed054ae84918484, 0xa7c5b7a772967272, 0xddecd5dd394b3939, 0x61165a614cd44c4c,
    0x3b94ca3b5ee25e5e, 0x859fe78578887878, 0xd8e5ddd838483838, 0x869814868c898c8c,
    0xb217c6b2d16ed1d1, 0x0be4410ba5f2a5a5, 0x4da1434de23be2e2, 0xf84e2ff861a36161,
    0x4542f145b3c8b3b3, 0xa53415a521632121, 0xd60894d69cb99c9c, 0x66eef0661e221e1e,
    0x5261225243c54343, 0xfcb176fcc754c7c7, 0x2b4fb32bfc19fcfc, 0x14242014040c0404,
    0x08e3b20851f35151, 0xc725bcc799b69999, 0xc4224fc46db76d6d, 0x396568390d170d0d,
    0x35798335fa13fafa, 0x8469b684df7cdfdf, 0x9ba9d79b7e827e7e, 0xb4193db4246c2424,
    0xd7fec5d73b4d3b3b, 0x3d9a313dabe0abab, 0xd1f03ed1ce4fcece, 0x5599885511331111,
    0x89830c898f8c8f8f, 0x6b044a6b4ed24e4e, 0x5166d151b7c4b7b7, 0x60e00b60eb20ebeb,
    0xccc1fdcc3c443c3c, 0xbffd7cbf819e8181, 0xfe40d4fe94a19494, 0x0c1ceb0cf704f7f7,
    0x6718a167b9d6b9b9, 0x5f8b985f13351313, 0x9c517d9c2c742c2c, 0xb805d6b8d368d3d3,
    0x5c8c6b5ce734e7e7, 0xcb3957cb6eb26e6e, 0xf3aa6ef3c451c4c4, 0x0f1b180f03050303,
    0x13dc8a1356fa5656, 0x495e1a4944cc4444, 0x9ea0df9e7f817f7f, 0x37882137a9e6a9a9,
    0x82674d822a7e2a2a, 0x6d0ab16dbbd0bbbb, 0xe28746e2c15ec1c1, 0x02f1a20253f55353,
    0x8b72ae8bdc79dcdc, 0x275358270b1d0b0b, 0xd3019cd39dba9d9d, 0xc12b47c16cb46c6c,
    0xf5a495f531533131, 0xb9f387b9749c7474, 0x0915e309f607f6f6, 0x434c0a4346ca4646,
    0x26a50926ace9acac, 0x97b53c9789868989, 0x44b4a044143c1414, 0x42ba5b42e13ee1e1,
    0x4ea6b04e163a1616, 0xd2f7cdd23a4e3a3a, 0xd0066fd069bb6969, 0x2d41482d091b0909,
    0xadd7a7ad70907070, 0x546fd954b6c7b6b6, 0xb71eceb7d06dd0d0, 0x7ed63b7eed2aeded,
    0xdbe22edbcc49cccc, 0x57682a5742c64242, 0xc22cb4c298b59898, 0x0eed490ea4f1a4a4,
    0x88755d8828782828, 0x3186da315ce45c5c, 0x3f6b933ff815f8f8, 0xa4c244a486978686
  },
};

// The round constants of each variant. Constant r holds the S-box outputs of 8r to 8r+7, the first
// one in the low bits.

CONSTANT_VK u64a whirlpool01_rc[2][10] =
{
  {
    0xe46a9d482bebd068, 0x9e85f17d8156a3e3, 0xd561a917ca788e2c, 0x422251773c8c0b5d,
    0x18b386cc8041543f, 0x6bd136f46206572e, 0xf92649da1075651b, 0xab5250aebae766cb,
    0xfe20043b730df005, 0xa0c0b50a5fb4f5dd
  },
  {
    0x4f01b887e8c62318, 0x52916f79f5d2a636, 0x357b0ca38e9bbc60, 0x57fe4b2ec2d7e01d,
    0xda4af09fe5377715, 0x856ba0b10a29c958, 0x67053ecbf4105dbd, 0xd8957da78b4127e4,
    0x9e4717dd667ceefb, 0x33835aad07bf2dca
  },
};

#if   VECT_SIZE == 1
#define WHIRLPOOL01_BOX(S,i) ((S)[(i)])
#elif VECT_SIZE == 2
#define WHIRLPOOL01_BOX(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1])
#elif VECT_SIZE == 4
#define WHIRLPOOL01_BOX(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#elif VECT_SIZE == 8
#define WHIRLPOOL01_BOX(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#elif VECT_SIZE == 16
#define WHIRLPOOL01_BOX(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#endif

#define WHIRLPOOL01_BOX_S(S,i) ((S)[(i)])

// Row D of a round over the state A, whose word i is row i. Column j of D takes its input byte from
// row Bj, which is the cyclic shift of the columns. Each lookup, rotated by j bytes, does the S-box
// and the share of that byte in the diffusion of the row.

#define WHIRLPOOL01_ELT(TI,L,BOX,ROTL,S,D,A,B0,B1,B2,B3,B4,B5,B6,B7)            \
{                                                                               \
  const TI i0 = L ((A)[B0] >>  0) & 0xff;                                       \
  const TI i1 = L ((A)[B1] >>  8) & 0xff;                                       \
  const TI i2 = L ((A)[B2] >> 16) & 0xff;                                       \
  const TI i3 = L ((A)[B3] >> 24) & 0xff;                                       \
  const TI i4 = L ((A)[B4] >> 32) & 0xff;                                       \
  const TI i5 = L ((A)[B5] >> 40) & 0xff;                                       \
  const TI i6 = L ((A)[B6] >> 48) & 0xff;                                       \
  const TI i7 = L ((A)[B7] >> 56) & 0xff;                                       \
                                                                                \
  (D) = BOX (S, i0)                                                             \
      ^ ROTL (BOX (S, i1),  8)                                                  \
      ^ ROTL (BOX (S, i2), 16)                                                  \
      ^ ROTL (BOX (S, i3), 24)                                                  \
      ^ ROTL (BOX (S, i4), 32)                                                  \
      ^ ROTL (BOX (S, i5), 40)                                                  \
      ^ ROTL (BOX (S, i6), 48)                                                  \
      ^ ROTL (BOX (S, i7), 56);                                                 \
}

#define WHIRLPOOL01_ROUND(TI,L,BOX,ROTL,S,D,A)                                  \
{                                                                               \
  WHIRLPOOL01_ELT (TI, L, BOX, ROTL, S, (D)[0], A, 0, 7, 6, 5, 4, 3, 2, 1);     \
  WHIRLPOOL01_ELT (TI, L, BOX, ROTL, S, (D)[1], A, 1, 0, 7, 6, 5, 4, 3, 2);     \
  WHIRLPOOL01_ELT (TI, L, BOX, ROTL, S, (D)[2], A, 2, 1, 0, 7, 6, 5, 4, 3);     \
  WHIRLPOOL01_ELT (TI, L, BOX, ROTL, S, (D)[3], A, 3, 2, 1, 0, 7, 6, 5, 4);     \
  WHIRLPOOL01_ELT (TI, L, BOX, ROTL, S, (D)[4], A, 4, 3, 2, 1, 0, 7, 6, 5);     \
  WHIRLPOOL01_ELT (TI, L, BOX, ROTL, S, (D)[5], A, 5, 4, 3, 2, 1, 0, 7, 6);     \
  WHIRLPOOL01_ELT (TI, L, BOX, ROTL, S, (D)[6], A, 6, 5, 4, 3, 2, 1, 0, 7);     \
  WHIRLPOOL01_ELT (TI, L, BOX, ROTL, S, (D)[7], A, 7, 6, 5, 4, 3, 2, 1, 0);     \
}

// The compression function: the block cipher W with h as the key encrypts the block m, and the
// result, h and m are added. Each of the 10 rounds derives the next round key from the last one,
// with the round constant in its first word, and adds it to the round of the data.

DECLSPEC void whirlpool01_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u32 *w, SHM_TYPE u64a *s_wrl, const int var)
{
  u64 m[8];
  u64 k[8];
  u64 s[8];

  for (u32 i = 0; i < 8; i++)
  {
    m[i] = hl32_to_64_S (w[(i * 2) + 1], w[(i * 2) + 0]);
    k[i] = h[i];
    s[i] = m[i] ^ k[i];
  }

  for (u32 r = 0; r < 10; r++)
  {
    u64 t[8];

    WHIRLPOOL01_ROUND (u32, l32_from_64_S, WHIRLPOOL01_BOX_S, hc_rotl64_S, s_wrl, t, k);

    t[0] ^= whirlpool01_rc[var][r];

    for (u32 i = 0; i < 8; i++) k[i] = t[i];

    WHIRLPOOL01_ROUND (u32, l32_from_64_S, WHIRLPOOL01_BOX_S, hc_rotl64_S, s_wrl, t, s);

    for (u32 i = 0; i < 8; i++) s[i] = t[i] ^ k[i];
  }

  for (u32 i = 0; i < 8; i++) h[i] ^= s[i] ^ m[i];
}

// The initial state is zero.

DECLSPEC void whirlpool01_init (PRIVATE_AS whirlpool01_ctx_t *ctx, SHM_TYPE u64a (*s_whirlpool01)[256], const int var)
{
  for (u32 i = 0; i < 8; i++) ctx->h[i] = 0;

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
  ctx->var = var;

  ctx->s_wrl = s_whirlpool01[var];
}

DECLSPEC void whirlpool01_block (PRIVATE_AS whirlpool01_ctx_t *ctx)
{
  whirlpool01_transform (ctx->h, ctx->w, ctx->s_wrl, ctx->var);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

// Add the n bytes of v to the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, hash it and use any remaining
// bytes to start the next block.

DECLSPEC void whirlpool01_absorb (PRIVATE_AS whirlpool01_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32 x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->w[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    whirlpool01_block (ctx);

    if (n > fit)
    {
      ctx->w[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void whirlpool01_update (PRIVATE_AS whirlpool01_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    whirlpool01_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void whirlpool01_absorb_utf16le (PRIVATE_AS whirlpool01_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  whirlpool01_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) whirlpool01_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void whirlpool01_update_utf16le (PRIVATE_AS whirlpool01_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      whirlpool01_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    whirlpool01_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void whirlpool01_update_global (PRIVATE_AS whirlpool01_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    whirlpool01_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void whirlpool01_update_global_utf16le (PRIVATE_AS whirlpool01_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      whirlpool01_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    whirlpool01_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The padding is a 0x80 byte, zeros up to byte 32 of a block and the message length in bits, as a
// big endian 256 bit number. Only its last 8 bytes can be nonzero for the lengths of an int. A
// context with invalid UTF-8 input produces a digest with every bit flipped, so that no candidate
// matches it by chance.

DECLSPEC void whirlpool01_final (PRIVATE_AS whirlpool01_ctx_t *ctx)
{
  const u64 bits = ((u64) (u32) ctx->len) << 3;

  whirlpool01_absorb (ctx, 0x80, 1);

  if (ctx->pos > 32) whirlpool01_block (ctx);

  ctx->w[14] = hc_swap32_S (h32_from_64_S (bits));
  ctx->w[15] = hc_swap32_S (l32_from_64_S (bits));

  whirlpool01_block (ctx);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 8; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void whirlpool01_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u32x *w, SHM_TYPE u64a *s_wrl, const int var)
{
  u64x m[8];
  u64x k[8];
  u64x s[8];

  for (u32 i = 0; i < 8; i++)
  {
    m[i] = hl32_to_64 (w[(i * 2) + 1], w[(i * 2) + 0]);
    k[i] = h[i];
    s[i] = m[i] ^ k[i];
  }

  for (u32 r = 0; r < 10; r++)
  {
    u64x t[8];

    WHIRLPOOL01_ROUND (u32x, l32_from_64, WHIRLPOOL01_BOX, hc_rotl64, s_wrl, t, k);

    t[0] ^= whirlpool01_rc[var][r];

    for (u32 i = 0; i < 8; i++) k[i] = t[i];

    WHIRLPOOL01_ROUND (u32x, l32_from_64, WHIRLPOOL01_BOX, hc_rotl64, s_wrl, t, s);

    for (u32 i = 0; i < 8; i++) s[i] = t[i] ^ k[i];
  }

  for (u32 i = 0; i < 8; i++) h[i] ^= s[i] ^ m[i];
}

DECLSPEC void whirlpool01_init_vector (PRIVATE_AS whirlpool01_ctx_vector_t *ctx, SHM_TYPE u64a (*s_whirlpool01)[256], const int var)
{
  for (u32 i = 0; i < 8; i++) ctx->h[i] = 0;

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
  ctx->var = var;

  ctx->s_wrl = s_whirlpool01[var];
}

DECLSPEC void whirlpool01_block_vector (PRIVATE_AS whirlpool01_ctx_vector_t *ctx)
{
  whirlpool01_transform_vector (ctx->h, ctx->w, ctx->s_wrl, ctx->var);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void whirlpool01_absorb_vector (PRIVATE_AS whirlpool01_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->w[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    whirlpool01_block_vector (ctx);

    if (n > fit)
    {
      ctx->w[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void whirlpool01_update_vector (PRIVATE_AS whirlpool01_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    whirlpool01_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void whirlpool01_update_vector_utf16le (PRIVATE_AS whirlpool01_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    whirlpool01_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) whirlpool01_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void whirlpool01_final_vector (PRIVATE_AS whirlpool01_ctx_vector_t *ctx)
{
  const u64 bits = ((u64) (u32) ctx->len) << 3;

  whirlpool01_absorb_vector (ctx, make_u32x (0x80), 1);

  if (ctx->pos > 32) whirlpool01_block_vector (ctx);

  ctx->w[14] = hc_swap32_S (h32_from_64_S (bits));
  ctx->w[15] = hc_swap32_S (l32_from_64_S (bits));

  whirlpool01_block_vector (ctx);
}
