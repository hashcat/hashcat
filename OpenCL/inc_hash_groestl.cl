/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_groestl.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off. State word i holds column i of the Groestl state, its first byte in
// the low bits, so 2 input words make one state word.

// The table T0 of the Groestl submission in that byte order. Each entry is the MixBytes column of
// an S-box output. The submission's T1 to T7 are T0 rotated left by 8 to 56 bits, and the rounds
// rotate rather than read 7 more tables, which keeps the table at 2 KiB of shared memory.

CONSTANT_VK u64a groestl_t0[256] =
{
  0xc6a597f4a5f432c6, 0xf884eb9784976ff8, 0xee99c7b099b05eee, 0xf68df78c8d8c7af6,
  0xff0de5170d17e8ff, 0xd6bdb7dcbddc0ad6, 0xdeb1a7c8b1c816de, 0x915439fc54fc6d91,
  0x6050c0f050f09060, 0x0203040503050702, 0xcea987e0a9e02ece, 0x567dac877d87d156,
  0xe719d52b192bcce7, 0xb56271a662a613b5, 0x4de69a31e6317c4d, 0xec9ac3b59ab559ec,
  0x8f4505cf45cf408f, 0x1f9d3ebc9dbca31f, 0x894009c040c04989, 0xfa87ef92879268fa,
  0xef15c53f153fd0ef, 0xb2eb7f26eb2694b2, 0x8ec90740c940ce8e, 0xfb0bed1d0b1de6fb,
  0x41ec822fec2f6e41, 0xb3677da967a91ab3, 0x5ffdbe1cfd1c435f, 0x45ea8a25ea256045,
  0x23bf46dabfdaf923, 0x53f7a602f7025153, 0xe496d3a196a145e4, 0x9b5b2ded5bed769b,
  0x75c2ea5dc25d2875, 0xe11cd9241c24c5e1, 0x3dae7ae9aee9d43d, 0x4c6a98be6abef24c,
  0x6c5ad8ee5aee826c, 0x7e41fcc341c3bd7e, 0xf502f1060206f3f5, 0x834f1dd14fd15283,
  0x685cd0e45ce48c68, 0x51f4a207f4075651, 0xd134b95c345c8dd1, 0xf908e9180818e1f9,
  0xe293dfae93ae4ce2, 0xab734d9573953eab, 0x6253c4f553f59762, 0x2a3f54413f416b2a,
  0x080c10140c141c08, 0x955231f652f66395, 0x46658caf65afe946, 0x9d5e21e25ee27f9d,
  0x3028607828784830, 0x37a16ef8a1f8cf37, 0x0a0f14110f111b0a, 0x2fb55ec4b5c4eb2f,
  0x0e091c1b091b150e, 0x2436485a365a7e24, 0x1b9b36b69bb6ad1b, 0xdf3da5473d4798df,
  0xcd26816a266aa7cd, 0x4e699cbb69bbf54e, 0x7fcdfe4ccd4c337f, 0xea9fcfba9fba50ea,
  0x121b242d1b2d3f12, 0x1d9e3ab99eb9a41d, 0x5874b09c749cc458, 0x342e68722e724634,
  0x362d6c772d774136, 0xdcb2a3cdb2cd11dc, 0xb4ee7329ee299db4, 0x5bfbb616fb164d5b,
  0xa4f65301f601a5a4, 0x764decd74dd7a176, 0xb76175a361a314b7, 0x7dcefa49ce49347d,
  0x527ba48d7b8ddf52, 0xdd3ea1423e429fdd, 0x5e71bc937193cd5e, 0x139726a297a2b113,
  0xa6f55704f504a2a6, 0xb96869b868b801b9, 0x0000000000000000, 0xc12c99742c74b5c1,
  0x406080a060a0e040, 0xe31fdd211f21c2e3, 0x79c8f243c8433a79, 0xb6ed772ced2c9ab6,
  0xd4beb3d9bed90dd4, 0x8d4601ca46ca478d, 0x67d9ce70d9701767, 0x724be4dd4bddaf72,
  0x94de3379de79ed94, 0x98d42b67d467ff98, 0xb0e87b23e82393b0, 0x854a11de4ade5b85,
  0xbb6b6dbd6bbd06bb, 0xc52a917e2a7ebbc5, 0x4fe59e34e5347b4f, 0xed16c13a163ad7ed,
  0x86c51754c554d286, 0x9ad72f62d762f89a, 0x6655ccff55ff9966, 0x119422a794a7b611,
  0x8acf0f4acf4ac08a, 0xe910c9301030d9e9, 0x0406080a060a0e04, 0xfe81e798819866fe,
  0xa0f05b0bf00baba0, 0x7844f0cc44ccb478, 0x25ba4ad5bad5f025, 0x4be3963ee33e754b,
  0xa2f35f0ef30eaca2, 0x5dfeba19fe19445d, 0x80c01b5bc05bdb80, 0x058a0a858a858005,
  0x3fad7eecadecd33f, 0x21bc42dfbcdffe21, 0x7048e0d848d8a870, 0xf104f90c040cfdf1,
  0x63dfc67adf7a1963, 0x77c1ee58c1582f77, 0xaf75459f759f30af, 0x426384a563a5e742,
  0x2030405030507020, 0xe51ad12e1a2ecbe5, 0xfd0ee1120e12effd, 0xbf6d65b76db708bf,
  0x814c19d44cd45581, 0x1814303c143c2418, 0x26354c5f355f7926, 0xc32f9d712f71b2c3,
  0xbee16738e13886be, 0x35a26afda2fdc835, 0x88cc0b4fcc4fc788, 0x2e395c4b394b652e,
  0x93573df957f96a93, 0x55f2aa0df20d5855, 0xfc82e39d829d61fc, 0x7a47f4c947c9b37a,
  0xc8ac8befacef27c8, 0xbae76f32e73288ba, 0x322b647d2b7d4f32, 0xe695d7a495a442e6,
  0xc0a09bfba0fb3bc0, 0x199832b398b3aa19, 0x9ed12768d168f69e, 0xa37f5d817f8122a3,
  0x446688aa66aaee44, 0x547ea8827e82d654, 0x3bab76e6abe6dd3b, 0x0b83169e839e950b,
  0x8cca0345ca45c98c, 0xc729957b297bbcc7, 0x6bd3d66ed36e056b, 0x283c50443c446c28,
  0xa779558b798b2ca7, 0xbce2633de23d81bc, 0x161d2c271d273116, 0xad76419a769a37ad,
  0xdb3bad4d3b4d96db, 0x6456c8fa56fa9e64, 0x744ee8d24ed2a674, 0x141e28221e223614,
  0x92db3f76db76e492, 0x0c0a181e0a1e120c, 0x486c90b46cb4fc48, 0xb8e46b37e4378fb8,
  0x9f5d25e75de7789f, 0xbd6e61b26eb20fbd, 0x43ef862aef2a6943, 0xc4a693f1a6f135c4,
  0x39a872e3a8e3da39, 0x31a462f7a4f7c631, 0xd337bd5937598ad3, 0xf28bff868b8674f2,
  0xd532b156325683d5, 0x8b430dc543c54e8b, 0x6e59dceb59eb856e, 0xdab7afc2b7c218da,
  0x018c028f8c8f8e01, 0xb16479ac64ac1db1, 0x9cd2236dd26df19c, 0x49e0923be03b7249,
  0xd8b4abc7b4c71fd8, 0xacfa4315fa15b9ac, 0xf307fd090709faf3, 0xcf25856f256fa0cf,
  0xcaaf8feaafea20ca, 0xf48ef3898e897df4, 0x47e98e20e9206747, 0x1018202818283810,
  0x6fd5de64d5640b6f, 0xf088fb83888373f0, 0x4a6f94b16fb1fb4a, 0x5c72b8967296ca5c,
  0x3824706c246c5438, 0x57f1ae08f1085f57, 0x73c7e652c7522173, 0x975135f351f36497,
  0xcb238d652365aecb, 0xa17c59847c8425a1, 0xe89ccbbf9cbf57e8, 0x3e217c6321635d3e,
  0x96dd377cdd7cea96, 0x61dcc27fdc7f1e61, 0x0d861a9186919c0d, 0x0f851e9485949b0f,
  0xe090dbab90ab4be0, 0x7c42f8c642c6ba7c, 0x71c4e257c4572671, 0xccaa83e5aae529cc,
  0x90d83b73d873e390, 0x06050c0f050f0906, 0xf701f5030103f4f7, 0x1c12383612362a1c,
  0xc2a39ffea3fe3cc2, 0x6a5fd4e15fe18b6a, 0xaef94710f910beae, 0x69d0d26bd06b0269,
  0x17912ea891a8bf17, 0x995829e858e87199, 0x3a2774692769533a, 0x27b94ed0b9d0f727,
  0xd938a948384891d9, 0xeb13cd351335deeb, 0x2bb356ceb3cee52b, 0x2233445533557722,
  0xd2bbbfd6bbd604d2, 0xa9704990709039a9, 0x07890e8089808707, 0x33a766f2a7f2c133,
  0x2db65ac1b6c1ec2d, 0x3c22786622665a3c, 0x15922aad92adb815, 0xc92089602060a9c9,
  0x874915db49db5c87, 0xaaff4f1aff1ab0aa, 0x5078a0887888d850, 0xa57a518e7a8e2ba5,
  0x038f068a8f8a8903, 0x59f8b213f8134a59, 0x0980129b809b9209, 0x1a1734391739231a,
  0x65daca75da751065, 0xd731b553315384d7, 0x84c61351c651d584, 0xd0b8bbd3b8d303d0,
  0x82c31f5ec35edc82, 0x29b052cbb0cbe229, 0x5a77b4997799c35a, 0x1e113c3311332d1e,
  0x7bcbf646cb463d7b, 0xa8fc4b1ffc1fb7a8, 0x6dd6da61d6610c6d, 0x2c3a584e3a4e622c,
};

#if   VECT_SIZE == 1
#define GROESTL_BOX(S,i) ((S)[(i)])
#elif VECT_SIZE == 2
#define GROESTL_BOX(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1])
#elif VECT_SIZE == 4
#define GROESTL_BOX(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#elif VECT_SIZE == 8
#define GROESTL_BOX(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#elif VECT_SIZE == 16
#define GROESTL_BOX(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#endif

#define GROESTL_BOX_S(S,i) ((S)[(i)])

// One column D of a round. Row k of it comes from column Bk of A, which is ShiftBytes, and the
// lookup with its rotation by row does SubBytes and MixBytes.

#define GROESTL_COL(TI,L,BOX,ROTL,S,D,A,B0,B1,B2,B3,B4,B5,B6,B7)                \
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

// The permutations P and Q differ in their round constants and in the shifts of the rows. P adds
// its constant to the first row. Q inverts the state and adds its constant to the last row. The
// 512 bit state has 8 columns and 10 rounds, the 1024 bit state 16 columns and 14 rounds.

#define GROESTL_PERM_SMALL_P(T,TI,L,BOX,ROTL,S,A)                               \
{                                                                               \
  for (u32 r = 0; r < 10; r++)                                                  \
  {                                                                             \
    for (u32 i = 0; i < 8; i++) (A)[i] ^= (u64) ((i << 4) | r);                 \
                                                                                \
    T t[8];                                                                     \
                                                                                \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[0], A, 0, 1, 2, 3, 4, 5, 6, 7);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[1], A, 1, 2, 3, 4, 5, 6, 7, 0);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[2], A, 2, 3, 4, 5, 6, 7, 0, 1);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[3], A, 3, 4, 5, 6, 7, 0, 1, 2);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[4], A, 4, 5, 6, 7, 0, 1, 2, 3);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[5], A, 5, 6, 7, 0, 1, 2, 3, 4);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[6], A, 6, 7, 0, 1, 2, 3, 4, 5);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[7], A, 7, 0, 1, 2, 3, 4, 5, 6);         \
                                                                                \
    for (u32 i = 0; i < 8; i++) (A)[i] = t[i];                                  \
  }                                                                             \
}

#define GROESTL_PERM_SMALL_Q(T,TI,L,BOX,ROTL,S,A)                               \
{                                                                               \
  for (u32 r = 0; r < 10; r++)                                                  \
  {                                                                             \
    for (u32 i = 0; i < 8; i++) (A)[i] ^= ~((u64) ((i << 4) | r) << 56);        \
                                                                                \
    T t[8];                                                                     \
                                                                                \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[0], A, 1, 3, 5, 7, 0, 2, 4, 6);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[1], A, 2, 4, 6, 0, 1, 3, 5, 7);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[2], A, 3, 5, 7, 1, 2, 4, 6, 0);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[3], A, 4, 6, 0, 2, 3, 5, 7, 1);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[4], A, 5, 7, 1, 3, 4, 6, 0, 2);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[5], A, 6, 0, 2, 4, 5, 7, 1, 3);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[6], A, 7, 1, 3, 5, 6, 0, 2, 4);         \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[7], A, 0, 2, 4, 6, 7, 1, 3, 5);         \
                                                                                \
    for (u32 i = 0; i < 8; i++) (A)[i] = t[i];                                  \
  }                                                                             \
}

#define GROESTL_PERM_BIG_P(T,TI,L,BOX,ROTL,S,A)                                  \
{                                                                                \
  for (u32 r = 0; r < 14; r++)                                                   \
  {                                                                              \
    for (u32 i = 0; i < 16; i++) (A)[i] ^= (u64) ((i << 4) | r);                 \
                                                                                 \
    T t[16];                                                                     \
                                                                                 \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 0], A,  0,  1,  2,  3,  4,  5,  6, 11); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 1], A,  1,  2,  3,  4,  5,  6,  7, 12); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 2], A,  2,  3,  4,  5,  6,  7,  8, 13); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 3], A,  3,  4,  5,  6,  7,  8,  9, 14); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 4], A,  4,  5,  6,  7,  8,  9, 10, 15); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 5], A,  5,  6,  7,  8,  9, 10, 11,  0); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 6], A,  6,  7,  8,  9, 10, 11, 12,  1); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 7], A,  7,  8,  9, 10, 11, 12, 13,  2); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 8], A,  8,  9, 10, 11, 12, 13, 14,  3); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 9], A,  9, 10, 11, 12, 13, 14, 15,  4); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[10], A, 10, 11, 12, 13, 14, 15,  0,  5); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[11], A, 11, 12, 13, 14, 15,  0,  1,  6); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[12], A, 12, 13, 14, 15,  0,  1,  2,  7); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[13], A, 13, 14, 15,  0,  1,  2,  3,  8); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[14], A, 14, 15,  0,  1,  2,  3,  4,  9); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[15], A, 15,  0,  1,  2,  3,  4,  5, 10); \
                                                                                 \
    for (u32 i = 0; i < 16; i++) (A)[i] = t[i];                                  \
  }                                                                              \
}

#define GROESTL_PERM_BIG_Q(T,TI,L,BOX,ROTL,S,A)                                  \
{                                                                                \
  for (u32 r = 0; r < 14; r++)                                                   \
  {                                                                              \
    for (u32 i = 0; i < 16; i++) (A)[i] ^= ~((u64) ((i << 4) | r) << 56);        \
                                                                                 \
    T t[16];                                                                     \
                                                                                 \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 0], A,  1,  3,  5, 11,  0,  2,  4,  6); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 1], A,  2,  4,  6, 12,  1,  3,  5,  7); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 2], A,  3,  5,  7, 13,  2,  4,  6,  8); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 3], A,  4,  6,  8, 14,  3,  5,  7,  9); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 4], A,  5,  7,  9, 15,  4,  6,  8, 10); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 5], A,  6,  8, 10,  0,  5,  7,  9, 11); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 6], A,  7,  9, 11,  1,  6,  8, 10, 12); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 7], A,  8, 10, 12,  2,  7,  9, 11, 13); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 8], A,  9, 11, 13,  3,  8, 10, 12, 14); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[ 9], A, 10, 12, 14,  4,  9, 11, 13, 15); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[10], A, 11, 13, 15,  5, 10, 12, 14,  0); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[11], A, 12, 14,  0,  6, 11, 13, 15,  1); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[12], A, 13, 15,  1,  7, 12, 14,  0,  2); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[13], A, 14,  0,  2,  8, 13, 15,  1,  3); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[14], A, 15,  1,  3,  9, 14,  0,  2,  4); \
    GROESTL_COL (TI, L, BOX, ROTL, S, t[15], A,  0,  2,  4, 10, 15,  1,  3,  5); \
                                                                                 \
    for (u32 i = 0; i < 16; i++) (A)[i] = t[i];                                  \
  }                                                                              \
}

// The scalar and the vector flavors of the permutations

#define GROESTL_PERM_SMALL_P_S(S,A) GROESTL_PERM_SMALL_P (u64, u32, l32_from_64_S, GROESTL_BOX_S, hc_rotl64_S, S, A)
#define GROESTL_PERM_SMALL_Q_S(S,A) GROESTL_PERM_SMALL_Q (u64, u32, l32_from_64_S, GROESTL_BOX_S, hc_rotl64_S, S, A)
#define GROESTL_PERM_BIG_P_S(S,A)   GROESTL_PERM_BIG_P   (u64, u32, l32_from_64_S, GROESTL_BOX_S, hc_rotl64_S, S, A)
#define GROESTL_PERM_BIG_Q_S(S,A)   GROESTL_PERM_BIG_Q   (u64, u32, l32_from_64_S, GROESTL_BOX_S, hc_rotl64_S, S, A)

#define GROESTL_PERM_SMALL_P_V(S,A) GROESTL_PERM_SMALL_P (u64x, u32x, l32_from_64, GROESTL_BOX, hc_rotl64, S, A)
#define GROESTL_PERM_SMALL_Q_V(S,A) GROESTL_PERM_SMALL_Q (u64x, u32x, l32_from_64, GROESTL_BOX, hc_rotl64, S, A)
#define GROESTL_PERM_BIG_P_V(S,A)   GROESTL_PERM_BIG_P   (u64x, u32x, l32_from_64, GROESTL_BOX, hc_rotl64, S, A)
#define GROESTL_PERM_BIG_Q_V(S,A)   GROESTL_PERM_BIG_Q   (u64x, u32x, l32_from_64, GROESTL_BOX, hc_rotl64, S, A)

// groestl256: digests of 28 and 32 bytes, 64 byte blocks

// The compression function: P (h ^ m) ^ Q (m) ^ h

DECLSPEC void groestl256_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u32 *w, SHM_TYPE u64a *s_groestl)
{
  u64 g[8];
  u64 m[8];

  for (u32 i = 0; i < 8; i++)
  {
    m[i] = hl32_to_64_S (w[(i * 2) + 1], w[(i * 2) + 0]);
    g[i] = m[i] ^ h[i];
  }

  GROESTL_PERM_SMALL_P_S (s_groestl, g);
  GROESTL_PERM_SMALL_Q_S (s_groestl, m);

  for (u32 i = 0; i < 8; i++) h[i] ^= g[i] ^ m[i];
}

// The initial state is zero except for the digest size in bits, a big endian number in its last
// bytes.

DECLSPEC void groestl256_init (PRIVATE_AS groestl256_ctx_t *ctx, const int dlen, SHM_TYPE u64a *s_groestl)
{
  for (u32 i = 0; i < 7; i++) ctx->h[i] = 0;

  ctx->h[7] = hc_swap64_S ((u64) (dlen * 8));

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;

  ctx->s_groestl = s_groestl;
}

DECLSPEC void groestl256_block (PRIVATE_AS groestl256_ctx_t *ctx)
{
  groestl256_transform (ctx->h, ctx->w, ctx->s_groestl);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->cnt++;

  ctx->pos = 0;
}

// Add the n bytes of v to the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, hash it and use any remaining
// bytes to start the next block.

DECLSPEC void groestl256_absorb (PRIVATE_AS groestl256_ctx_t *ctx, const u32 v, const int n)
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
    groestl256_block (ctx);

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

DECLSPEC void groestl256_update (PRIVATE_AS groestl256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    groestl256_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void groestl256_absorb_utf16le (PRIVATE_AS groestl256_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  groestl256_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) groestl256_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void groestl256_update_utf16le (PRIVATE_AS groestl256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      groestl256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    groestl256_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void groestl256_update_global (PRIVATE_AS groestl256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    groestl256_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void groestl256_update_global_utf16le (PRIVATE_AS groestl256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      groestl256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    groestl256_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The padding is a 0x80 byte, zeros up to byte 56 of a block and the number of blocks including
// the padding, as a big endian 64 bit number. The output transform is P (h) ^ h, and the digest is
// the last dlen bytes of it, which this moves to the start of h. A context with invalid UTF-8
// input produces a digest with every bit flipped, so that no candidate matches it by chance.

DECLSPEC void groestl256_final (PRIVATE_AS groestl256_ctx_t *ctx)
{
  groestl256_absorb (ctx, 0x80, 1);

  if (ctx->pos > 56) groestl256_block (ctx);

  ctx->w[15] = hc_swap32_S (ctx->cnt + 1);

  groestl256_block (ctx);

  u64 x[8];

  for (u32 i = 0; i < 8; i++) x[i] = ctx->h[i];

  GROESTL_PERM_SMALL_P_S (ctx->s_groestl, x);

  for (u32 i = 4; i < 8; i++) ctx->h[i] ^= x[i];

  if (ctx->dlen == 28)
  {
    for (u32 i = 0; i < 3; i++) ctx->h[i] = (ctx->h[4 + i] >> 32) | (ctx->h[5 + i] << 32);

    ctx->h[3] = ctx->h[7] >> 32;
  }
  else
  {
    for (u32 i = 0; i < 4; i++) ctx->h[i] = ctx->h[4 + i];
  }

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 4; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void groestl256_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u32x *w, SHM_TYPE u64a *s_groestl)
{
  u64x g[8];
  u64x m[8];

  for (u32 i = 0; i < 8; i++)
  {
    m[i] = hl32_to_64 (w[(i * 2) + 1], w[(i * 2) + 0]);
    g[i] = m[i] ^ h[i];
  }

  GROESTL_PERM_SMALL_P_V (s_groestl, g);
  GROESTL_PERM_SMALL_Q_V (s_groestl, m);

  for (u32 i = 0; i < 8; i++) h[i] ^= g[i] ^ m[i];
}

DECLSPEC void groestl256_init_vector (PRIVATE_AS groestl256_ctx_vector_t *ctx, const int dlen, SHM_TYPE u64a *s_groestl)
{
  for (u32 i = 0; i < 7; i++) ctx->h[i] = 0;

  ctx->h[7] = make_u64x (hc_swap64_S ((u64) (dlen * 8)));

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;

  ctx->s_groestl = s_groestl;
}

DECLSPEC void groestl256_block_vector (PRIVATE_AS groestl256_ctx_vector_t *ctx)
{
  groestl256_transform_vector (ctx->h, ctx->w, ctx->s_groestl);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->cnt++;

  ctx->pos = 0;
}

DECLSPEC void groestl256_absorb_vector (PRIVATE_AS groestl256_ctx_vector_t *ctx, const u32x v, const int n)
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
    groestl256_block_vector (ctx);

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

DECLSPEC void groestl256_update_vector (PRIVATE_AS groestl256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    groestl256_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void groestl256_update_vector_utf16le (PRIVATE_AS groestl256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    groestl256_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) groestl256_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void groestl256_final_vector (PRIVATE_AS groestl256_ctx_vector_t *ctx)
{
  groestl256_absorb_vector (ctx, make_u32x (0x80), 1);

  if (ctx->pos > 56) groestl256_block_vector (ctx);

  ctx->w[15] = hc_swap32_S (ctx->cnt + 1);

  groestl256_block_vector (ctx);

  u64x x[8];

  for (u32 i = 0; i < 8; i++) x[i] = ctx->h[i];

  GROESTL_PERM_SMALL_P_V (ctx->s_groestl, x);

  for (u32 i = 4; i < 8; i++) ctx->h[i] ^= x[i];

  if (ctx->dlen == 28)
  {
    for (u32 i = 0; i < 3; i++) ctx->h[i] = (ctx->h[4 + i] >> 32) | (ctx->h[5 + i] << 32);

    ctx->h[3] = ctx->h[7] >> 32;
  }
  else
  {
    for (u32 i = 0; i < 4; i++) ctx->h[i] = ctx->h[4 + i];
  }
}

// groestl512: digests of 48 and 64 bytes, 128 byte blocks

DECLSPEC void groestl512_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u32 *w, SHM_TYPE u64a *s_groestl)
{
  u64 g[16];
  u64 m[16];

  for (u32 i = 0; i < 16; i++)
  {
    m[i] = hl32_to_64_S (w[(i * 2) + 1], w[(i * 2) + 0]);
    g[i] = m[i] ^ h[i];
  }

  GROESTL_PERM_BIG_P_S (s_groestl, g);
  GROESTL_PERM_BIG_Q_S (s_groestl, m);

  for (u32 i = 0; i < 16; i++) h[i] ^= g[i] ^ m[i];
}

DECLSPEC void groestl512_init (PRIVATE_AS groestl512_ctx_t *ctx, const int dlen, SHM_TYPE u64a *s_groestl)
{
  for (u32 i = 0; i < 15; i++) ctx->h[i] = 0;

  ctx->h[15] = hc_swap64_S ((u64) (dlen * 8));

  for (u32 i = 0; i < 32; i++) ctx->w[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;

  ctx->s_groestl = s_groestl;
}

DECLSPEC void groestl512_block (PRIVATE_AS groestl512_ctx_t *ctx)
{
  groestl512_transform (ctx->h, ctx->w, ctx->s_groestl);

  for (u32 i = 0; i < 32; i++) ctx->w[i] = 0;

  ctx->cnt++;

  ctx->pos = 0;
}

DECLSPEC void groestl512_absorb (PRIVATE_AS groestl512_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32 x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->w[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    groestl512_block (ctx);

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

DECLSPEC void groestl512_update (PRIVATE_AS groestl512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    groestl512_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void groestl512_absorb_utf16le (PRIVATE_AS groestl512_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  groestl512_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) groestl512_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void groestl512_update_utf16le (PRIVATE_AS groestl512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      groestl512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    groestl512_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void groestl512_update_global (PRIVATE_AS groestl512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    groestl512_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void groestl512_update_global_utf16le (PRIVATE_AS groestl512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      groestl512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    groestl512_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// As groestl256_final (), with the block count in bytes 120 to 127 and the digest taken from the
// last 64 bytes of the state.

DECLSPEC void groestl512_final (PRIVATE_AS groestl512_ctx_t *ctx)
{
  groestl512_absorb (ctx, 0x80, 1);

  if (ctx->pos > 120) groestl512_block (ctx);

  ctx->w[31] = hc_swap32_S (ctx->cnt + 1);

  groestl512_block (ctx);

  u64 x[16];

  for (u32 i = 0; i < 16; i++) x[i] = ctx->h[i];

  GROESTL_PERM_BIG_P_S (ctx->s_groestl, x);

  for (u32 i = 8; i < 16; i++) ctx->h[i] ^= x[i];

  if (ctx->dlen == 48)
  {
    for (u32 i = 0; i < 6; i++) ctx->h[i] = ctx->h[10 + i];
  }
  else
  {
    for (u32 i = 0; i < 8; i++) ctx->h[i] = ctx->h[8 + i];
  }

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 8; i++) ctx->h[i] = ~ctx->h[i];
  }
}

DECLSPEC void groestl512_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u32x *w, SHM_TYPE u64a *s_groestl)
{
  u64x g[16];
  u64x m[16];

  for (u32 i = 0; i < 16; i++)
  {
    m[i] = hl32_to_64 (w[(i * 2) + 1], w[(i * 2) + 0]);
    g[i] = m[i] ^ h[i];
  }

  GROESTL_PERM_BIG_P_V (s_groestl, g);
  GROESTL_PERM_BIG_Q_V (s_groestl, m);

  for (u32 i = 0; i < 16; i++) h[i] ^= g[i] ^ m[i];
}

DECLSPEC void groestl512_init_vector (PRIVATE_AS groestl512_ctx_vector_t *ctx, const int dlen, SHM_TYPE u64a *s_groestl)
{
  for (u32 i = 0; i < 15; i++) ctx->h[i] = 0;

  ctx->h[15] = make_u64x (hc_swap64_S ((u64) (dlen * 8)));

  for (u32 i = 0; i < 32; i++) ctx->w[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;

  ctx->s_groestl = s_groestl;
}

DECLSPEC void groestl512_block_vector (PRIVATE_AS groestl512_ctx_vector_t *ctx)
{
  groestl512_transform_vector (ctx->h, ctx->w, ctx->s_groestl);

  for (u32 i = 0; i < 32; i++) ctx->w[i] = 0;

  ctx->cnt++;

  ctx->pos = 0;
}

DECLSPEC void groestl512_absorb_vector (PRIVATE_AS groestl512_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->w[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    groestl512_block_vector (ctx);

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

DECLSPEC void groestl512_update_vector (PRIVATE_AS groestl512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    groestl512_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void groestl512_update_vector_utf16le (PRIVATE_AS groestl512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    groestl512_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) groestl512_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void groestl512_final_vector (PRIVATE_AS groestl512_ctx_vector_t *ctx)
{
  groestl512_absorb_vector (ctx, make_u32x (0x80), 1);

  if (ctx->pos > 120) groestl512_block_vector (ctx);

  ctx->w[31] = hc_swap32_S (ctx->cnt + 1);

  groestl512_block_vector (ctx);

  u64x x[16];

  for (u32 i = 0; i < 16; i++) x[i] = ctx->h[i];

  GROESTL_PERM_BIG_P_V (ctx->s_groestl, x);

  for (u32 i = 8; i < 16; i++) ctx->h[i] ^= x[i];

  if (ctx->dlen == 48)
  {
    for (u32 i = 0; i < 6; i++) ctx->h[i] = ctx->h[10 + i];
  }
  else
  {
    for (u32 i = 0; i < 8; i++) ctx->h[i] = ctx->h[8 + i];
  }
}
