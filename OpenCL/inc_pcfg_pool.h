/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_PCFG_POOL_H
#define INC_PCFG_POOL_H

// One logical array of words, handed over in up to PCFG_POOL_PARTS buffers.
//
// A device will not always allocate the whole pool in one block: the largest single allocation it
// offers is often a fraction of the memory it has. A grammar trained on the whole of hashmob's
// combined founds packs 4269 MiB of terminals, against 3456 MiB on one OpenCL runtime and 3993 on
// another, so the pool is refused whole on cards with memory to spare. Cutting it into equal parts
// takes that ceiling off the total and leaves it only on a part.
//
// A read finds its part by where the logical index falls, which costs a few comparisons but lets a
// part be as large as the device will hand out rather than the power of two below it. Whether the
// pool was cut is settled before the kernel is built, so where it went over in one piece the search
// is compiled out and a read is a read.

// Four is written out by hand elsewhere: the buffers a kernel takes in inc_common.h, the starts
// carried in kernel_param, the macros below, and the branches of the search. None of them would fail
// to build if this changed, they would read the wrong part, so the coupling is made to fail here.

#if PCFG_POOL_PARTS != 4
#error "PCFG_POOL_PARTS is written out by hand in inc_common.h, kernel_param and the search in inc_pcfg.cl"
#endif

// The parts travel as arguments rather than as a struct. A local struct whose address is taken goes
// to private memory, and every read of the descriptor is then a scratch access. Measured on gfx1030,
// one buffer takes 608 bytes of private memory and 70 buffer_load, four buffers behind a struct take
// 656 and 226, and the 48 bytes between them are the struct. As arguments, four buffers cost what
// one does, which is a fifth off the kernel time on that card and nothing either way on NVIDIA.

#define PCFG_POOL_ARGS                                        \
  MAYBE_UNUSED GLOBAL_AS const u32 *pool0,                    \
  MAYBE_UNUSED GLOBAL_AS const u32 *pool1,                    \
  MAYBE_UNUSED GLOBAL_AS const u32 *pool2,                    \
  MAYBE_UNUSED GLOBAL_AS const u32 *pool3,                    \
  MAYBE_UNUSED const u32 pool_at1,                            \
  MAYBE_UNUSED const u32 pool_at2,                            \
  MAYBE_UNUSED const u32 pool_at3

#define PCFG_POOL_PASS  pool0, pool1, pool2, pool3, pool_at1, pool_at2, pool_at3

#define PCFG_POOL_REF(v)  v##0, v##1, v##2, v##3, v##_at1, v##_at2, v##_at3

#define PCFG_POOL_KERN(v)                                     \
  MAYBE_UNUSED GLOBAL_AS const u32 *v##0 = pcfg_pool;         \
  MAYBE_UNUSED GLOBAL_AS const u32 *v##1 = pcfg_pool1;        \
  MAYBE_UNUSED GLOBAL_AS const u32 *v##2 = pcfg_pool2;        \
  MAYBE_UNUSED GLOBAL_AS const u32 *v##3 = pcfg_pool3;        \
  MAYBE_UNUSED const u32 v##_at1 = PCFG_POOL_AT1;             \
  MAYBE_UNUSED const u32 v##_at2 = PCFG_POOL_AT2;             \
  MAYBE_UNUSED const u32 v##_at3 = PCFG_POOL_AT3;

// The part a word falls in, with the word it starts at and the word the next part starts at. A caller
// that reads a run of bytes asks once and then indexes the buffer itself, rather than asking again
// for every byte.

DECLSPEC GLOBAL_AS const u32 *pcfg_pool_span (PCFG_POOL_ARGS, MAYBE_UNUSED const u32 at, PRIVATE_AS u32 *base, PRIVATE_AS u32 *end);

DECLSPEC void pcfg_pool_copy (PCFG_POOL_ARGS, PRIVATE_AS u32 *w, const u32 dst, const u32 src, const u32 len);

DECLSPEC u32 pcfg_pool_u32  (PCFG_POOL_ARGS, const u32 at);
DECLSPEC u32 pcfg_pool_byte (PCFG_POOL_ARGS, const u32 off);

#endif // INC_PCFG_POOL_H
