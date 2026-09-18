/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// hashcat's own RAR3 decoder, for -m 23800. Given a decrypted packed stream it answers what the CRC32
// of the plaintext is and whether the unpack reached the expected length. Every constant here was
// measured against the rar utility as a black box. The PPMd codec is not hashcat's, see ppmd7/ORIGIN.txt.

#include "rar3/rar3_status.h"

#include "rar3/ppmd7/Ppmd7.c"
#include "rar3/ppmd7/Ppmd7aDec.c"

#define RAR3_PACK_MAX   327680
#define RAR3_UNPACK_MAX 655360

// How much is decrypted before the first attempt. The rest follows only if the decode wants more.

#define RAR3_FIRST_CHUNK 4096

// The window a match reaches back into. The next power of 2 above RAR3_UNPACK_MAX never wraps.

#define RAR3_WIN_SIZE 0x100000

#define RAR3_WIN_MASK (RAR3_WIN_SIZE - 1)

// A filter is applied to at most this many bytes at a time.

#define RAR3_FILTER_SIZE 0x10000

// The most filter blocks one stream may queue. All of them are queued before the first output byte.

#define RAR3_FILTER_MAX 4096

// The PPM model memory. The header byte is the size in MiB, minus 1.

#define RAR3_PPM_MAX_MB 128

#define RAR3_PPM_ARENA (((size_t) RAR3_PPM_MAX_MB << 20) + 0x100000)

// The LZ block header. 2 flag bits, then 20 code lengths of 4 bits, with 15 escaping a run of zeros.

#define RAR3_PRE_TABLE_SIZE   20
#define RAR3_PRE_TABLE_BITS    4
#define RAR3_PRE_TABLE_ESCAPE 15

// The 4 tables a block describes, in the order their code lengths appear.

#define RAR3_TABLE_MAIN  299
#define RAR3_TABLE_DIST   60
#define RAR3_TABLE_LOW    17
#define RAR3_TABLE_REP    28

#define RAR3_TABLE_TOTAL (RAR3_TABLE_MAIN + RAR3_TABLE_DIST + RAR3_TABLE_LOW + RAR3_TABLE_REP)

#define RAR3_MAX_TABLE RAR3_TABLE_MAIN

#define RAR3_MAX_CODE_LEN 15

// The symbols of the first table that are not literals.

#define RAR3_END_OF_BLOCK   256
#define RAR3_FILTER_RECORD  257
#define RAR3_REPEAT_SAME    258
#define RAR3_REPEAT_FIRST   259
#define RAR3_REPEAT_LAST    262
#define RAR3_SHORT_FIRST    263
#define RAR3_LENGTH_FIRST   271

// How many distances a block remembers, and where a match runs 1 byte longer than its symbol says.

#define RAR3_OLD_DIST  4
#define RAR3_LONG_DIST   0x2000
#define RAR3_LONGER_DIST 0x40000

// The third table's 17th entry takes a distance's low 4 bits from the match before, for 16 matches.

#define RAR3_LOW_REPEAT_SYMBOL 16
#define RAR3_LOW_REPEAT_COUNT  15

#define RAR3_DIST_LOW_BITS 4

// The lengths a match symbol names, and how many extra bits each reads.

static const u16 RAR3_LENGTH_BASE[RAR3_TABLE_REP] =
{
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
  35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227,
};

static const u8 RAR3_LENGTH_EXTRA[RAR3_TABLE_REP] =
{
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
  3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
};

// A match exactly 2 bytes long has 8 symbols of its own and never touches the distance table.

static const u16 RAR3_SHORT_BASE[8] = { 1, 5, 9, 17, 33, 65, 129, 193 };

static const u8  RAR3_SHORT_EXTRA[8] = { 2, 2, 3, 4, 5, 6, 6, 6 };

// The filter programs, one per filter, taken out of records the encoders wrote.

#include "rar3/rar3_programs.c"

typedef enum rar3_filter
{
  RAR3_FILTER_NONE    = 0,
  RAR3_FILTER_X86     = 1,
  RAR3_FILTER_ITANIUM = 2,
  RAR3_FILTER_DELTA   = 3,
  RAR3_FILTER_RGB     = 4,
  RAR3_FILTER_AUDIO   = 5,
  RAR3_FILTER_E8E9    = 6,

} rar3_filter_t;

typedef struct rar3_program
{
  rar3_filter_t  filter;
  const u8      *bytes;
  u32            size;

} rar3_program_t;

static const rar3_program_t RAR3_PROGRAMS[] =
{
  { RAR3_FILTER_X86,     RAR3_PROGRAM_X86,     sizeof (RAR3_PROGRAM_X86)     },
  { RAR3_FILTER_E8E9,    RAR3_PROGRAM_E8E9,    sizeof (RAR3_PROGRAM_E8E9)    },
  { RAR3_FILTER_ITANIUM, RAR3_PROGRAM_ITANIUM, sizeof (RAR3_PROGRAM_ITANIUM) },
  { RAR3_FILTER_DELTA,   RAR3_PROGRAM_DELTA,   sizeof (RAR3_PROGRAM_DELTA)   },
  { RAR3_FILTER_RGB,     RAR3_PROGRAM_RGB,     sizeof (RAR3_PROGRAM_RGB)     },
  { RAR3_FILTER_AUDIO,   RAR3_PROGRAM_AUDIO,   sizeof (RAR3_PROGRAM_AUDIO)   },
};

typedef struct rar3_block
{
  rar3_filter_t filter;

  u32 start;
  u32 length;

  u32 param[2];
  u32 params;

} rar3_block_t;

// A canonical Huffman code, handed out shortest first and, within one length, in symbol order.

typedef struct rar3_huff
{
  u32 count[RAR3_MAX_CODE_LEN + 1];
  u32 first_code[RAR3_MAX_CODE_LEN + 1];
  u32 first_index[RAR3_MAX_CODE_LEN + 1];

  u16 symbol[RAR3_MAX_TABLE];

} rar3_huff_t;

typedef struct rar3_ctx
{
  const u8 *in;
  u64       in_bits;
  u64       bit;

  u8 *win;
  u64 produced;

  u8 *filter_buf;

  // The filter block queue, caller owned because it is too large for the stack.

  rar3_block_t *blocks;
  u32           block_cnt;
  u32           block_at;

  // Where the filter that is being collected started, and how far into it the output has come.

  u32 collecting;
  u32 collected;

  u32 crc;

  u32 dest_size;

  u8 lengths[RAR3_TABLE_TOTAL];

  rar3_huff_t huff[4];

  void *ppm_arena;

  int status;

} rar3_ctx_t;

// CRC32, the ordinary reflected one the RAR file header carries.

static u32 rar3_crc32_table[256];

static int rar3_crc32_ready = 0;

static void rar3_crc32_init (void)
{
  if (rar3_crc32_ready == 1) return;

  for (u32 i = 0; i < 256; i++)
  {
    u32 c = i;

    for (u32 k = 0; k < 8; k++)
    {
      c = (c & 1) ? (0xedb88320 ^ (c >> 1)) : (c >> 1);
    }

    rar3_crc32_table[i] = c;
  }

  rar3_crc32_ready = 1;
}

static u32 rar3_crc32 (u32 crc, const u8 *buf, const u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    crc = rar3_crc32_table[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
  }

  return crc;
}

// The bit reader. Bits come out most significant first, from bytes read in order.

static u32 rar3_bit (rar3_ctx_t *ctx)
{
  if (ctx->bit >= ctx->in_bits)
  {
    ctx->bit++;

    return 0;
  }

  const u32 v = (ctx->in[ctx->bit >> 3] >> (7 - (ctx->bit & 7))) & 1;

  ctx->bit++;

  return v;
}

static u32 rar3_bits (rar3_ctx_t *ctx, const u32 count)
{
  u32 v = 0;

  for (u32 i = 0; i < count; i++)
  {
    v = (v << 1) | rar3_bit (ctx);
  }

  return v;
}

static int rar3_ended (const rar3_ctx_t *ctx)
{
  return (ctx->bit > ctx->in_bits) ? 1 : 0;
}

static int rar3_huff_build (rar3_huff_t *h, const u8 *lengths, const u32 size)
{
  memset (h, 0, sizeof (rar3_huff_t));

  for (u32 i = 0; i < size; i++)
  {
    h->count[lengths[i]]++;
  }

  h->count[0] = 0;

  u32 code  = 0;
  u32 index = 0;

  for (u32 len = 1; len <= RAR3_MAX_CODE_LEN; len++)
  {
    h->first_code[len]  = code;
    h->first_index[len] = index;

    code  += h->count[len];
    index += h->count[len];

    code <<= 1;
  }

  u32 next[RAR3_MAX_CODE_LEN + 1];

  for (u32 len = 0; len <= RAR3_MAX_CODE_LEN; len++) next[len] = h->first_index[len];

  for (u32 i = 0; i < size; i++)
  {
    const u32 len = lengths[i];

    if (len == 0) continue;

    h->symbol[next[len]] = (u16) i;

    next[len]++;
  }

  return 0;
}

// A table is either a complete prefix code or entirely unused. Anything else is refused.

static int rar3_huff_complete (const u8 *lengths, const u32 size)
{
  u32 used = 0;

  for (u32 i = 0; i < size; i++)
  {
    if (lengths[i] > 0) used++;
  }

  if (used == 0) return 1;

  u32 left = 1;

  for (u32 len = 1; len <= RAR3_MAX_CODE_LEN; len++)
  {
    left <<= 1;

    for (u32 i = 0; i < size; i++)
    {
      if (lengths[i] == len) left--;
    }

    if (left > (1u << 20)) return 0;
  }

  return (left == 0) ? 1 : 0;
}

static int rar3_decode_symbol (rar3_ctx_t *ctx, const rar3_huff_t *h)
{
  u32 code = 0;

  for (u32 len = 1; len <= RAR3_MAX_CODE_LEN; len++)
  {
    code = (code << 1) | rar3_bit (ctx);

    if (h->count[len] == 0) continue;

    const u32 offset = code - h->first_code[len];

    if (offset < h->count[len]) return (int) h->symbol[h->first_index[len] + offset];
  }

  return -1;
}

static int rar3_read_pre_table (rar3_ctx_t *ctx, u8 *pre)
{
  u32 n = 0;

  while (n < RAR3_PRE_TABLE_SIZE)
  {
    const u32 length = rar3_bits (ctx, RAR3_PRE_TABLE_BITS);

    if (length != RAR3_PRE_TABLE_ESCAPE)
    {
      pre[n] = (u8) length;

      n++;

      continue;
    }

    const u32 zeros = rar3_bits (ctx, RAR3_PRE_TABLE_BITS);

    if (zeros == 0)
    {
      pre[n] = RAR3_PRE_TABLE_ESCAPE;

      n++;

      continue;
    }

    for (u32 i = 0; i < (zeros + 2); i++)
    {
      if (n >= RAR3_PRE_TABLE_SIZE) break;

      pre[n] = 0;

      n++;
    }
  }

  return rar3_ended (ctx);
}

// One block's 4 tables. Flag bit 2 set means a plain length is a difference against the previous block's, modulo 16.

static int rar3_read_tables (rar3_ctx_t *ctx)
{
  if (rar3_bit (ctx) != 0) return -1;

  const u32 keep = rar3_bit (ctx);

  if (keep == 0) memset (ctx->lengths, 0, sizeof (ctx->lengths));

  u8 pre[RAR3_PRE_TABLE_SIZE];

  if (rar3_read_pre_table (ctx, pre) != 0) return -1;

  if (rar3_huff_complete (pre, RAR3_PRE_TABLE_SIZE) == 0) return -1;

  rar3_huff_t code;

  rar3_huff_build (&code, pre, RAR3_PRE_TABLE_SIZE);

  u32 n = 0;

  while (n < RAR3_TABLE_TOTAL)
  {
    const int sym = rar3_decode_symbol (ctx, &code);

    if (sym < 0) return -1;

    if (rar3_ended (ctx) != 0) return -1;

    if (sym < 16)
    {
      ctx->lengths[n] = (u8) ((sym + ctx->lengths[n]) & 15);

      n++;

      continue;
    }

    u32 width = 0;
    u32 bias  = 0;
    u32 fill  = 0;

    if (sym == 16) { width = 3; bias =  3; fill = 1; }
    if (sym == 17) { width = 7; bias = 11; fill = 1; }
    if (sym == 18) { width = 3; bias =  3; fill = 0; }
    if (sym == 19) { width = 7; bias = 11; fill = 0; }

    if (sym > 19) return -1;

    const u32 count = bias + rar3_bits (ctx, width);

    for (u32 i = 0; i < count; i++)
    {
      if (n >= RAR3_TABLE_TOTAL) break;

      ctx->lengths[n] = ((fill == 1) && (n > 0)) ? ctx->lengths[n - 1] : 0;

      n++;
    }
  }

  const u8 *at = ctx->lengths;

  const u32 sizes[4] = { RAR3_TABLE_MAIN, RAR3_TABLE_DIST, RAR3_TABLE_LOW, RAR3_TABLE_REP };

  for (u32 t = 0; t < 4; t++)
  {
    if (rar3_huff_complete (at, sizes[t]) == 0) return -1;

    rar3_huff_build (&ctx->huff[t], at, sizes[t]);

    at += sizes[t];
  }

  return 0;
}

static void rar3_filter_x86 (u8 *data, const u32 len, const u32 start, const int with_e9)
{
  // At every 0xE8 the 4 bytes after it are a little endian value. Below 2^24 it is an address and the
  // file has it minus its own position in the whole file. Within 2^24 of the top it is an offset.

  if (len < 5) return;

  const u32 span = 1 << 24;

  u32 i = 0;

  while (i < (len - 4))
  {
    // E8E9 rewrites a jump, 0xE9, the same way. rar picks it for 64 bit code and x86 for 32 bit.

    const int mark = (data[i] == 0xe8) || ((with_e9 == 1) && (data[i] == 0xe9));

    if (mark == 0)
    {
      i++;

      continue;
    }

    const u32 pos = start + i + 1;

    const u32 v = (u32) data[i + 1] | ((u32) data[i + 2] << 8) | ((u32) data[i + 3] << 16) | ((u32) data[i + 4] << 24);

    u32 w = v;

    if (v < span)
    {
      w = v - pos;
    }
    else if ((v >= (0xffffffff - span + 1)) && (((u64) v + pos) >= 0x100000000ULL))
    {
      w = v + span;
    }

    data[i + 1] = (u8) (w >>  0);
    data[i + 2] = (u8) (w >>  8);
    data[i + 3] = (u8) (w >> 16);
    data[i + 4] = (u8) (w >> 24);

    i += 5;
  }
}

// An IA-64 bundle is 16 bytes: 5 bits of template and 3 slots of 41 bits. A slot is a branch when its template says so and bits 37-40 hold 5.

static const u8 RAR3_ITANIUM_SLOTS[32] =
{
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0,
};

static u64 rar3_bundle_get (const u64 lo, const u64 hi, const u32 at, const u32 count)
{
  u64 v = 0;

  for (u32 i = 0; i < count; i++)
  {
    const u32 p = at + i;

    const u64 b = (p < 64) ? ((lo >> p) & 1) : ((hi >> (p - 64)) & 1);

    v |= b << i;
  }

  return v;
}

static void rar3_bundle_set (u64 *lo, u64 *hi, const u32 at, const u32 count, const u64 value)
{
  for (u32 i = 0; i < count; i++)
  {
    const u32 p = at + i;

    const u64 b = (value >> i) & 1;

    if (p < 64)
    {
      *lo = (*lo & ~(1ULL << p)) | (b << p);
    }
    else
    {
      *hi = (*hi & ~(1ULL << (p - 64))) | (b << (p - 64));
    }
  }
}

static void rar3_filter_itanium (u8 *data, const u32 len, const u32 start)
{
  // The target is 20 bits at bit 13, minus the bundle number in the whole file. The last is untouched.

  u32 pos = 0;

  while ((pos + 16) < len)
  {
    u64 lo = 0;
    u64 hi = 0;

    for (u32 i = 0; i < 8; i++) lo |= ((u64) data[pos + i]) << (i * 8);
    for (u32 i = 0; i < 8; i++) hi |= ((u64) data[pos + 8 + i]) << (i * 8);

    const u32 mask = RAR3_ITANIUM_SLOTS[lo & 0x1f];

    for (u32 slot = 0; slot < 3; slot++)
    {
      if ((mask & (1u << slot)) == 0) continue;

      const u32 base = 5 + (41 * slot);

      if (rar3_bundle_get (lo, hi, base + 37, 4) != 5) continue;

      const u64 imm = rar3_bundle_get (lo, hi, base + 13, 20);

      const u64 want = (imm - ((start + pos) / 16)) & 0xfffff;

      rar3_bundle_set (&lo, &hi, base + 13, 20, want);
    }

    for (u32 i = 0; i < 8; i++) data[pos + i]     = (u8) (lo >> (i * 8));
    for (u32 i = 0; i < 8; i++) data[pos + 8 + i] = (u8) (hi >> (i * 8));

    pos += 16;
  }
}

static void rar3_filter_delta (u8 *data, const u32 len, const u32 channels, u8 *scratch)
{
  // The channels arrive separated out, each byte being the sample before it minus the sample itself.

  if (channels == 0) return;

  // A channel past the end of the block holds no bytes, so a count above the length is capped to it.

  const u32 lanes = (channels > len) ? len : channels;

  u32 j = 0;

  for (u32 c = 0; c < lanes; c++)
  {
    u8 prev = 0;

    for (u32 i = c; i < len; i += channels)
    {
      prev = (u8) (prev - data[j]);

      scratch[i] = prev;

      j++;
    }
  }

  memcpy (data, scratch, len);
}

// The audio filter. Each channel is the sample before plus a weighted sum of the last 3 differences,
// shifted down by 3. Every 32 samples the cheapest of 7 weight moves is taken, ties going to no move.

#define RAR3_AUDIO_BLOCK 32
#define RAR3_AUDIO_MOVES 7

static const int RAR3_AUDIO_MOVE[RAR3_AUDIO_MOVES][3] =
{
  {  0,  0,  0 },
  {  1,  0,  0 },
  { -1,  0,  0 },
  {  0,  1,  0 },
  {  0, -1,  0 },
  {  0,  0,  1 },
  {  0,  0, -1 },
};

static int rar3_audio_signed (const u8 v)
{
  const int out = (v >= 128) ? ((int) v - 256) : (int) v;

  return out;
}

static void rar3_filter_audio (u8 *data, const u32 len, const u32 channels, u8 *scratch)
{
  if (channels == 0) return;

  const u32 lanes = (channels > len) ? len : channels;

  u8 *out = scratch;

  u32 at = 0;

  for (u32 c = 0; c < lanes; c++)
  {
    int k[3];

    k[0] = 0;
    k[1] = 0;
    k[2] = 0;

    int cost[RAR3_AUDIO_MOVES];

    for (u32 m = 0; m < RAR3_AUDIO_MOVES; m++) cost[m] = 0;

    int d1 = 0;
    int d2 = 0;
    int d3 = 0;

    int last = 0;

    u32 n = 0;

    for (u32 i = c; i < len; i += channels)
    {
      const int t1 = d1;
      const int t2 = d1 - d2;
      const int t3 = d2 - d3;

      const int q = ((k[0] * t1) + (k[1] * t2) + (k[2] * t3)) >> 3;

      const u8 written = data[at + n];

      const u8 sample = (u8) ((last + q) - written);

      out[i] = sample;

      const int e = rar3_audio_signed (written);

      for (u32 m = 0; m < RAR3_AUDIO_MOVES; m++)
      {
        const int d = (RAR3_AUDIO_MOVE[m][0] * t1) + (RAR3_AUDIO_MOVE[m][1] * t2) + (RAR3_AUDIO_MOVE[m][2] * t3);

        const int v = (8 * e) + d;

        cost[m] += (v < 0) ? -v : v;
      }

      d3 = d2;
      d2 = d1;
      d1 = rar3_audio_signed ((u8) (sample - last));

      last = sample;

      // The first look is after 1 sample and every 32 after that.

      if ((n % RAR3_AUDIO_BLOCK) == 0)
      {
        u32 best = 0;

        for (u32 m = 1; m < RAR3_AUDIO_MOVES; m++)
        {
          if (cost[m] < cost[best]) best = m;
        }

        k[0] += RAR3_AUDIO_MOVE[best][0];
        k[1] += RAR3_AUDIO_MOVE[best][1];
        k[2] += RAR3_AUDIO_MOVE[best][2];

        for (u32 m = 0; m < RAR3_AUDIO_MOVES; m++) cost[m] = 0;
      }

      n++;
    }

    at += n;
  }

  memcpy (data, out, len);
}

static int rar3_paeth (const int left, const int upper, const int upperleft)
{
  const int p = left + upper - upperleft;

  const int a = abs (p - left);
  const int b = abs (p - upper);
  const int c = abs (p - upperleft);

  if ((a <= b) && (a <= c)) return left;

  if (b <= c) return upper;

  return upperleft;
}

static int rar3_rgb_offset (const u32 c, const u32 ref)
{
  // The nearest byte of the reference channel: 1 before for the channel after it, 1 after for the one before.

  int d = (int) ref - (int) c;

  if (d < -1) d += 3;
  if (d >  1) d -= 3;

  return d;
}

static void rar3_filter_rgb (u8 *data, const u32 len, const u32 width, const u32 ref, u8 *scratch)
{
  // A channel is read from one run and written back interleaved, so this cannot be done in place.

  u8 *out = scratch;
  u8 *seq = scratch + RAR3_FILTER_SIZE;

  u32 counts[3];
  u32 at[3];

  u32 off = 0;

  for (u32 c = 0; c < 3; c++)
  {
    counts[c] = (len > c) ? (((len - c) + 2) / 3) : 0;

    at[c] = off;

    off += counts[c];
  }

  const u32 order[3] = { ref, (ref + 1) % 3, (ref + 2) % 3 };

  for (u32 k = 0; k < 3; k++)
  {
    const u32 c = order[k];

    const int d = rar3_rgb_offset (c, ref);

    for (u32 i = 0; i < counts[c]; i++)
    {
      const int left = (i >= 1) ? seq[i - 1] : 0;
      const int up   = (i >  width) ? seq[i - width] : 0;
      const int ul   = (i >  width) ? seq[i - width - 1] : 0;

      const u8 v = (u8) (rar3_paeth (left, up, ul) - data[at[c] + i]);

      seq[i] = v;

      const u32 p = (i * 3) + c;

      u8 byte = v;

      if (c != ref)
      {
        const int q = (int) p + d;

        // The reference byte is used only at index 1 or later and at least 2 bytes before the end.

        if ((q >= 1) && (q < ((int) len - 1))) byte = (u8) (v + out[q]);
      }

      out[p] = byte;
    }
  }

  memcpy (data, out, len);
}

static rar3_filter_t rar3_filter_of (const u8 *program, const u32 size)
{
  for (u32 i = 0; i < (sizeof (RAR3_PROGRAMS) / sizeof (RAR3_PROGRAMS[0])); i++)
  {
    if (RAR3_PROGRAMS[i].size != size) continue;

    if (memcmp (RAR3_PROGRAMS[i].bytes, program, size) == 0) return RAR3_PROGRAMS[i].filter;
  }

  return RAR3_FILTER_NONE;
}

// A number in a record body is 2 bits saying how wide it is and then that many bits.

typedef struct rar3_body
{
  const u8 *buf;
  u32       len;
  u32       pos;
  int       over;

} rar3_body_t;

static u32 rar3_body_bit (rar3_body_t *b)
{
  if (b->pos >= (b->len * 8))
  {
    b->over = 1;

    return 0;
  }

  const u32 v = (b->buf[b->pos >> 3] >> (7 - (b->pos & 7))) & 1;

  b->pos++;

  return v;
}

static u32 rar3_body_bits (rar3_body_t *b, const u32 count)
{
  u32 v = 0;

  for (u32 i = 0; i < count; i++) v = (v << 1) | rar3_body_bit (b);

  return v;
}

static u32 rar3_body_number (rar3_body_t *b)
{
  static const u8 widths[4] = { 4, 8, 16, 32 };

  const u32 sel = rar3_body_bits (b, 2);

  return rar3_body_bits (b, widths[sel]);
}

// Reading a filter setup record. The flags byte says which fields the body holds.

#define RAR3_REC_HAS_NUMBER 0x80

#define RAR3_REC_FAR_START  0x40

#define RAR3_REC_HAS_LENGTH 0x20
#define RAR3_REC_HAS_PARAMS 0x10
#define RAR3_REC_UNKNOWN    0x08

// How many filters one stream may set up. Naming one past the end is refused.

#define RAR3_SLOT_MAX 64

typedef struct rar3_slots
{
  // What each filter is, and the length and parameters its last block had. A record may leave any out.

  rar3_filter_t filter[RAR3_SLOT_MAX];

  u32 length[RAR3_SLOT_MAX];
  int has_length[RAR3_SLOT_MAX];

  u32 param[RAR3_SLOT_MAX][2];
  u32 params[RAR3_SLOT_MAX];

  u32 count;
  u32 last;
  int has_last;

} rar3_slots_t;

// -1 is not a record at all, which is what noise gives. -2 read cleanly and asks for the unimplemented.

#define RAR3_RECORD_MALFORMED   -1
#define RAR3_RECORD_UNSUPPORTED -2

static int rar3_read_record (rar3_ctx_t *ctx, rar3_slots_t *slots)
{
  const u32 first = rar3_bits (ctx, 8);

  u32 size = (first & 7) + 1;

  if (size == 7)
  {
    size = rar3_bits (ctx, 8) + 7;
  }
  else if (size > 7)
  {
      return RAR3_RECORD_MALFORMED;
  }

  u8 body[256 + 8];

  for (u32 i = 0; i < size; i++) body[i] = (u8) rar3_bits (ctx, 8);

  if (rar3_ended (ctx) != 0) return RAR3_RECORD_MALFORMED;

  if ((first & RAR3_REC_UNKNOWN) != 0) return RAR3_RECORD_MALFORMED;

  rar3_body_t b;

  b.buf  = body;
  b.len  = size;
  b.pos  = 0;
  b.over = 0;

  // The number names filter n - 1, and 0 and 1 both name the first. No number means the last one used.

  u32 idx = 0;

  if ((first & RAR3_REC_HAS_NUMBER) != 0)
  {
    const u32 which = rar3_body_number (&b);

    idx = (which == 0) ? 0 : (which - 1);
  }
  else
  {
    if (slots->has_last == 0) return RAR3_RECORD_MALFORMED;

    idx = slots->last;
  }

  if (idx > slots->count) return RAR3_RECORD_MALFORMED;

  if (idx >= RAR3_SLOT_MAX) return RAR3_RECORD_MALFORMED;

  const int is_new = (idx == slots->count) ? 1 : 0;

  const u32 start = rar3_body_number (&b);

  u32 length = 0;

  int has_length = 0;

  if ((first & RAR3_REC_HAS_LENGTH) != 0)
  {
    length = rar3_body_number (&b);

    has_length = 1;
  }

  u32 param[2];
  u32 params = 0;

  if ((first & RAR3_REC_HAS_PARAMS) != 0)
  {
    const u32 count = rar3_body_number (&b);

    if (count > 1) return RAR3_RECORD_MALFORMED;

    rar3_body_bit (&b);

    for (u32 i = 0; i <= count; i++)
    {
      const u32 v = rar3_body_number (&b);

      if (i < 2) param[i] = v;
    }

    params = count + 1;
  }

  rar3_filter_t filter = RAR3_FILTER_NONE;

  u8  program[256];
  u32 program_size = 0;

  // A program follows when whole bytes are left. One naming an existing filter redefines it.

  const int has_program = (((b.len * 8) - b.pos) >= 8) ? 1 : 0;

  if (has_program == 1)
  {
    program_size = rar3_body_number (&b);

    if (b.over != 0) return RAR3_RECORD_MALFORMED;

    if (program_size > sizeof (program)) return RAR3_RECORD_MALFORMED;

    if ((b.pos + (8 * program_size)) > (b.len * 8)) return RAR3_RECORD_MALFORMED;

    for (u32 i = 0; i < program_size; i++) program[i] = (u8) rar3_body_bits (&b, 8);
  }

  if ((is_new == 1) && (has_program == 0)) return RAR3_RECORD_MALFORMED;

  if (b.over != 0) return RAR3_RECORD_MALFORMED;

  if (((b.len * 8) - b.pos) >= 8) return RAR3_RECORD_MALFORMED;

  while (b.pos < (b.len * 8))
  {
    if (rar3_body_bit (&b) != 0) return RAR3_RECORD_MALFORMED;
  }

  // The body read exactly, so from here on anything unimplemented is worth saying out loud.

  if (has_program == 1)
  {
    filter = rar3_filter_of (program, program_size);

    if (filter == RAR3_FILTER_NONE) return RAR3_RECORD_UNSUPPORTED;

    if (is_new == 1)
    {
      slots->count++;

      slots->has_length[idx] = 0;
      slots->params[idx]     = 0;
    }

    slots->filter[idx] = filter;
  }
  else
  {
    filter = slots->filter[idx];
  }

  slots->last     = idx;
  slots->has_last = 1;

    if (ctx->block_cnt >= RAR3_FILTER_MAX) return RAR3_RECORD_UNSUPPORTED;

  // Where the block starts. The field carries it, and bit 6 of the flags byte says to add 258.

  const u32 at = start + (((first & RAR3_REC_FAR_START) != 0) ? 258 : 0);

  if (at < ctx->produced) return RAR3_RECORD_MALFORMED;

  if (at > ctx->dest_size) return RAR3_RECORD_MALFORMED;

  // A record with no length takes the one the last block of that same filter had, not of any filter.

  if (has_length == 0)
  {
    if (slots->has_length[idx] == 0) return RAR3_RECORD_MALFORMED;

    length = slots->length[idx];
  }

  slots->length[idx]     = length;
  slots->has_length[idx] = 1;

  // Parameters work the same way, and a record that carries none means the ones that filter had.

  if (params > 0)
  {
    slots->param[idx][0] = (params > 0) ? param[0] : 0;
    slots->param[idx][1] = (params > 1) ? param[1] : 0;
    slots->params[idx]   = params;
  }

  params   = slots->params[idx];
  param[0] = slots->param[idx][0];
  param[1] = slots->param[idx][1];

  if (length > RAR3_FILTER_SIZE) return RAR3_RECORD_MALFORMED;

  rar3_block_t *block = &ctx->blocks[ctx->block_cnt];

  block->filter = filter;
  block->start  = at;
  block->length = length;
  block->params = params;

  block->param[0] = (params > 0) ? param[0] : 0;
  block->param[1] = (params > 1) ? param[1] : 0;

  ctx->block_cnt++;

  return 0;
}

static void rar3_run_filter (rar3_ctx_t *ctx, const rar3_block_t *block, u8 *scratch)
{
  u8 *data = ctx->filter_buf;

  const u32 len = block->length;

  if (block->filter == RAR3_FILTER_X86)     rar3_filter_x86     (data, len, block->start, 0);
  if (block->filter == RAR3_FILTER_E8E9)    rar3_filter_x86     (data, len, block->start, 1);
  if (block->filter == RAR3_FILTER_ITANIUM) rar3_filter_itanium (data, len, block->start);
  if (block->filter == RAR3_FILTER_DELTA)   rar3_filter_delta   (data, len, block->param[0], scratch);
  if (block->filter == RAR3_FILTER_AUDIO)   rar3_filter_audio   (data, len, block->param[0], scratch);

  if (block->filter == RAR3_FILTER_RGB)
  {
    // 3 times one more than the row width, and the reference channel less 1 modulo 3.

    const u32 width = (block->param[0] / 3) - 1;
    const u32 ref   = (block->param[1] + 1) % 3;

    rar3_filter_rgb (data, len, width, ref, scratch);
  }

  ctx->crc = rar3_crc32 (ctx->crc, data, len);
}

// A filter block has all its bytes, so it runs and the queue moves on.

static void rar3_finish_block (rar3_ctx_t *ctx, u8 *scratch)
{
  rar3_run_filter (ctx, &ctx->blocks[ctx->block_at], scratch);

  ctx->collecting = 0;
  ctx->collected  = 0;

  ctx->block_at++;
}

static void rar3_emit (rar3_ctx_t *ctx, const u8 byte, u8 *scratch)
{
  ctx->win[ctx->produced & RAR3_WIN_MASK] = byte;

  const u32 at = (u32) ctx->produced;

  ctx->produced++;

  if (ctx->collecting == 1)
  {
    ctx->filter_buf[ctx->collected] = byte;

    ctx->collected++;

    if (ctx->collected >= ctx->blocks[ctx->block_at].length) rar3_finish_block (ctx, scratch);

    return;
  }

  if ((ctx->block_at < ctx->block_cnt) && (at > ctx->blocks[ctx->block_at].start))
  {
    // Output past a filter's block that was never collected would reach the CRC32 untransformed.

    ctx->status = HC_RAR3_UNPACK_UNSUPPORTED;

    return;
  }

  if ((ctx->block_at < ctx->block_cnt) && (at == ctx->blocks[ctx->block_at].start))
  {
    ctx->collecting = 1;
    ctx->collected  = 1;

    ctx->filter_buf[0] = byte;

    if (ctx->blocks[ctx->block_at].length <= 1) rar3_finish_block (ctx, scratch);

    return;
  }

  ctx->crc = rar3_crc32 (ctx->crc, &byte, 1);
}

// Copying a match out of the window. Returns the last byte emitted, which the PPM path needs, and
// last unchanged when the output ran out before anything was copied.

static u8 rar3_copy_match (rar3_ctx_t *ctx, const u32 dist, const u32 length, const u8 last, u8 *scratch)
{
  u8 out = last;

  for (u32 i = 0; i < length; i++)
  {
    if (ctx->produced >= ctx->dest_size) break;

    out = ctx->win[(ctx->produced - dist) & RAR3_WIN_MASK];

    rar3_emit (ctx, out, scratch);
  }

  return out;
}

// How many extra bits a distance symbol reads. Every pair doubles the span, stopping at 16 bits.

static u32 rar3_dist_extra (const u32 sym)
{
  if (sym < 4) return 0;

  const u32 e = (sym - 2) / 2;

  if (e >= 16) return 16;

  return e;
}

static void rar3_unpack_lz (rar3_ctx_t *ctx, u8 *scratch)
{
  if (rar3_read_tables (ctx) != 0)
  {
    ctx->status = HC_RAR3_UNPACK_REJECTED_LZ;

    return;
  }

  rar3_slots_t slots;

  memset (&slots, 0, sizeof (slots));

  u32 history[RAR3_OLD_DIST];
  u32 history_cnt = 0;

  u32 last_length = 0;

  u32 last_low   = 0;
  u32 low_repeat = 0;

  while (ctx->produced < ctx->dest_size)
  {
    const int sym = rar3_decode_symbol (ctx, &ctx->huff[0]);

    if (sym < 0) return;

    if (rar3_ended (ctx) != 0) return;

    if (sym < 256)
    {
      rar3_emit (ctx, (u8) sym, scratch);

      continue;
    }

    if (sym == RAR3_FILTER_RECORD)
    {
      const int ok = rar3_read_record (ctx, &slots);

      if (ok == RAR3_RECORD_UNSUPPORTED)
      {
        ctx->status = HC_RAR3_UNPACK_UNSUPPORTED;

        return;
      }

      if (ok != 0) return;

      continue;
    }

    if (sym == RAR3_END_OF_BLOCK)
    {
      // The next block's tables begin at the next whole byte, and a whole byte is always stepped over.

      ctx->bit = ((ctx->bit / 8) + 1) * 8;

      if (rar3_read_tables (ctx) != 0) return;

      continue;
    }

    u32 length = 0;
    u32 dist   = 0;

    int remember = 1;

    if (sym == RAR3_REPEAT_SAME)
    {
      if (history_cnt == 0) return;

      length = last_length;

      dist = history[0];

      remember = 0;
    }
    else if ((sym >= RAR3_REPEAT_FIRST) && (sym <= RAR3_REPEAT_LAST))
    {
      const u32 j = (u32) sym - RAR3_REPEAT_FIRST;

      if (j >= history_cnt) return;

      dist = history[j];

      const int lsym = rar3_decode_symbol (ctx, &ctx->huff[3]);

      if (lsym < 0) return;

      if (lsym >= RAR3_TABLE_REP) return;

      // The fourth table's 28 entries are the 28 length symbols with every base 1 lower.

      length = (RAR3_LENGTH_BASE[lsym] - 1) + rar3_bits (ctx, RAR3_LENGTH_EXTRA[lsym]);

      // Naming an older distance moves it back to the front.

      for (u32 k = j; k > 0; k--) history[k] = history[k - 1];

      history[0] = dist;

      remember = 0;
    }
    else if (sym >= RAR3_LENGTH_FIRST)
    {
      const u32 k = (u32) sym - RAR3_LENGTH_FIRST;

      if (k >= RAR3_TABLE_REP) return;

      length = RAR3_LENGTH_BASE[k] + rar3_bits (ctx, RAR3_LENGTH_EXTRA[k]);

      const int dsym = rar3_decode_symbol (ctx, &ctx->huff[1]);

      if (dsym < 0) return;

      if (dsym >= RAR3_TABLE_DIST) return;

      // Once a distance symbol reads 4 or more extra bits, its low 4 come from the third table.

      const u32 e = rar3_dist_extra ((u32) dsym);

      u32 base = 1;

      for (u32 i = 0; i < (u32) dsym; i++) base += 1u << rar3_dist_extra (i);

      u32 off = 0;

      if (e >= RAR3_DIST_LOW_BITS)
      {
        const u32 high = (e > RAR3_DIST_LOW_BITS) ? rar3_bits (ctx, e - RAR3_DIST_LOW_BITS) : 0;

        u32 low = 0;

        if (low_repeat > 0)
        {
          low_repeat--;

          low = last_low;
        }
        else
        {
          const int lsym = rar3_decode_symbol (ctx, &ctx->huff[2]);

          if (lsym < 0) return;

          if (lsym == RAR3_LOW_REPEAT_SYMBOL)
          {
            low = last_low;

            low_repeat = RAR3_LOW_REPEAT_COUNT;
          }
          else if (lsym >= (1 << RAR3_DIST_LOW_BITS))
          {
            return;
          }
          else
          {
            low = (u32) lsym;

            last_low = low;
          }
        }

        off = (high << RAR3_DIST_LOW_BITS) | low;
      }
      else
      {
        off = (e > 0) ? rar3_bits (ctx, e) : 0;
      }

      dist = base + off;

      if (dist >= RAR3_LONGER_DIST) length += 2;
      else if (dist >= RAR3_LONG_DIST) length += 1;
    }
    else if (sym >= RAR3_SHORT_FIRST)
    {
      const u32 k = (u32) sym - RAR3_SHORT_FIRST;

      length = 2;

      dist = RAR3_SHORT_BASE[k] + rar3_bits (ctx, RAR3_SHORT_EXTRA[k]);
    }
    else
    {
      return;
    }

    if ((dist == 0) || (dist > ctx->produced)) return;

    if (dist > RAR3_WIN_SIZE) return;

    if (remember == 1)
    {
      for (u32 k = RAR3_OLD_DIST - 1; k > 0; k--) history[k] = history[k - 1];

      history[0] = dist;

      if (history_cnt < RAR3_OLD_DIST) history_cnt++;
    }

    last_length = length;

    rar3_copy_match (ctx, dist, length, 0, scratch);
  }
}

// The PPM path. The codec is adopted. The block header, the escape protocol and the arena are not.

// The 2 rules a PPM block header has to satisfy. module_23800.c applies them to the first decrypted
// block before it decrypts the rest, which is the cheapest rejection a wrong password gets.

static int rar3_ppm_header_ok (const u8 *in)
{
  if ((in[0] & 0x20) == 0) return 0;   // the model has to be reset
  if ((in[1] & 0x80) != 0) return 0;   // the memory field cannot name more than RAR3_PPM_MAX_MB

  return 1;
}

#define RAR3_PPM_DATA_OFFSET 3

#define RAR3_PPM_CMD_MATCH  0x04
#define RAR3_PPM_CMD_REPEAT 0x05

#define RAR3_PPM_DIST_BIAS   2
#define RAR3_PPM_MATCH_BIAS 32

typedef struct rar3_byte_in
{
  IByteIn vt;

  const Byte *buf;
  size_t      pos;
  size_t      len;

  // The codec reads bytes here, not through the bit reader, so a read past the end is marked here too.

  rar3_ctx_t *ctx;

} rar3_byte_in_t;

static Byte rar3_byte_in_read (IByteInPtr pp)
{
  rar3_byte_in_t *p = Z7_CONTAINER_FROM_VTBL (pp, rar3_byte_in_t, vt);

  if (p->pos >= p->len)
  {
    p->pos++;

    p->ctx->bit = p->ctx->in_bits + 1;

    return 0;
  }

  const Byte b = p->buf[p->pos];

  p->pos++;

  return b;
}

// The codec asks for its arena once, and is handed the buffer the module already owns.

typedef struct rar3_arena
{
  ISzAlloc vt;

  void  *base;
  size_t size;

} rar3_arena_t;

static void *rar3_arena_alloc (ISzAllocPtr pp, size_t size)
{
  rar3_arena_t *p = (rar3_arena_t *) pp;

  if (size > p->size) return NULL;

  return p->base;
}

static void rar3_arena_free (ISzAllocPtr pp, void *address)
{
  (void) pp;
  (void) address;
}

static void rar3_unpack_ppm (rar3_ctx_t *ctx, u8 *scratch)
{
  const u8 *in = ctx->in;

  const u32 in_len = (u32) (ctx->in_bits / 8);

  if (in_len < (RAR3_PPM_DATA_OFFSET + 1))
  {
    ctx->status = HC_RAR3_UNPACK_REJECTED_PPM;

    return;
  }

  // byte 0   bit 7 selects PPM, bit 5 says the model is reset and the 2 fields below are present,
  //          bits 4-0 the order field
  // byte 1   the model memory in MiB, minus 1
  // byte 2   the escape character, which the encoder picks from the data
  // byte 3   the first byte of the range coded data

  const u8 b0  = in[0];
  const u8 esc = in[2];

  if (rar3_ppm_header_ok (in) == 0)
  {
    ctx->status = HC_RAR3_UNPACK_REJECTED_PPM;

    return;
  }

  const u32 n = (u32) (b0 & 0x1f) + 1;

  const u32 order = (n > 16) ? (16 + (3 * (n - 16))) : n;

  const u32 mem_mb = (u32) in[1] + 1;

  rar3_byte_in_t reader;

  reader.vt.Read = rar3_byte_in_read;
  reader.buf     = (const Byte *) in;
  reader.pos     = RAR3_PPM_DATA_OFFSET;
  reader.len     = in_len;
  reader.ctx     = ctx;

  rar3_arena_t arena;

  arena.vt.Alloc = rar3_arena_alloc;
  arena.vt.Free  = rar3_arena_free;
  arena.base     = ctx->ppm_arena;
  arena.size     = RAR3_PPM_ARENA;

  CPpmd7 ppmd;

  Ppmd7_Construct (&ppmd);

  if (Ppmd7_Alloc (&ppmd, (UInt32) mem_mb << 20, &arena.vt) == False)
  {
    ctx->status = HC_RAR3_UNPACK_REJECTED_PPM;

    return;
  }

  ppmd.rc.dec.Stream = &reader.vt;

  if (Ppmd7a_RangeDec_Init (&ppmd.rc.dec) == False)
  {
    ctx->status = HC_RAR3_UNPACK_REJECTED_PPM;

    return;
  }

  Ppmd7_Init (&ppmd, order);

  u8 last = 0;

  while (ctx->produced < ctx->dest_size)
  {
    const int sym = Ppmd7a_DecodeSymbol (&ppmd);

    if (sym < 0) return;

    if ((u8) sym != esc)
    {
      last = (u8) sym;

      rar3_emit (ctx, last, scratch);

      continue;
    }

    const int cmd = Ppmd7a_DecodeSymbol (&ppmd);

    if (cmd < 0) return;

    if (cmd == esc)
    {
      // The escape character itself, written out by escaping it.

      last = (u8) esc;

      rar3_emit (ctx, last, scratch);

      continue;
    }

    if (cmd == RAR3_PPM_CMD_REPEAT)
    {
      const int param = Ppmd7a_DecodeSymbol (&ppmd);

      if (param < 0) return;

      // The run is param + 5 long in total and one byte of it already went out as a literal.

      const u32 count = (u32) param + 4;

      for (u32 i = 0; i < count; i++)
      {
        if (ctx->produced >= ctx->dest_size) break;

        rar3_emit (ctx, last, scratch);
      }

      continue;
    }

    if (cmd == RAR3_PPM_CMD_MATCH)
    {
      const int d0 = Ppmd7a_DecodeSymbol (&ppmd);
      const int d1 = Ppmd7a_DecodeSymbol (&ppmd);
      const int d2 = Ppmd7a_DecodeSymbol (&ppmd);
      const int ln = Ppmd7a_DecodeSymbol (&ppmd);

      if ((d0 < 0) || (d1 < 0) || (d2 < 0) || (ln < 0)) return;

      const u64 dist = (u64) (((u32) d0 << 16) | ((u32) d1 << 8) | (u32) d2) + RAR3_PPM_DIST_BIAS;

      const u32 length = (u32) ln + RAR3_PPM_MATCH_BIAS;

      if ((dist == 0) || (dist > ctx->produced)) return;

      if (dist > RAR3_WIN_SIZE) return;

      last = rar3_copy_match (ctx, dist, length, last, scratch);

      continue;
    }

    // The escape protocol has no framing, so an unknown command cannot be told apart from noise.

    return;
  }
}

// Returns the CRC32 of the plaintext, and writes why the unpack produced no usable one.
// ran_off_the_end says the decode wanted a byte it was not given, the cue to decrypt more.

#define RAR3_BLOCKS_BYTES (RAR3_FILTER_MAX * sizeof (rar3_block_t))

static u32 rar3_decode (u8 *win, u8 *filter_buf, u8 *scratch, void *ppm_arena, void *blocks, const u8 *in, const u32 pack_size, const u32 unpack_size, u32 *unpack_status, int *ran_off_the_end)
{
  rar3_crc32_init ();

  rar3_ctx_t ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.in      = in;
  ctx.in_bits = (u64) pack_size * 8;
  ctx.bit     = 0;

  ctx.win        = win;
  ctx.filter_buf = filter_buf;
  ctx.ppm_arena  = ppm_arena;
  ctx.blocks     = (rar3_block_t *) blocks;

  ctx.dest_size = unpack_size;

  ctx.crc = 0xffffffff;

  ctx.status = HC_RAR3_UNPACK_OK;

  *ran_off_the_end = 0;

  if (pack_size == 0)
  {
    *unpack_status = (unpack_size == 0) ? HC_RAR3_UNPACK_OK : HC_RAR3_UNPACK_SHORT_OUTPUT;

    return ctx.crc ^ 0xffffffff;
  }

  if ((in[0] & 0x80) != 0)
  {
    rar3_unpack_ppm (&ctx, scratch);
  }
  else
  {
    rar3_unpack_lz (&ctx, scratch);
  }

  if (ctx.status == HC_RAR3_UNPACK_OK)
  {
    // A filter left half collected means the stream stopped inside one, so the length is short anyway.

    ctx.status = (ctx.produced == unpack_size) ? HC_RAR3_UNPACK_OK : HC_RAR3_UNPACK_SHORT_OUTPUT;

    if (ctx.collecting == 1) ctx.status = HC_RAR3_UNPACK_SHORT_OUTPUT;
  }

  *ran_off_the_end = (ctx.bit > ctx.in_bits) ? 1 : 0;

  *unpack_status = (u32) ctx.status;

  return ctx.crc ^ 0xffffffff;
}
