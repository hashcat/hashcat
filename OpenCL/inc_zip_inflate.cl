/*

PKZIP Kernels for Hashcat (c) 2018, European Union

PKZIP Kernels for Hashcat has been developed by the Joint Research Centre of the European Commission.
It is released as open source software under the MIT License.

PKZIP Kernels for Hashcat makes use of two primary external components, which continue to be subject
to the terms and conditions stipulated in the respective licences they have been released under. These
external components include, but are not necessarily limited to, the following:

-----

1. Hashcat: MIT License

Copyright (c) 2015-2018 Jens Steube

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-----

2. Miniz: MIT License

Copyright 2013-2014 RAD Game Tools and Valve Software
Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC

All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-----

The European Union disclaims all liability related to or arising out of the use made by third parties of
any external components and dependencies which may be included with PKZIP Kernels for Hashcat.

*/

enum{
    MZ_OK = 0,
    MZ_STREAM_END = 1,
    MZ_NEED_DICT = 2,
    MZ_ERRNO = -1,
    MZ_STREAM_ERROR = -2,
    MZ_DATA_ERROR = -3,
    MZ_MEM_ERROR = -4,
    MZ_BUF_ERROR = -5,
    MZ_VERSION_ERROR = -6,
    MZ_PARAM_ERROR = -10000
};
typedef unsigned long mz_ulong;

#ifndef MINIZ_NO_ZLIB_COMPATIBLE_NAMES
typedef unsigned char Byte;
typedef unsigned int uInt;
typedef mz_ulong uLong;
typedef Byte Bytef;
typedef uInt uIntf;
typedef char charf;
typedef int intf;
typedef void *voidpf;
typedef uLong uLongf;
typedef void *voidp;
typedef void *const voidpc;
#define Z_NULL 0
#define Z_NO_FLUSH MZ_NO_FLUSH
#define Z_PARTIAL_FLUSH MZ_PARTIAL_FLUSH
#define Z_SYNC_FLUSH MZ_SYNC_FLUSH
#define Z_FULL_FLUSH MZ_FULL_FLUSH
#define Z_FINISH MZ_FINISH
#define Z_BLOCK MZ_BLOCK
#define Z_OK MZ_OK
#define Z_STREAM_END MZ_STREAM_END
#define Z_NEED_DICT MZ_NEED_DICT
#define Z_ERRNO MZ_ERRNO
#define Z_STREAM_ERROR MZ_STREAM_ERROR
#define Z_DATA_ERROR MZ_DATA_ERROR
#define Z_MEM_ERROR MZ_MEM_ERROR
#define Z_BUF_ERROR MZ_BUF_ERROR
#define Z_VERSION_ERROR MZ_VERSION_ERROR
#define Z_PARAM_ERROR MZ_PARAM_ERROR
#define Z_NO_COMPRESSION MZ_NO_COMPRESSION
#define Z_BEST_SPEED MZ_BEST_SPEED
#define Z_BEST_COMPRESSION MZ_BEST_COMPRESSION
#define Z_DEFAULT_COMPRESSION MZ_DEFAULT_COMPRESSION
#define Z_DEFAULT_STRATEGY MZ_DEFAULT_STRATEGY
#define Z_FILTERED MZ_FILTERED
#define Z_HUFFMAN_ONLY MZ_HUFFMAN_ONLY
#define Z_RLE MZ_RLE
#define Z_FIXED MZ_FIXED
#define Z_DEFLATED MZ_DEFLATED
#define Z_DEFAULT_WINDOW_BITS MZ_DEFAULT_WINDOW_BITS
#define z_stream mz_stream
#define deflateInit mz_deflateInit
#define deflateInit2 mz_deflateInit2
#define deflateReset mz_deflateReset
#define deflate mz_deflate
#define deflateEnd mz_deflateEnd
#define deflateBound mz_deflateBound
#define compress mz_compress
#define compress2 mz_compress2
#define compressBound mz_compressBound
#define inflateInit mz_inflateInit
#define inflateInit2 mz_inflateInit2
#define inflate mz_inflate
#define inflateEnd mz_inflateEnd
#define uncompress mz_uncompress
#define adler32 mz_adler32
#define MAX_WBITS 15
#define MAX_MEM_LEVEL 9
#define ZLIB_VERSION MZ_VERSION
#define ZLIB_VERNUM MZ_VERNUM
#define ZLIB_VER_MAJOR MZ_VER_MAJOR
#define ZLIB_VER_MINOR MZ_VER_MINOR
#define ZLIB_VER_REVISION MZ_VER_REVISION
#define ZLIB_VER_SUBREVISION MZ_VER_SUBREVISION
#define zlibVersion mz_version
#define zlib_version mz_version()
#endif /* #ifndef MINIZ_NO_ZLIB_COMPATIBLE_NAMES */

#define MZ_MACRO_END while (0)

#define tinfl_init(r)     \
    do                    \
    {                     \
        (r)->m_state = 0; \
    }                     \
    MZ_MACRO_END

enum
{
    TINFL_FLAG_PARSE_ZLIB_HEADER = 1,
    TINFL_FLAG_HAS_MORE_INPUT = 2,
    TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF = 4,
    TINFL_FLAG_COMPUTE_ADLER32 = 8
};

enum
{
    TINFL_MAX_HUFF_TABLES = 3,
    TINFL_MAX_HUFF_SYMBOLS_0 = 288,
    TINFL_MAX_HUFF_SYMBOLS_1 = 32,
    TINFL_MAX_HUFF_SYMBOLS_2 = 19,
    TINFL_FAST_LOOKUP_BITS = 10,
    TINFL_FAST_LOOKUP_SIZE = 1 << TINFL_FAST_LOOKUP_BITS
};

typedef unsigned char mz_uint8;
typedef signed short mz_int16;
typedef unsigned short mz_uint16;
typedef unsigned int mz_uint32;
typedef unsigned int mz_uint;
typedef u64 mz_uint64;
typedef int mz_bool;

typedef mz_uint64 tinfl_bit_buf_t;

DECLSPEC void memcpy(void *dest, const void *src, u32 n){
  char *csrc = (char *)src;
  char *cdest = (char *)dest;
  for (int i=0; i<n; i++){
    cdest[i] = csrc[i];
  }
}


DECLSPEC void *memset(u8 *s, int c, u32 len){
  u8 *dst = s;
  while (len > 0) {
      *dst = (u8) c;
      dst++;
      len--;
  }
  return s;
}


#define MZ_MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MZ_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MZ_DEFAULT_WINDOW_BITS 15
#define TINFL_LZ_DICT_SIZE 32768
#define TINFL_MEMCPY(d, s, l) memcpy(d, s, l)
#define TINFL_MEMCPY_G(d, s, l, p) memcpy_g(d, s, l, p)
#define TINFL_MEMSET(p, c, l) memset(p, c, (u32)l)
#define MZ_CLEAR_OBJ(obj) memset(&(obj), 0, sizeof(obj))

#define TINFL_CR_FINISH }
#define TINFL_CR_BEGIN  \
    switch (r->m_state) \
    {                   \
        case 0:

enum
{
    MZ_NO_FLUSH = 0,
    MZ_PARTIAL_FLUSH = 1,
    MZ_SYNC_FLUSH = 2,
    MZ_FULL_FLUSH = 3,
    MZ_FINISH = 4,
    MZ_BLOCK = 5
};

#define MZ_READ_LE16(p) *((const mz_uint16 *)(p))
//#define MZ_READ_LE32(p) *((const mz_uint32 *)(p))
#define MZ_READ_LE32(p) *((mz_uint32 *)(p))

#define TINFL_NEED_BITS(state_index, n)                \
    do                                                 \
    {                                                  \
        mz_uint c;                                     \
        TINFL_GET_BYTE(state_index, c);                \
        bit_buf |= (((tinfl_bit_buf_t)c) << num_bits); \
        num_bits += 8;                                 \
    } while (num_bits < (mz_uint)(n))

#define TINFL_SKIP_BITS(state_index, n)      \
    do                                       \
    {                                        \
        if (num_bits < (mz_uint)(n))         \
        {                                    \
            TINFL_NEED_BITS(state_index, n); \
        }                                    \
        bit_buf >>= (n);                     \
        num_bits -= (n);                     \
    }                                        \
    MZ_MACRO_END

#define TINFL_GET_BITS(state_index, b, n)    \
    do                                       \
    {                                        \
        if (num_bits < (mz_uint)(n))         \
        {                                    \
            TINFL_NEED_BITS(state_index, n); \
        }                                    \
        b = bit_buf & ((1 << (n)) - 1);      \
        bit_buf >>= (n);                     \
        num_bits -= (n);                     \
    }                                        \
    MZ_MACRO_END

#define TINFL_CR_RETURN(state_index, result) \
    do                                       \
    {                                        \
        status = result;                     \
        r->m_state = state_index;            \
        goto common_exit;                    \
        case state_index:;                   \
    }                                        \
    MZ_MACRO_END

#define TINFL_CR_RETURN_FOREVER(state_index, result) \
    do                                               \
    {                                                \
        for (;;)                                     \
        {                                            \
            TINFL_CR_RETURN(state_index, result);    \
        }                                            \
    }                                                \
    MZ_MACRO_END

#define TINFL_GET_BYTE(state_index, c)                                                                                                                           \
    do                                                                                                                                                           \
    {                                                                                                                                                            \
        while (pIn_buf_cur >= pIn_buf_end)                                                                                                                       \
        {                                                                                                                                                        \
            TINFL_CR_RETURN(state_index, (decomp_flags & TINFL_FLAG_HAS_MORE_INPUT) ? TINFL_STATUS_NEEDS_MORE_INPUT : TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS); \
        }                                                                                                                                                        \
        c = pIn_xor_byte (*pIn_buf_cur++, pStream);                                                                                                              \
    }                                                                                                                                                            \
    MZ_MACRO_END

#define TINFL_HUFF_DECODE(state_index, sym, pHuff)                                                                                  \
    do                                                                                                                              \
    {                                                                                                                               \
        int temp;                                                                                                                   \
        mz_uint code_len, c;                                                                                                        \
        if (num_bits < 15)                                                                                                          \
        {                                                                                                                           \
            if ((pIn_buf_end - pIn_buf_cur) < 2)                                                                                    \
            {                                                                                                                       \
                TINFL_HUFF_BITBUF_FILL(state_index, pHuff);                                                                         \
            }                                                                                                                       \
            else                                                                                                                    \
            {                                                                                                                       \
                bit_buf |= (((tinfl_bit_buf_t) pIn_xor_byte (pIn_buf_cur[0], pStream)) << num_bits) | (((tinfl_bit_buf_t) pIn_xor_byte (pIn_buf_cur[1], pStream)) << (num_bits + 8)); \
                pIn_buf_cur += 2;                                                                                                   \
                num_bits += 16;                                                                                                     \
            }                                                                                                                       \
        }                                                                                                                           \
        if ((temp = (pHuff)->m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0)                                               \
            code_len = temp >> 9, temp &= 511;                                                                                      \
        else                                                                                                                        \
        {                                                                                                                           \
            code_len = TINFL_FAST_LOOKUP_BITS;                                                                                      \
            do                                                                                                                      \
            {                                                                                                                       \
                temp = (pHuff)->m_tree[~temp + ((bit_buf >> code_len++) & 1)];                                                      \
            } while (temp < 0);                                                                                                     \
        }                                                                                                                           \
        sym = temp;                                                                                                                 \
        bit_buf >>= code_len;                                                                                                       \
        num_bits -= code_len;                                                                                                       \
    }                                                                                                                               \
    MZ_MACRO_END

#define TINFL_HUFF_BITBUF_FILL(state_index, pHuff)                             \
    do                                                                         \
    {                                                                          \
        temp = (pHuff)->m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)];     \
        if (temp >= 0)                                                         \
        {                                                                      \
            code_len = temp >> 9;                                              \
            if ((code_len) && (num_bits >= code_len))                          \
                break;                                                         \
        }                                                                      \
        else if (num_bits > TINFL_FAST_LOOKUP_BITS)                            \
        {                                                                      \
            code_len = TINFL_FAST_LOOKUP_BITS;                                 \
            do                                                                 \
            {                                                                  \
                temp = (pHuff)->m_tree[~temp + ((bit_buf >> code_len++) & 1)]; \
            } while ((temp < 0) && (num_bits >= (code_len + 1)));              \
            if (temp >= 0)                                                     \
                break;                                                         \
        }                                                                      \
        TINFL_GET_BYTE(state_index, c);                                        \
        bit_buf |= (((tinfl_bit_buf_t)c) << num_bits);                         \
        num_bits += 8;                                                         \
    } while (num_bits < 15);

typedef struct
{
    mz_uint8 m_code_size[TINFL_MAX_HUFF_SYMBOLS_0];
    mz_int16 m_look_up[TINFL_FAST_LOOKUP_SIZE], m_tree[TINFL_MAX_HUFF_SYMBOLS_0 * 2];
} tinfl_huff_table;

typedef enum {
    /* This flags indicates the inflator needs 1 or more input bytes to make forward progress, but the caller is indicating that no more are available. The compressed data */
    /* is probably corrupted. If you call the inflator again with more bytes it'll try to continue processing the input but this is a BAD sign (either the data is corrupted or you called it incorrectly). */
    /* If you call it again with no input you'll just get TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS again. */
    TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS = -4,

    /* This flag indicates that one or more of the input parameters was obviously bogus. (You can try calling it again, but if you get this error the calling code is wrong.) */
    TINFL_STATUS_BAD_PARAM = -3,

    /* This flags indicate the inflator is finished but the adler32 check of the uncompressed data didn't match. If you call it again it'll return TINFL_STATUS_DONE. */
    TINFL_STATUS_ADLER32_MISMATCH = -2,

    /* This flags indicate the inflator has somehow failed (bad code, corrupted input, etc.). If you call it again without resetting via tinfl_init() it it'll just keep on returning the same status failure code. */
    TINFL_STATUS_FAILED = -1,

    /* Any status code less than TINFL_STATUS_DONE must indicate a failure. */

    /* This flag indicates the inflator has returned every byte of uncompressed data that it can, has consumed every byte that it needed, has successfully reached the end of the deflate stream, and */
    /* if zlib headers and adler32 checking enabled that it has successfully checked the uncompressed data's adler32. If you call it again you'll just get TINFL_STATUS_DONE over and over again. */
    TINFL_STATUS_DONE = 0,

    /* This flag indicates the inflator MUST have more input data (even 1 byte) before it can make any more forward progress, or you need to clear the TINFL_FLAG_HAS_MORE_INPUT */
    /* flag on the next call if you don't have any more source data. If the source data was somehow corrupted it's also possible (but unlikely) for the inflator to keep on demanding input to */
    /* proceed, so be sure to properly set the TINFL_FLAG_HAS_MORE_INPUT flag. */
    TINFL_STATUS_NEEDS_MORE_INPUT = 1,

    /* This flag indicates the inflator definitely has 1 or more bytes of uncompressed data available, but it cannot write this data into the output buffer. */
    /* Note if the source compressed data was corrupted it's possible for the inflator to return a lot of uncompressed data to the caller. I've been assuming you know how much uncompressed data to expect */
    /* (either exact or worst case) and will stop calling the inflator and fail after receiving too much. In pure streaming scenarios where you have no idea how many bytes to expect this may not be possible */
    /* so I may need to add some code to address this. */
    TINFL_STATUS_HAS_MORE_OUTPUT = 2
} tinfl_status;

#define tinfl_get_adler32(r) (r)->m_check_adler32



struct tinfl_decompressor_tag
{
    mz_uint32 m_state, m_num_bits, m_zhdr0, m_zhdr1, m_z_adler32, m_final, m_type, m_check_adler32, m_dist, m_counter, m_num_extra, m_table_sizes[TINFL_MAX_HUFF_TABLES];
    tinfl_bit_buf_t m_bit_buf;
    size_t m_dist_from_out_buf_start;
    tinfl_huff_table m_tables[TINFL_MAX_HUFF_TABLES];
    mz_uint8 m_raw_header[4], m_len_codes[TINFL_MAX_HUFF_SYMBOLS_0 + TINFL_MAX_HUFF_SYMBOLS_1 + 137];
};
typedef struct tinfl_decompressor_tag tinfl_decompressor;

typedef struct
{
    tinfl_decompressor m_decomp;
    mz_uint m_dict_ofs, m_dict_avail, m_first_call, m_has_flushed;
    int m_window_bits;
    mz_uint8 m_dict[1]; // hashcat-patched: we do not need m_dict because we have our own output buffer
    tinfl_status m_last_status;

} inflate_state;

typedef struct mz_stream_s
{
    GLOBAL_AS const unsigned char *next_in; /* pointer to next byte to read */
    unsigned int avail_in;        /* number of bytes available at next_in */
    mz_ulong total_in;            /* total number of bytes consumed so far */

    unsigned char *next_out; /* pointer to next byte to write */
    unsigned int avail_out;  /* number of bytes that can be written to next_out */
    mz_ulong total_out;      /* total number of bytes produced so far */

    char *msg;                       /* error msg (unused) */
    inflate_state *state; /* internal state, allocated by zalloc/zfree */

    void *opaque;         /* heap alloc function user pointer */

    int data_type;     /* data_type (unused) */
    mz_ulong adler;    /* adler32 of the source or uncompressed data */
    mz_ulong reserved; /* not used */

    #ifdef CRC32_IN_INFLATE
    u32 key0;
    u32 key1;
    u32 key2;
    u32 crc32;
    LOCAL_AS u32 *crc32tab;
    #endif

} mz_stream;

typedef mz_stream *mz_streamp;

// hashcat-patched: not needed functions:
// void miniz_def_free_func(void *opaque, void *address);
// void *miniz_def_alloc_func(void *opaque, size_t items, size_t size);
DECLSPEC int mz_inflate(mz_streamp pStream, int flush);
DECLSPEC int mz_inflateEnd(mz_streamp pStream);



DECLSPEC int mz_inflateInit2(mz_streamp pStream, int window_bits, inflate_state*);


DECLSPEC const mz_uint8 pIn_xor_byte (const mz_uint8 c, mz_streamp pStream)
{
  mz_uint8 r = c;

  u32 key3;

  update_key3 (pStream->key2, key3);
  u32 plain = c ^ key3;
  update_key012 (pStream->key0, pStream->key1, pStream->key2, plain, pStream->crc32tab);

  return (mz_uint8) plain;
}


DECLSPEC void memcpy_g(void *dest, GLOBAL_AS const void *src, size_t n, mz_streamp pStream){
  GLOBAL_AS char *csrc = (GLOBAL_AS char *)src;
  char *cdest = (char *)dest;
  for (int i=0; i<n; i++){
    cdest[i] = pIn_xor_byte (csrc[i], pStream);
  }
}

DECLSPEC tinfl_status tinfl_decompress(tinfl_decompressor *r, GLOBAL_AS const mz_uint8 *pIn_buf_next, size_t *pIn_buf_size, mz_uint8 *pOut_buf_start, mz_uint8 *pOut_buf_next, size_t *pOut_buf_size, const mz_uint32 decomp_flags, mz_streamp pStream)
{

    const int s_length_base[31] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0 };
    const int s_length_extra[31] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0 };
    const int s_dist_base[32] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0 };
    const int s_dist_extra[32] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
    const mz_uint8 s_length_dezigzag[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    const int s_min_table_sizes[3] = { 257, 1, 4 };

    tinfl_status status = TINFL_STATUS_FAILED;
    mz_uint32 num_bits, dist, counter, num_extra;
    tinfl_bit_buf_t bit_buf;
    GLOBAL_AS const mz_uint8 *pIn_buf_cur = pIn_buf_next;
    GLOBAL_AS const mz_uint8 *pIn_buf_end = pIn_buf_next + *pIn_buf_size;
    mz_uint8 *pOut_buf_cur = pOut_buf_next, *const pOut_buf_end = pOut_buf_next + *pOut_buf_size;
    size_t out_buf_size_mask = (decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF) ? (size_t)-1 : ((pOut_buf_next - pOut_buf_start) + *pOut_buf_size) - 1, dist_from_out_buf_start;

    /* Ensure the output buffer's size is a power of 2, unless the output buffer is large enough to hold the entire output file (in which case it doesn't matter). */
    if (((out_buf_size_mask + 1) & out_buf_size_mask) || (pOut_buf_next < pOut_buf_start))
    {
        *pIn_buf_size = *pOut_buf_size = 0;
        return TINFL_STATUS_BAD_PARAM;
    }

    num_bits = r->m_num_bits;
    bit_buf = r->m_bit_buf;
    dist = r->m_dist;
    counter = r->m_counter;
    num_extra = r->m_num_extra;
    dist_from_out_buf_start = r->m_dist_from_out_buf_start;
    TINFL_CR_BEGIN

    bit_buf = num_bits = dist = counter = num_extra = r->m_zhdr0 = r->m_zhdr1 = 0;
    r->m_z_adler32 = r->m_check_adler32 = 1;
    if (decomp_flags & TINFL_FLAG_PARSE_ZLIB_HEADER)
    {
        TINFL_GET_BYTE(1, r->m_zhdr0);
        TINFL_GET_BYTE(2, r->m_zhdr1);
        counter = (((r->m_zhdr0 * 256 + r->m_zhdr1) % 31 != 0) || (r->m_zhdr1 & 32) || ((r->m_zhdr0 & 15) != 8));
        if (!(decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF))
            counter |= (((1U << (8U + (r->m_zhdr0 >> 4))) > 32768U) || ((out_buf_size_mask + 1) < (size_t)(1U << (8U + (r->m_zhdr0 >> 4)))));
        if (counter)
        {
            TINFL_CR_RETURN_FOREVER(36, TINFL_STATUS_FAILED);
        }
    }

    do
    {
        TINFL_GET_BITS(3, r->m_final, 3);
        r->m_type = r->m_final >> 1;
        if (r->m_type == 0)
        {
            TINFL_SKIP_BITS(5, num_bits & 7);
            for (counter = 0; counter < 4; ++counter)
            {
                if (num_bits)
                    TINFL_GET_BITS(6, r->m_raw_header[counter], 8);
                else
                    TINFL_GET_BYTE(7, r->m_raw_header[counter]);
            }
            if ((counter = (r->m_raw_header[0] | (r->m_raw_header[1] << 8))) != (mz_uint)(0xFFFF ^ (r->m_raw_header[2] | (r->m_raw_header[3] << 8))))
            {
                TINFL_CR_RETURN_FOREVER(39, TINFL_STATUS_FAILED);
            }
            while ((counter) && (num_bits))
            {
                TINFL_GET_BITS(51, dist, 8);
                while (pOut_buf_cur >= pOut_buf_end)
                {
                    TINFL_CR_RETURN(52, TINFL_STATUS_HAS_MORE_OUTPUT);
                }
                *pOut_buf_cur++ = (mz_uint8)dist;
                counter--;
            }
            while (counter)
            {
                size_t n;
                while (pOut_buf_cur >= pOut_buf_end)
                {
                    TINFL_CR_RETURN(9, TINFL_STATUS_HAS_MORE_OUTPUT);
                }
                while (pIn_buf_cur >= pIn_buf_end)
                {
                    TINFL_CR_RETURN(38, (decomp_flags & TINFL_FLAG_HAS_MORE_INPUT) ? TINFL_STATUS_NEEDS_MORE_INPUT : TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS);
                }
                n = MZ_MIN(MZ_MIN((size_t)(pOut_buf_end - pOut_buf_cur), (size_t)(pIn_buf_end - pIn_buf_cur)), counter);
                TINFL_MEMCPY_G(pOut_buf_cur, pIn_buf_cur, n, pStream);
                pIn_buf_cur += n;
                pOut_buf_cur += n;
                counter -= (mz_uint)n;
            }
        }
        else if (r->m_type == 3)
        {
            TINFL_CR_RETURN_FOREVER(10, TINFL_STATUS_FAILED);
        }
        else
        {
            if (r->m_type == 1)
            {
                mz_uint8 *p = r->m_tables[0].m_code_size;
                mz_uint i;
                r->m_table_sizes[0] = 288;
                r->m_table_sizes[1] = 32;
                TINFL_MEMSET(r->m_tables[1].m_code_size, 5, 32);
                for (i = 0; i <= 143; ++i)
                    *p++ = 8;
                for (; i <= 255; ++i)
                    *p++ = 9;
                for (; i <= 279; ++i)
                    *p++ = 7;
                for (; i <= 287; ++i)
                    *p++ = 8;
            }
            else
            {
                for (counter = 0; counter < 3; counter++)
                {
                    TINFL_GET_BITS(11, r->m_table_sizes[counter], "\05\05\04"[counter]);
                    r->m_table_sizes[counter] += s_min_table_sizes[counter];
                }
                MZ_CLEAR_OBJ(r->m_tables[2].m_code_size);
                for (counter = 0; counter < r->m_table_sizes[2]; counter++)
                {
                    mz_uint s;
                    TINFL_GET_BITS(14, s, 3);
                    r->m_tables[2].m_code_size[s_length_dezigzag[counter]] = (mz_uint8)s;
                }
                r->m_table_sizes[2] = 19;
            }
            for (; (int)r->m_type >= 0; r->m_type--)
            {
                int tree_next, tree_cur;
                tinfl_huff_table *pTable;
                mz_uint i, j, used_syms, total, sym_index, next_code[17], total_syms[16];
                pTable = &r->m_tables[r->m_type];
                MZ_CLEAR_OBJ(total_syms);
                MZ_CLEAR_OBJ(pTable->m_look_up);
                MZ_CLEAR_OBJ(pTable->m_tree);
                for (i = 0; i < r->m_table_sizes[r->m_type]; ++i)
                    total_syms[pTable->m_code_size[i]]++;
                used_syms = 0, total = 0;
                next_code[0] = next_code[1] = 0;
                for (i = 1; i <= 15; ++i)
                {
                    used_syms += total_syms[i];
                    next_code[i + 1] = (total = ((total + total_syms[i]) << 1));
                }
                if ((65536 != total) && (used_syms > 1))
                {
                    TINFL_CR_RETURN_FOREVER(35, TINFL_STATUS_FAILED);
                }
                for (tree_next = -1, sym_index = 0; sym_index < r->m_table_sizes[r->m_type]; ++sym_index)
                {
                    mz_uint rev_code = 0, l, cur_code, code_size = pTable->m_code_size[sym_index];
                    if (!code_size)
                        continue;
                    cur_code = next_code[code_size]++;
                    for (l = code_size; l > 0; l--, cur_code >>= 1)
                        rev_code = (rev_code << 1) | (cur_code & 1);
                    if (code_size <= TINFL_FAST_LOOKUP_BITS)
                    {
                        mz_int16 k = (mz_int16)((code_size << 9) | sym_index);
                        while (rev_code < TINFL_FAST_LOOKUP_SIZE)
                        {
                            pTable->m_look_up[rev_code] = k;
                            rev_code += (1 << code_size);
                        }
                        continue;
                    }
                    if (0 == (tree_cur = pTable->m_look_up[rev_code & (TINFL_FAST_LOOKUP_SIZE - 1)]))
                    {
                        pTable->m_look_up[rev_code & (TINFL_FAST_LOOKUP_SIZE - 1)] = (mz_int16)tree_next;
                        tree_cur = tree_next;
                        tree_next -= 2;
                    }
                    rev_code >>= (TINFL_FAST_LOOKUP_BITS - 1);
                    for (j = code_size; j > (TINFL_FAST_LOOKUP_BITS + 1); j--)
                    {
                        tree_cur -= ((rev_code >>= 1) & 1);
                        if (!pTable->m_tree[-tree_cur - 1])
                        {
                            pTable->m_tree[-tree_cur - 1] = (mz_int16)tree_next;
                            tree_cur = tree_next;
                            tree_next -= 2;
                        }
                        else
                            tree_cur = pTable->m_tree[-tree_cur - 1];
                    }
                    tree_cur -= ((rev_code >>= 1) & 1);
                    pTable->m_tree[-tree_cur - 1] = (mz_int16)sym_index;
                }
                if (r->m_type == 2)
                {
                    for (counter = 0; counter < (r->m_table_sizes[0] + r->m_table_sizes[1]);)
                    {
                        mz_uint s;
                        TINFL_HUFF_DECODE(16, dist, &r->m_tables[2]);
                        if (dist < 16)
                        {
                            r->m_len_codes[counter++] = (mz_uint8)dist;
                            continue;
                        }
                        if ((dist == 16) && (!counter))
                        {
                            TINFL_CR_RETURN_FOREVER(17, TINFL_STATUS_FAILED);
                        }
                        num_extra = "\02\03\07"[dist - 16];
                        TINFL_GET_BITS(18, s, num_extra);
                        s += "\03\03\013"[dist - 16];
                        TINFL_MEMSET(r->m_len_codes + counter, (dist == 16) ? r->m_len_codes[counter - 1] : 0, s);
                        counter += s;
                    }
                    if ((r->m_table_sizes[0] + r->m_table_sizes[1]) != counter)
                    {
                        TINFL_CR_RETURN_FOREVER(21, TINFL_STATUS_FAILED);
                    }
                    TINFL_MEMCPY(r->m_tables[0].m_code_size, r->m_len_codes, r->m_table_sizes[0]);
                    TINFL_MEMCPY(r->m_tables[1].m_code_size, r->m_len_codes + r->m_table_sizes[0], r->m_table_sizes[1]);
                }
            }
            for (;;)
            {
                mz_uint8 *pSrc;
                for (;;)
                {
                    if (((pIn_buf_end - pIn_buf_cur) < 4) || ((pOut_buf_end - pOut_buf_cur) < 2))
                    {
                        TINFL_HUFF_DECODE(23, counter, &r->m_tables[0]);
                        if (counter >= 256)
                            break;
                        while (pOut_buf_cur >= pOut_buf_end)
                        {
                            TINFL_CR_RETURN(24, TINFL_STATUS_HAS_MORE_OUTPUT);
                        }
                        *pOut_buf_cur++ = (mz_uint8)counter;
                    }
                    else
                    {
                        int sym2;
                        mz_uint code_len;
                        if (num_bits < 30)
                        {
                            u32 num = pIn_xor_byte (*pIn_buf_cur, pStream);
                            pIn_buf_cur++;
                            for(int i=1;i<4;i++){
                              num |=  pIn_xor_byte (*pIn_buf_cur, pStream) << 8*i;
                              pIn_buf_cur++;
                            }
                            //bit_buf |= (((tinfl_bit_buf_t)MZ_READ_LE32(pIn_buf_cur)) << num_bits);
                            bit_buf |= ((tinfl_bit_buf_t)num) << num_bits;
                            //pIn_buf_cur += 4;
                            num_bits += 32;
                        }
                        if ((sym2 = r->m_tables[0].m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0)
                            code_len = sym2 >> 9;
                        else
                        {
                            code_len = TINFL_FAST_LOOKUP_BITS;
                            do
                            {
                                sym2 = r->m_tables[0].m_tree[~sym2 + ((bit_buf >> code_len++) & 1)];
                            } while (sym2 < 0);
                        }
                        counter = sym2;
                        bit_buf >>= code_len;
                        num_bits -= code_len;
                        if (counter & 256)
                            break;

                        if ((sym2 = r->m_tables[0].m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0)
                            code_len = sym2 >> 9;
                        else
                        {
                            code_len = TINFL_FAST_LOOKUP_BITS;
                            do
                            {
                                sym2 = r->m_tables[0].m_tree[~sym2 + ((bit_buf >> code_len++) & 1)];
                            } while (sym2 < 0);
                        }
                        bit_buf >>= code_len;
                        num_bits -= code_len;

                        pOut_buf_cur[0] = (mz_uint8)counter;
                        if (sym2 & 256)
                        {
                            pOut_buf_cur++;
                            counter = sym2;
                            break;
                        }
                        pOut_buf_cur[1] = (mz_uint8)sym2;
                        pOut_buf_cur += 2;
                    }
                }
                if ((counter &= 511) == 256)
                    break;

                num_extra = s_length_extra[counter - 257];
                counter = s_length_base[counter - 257];
                if (num_extra)
                {
                    mz_uint extra_bits;
                    TINFL_GET_BITS(25, extra_bits, num_extra);
                    counter += extra_bits;
                }

                TINFL_HUFF_DECODE(26, dist, &r->m_tables[1]);
                num_extra = s_dist_extra[dist];
                dist = s_dist_base[dist];
                if (num_extra)
                {
                    mz_uint extra_bits;
                    TINFL_GET_BITS(27, extra_bits, num_extra);
                    dist += extra_bits;
                }

                dist_from_out_buf_start = pOut_buf_cur - pOut_buf_start;
                if ((dist > dist_from_out_buf_start) && (decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF))
                {
                    TINFL_CR_RETURN_FOREVER(37, TINFL_STATUS_FAILED);
                }

                pSrc = pOut_buf_start + ((dist_from_out_buf_start - dist) & out_buf_size_mask);

                if ((MZ_MAX(pOut_buf_cur, pSrc) + counter) > pOut_buf_end)
                {
                    while (counter--)
                    {
                        while (pOut_buf_cur >= pOut_buf_end)
                        {
                            TINFL_CR_RETURN(53, TINFL_STATUS_HAS_MORE_OUTPUT);
                        }
                        *pOut_buf_cur++ = pOut_buf_start[(dist_from_out_buf_start++ - dist) & out_buf_size_mask];
                    }
                    continue;
                }
                else if ((counter >= 9) && (counter <= dist))
                {
                    const mz_uint8 *pSrc_end = pSrc + (counter & ~7);
                    do
                    {
                        //((mz_uint32 *)pOut_buf_cur)[0] = ((const mz_uint32 *)pSrc)[0];
                        //((mz_uint32 *)pOut_buf_cur)[1] = ((const mz_uint32 *)pSrc)[1];

                        for(int i=0;i<8;i++){
                          pOut_buf_cur[i] = pSrc[i];
                        }

                        pOut_buf_cur += 8;
                    } while ((pSrc += 8) < pSrc_end);
                    if ((counter &= 7) < 3)
                    {
                        if (counter)
                        {
                            pOut_buf_cur[0] = pSrc[0];
                            if (counter > 1)
                                pOut_buf_cur[1] = pSrc[1];
                            pOut_buf_cur += counter;
                        }
                        continue;
                    }
                }
                while(counter>2)
                {
                    pOut_buf_cur[0] = pSrc[0];
                    pOut_buf_cur[1] = pSrc[1];
                    pOut_buf_cur[2] = pSrc[2];
                    pOut_buf_cur += 3;
                    pSrc += 3;
					counter -= 3;
                }
                if (counter > 0)
                {
                    pOut_buf_cur[0] = pSrc[0];
                    if (counter > 1)
                        pOut_buf_cur[1] = pSrc[1];
                    pOut_buf_cur += counter;
                }
            }
        }
    } while (!(r->m_final & 1));

    /* Ensure byte alignment and put back any bytes from the bitbuf if we've looked ahead too far on gzip, or other Deflate streams followed by arbitrary data. */
    /* I'm being super conservative here. A number of simplifications can be made to the byte alignment part, and the Adler32 check shouldn't ever need to worry about reading from the bitbuf now. */
    TINFL_SKIP_BITS(32, num_bits & 7);
    while ((pIn_buf_cur > pIn_buf_next) && (num_bits >= 8))
    {
        --pIn_buf_cur;
        num_bits -= 8;
    }
    bit_buf &= (tinfl_bit_buf_t)((((mz_uint64)1) << num_bits) - (mz_uint64)1);


    if (decomp_flags & TINFL_FLAG_PARSE_ZLIB_HEADER)
    {
        for (counter = 0; counter < 4; ++counter)
        {
            mz_uint s;
            if (num_bits)
                TINFL_GET_BITS(41, s, 8);
            else
                TINFL_GET_BYTE(42, s);
            r->m_z_adler32 = (r->m_z_adler32 << 8) | s;
        }
    }
    TINFL_CR_RETURN_FOREVER(34, TINFL_STATUS_DONE);

    TINFL_CR_FINISH

common_exit:
    /* As long as we aren't telling the caller that we NEED more input to make forward progress: */
    /* Put back any bytes from the bitbuf in case we've looked ahead too far on gzip, or other Deflate streams followed by arbitrary data. */
    /* We need to be very careful here to NOT push back any bytes we definitely know we need to make forward progress, though, or we'll lock the caller up into an inf loop. */
    if ((status != TINFL_STATUS_NEEDS_MORE_INPUT) && (status != TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS))
    {
        while ((pIn_buf_cur > pIn_buf_next) && (num_bits >= 8))
        {
            --pIn_buf_cur;
            num_bits -= 8;
        }
    }
    r->m_num_bits = num_bits;
    r->m_bit_buf = bit_buf & (tinfl_bit_buf_t)((((mz_uint64)1) << num_bits) - (mz_uint64)1);
    r->m_dist = dist;
    r->m_counter = counter;
    r->m_num_extra = num_extra;
    r->m_dist_from_out_buf_start = dist_from_out_buf_start;
    *pIn_buf_size = pIn_buf_cur - pIn_buf_next;
    *pOut_buf_size = pOut_buf_cur - pOut_buf_next;
    if ((decomp_flags & (TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_COMPUTE_ADLER32)) && (status >= 0))
    {
        const mz_uint8 *ptr = pOut_buf_next;
        size_t buf_len = *pOut_buf_size;
        mz_uint32 i, s1 = r->m_check_adler32 & 0xffff, s2 = r->m_check_adler32 >> 16;
        size_t block_len = buf_len % 5552;
        while (buf_len)
        {
            for (i = 0; i + 7 < block_len; i += 8, ptr += 8)
            {
                s1 += ptr[0], s2 += s1;
                s1 += ptr[1], s2 += s1;
                s1 += ptr[2], s2 += s1;
                s1 += ptr[3], s2 += s1;
                s1 += ptr[4], s2 += s1;
                s1 += ptr[5], s2 += s1;
                s1 += ptr[6], s2 += s1;
                s1 += ptr[7], s2 += s1;
            }
            for (; i < block_len; ++i)
                s1 += *ptr++, s2 += s1;
            s1 %= 65521U, s2 %= 65521U;
            buf_len -= block_len;
            block_len = 5552;
        }
        r->m_check_adler32 = (s2 << 16) + s1;
        if ((status == TINFL_STATUS_DONE) && (decomp_flags & TINFL_FLAG_PARSE_ZLIB_HEADER) && (r->m_check_adler32 != r->m_z_adler32))
            status = TINFL_STATUS_ADLER32_MISMATCH;
    }
    return status;
}


DECLSPEC int mz_inflateInit2(mz_streamp pStream, int window_bits, inflate_state *pDecomp)
{
    if (pStream == 0)
        return MZ_STREAM_ERROR;
    if ((window_bits != MZ_DEFAULT_WINDOW_BITS) && (-window_bits != MZ_DEFAULT_WINDOW_BITS))
        return MZ_PARAM_ERROR;

    pStream->data_type = 0;
    pStream->adler = 0;
    pStream->msg = Z_NULL;
    pStream->total_in = 0;
    pStream->total_out = 0;
    pStream->reserved = 0;

    //pStream->state = (struct mz_internal_state *)pDecomp;
    pStream->state = (inflate_state *) pDecomp;

    tinfl_init(&pDecomp->m_decomp);
    pDecomp->m_dict_ofs = 0;
    pDecomp->m_dict_avail = 0;
    pDecomp->m_last_status = TINFL_STATUS_NEEDS_MORE_INPUT;
    pDecomp->m_first_call = 1;
    pDecomp->m_has_flushed = 0;
    pDecomp->m_window_bits = window_bits;

    return MZ_OK;
}

DECLSPEC int mz_inflate(mz_streamp pStream, int flush)
{
    inflate_state *pState;
    mz_uint n, first_call, decomp_flags = TINFL_FLAG_COMPUTE_ADLER32;
    size_t in_bytes, out_bytes, orig_avail_in;
    tinfl_status status;

    if ((pStream == 0) || (pStream->state == 0))
        return MZ_STREAM_ERROR;
    if (flush == MZ_PARTIAL_FLUSH)
        flush = MZ_SYNC_FLUSH;
    if ((flush) && (flush != MZ_SYNC_FLUSH) && (flush != MZ_FINISH))
        return MZ_STREAM_ERROR;

    pState = (inflate_state *)pStream->state;
    if (pState->m_window_bits > 0)
        decomp_flags |= TINFL_FLAG_PARSE_ZLIB_HEADER;
    orig_avail_in = pStream->avail_in;

    first_call = pState->m_first_call;
    pState->m_first_call = 0;
    if (pState->m_last_status < 0)
        return MZ_DATA_ERROR;

    if (pState->m_has_flushed && (flush != MZ_FINISH))
        return MZ_STREAM_ERROR;
    pState->m_has_flushed |= (flush == MZ_FINISH);

    if ((flush == MZ_FINISH) && (first_call))
    {
        /* MZ_FINISH on the first call implies that the input and output buffers are large enough to hold the entire compressed/decompressed file. */
        decomp_flags |= TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        in_bytes = pStream->avail_in;
        out_bytes = pStream->avail_out;
        status = tinfl_decompress(&pState->m_decomp, pStream->next_in, &in_bytes, pStream->next_out, pStream->next_out, &out_bytes, decomp_flags, pStream);

        for (int i = 0; i < out_bytes; i++)
        {
          pStream->crc32 = CRC32 (pStream->crc32, pStream->next_out[i], pStream->crc32tab);
        }

        pState->m_last_status = status;
        pStream->next_in += (mz_uint)in_bytes;
        pStream->avail_in -= (mz_uint)in_bytes;
        pStream->total_in += (mz_uint)in_bytes;
        pStream->adler = tinfl_get_adler32(&pState->m_decomp);
        //pStream->next_out += (mz_uint)out_bytes;
        //pStream->avail_out -= (mz_uint)out_bytes;
        pStream->total_out += (mz_uint)out_bytes;

        if (status < 0)
            return MZ_DATA_ERROR;
        else if (status != TINFL_STATUS_DONE)
        {
            pState->m_last_status = TINFL_STATUS_FAILED;
            return MZ_BUF_ERROR;
        }
        return MZ_STREAM_END;
    }
    /* flush != MZ_FINISH then we must assume there's more input. */
    if (flush != MZ_FINISH)
        decomp_flags |= TINFL_FLAG_HAS_MORE_INPUT;

    if (pState->m_dict_avail)
    {
        n = MZ_MIN(pState->m_dict_avail, pStream->avail_out);
        memcpy(pStream->next_out, pState->m_dict + pState->m_dict_ofs, n);

        for (int i = 0; i < n; i++)
        {
          pStream->crc32 = CRC32 (pStream->crc32, pStream->next_out[i], pStream->crc32tab);
        }

        //pStream->next_out += n;
        //pStream->avail_out -= n;
        pStream->total_out += n;
        pState->m_dict_avail -= n;
        pState->m_dict_ofs = (pState->m_dict_ofs + n) & (TINFL_LZ_DICT_SIZE - 1);
        return ((pState->m_last_status == TINFL_STATUS_DONE) && (!pState->m_dict_avail)) ? MZ_STREAM_END : MZ_OK;
    }


    for (;;)
    {
        in_bytes = pStream->avail_in;
        out_bytes = TINFL_LZ_DICT_SIZE - pState->m_dict_ofs;

        status = tinfl_decompress(&pState->m_decomp, pStream->next_in, &in_bytes, pState->m_dict, pState->m_dict + pState->m_dict_ofs, &out_bytes, decomp_flags, pStream);
        pState->m_last_status = status;

        pStream->next_in += (mz_uint)in_bytes;
        pStream->avail_in -= (mz_uint)in_bytes;
        pStream->total_in += (mz_uint)in_bytes;
        pStream->adler = tinfl_get_adler32(&pState->m_decomp);

        pState->m_dict_avail = (mz_uint)out_bytes;

        n = MZ_MIN(pState->m_dict_avail, pStream->avail_out);
        memcpy(pStream->next_out, pState->m_dict + pState->m_dict_ofs, n);

        for (int i = 0; i < n; i++)
        {
          pStream->crc32 = CRC32 (pStream->crc32, pStream->next_out[i], pStream->crc32tab);
        }

        //pStream->next_out += n;
        //pStream->avail_out -= n;
        pStream->total_out += n;
        pState->m_dict_avail -= n;
        pState->m_dict_ofs = (pState->m_dict_ofs + n) & (TINFL_LZ_DICT_SIZE - 1);

        if (status < 0)
            return MZ_DATA_ERROR; /* Stream is corrupted (there could be some uncompressed data left in the output dictionary - oh well). */
        else if ((status == TINFL_STATUS_NEEDS_MORE_INPUT) && (!orig_avail_in))
            return MZ_BUF_ERROR; /* Signal caller that we can't make forward progress without supplying more input or by setting flush to MZ_FINISH. */
        else if (flush == MZ_FINISH)
        {
            /* The output buffer MUST be large to hold the remaining uncompressed data when flush==MZ_FINISH. */
            if (status == TINFL_STATUS_DONE)
                return pState->m_dict_avail ? MZ_BUF_ERROR : MZ_STREAM_END;
            /* status here must be TINFL_STATUS_HAS_MORE_OUTPUT, which means there's at least 1 more byte on the way. If there's no more room left in the output buffer then something is wrong. */
            else if (!pStream->avail_out)
                return MZ_BUF_ERROR;
        }
        else if ((status == TINFL_STATUS_DONE) || (!pStream->avail_in) || (!pStream->avail_out) || (pState->m_dict_avail))
            break;
    }

    return ((status == TINFL_STATUS_DONE) && (!pState->m_dict_avail)) ? MZ_STREAM_END : MZ_OK;
}

// hashcat-patched: helper function for shifted u32

DECLSPEC u32 GETSHIFTEDINT (u32 *a, const int n)
{
  const int d = n / 4;
  const int m = n & 3;

  u64 tmp = hl32_to_64_S (a[d + 1], a[d + 0]);

  tmp >>= m * 8;

  return l32_from_64_S (tmp);
}

// hashcat-patched: faster memcpy for our large (TINFL_LZ_DICT_SIZE) move of bytes from the old output to the window/lookup table

DECLSPEC void hc_shift_inflate_dict (u8 *buf, const u32 offset, const u32 len)
{
  u32 *ptr = (u32 *) buf;

  // we need to use len - 4 here to avoid buffer overflows caused by the u64 type in GETSHIFTEDINT

  u32 i, j;

  for (i = 0, j = 0; i < len - 4; i += 4, j++)
  {
    ptr[j] = GETSHIFTEDINT (ptr, offset + i);
  }

  // final step (last 4 bytes are special):

  ptr[j] = (buf[offset + i + 3] << 24) | (buf[offset + i + 2] << 16) | (buf[offset + i + 1] << 8) | buf[offset + i];
}

// hashcat-patched: the mz_inflate () function from above doesn't work for us because we need to allow larger input/output and
// we only need the crc32 checksum actually

DECLSPEC int hc_inflate (mz_streamp pStream)
{
  // we can't use the full TINFL_LZ_DICT_SIZE buffer because even with only 16 input bytes
  // we can get pretty close to our max available output buffer:

  // size_t in_bytes = MZ_MIN (TINFL_LZ_DICT_SIZE, pStream->avail_in);
  size_t in_bytes = MZ_MIN (16, pStream->avail_in);

  mz_uint decomp_flags = ((pStream->avail_in - in_bytes) > 0) ? TINFL_FLAG_HAS_MORE_INPUT : 0;

  decomp_flags |= TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;

  inflate_state *pState = pStream->state;

  size_t out_bytes = pStream->avail_out;

  tinfl_status status = tinfl_decompress (&pState->m_decomp, pStream->next_in, &in_bytes, pStream->next_out, pStream->next_out + pStream->total_out, &out_bytes, decomp_flags, pStream);

  for (int i = 0; i < out_bytes; i++)
  {
    pStream->crc32 = CRC32 (pStream->crc32, pStream->next_out[pStream->total_out + i], pStream->crc32tab);
  }

  pStream->next_in  += (mz_uint) in_bytes;
  pStream->avail_in -= (mz_uint) in_bytes;
  pStream->total_in += (mz_uint) in_bytes;

  pStream->avail_out -= out_bytes;
  pStream->total_out += out_bytes;

  if (pStream->avail_out < TINFL_LZ_DICT_SIZE)
  {
    // reset:

    // move the last TINFL_LZ_DICT_SIZE bytes to the start of the output buffer

    // memcpy (pStream->next_out, pStream->next_out + pStream->total_out - TINFL_LZ_DICT_SIZE, TINFL_LZ_DICT_SIZE);
    hc_shift_inflate_dict (pStream->next_out, pStream->total_out - TINFL_LZ_DICT_SIZE, TINFL_LZ_DICT_SIZE);

    pStream->avail_out = TINFL_LZ_DICT_SIZE;
    pStream->total_out = TINFL_LZ_DICT_SIZE;
  }

  if (status < 0)
  {
    return MZ_DATA_ERROR;
  }

  if (in_bytes == 0)
  {
    return MZ_STREAM_END;
  }

  if (pStream->avail_in == 0)
  {
    return MZ_STREAM_END;
  }

  return (status == TINFL_STATUS_DONE) ? MZ_STREAM_END : MZ_OK;
}
