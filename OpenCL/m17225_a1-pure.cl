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

-----

The MIT License

Copyright (c) 2018, EUROPEAN UNION

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

Author:              Sein Coray
Related publication: https://scitepress.org/PublicationsDetail.aspx?ID=KLPzPqStp5g=

*/

#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)

#define MAX_LOCAL 512 // too much leaves no room for compiler optimizations, simply benchmark to find a good trade-off - make it as big as possible
#define TMPSIZ    (2 * TINFL_LZ_DICT_SIZE)

#define CRC32(x,c,t) (((x) >> 8) ^ (t)[((x) ^ (c)) & 0xff])
#define MSB(x)       ((x) >> 24)
#define CONST        0x08088405

#define MAX_DATA (320 * 1024)

#define update_key012(k0,k1,k2,c,t)           \
{                                             \
  (k0) = CRC32 ((k0), c, (t));                \
  (k1) = ((k1) + ((k0) & 0xff)) * CONST + 1;  \
  (k2) = CRC32 ((k2), MSB (k1), (t));         \
}

// One buffer of the candidate through the key schedule. -a 12 assembles a candidate from five
// pieces, so this runs once per piece rather than once for the base word and once for the amplifier.

#define update_key012_buf(k0,k1,k2,buf,len,t)                                             \
{                                                                                         \
  const u32 blen = (len);                                                                 \
                                                                                          \
  for (u32 bi = 0, bj = 0; bi < blen; bi += 4, bj += 1)                                   \
  {                                                                                       \
    if (blen >= (bi + 1)) update_key012 (k0, k1, k2, unpack_v8a_from_v32_S ((buf)[bj]), t); \
    if (blen >= (bi + 2)) update_key012 (k0, k1, k2, unpack_v8b_from_v32_S ((buf)[bj]), t); \
    if (blen >= (bi + 3)) update_key012 (k0, k1, k2, unpack_v8c_from_v32_S ((buf)[bj]), t); \
    if (blen >= (bi + 4)) update_key012 (k0, k1, k2, unpack_v8d_from_v32_S ((buf)[bj]), t); \
  }                                                                                       \
}

#define update_key3(k2,k3)                  \
{                                           \
  const u32 temp = ((k2) & 0xffff) | 3;     \
                                            \
  (k3) = ((temp * (temp ^ 1)) >> 8) & 0xff; \
}

// this is required to force mingw to accept the packed attribute
#pragma pack(push,1)

struct pkzip_hash
{
  u8  data_type_enum;
  u8  magic_type_enum;
  u32 compressed_length;
  u32 uncompressed_length;
  u32 crc32;
  u32 offset;
  u32 additional_offset;
  u8  compression_type;
  u32 data_length;
  u16 checksum_from_crc;
  u16 checksum_from_timestamp;
  u32 data[MAX_DATA / 4]; // a quarter because of the u32 type

} __attribute__((packed));

typedef struct pkzip_hash pkzip_hash_t;

struct pkzip
{
  u8 hash_count;
  u8 checksum_size;
  u8 version;

  pkzip_hash_t hashes[8];

} __attribute__((packed));

typedef struct pkzip pkzip_t;

#pragma pack(pop)

#define CRC32_IN_INFLATE

#include M2S(INCLUDE_PATH/inc_zip_inflate.cl)

typedef struct {
    u8  op;          /* operation, extra bits, table bits */
    u8  bits;        /* bits in this part of the code */
    u16 val;         /* offset in table or code value */
} code;

CONSTANT_VK code lenfix[512] = {
    {96,7,0},{0,8,80},{0,8,16},{20,8,115},{18,7,31},{0,8,112},{0,8,48},
    {0,9,192},{16,7,10},{0,8,96},{0,8,32},{0,9,160},{0,8,0},{0,8,128},
    {0,8,64},{0,9,224},{16,7,6},{0,8,88},{0,8,24},{0,9,144},{19,7,59},
    {0,8,120},{0,8,56},{0,9,208},{17,7,17},{0,8,104},{0,8,40},{0,9,176},
    {0,8,8},{0,8,136},{0,8,72},{0,9,240},{16,7,4},{0,8,84},{0,8,20},
    {21,8,227},{19,7,43},{0,8,116},{0,8,52},{0,9,200},{17,7,13},{0,8,100},
    {0,8,36},{0,9,168},{0,8,4},{0,8,132},{0,8,68},{0,9,232},{16,7,8},
    {0,8,92},{0,8,28},{0,9,152},{20,7,83},{0,8,124},{0,8,60},{0,9,216},
    {18,7,23},{0,8,108},{0,8,44},{0,9,184},{0,8,12},{0,8,140},{0,8,76},
    {0,9,248},{16,7,3},{0,8,82},{0,8,18},{21,8,163},{19,7,35},{0,8,114},
    {0,8,50},{0,9,196},{17,7,11},{0,8,98},{0,8,34},{0,9,164},{0,8,2},
    {0,8,130},{0,8,66},{0,9,228},{16,7,7},{0,8,90},{0,8,26},{0,9,148},
    {20,7,67},{0,8,122},{0,8,58},{0,9,212},{18,7,19},{0,8,106},{0,8,42},
    {0,9,180},{0,8,10},{0,8,138},{0,8,74},{0,9,244},{16,7,5},{0,8,86},
    {0,8,22},{64,8,0},{19,7,51},{0,8,118},{0,8,54},{0,9,204},{17,7,15},
    {0,8,102},{0,8,38},{0,9,172},{0,8,6},{0,8,134},{0,8,70},{0,9,236},
    {16,7,9},{0,8,94},{0,8,30},{0,9,156},{20,7,99},{0,8,126},{0,8,62},
    {0,9,220},{18,7,27},{0,8,110},{0,8,46},{0,9,188},{0,8,14},{0,8,142},
    {0,8,78},{0,9,252},{96,7,0},{0,8,81},{0,8,17},{21,8,131},{18,7,31},
    {0,8,113},{0,8,49},{0,9,194},{16,7,10},{0,8,97},{0,8,33},{0,9,162},
    {0,8,1},{0,8,129},{0,8,65},{0,9,226},{16,7,6},{0,8,89},{0,8,25},
    {0,9,146},{19,7,59},{0,8,121},{0,8,57},{0,9,210},{17,7,17},{0,8,105},
    {0,8,41},{0,9,178},{0,8,9},{0,8,137},{0,8,73},{0,9,242},{16,7,4},
    {0,8,85},{0,8,21},{16,8,258},{19,7,43},{0,8,117},{0,8,53},{0,9,202},
    {17,7,13},{0,8,101},{0,8,37},{0,9,170},{0,8,5},{0,8,133},{0,8,69},
    {0,9,234},{16,7,8},{0,8,93},{0,8,29},{0,9,154},{20,7,83},{0,8,125},
    {0,8,61},{0,9,218},{18,7,23},{0,8,109},{0,8,45},{0,9,186},{0,8,13},
    {0,8,141},{0,8,77},{0,9,250},{16,7,3},{0,8,83},{0,8,19},{21,8,195},
    {19,7,35},{0,8,115},{0,8,51},{0,9,198},{17,7,11},{0,8,99},{0,8,35},
    {0,9,166},{0,8,3},{0,8,131},{0,8,67},{0,9,230},{16,7,7},{0,8,91},
    {0,8,27},{0,9,150},{20,7,67},{0,8,123},{0,8,59},{0,9,214},{18,7,19},
    {0,8,107},{0,8,43},{0,9,182},{0,8,11},{0,8,139},{0,8,75},{0,9,246},
    {16,7,5},{0,8,87},{0,8,23},{64,8,0},{19,7,51},{0,8,119},{0,8,55},
    {0,9,206},{17,7,15},{0,8,103},{0,8,39},{0,9,174},{0,8,7},{0,8,135},
    {0,8,71},{0,9,238},{16,7,9},{0,8,95},{0,8,31},{0,9,158},{20,7,99},
    {0,8,127},{0,8,63},{0,9,222},{18,7,27},{0,8,111},{0,8,47},{0,9,190},
    {0,8,15},{0,8,143},{0,8,79},{0,9,254},{96,7,0},{0,8,80},{0,8,16},
    {20,8,115},{18,7,31},{0,8,112},{0,8,48},{0,9,193},{16,7,10},{0,8,96},
    {0,8,32},{0,9,161},{0,8,0},{0,8,128},{0,8,64},{0,9,225},{16,7,6},
    {0,8,88},{0,8,24},{0,9,145},{19,7,59},{0,8,120},{0,8,56},{0,9,209},
    {17,7,17},{0,8,104},{0,8,40},{0,9,177},{0,8,8},{0,8,136},{0,8,72},
    {0,9,241},{16,7,4},{0,8,84},{0,8,20},{21,8,227},{19,7,43},{0,8,116},
    {0,8,52},{0,9,201},{17,7,13},{0,8,100},{0,8,36},{0,9,169},{0,8,4},
    {0,8,132},{0,8,68},{0,9,233},{16,7,8},{0,8,92},{0,8,28},{0,9,153},
    {20,7,83},{0,8,124},{0,8,60},{0,9,217},{18,7,23},{0,8,108},{0,8,44},
    {0,9,185},{0,8,12},{0,8,140},{0,8,76},{0,9,249},{16,7,3},{0,8,82},
    {0,8,18},{21,8,163},{19,7,35},{0,8,114},{0,8,50},{0,9,197},{17,7,11},
    {0,8,98},{0,8,34},{0,9,165},{0,8,2},{0,8,130},{0,8,66},{0,9,229},
    {16,7,7},{0,8,90},{0,8,26},{0,9,149},{20,7,67},{0,8,122},{0,8,58},
    {0,9,213},{18,7,19},{0,8,106},{0,8,42},{0,9,181},{0,8,10},{0,8,138},
    {0,8,74},{0,9,245},{16,7,5},{0,8,86},{0,8,22},{64,8,0},{19,7,51},
    {0,8,118},{0,8,54},{0,9,205},{17,7,15},{0,8,102},{0,8,38},{0,9,173},
    {0,8,6},{0,8,134},{0,8,70},{0,9,237},{16,7,9},{0,8,94},{0,8,30},
    {0,9,157},{20,7,99},{0,8,126},{0,8,62},{0,9,221},{18,7,27},{0,8,110},
    {0,8,46},{0,9,189},{0,8,14},{0,8,142},{0,8,78},{0,9,253},{96,7,0},
    {0,8,81},{0,8,17},{21,8,131},{18,7,31},{0,8,113},{0,8,49},{0,9,195},
    {16,7,10},{0,8,97},{0,8,33},{0,9,163},{0,8,1},{0,8,129},{0,8,65},
    {0,9,227},{16,7,6},{0,8,89},{0,8,25},{0,9,147},{19,7,59},{0,8,121},
    {0,8,57},{0,9,211},{17,7,17},{0,8,105},{0,8,41},{0,9,179},{0,8,9},
    {0,8,137},{0,8,73},{0,9,243},{16,7,4},{0,8,85},{0,8,21},{16,8,258},
    {19,7,43},{0,8,117},{0,8,53},{0,9,203},{17,7,13},{0,8,101},{0,8,37},
    {0,9,171},{0,8,5},{0,8,133},{0,8,69},{0,9,235},{16,7,8},{0,8,93},
    {0,8,29},{0,9,155},{20,7,83},{0,8,125},{0,8,61},{0,9,219},{18,7,23},
    {0,8,109},{0,8,45},{0,9,187},{0,8,13},{0,8,141},{0,8,77},{0,9,251},
    {16,7,3},{0,8,83},{0,8,19},{21,8,195},{19,7,35},{0,8,115},{0,8,51},
    {0,9,199},{17,7,11},{0,8,99},{0,8,35},{0,9,167},{0,8,3},{0,8,131},
    {0,8,67},{0,9,231},{16,7,7},{0,8,91},{0,8,27},{0,9,151},{20,7,67},
    {0,8,123},{0,8,59},{0,9,215},{18,7,19},{0,8,107},{0,8,43},{0,9,183},
    {0,8,11},{0,8,139},{0,8,75},{0,9,247},{16,7,5},{0,8,87},{0,8,23},
    {64,8,0},{19,7,51},{0,8,119},{0,8,55},{0,9,207},{17,7,15},{0,8,103},
    {0,8,39},{0,9,175},{0,8,7},{0,8,135},{0,8,71},{0,9,239},{16,7,9},
    {0,8,95},{0,8,31},{0,9,159},{20,7,99},{0,8,127},{0,8,63},{0,9,223},
    {18,7,27},{0,8,111},{0,8,47},{0,9,191},{0,8,15},{0,8,143},{0,8,79},
    {0,9,255}
};

CONSTANT_VK code distfix[32] = {
    {16,5,1},{23,5,257},{19,5,17},{27,5,4097},{17,5,5},{25,5,1025},
    {21,5,65},{29,5,16385},{16,5,3},{24,5,513},{20,5,33},{28,5,8193},
    {18,5,9},{26,5,2049},{22,5,129},{64,5,0},{16,5,2},{23,5,385},
    {19,5,25},{27,5,6145},{17,5,7},{25,5,1537},{21,5,97},{29,5,24577},
    {16,5,4},{24,5,769},{20,5,49},{28,5,12289},{18,5,13},{26,5,3073},
    {22,5,193},{64,5,0}
};

DECLSPEC int check_inflate_code2 (PRIVATE_AS u8 *next)
{
  u32 bits, hold, thisget, have, i;
  int left;
  u32 ncode;
  u32 ncount[2];  // ends up being an array of 8 u8 count values.  But we can clear it, and later 'check' it with 2 u32 instructions.
  u8 *count;    // this will point to ncount array. NOTE, this is alignment required 'safe' for Sparc systems or others requiring alignment.
  hold = *next + (((u32) next[1]) << 8) + (((u32) next[2]) << 16) + (((u32) next[3]) << 24);
  next += 3;  // we pre-increment when pulling it in the loop, thus we need to be 1 byte back.
  hold >>= 3;  // we already processed 3 bits
  count = (u8*)ncount;

  if (257 + (hold & 0x1F) > 286)
  {
    return 0;  // nlen, but we do not use it.
  }
  hold >>= 5;
  if (1 + (hold & 0x1F) > 30)
  {
    return 0;    // ndist, but we do not use it.
  }
  hold >>= 5;
  ncode = 4 + (hold & 0xF);
  hold >>= 4;

  // we have 15 bits left.
  hold += ((u32)(*++next)) << 15;
  hold += ((u32)(*++next)) << 23;
  // we now have 31 bits.  We need to know this for the loop below.
  bits = 31;

  // We have 31 bits now, in accum.  If we are processing 19 codes, we do 7, then have 10 bits.
  // Add 16 more and have 26, then use 21, have 5.  Then load 16 more, then eat 15 of them.
  have = 0;

  ncount[0] = ncount[1] = 0;
  for (;;)
  {
    if (have+7>ncode)
    {
      thisget = ncode-have;
    }
    else
    {
      thisget = 7;
    }
    have += thisget;
    bits -= thisget*3;
    while (thisget--)
    {
      ++count[hold&7];
      hold>>=3;
    }
    if (have == ncode)
    {
      break;
    }
    hold += ((u32)(*++next)) << bits;
    bits += 8;
    hold += ((u32)(*++next)) << bits;
    bits += 8;
  }
  count[0] = 0;
  if (!ncount[0] && !ncount[1])
  {
    return 0;
  }

  left = 1;
  for (i = 1; i <= 7; ++i)
  {
    left <<= 1;
    left -= count[i];
    if (left < 0)
    {
      return 0;
    }
  }
  if (left > 0)
  {
    return 0;
  }

  return 1;
}


DECLSPEC int check_inflate_code1 (PRIVATE_AS u8 *next, int left)
{
  u32 whave = 0, op, bits, hold,len;
  code here1;

  hold = *next + (((u32) next[1]) << 8) + (((u32) next[2]) << 16) + (((u32) next[3]) << 24);
  next += 3; // we pre-increment when pulling it in the loop, thus we need to be 1 byte back.
  left -= 4;
  hold >>= 3;  // we already processed 3 bits
  bits = 32-3;
  for (;;)
  {
    if (bits < 15)
    {
      if (left < 2)
      {
        return 1;  // we are out of bytes.  Return we had no error.
      }
      left -= 2;
      hold += (u32)(*++next) << bits;
      bits += 8;
      hold += (u32)(*++next) << bits;
      bits += 8;
    }
    here1=lenfix[hold & 0x1FF];
    op = (unsigned)(here1.bits);
    hold >>= op;
    bits -= op;
    op = (unsigned)(here1.op);
    if (op == 0)
    {
      ++whave;
    }
    else if (op & 16)
    {
      len = (unsigned)(here1.val);
      op &= 15;
      if (op)
      {
        if (bits < op)
        {
          if (!left)
          {
            return 1;
          }
          --left;
          hold += (u32)(*++next) << bits;
          bits += 8;
        }
        len += (unsigned)hold & ((1U << op) - 1);
        hold >>= op;
        bits -= op;
      }
      if (bits < 15)
      {
        if (left < 2)
        {
          return 1;
        }
        left -= 2;
        hold += (u32)(*++next) << bits;
        bits += 8;
        hold += (u32)(*++next) << bits;
        bits += 8;
      }
      code here2 = distfix[hold & 0x1F];
      op = (unsigned)(here2.bits);
      hold >>= op;
      bits -= op;
      op = (unsigned)(here2.op);
      if (op & 16) /* distance base */
      {
        u32 dist = (unsigned)(here2.val);
        op &= 15;
        if (bits < op)
        {
          if (!left)
          {
            return 1;
          }
          --left;
          hold += (u32)(*++next) << bits;
          bits += 8;
          if (bits < op)
          {
            if (!left)
            {
              return 1;
            }
            --left;
            hold += (u32)(*++next) << bits;
            bits += 8;
          }
        }
        dist += (unsigned)hold & ((1U << op) - 1);
        if (dist > whave)
        {
          return 0;
        }
        hold >>= op;
        bits -= op;

        whave += len;
      }
      else
      {
        return 0;
      }
    }
    else if (op & 32)
    {
      if (left == 0)
      {
        return 1;
      }
      return 0;
    }
    else
    {
      return 0;
    }
  }
}

KERNEL_FQ KERNEL_FA void m17225_sxx (KERN_ATTR_ESALT (pkzip_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
   */

  LOCAL_VK u32 l_crc32tab[256];

  for (u64 i = lid; i < 256; i += lsz)
  {
    l_crc32tab[i] = crc32tab[i];
  }

  SYNC_THREADS ();

  LOCAL_VK u32 l_data[MAX_LOCAL];

  for (u64 i = lid; i < MAX_LOCAL; i += lsz)
  {
    l_data[i] = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[0].data[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * prefetch from global memory
   */

  const u32 checksum_size = esalt_bufs[DIGESTS_OFFSET_HOST].checksum_size;
  const u32 hash_count    = esalt_bufs[DIGESTS_OFFSET_HOST].hash_count;

  /**
   * loop
   */

  u32x key0init = 0x12345678;
  u32x key1init = 0x23456789;
  u32x key2init = 0x34567890;

  // -a 12 puts the base word inside the amplifier instead of beside it, so the base word does not
  // start the candidate and the state in front of it is what the loop below has to begin from.

  const u32x key0empty = key0init;
  const u32x key1empty = key1init;
  const u32x key2empty = key2init;

  for (u32 i = 0, j = 0; i < pws[gid].pw_len; i += 4, j += 1)
  {
    if (pws[gid].pw_len >= (i + 1)) update_key012 (key0init, key1init, key2init, unpack_v8a_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 2)) update_key012 (key0init, key1init, key2init, unpack_v8b_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 3)) update_key012 (key0init, key1init, key2init, unpack_v8c_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 4)) update_key012 (key0init, key1init, key2init, unpack_v8d_from_v32_S (pws[gid].i[j]), l_crc32tab);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32x key0init2 = key0init;
    u32x key1init2 = key1init;
    u32x key2init2 = key2init;

    if (COMBS_IS_MIDDLE)
    {
      // five pieces in a fixed order: mask, base word, mask, second word, mask, and the state the
      // base word produced on its own is no longer the state this continues from

      key0init2 = key0empty;
      key1init2 = key1empty;
      key2init2 = key2empty;

      update_key012_buf (key0init2, key1init2, key2init2, COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len, l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, pws[gid].i,            pws[gid].pw_len,            l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len, l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len, l_crc32tab);
    }

    update_key012_buf (key0init2, key1init2, key2init2, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, l_crc32tab);

    u32 plain;
    u32 key3;
    u32 next;

    for (u32 idx = 0; idx < hash_count; idx++)
    {
      u32x key0 = key0init2;
      u32x key1 = key1init2;
      u32x key2 = key2init2;

      if (idx == 0) next = l_data[0];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[0];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8b_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8c_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8d_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      if (idx == 0) next = l_data[1];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[1];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8b_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8c_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8d_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      if (idx == 0) next = l_data[2];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[2];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8b_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8c_from_v32_S (next) ^ key3;
      if ((checksum_size == 2) && ((esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_crc & 0xff) != plain) && ((esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_timestamp & 0xff) != plain)) break;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8d_from_v32_S (next) ^ key3;
      if ((plain != (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_crc >> 8)) && (plain != (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_timestamp >> 8))) break;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 0 && esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_type_enum == 1)
      {
        continue; // so far everything matches for this hash, but it's only a partial and uncompressed one, so we need to continue with the next one
      }

      const u32 key0_sav = key0;
      const u32 key1_sav = key1;
      const u32 key2_sav = key2;

      u8 tmp[TMPSIZ];

      if (idx == 0) next = l_data[3];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[3];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 8 && ((plain & 6) == 6)) break;
      tmp[0] = plain;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8b_from_v32_S (next) ^ key3;
      tmp[1] = plain;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8c_from_v32_S (next) ^ key3;
      tmp[2] = plain;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8d_from_v32_S (next) ^ key3;
      tmp[3] = plain;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      for (int i = 16; i < 36; i += 4)
      {
        if (idx == 0) next = l_data[i / 4];
        else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[i / 4];

        update_key3 (key2, key3);
        plain = unpack_v8a_from_v32_S (next) ^ key3;
        tmp[i - 12 + 0] = plain;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        update_key3 (key2, key3);
        plain = unpack_v8b_from_v32_S (next) ^ key3;
        tmp[i - 12 + 1] = plain;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        update_key3 (key2, key3);
        plain = unpack_v8c_from_v32_S (next) ^ key3;
        tmp[i - 12 + 2] = plain;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        update_key3 (key2, key3);
        plain = unpack_v8d_from_v32_S (next) ^ key3;
        tmp[i - 12 + 3] = plain;
        update_key012 (key0, key1, key2, plain, l_crc32tab);
      }

      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 8 && esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_length >= 36 && ((tmp[0]) & 6) == 2 && !check_inflate_code1 (tmp, 24)) break;
      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 8 && esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_length >= 36 && ((tmp[0]) & 6) == 4 && !check_inflate_code2 (tmp))     break;

      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_type_enum == 1)
      {
        continue; // so far everything matches for this hash, but it's only a partial one, so we need to continue with the next one
      }

      u32x crc = 0xffffffff;

      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 8)
      {
        mz_stream infstream;

        inflate_state pStream;

        infstream.opaque    = Z_NULL;
        infstream.avail_in  = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_length           - 12; // size of input
        infstream.next_in   = (GLOBAL_AS u8 *) esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data + 12; // input char array
        infstream.avail_out = TMPSIZ; // size of output
        infstream.next_out  = tmp; // output char array

        #ifdef CRC32_IN_INFLATE
        infstream.key0      = key0_sav;
        infstream.key1      = key1_sav;
        infstream.key2      = key2_sav;
        infstream.crc32     = 0xffffffff;
        infstream.crc32tab  = l_crc32tab;
        #endif

        // inflateinit2 is needed because otherwise it checks for headers by default
        mz_inflateInit2 (&infstream, -MAX_WBITS, &pStream);

        int ret = hc_inflate (&infstream);

        while (ret == MZ_OK)
        {
          ret = hc_inflate (&infstream);
        }

        if (ret != MZ_STREAM_END || infstream.total_out != esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].uncompressed_length) break;

        crc = ~infstream.crc32;
      }
      else{
        const u32 data_length = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_length;

        key0 = key0_sav;
        key1 = key1_sav;
        key2 = key2_sav;

        for (u32 j = 3, i = 12; i < data_length; j++, i += 4)
        {
          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[j];

          if (data_length >= (i + 1))
          {
            update_key3 (key2, key3);
            plain = unpack_v8a_from_v32_S (next) ^ key3;
            update_key012 (key0, key1, key2, plain, l_crc32tab);

            crc = CRC32 (crc, plain, l_crc32tab);
          }

          if (data_length >= (i + 2))
          {
            update_key3 (key2, key3);
            plain = unpack_v8b_from_v32_S (next) ^ key3;
            update_key012 (key0, key1, key2, plain, l_crc32tab);

            crc = CRC32 (crc, plain, l_crc32tab);
          }

          if (data_length >= (i + 3))
          {
            update_key3 (key2, key3);
            plain = unpack_v8c_from_v32_S (next) ^ key3;
            update_key012 (key0, key1, key2, plain, l_crc32tab);

            crc = CRC32 (crc, plain, l_crc32tab);
          }

          if (data_length >= (i + 4))
          {
            update_key3 (key2, key3);
            plain = unpack_v8d_from_v32_S (next) ^ key3;
            update_key012 (key0, key1, key2, plain, l_crc32tab);

            crc = CRC32 (crc, plain, l_crc32tab);
          }
        }

        crc = ~crc;
      }

      // we check the crc32, but it might not necessarily be the last one (depending how strict
      if (crc == esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].crc32)
      {
        if (idx + 1 == hash_count)
        {
          /**
           * digest for last hash
           */

          const u32 search[4] =
          {
            digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0],
            0,
            0,
            0
          };

          const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[0].checksum_from_crc;
          const u32 r1 = 0;
          const u32 r2 = 0;
          const u32 r3 = 0;

          COMPARE_S_SIMD (r0, r1, r2, r3);
        }
      }
      else
      {
        break;
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m17225_mxx (KERN_ATTR_ESALT (pkzip_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
   */

  LOCAL_VK u32 l_crc32tab[256];

  for (u64 i = lid; i < 256; i += lsz)
  {
    l_crc32tab[i] = crc32tab[i];
  }

  SYNC_THREADS ();

  LOCAL_VK u32 l_data[MAX_LOCAL];

  for (u64 i = lid; i < MAX_LOCAL; i += lsz)
  {
    l_data[i] = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[0].data[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * prefetch from global memory
   */

  const u32 checksum_size = esalt_bufs[DIGESTS_OFFSET_HOST].checksum_size;
  const u32 hash_count    = esalt_bufs[DIGESTS_OFFSET_HOST].hash_count;

  /**
   * loop
   */

  u32x key0init = 0x12345678;
  u32x key1init = 0x23456789;
  u32x key2init = 0x34567890;

  // -a 12 puts the base word inside the amplifier instead of beside it, so the base word does not
  // start the candidate and the state in front of it is what the loop below has to begin from.

  const u32x key0empty = key0init;
  const u32x key1empty = key1init;
  const u32x key2empty = key2init;

  for (u32 i = 0, j = 0; i < pws[gid].pw_len; i += 4, j += 1)
  {
    if (pws[gid].pw_len >= (i + 1)) update_key012 (key0init, key1init, key2init, unpack_v8a_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 2)) update_key012 (key0init, key1init, key2init, unpack_v8b_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 3)) update_key012 (key0init, key1init, key2init, unpack_v8c_from_v32_S (pws[gid].i[j]), l_crc32tab);
    if (pws[gid].pw_len >= (i + 4)) update_key012 (key0init, key1init, key2init, unpack_v8d_from_v32_S (pws[gid].i[j]), l_crc32tab);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32x key0init2 = key0init;
    u32x key1init2 = key1init;
    u32x key2init2 = key2init;

    if (COMBS_IS_MIDDLE)
    {
      // five pieces in a fixed order: mask, base word, mask, second word, mask, and the state the
      // base word produced on its own is no longer the state this continues from

      key0init2 = key0empty;
      key1init2 = key1empty;
      key2init2 = key2empty;

      update_key012_buf (key0init2, key1init2, key2init2, COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len, l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, pws[gid].i,            pws[gid].pw_len,            l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len, l_crc32tab);
      update_key012_buf (key0init2, key1init2, key2init2, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len, l_crc32tab);
    }

    update_key012_buf (key0init2, key1init2, key2init2, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, l_crc32tab);

    u32 plain;
    u32 key3;
    u32 next;

    for (u32 idx = 0; idx < hash_count; idx++)
    {
      u32x key0 = key0init2;
      u32x key1 = key1init2;
      u32x key2 = key2init2;

      if (idx == 0) next = l_data[0];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[0];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8b_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8c_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8d_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      if (idx == 0) next = l_data[1];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[1];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8b_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8c_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8d_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      if (idx == 0) next = l_data[2];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[2];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8b_from_v32_S (next) ^ key3;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8c_from_v32_S (next) ^ key3;
      if ((checksum_size == 2) && ((esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_crc & 0xff) != plain) && ((esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_timestamp & 0xff) != plain)) break;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8d_from_v32_S (next) ^ key3;
      if ((plain != (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_crc >> 8)) && (plain != (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].checksum_from_timestamp >> 8))) break;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 0 && esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_type_enum == 1)
      {
        continue; // so far everything matches for this hash, but it's only a partial and uncompressed one, so we need to continue with the next one
      }

      const u32 key0_sav = key0;
      const u32 key1_sav = key1;
      const u32 key2_sav = key2;

      u8 tmp[TMPSIZ];

      if (idx == 0) next = l_data[3];
      else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[3];

      update_key3 (key2, key3);
      plain = unpack_v8a_from_v32_S (next) ^ key3;
      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 8 && ((plain & 6) == 6)) break;
      tmp[0] = plain;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8b_from_v32_S (next) ^ key3;
      tmp[1] = plain;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8c_from_v32_S (next) ^ key3;
      tmp[2] = plain;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      update_key3 (key2, key3);
      plain = unpack_v8d_from_v32_S (next) ^ key3;
      tmp[3] = plain;
      update_key012 (key0, key1, key2, plain, l_crc32tab);

      for (int i = 16; i < 36; i += 4)
      {
        if (idx == 0) next = l_data[i / 4];
        else          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[i / 4];

        update_key3 (key2, key3);
        plain = unpack_v8a_from_v32_S (next) ^ key3;
        tmp[i - 12 + 0] = plain;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        update_key3 (key2, key3);
        plain = unpack_v8b_from_v32_S (next) ^ key3;
        tmp[i - 12 + 1] = plain;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        update_key3 (key2, key3);
        plain = unpack_v8c_from_v32_S (next) ^ key3;
        tmp[i - 12 + 2] = plain;
        update_key012 (key0, key1, key2, plain, l_crc32tab);

        update_key3 (key2, key3);
        plain = unpack_v8d_from_v32_S (next) ^ key3;
        tmp[i - 12 + 3] = plain;
        update_key012 (key0, key1, key2, plain, l_crc32tab);
      }

      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 8 && esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_length >= 36 && ((tmp[0]) & 6) == 2 && !check_inflate_code1 (tmp, 24)) break;
      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 8 && esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_length >= 36 && ((tmp[0]) & 6) == 4 && !check_inflate_code2 (tmp))     break;

      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_type_enum == 1)
      {
        continue; // so far everything matches for this hash, but it's only a partial one, so we need to continue with the next one
      }

      u32x crc = 0xffffffff;

      if (esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].compression_type == 8)
      {
        mz_stream infstream;

        inflate_state pStream;

        infstream.opaque    = Z_NULL;
        infstream.avail_in  = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_length           - 12; // size of input
        infstream.next_in   = (GLOBAL_AS u8 *) esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data + 12; // input char array
        infstream.avail_out = TMPSIZ; // size of output
        infstream.next_out  = tmp; // output char array

        #ifdef CRC32_IN_INFLATE
        infstream.key0      = key0_sav;
        infstream.key1      = key1_sav;
        infstream.key2      = key2_sav;
        infstream.crc32     = 0xffffffff;
        infstream.crc32tab  = l_crc32tab;
        #endif

        // inflateinit2 is needed because otherwise it checks for headers by default
        mz_inflateInit2 (&infstream, -MAX_WBITS, &pStream);

        int ret = hc_inflate (&infstream);

        while (ret == MZ_OK)
        {
          ret = hc_inflate (&infstream);
        }

        if (ret != MZ_STREAM_END || infstream.total_out != esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].uncompressed_length) break;

        crc = ~infstream.crc32;
      }
      else{
        const u32 data_length = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data_length;

        key0 = key0_sav;
        key1 = key1_sav;
        key2 = key2_sav;

        for (u32 j = 3, i = 12; i < data_length; j++, i += 4)
        {
          next = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].data[j];

          if (data_length >= (i + 1))
          {
            update_key3 (key2, key3);
            plain = unpack_v8a_from_v32_S (next) ^ key3;
            update_key012 (key0, key1, key2, plain, l_crc32tab);

            crc = CRC32 (crc, plain, l_crc32tab);
          }

          if (data_length >= (i + 2))
          {
            update_key3 (key2, key3);
            plain = unpack_v8b_from_v32_S (next) ^ key3;
            update_key012 (key0, key1, key2, plain, l_crc32tab);

            crc = CRC32 (crc, plain, l_crc32tab);
          }

          if (data_length >= (i + 3))
          {
            update_key3 (key2, key3);
            plain = unpack_v8c_from_v32_S (next) ^ key3;
            update_key012 (key0, key1, key2, plain, l_crc32tab);

            crc = CRC32 (crc, plain, l_crc32tab);
          }

          if (data_length >= (i + 4))
          {
            update_key3 (key2, key3);
            plain = unpack_v8d_from_v32_S (next) ^ key3;
            update_key012 (key0, key1, key2, plain, l_crc32tab);

            crc = CRC32 (crc, plain, l_crc32tab);
          }
        }

        crc = ~crc;
      }

      // we check the crc32, but it might not necessarily be the last one (depending how strict
      if (crc == esalt_bufs[DIGESTS_OFFSET_HOST].hashes[idx].crc32)
      {
        if (idx + 1 == hash_count)
        {
          const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].hashes[0].checksum_from_crc;
          const u32 r1 = 0;
          const u32 r2 = 0;
          const u32 r3 = 0;

          COMPARE_M_SIMD (r0, r1, r2, r3);
        }
      }
      else
      {
        break;
      }
    }
  }
}

#undef MAX_LOCAL
#undef TMPSIZ
#undef CRC32
#undef MSB
#undef CONST
#undef MAX_DATA
#undef update_key012
#undef update_key3
