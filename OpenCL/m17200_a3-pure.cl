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

Author: Sein Coray

*/

#include "inc_zip_inflate.cl"

#define CRC32(x,c) (((x)>>8)^l_crc32tab[((x)^(c))&0xff])
#define MSB(x)     ((x)>>24)
#define CONST      0x08088405
#define POLYNOMIAL 0xEDB88320

#define MAX_COMPRESSED_LENGTH   2048
#define MAX_UNCOMPRESSED_LENGTH 4096

typedef struct {
    u8  op;          /* operation, extra bits, table bits */
    u8  bits;        /* bits in this part of the code */
    u16 val;         /* offset in table or code value */
} code;

typedef struct pkzip_hash
{
  u8  data_type_enum;
  u8  magic_type_enum;
  u32 compressed_length;
  u32 uncompressed_length;
  u32 crc32;
  u8  offset;
  u8  additional_offset;
  u8  compression_type;
  u32 data_length;
  u16 checksum_from_crc;
  u16 checksum_from_timestamp;
  u8  data[MAX_COMPRESSED_LENGTH];
} pkzip_hash_t;

typedef struct pkzip
{
  u8 hash_count;
  u8 checksum_size;
  u8 version;
  pkzip_hash_t hash;
} pkzip_t;

__constant code lenfix[512] = {
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

__constant code distfix[32] = {
    {16,5,1},{23,5,257},{19,5,17},{27,5,4097},{17,5,5},{25,5,1025},
    {21,5,65},{29,5,16385},{16,5,3},{24,5,513},{20,5,33},{28,5,8193},
    {18,5,9},{26,5,2049},{22,5,129},{64,5,0},{16,5,2},{23,5,385},
    {19,5,25},{27,5,6145},{17,5,7},{25,5,1537},{21,5,97},{29,5,24577},
    {16,5,4},{24,5,769},{20,5,49},{28,5,12289},{18,5,13},{26,5,3073},
    {22,5,193},{64,5,0}
};

DECLSPEC int check_inflate_code2(u8 *next)
{
  u32 bits, hold, thisget, have, i;
  int left;
  u32 ncode;
  u32 ncount[2];  // ends up being an array of 8 u8 count values.  But we can clear it, and later 'check' it with 2 u32 instructions.
  u8 *count;    // this will point to ncount array. NOTE, this is alignment required 'safe' for Sparc systems or others requiring alignment.
  hold = *next + (((u32)next[1])<<8) + (((u32)next[2])<<16) + (((u32)next[3])<<24);
  next += 3;  // we pre-increment when pulling it in the loop, thus we need to be 1 byte back.
  hold >>= 3;  // we already processed 3 bits
  count = (u8*)ncount;

  if (257+(hold&0x1F) > 286)
  {
    return 0;  // nlen, but we do not use it.
  }
  hold >>= 5;
  if (1+(hold&0x1F) > 30)
  {
    return 0;    // ndist, but we do not use it.
  }
  hold >>= 5;
  ncode = 4+(hold&0xF);
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


DECLSPEC int check_inflate_code1(u8 *next, int left){
  u32 whave = 0, op, bits, hold,len;
  code here1;

  hold = *next + (((u32)next[1])<<8) + (((u32)next[2])<<16) + (((u32)next[3])<<24);
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

__kernel void m17200_sxx (KERN_ATTR_VECTOR_ESALT (pkzip_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  __local u32 l_crc32tab[0x100];

  u32 remainder;
  u32 b = 0;
  u8 set = 0;
  for (u32 b = 0; b < 256; b++)
  {
    remainder = b;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    l_crc32tab[b] = remainder;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x key0, key1, key2;
  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    const u32x w0 = w0l | w0r;
    w[0] = w0;

    key0 = 0x12345678;
    key1 = 0x23456789;
    key2 = 0x34567890;

    for (u8 i = 0; i < pw_len; i++)
    {
      key0 = CRC32( key0, (w[i >> 2] >> ((i & 3) << 3)) & 0xff );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );
    }

    u8 compressed[MAX_COMPRESSED_LENGTH];
    u8 abort = 0;
    u8 plain;
    u8 key3;
    u16 temp;

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[0] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[1] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[2] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[3] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[4] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[5] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[6] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[7] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[8] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[9] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[10] ^ key3;

    if (esalt_bufs[digests_offset].checksum_size == 2 && plain != (esalt_bufs[digests_offset].hash.checksum_from_crc & 0xff) && plain != (esalt_bufs[digests_offset].hash.checksum_from_timestamp & 0xff))
    {
      continue;
    }

    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[11] ^ key3;

    if (plain != (esalt_bufs[digests_offset].hash.checksum_from_crc >> 8) && plain != (esalt_bufs[digests_offset].hash.checksum_from_timestamp >> 8))
    {
      continue;
    }

    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[12] ^ key3;

    if ((plain & 6) == 0 || (plain & 6) == 6)
    {
      continue;
    }

    compressed[0] = plain;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    for (unsigned int i = 13; i < 36; i++)
    {
      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hash.data[i] ^ key3;

      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      compressed[i-12] = plain;
    }

    if (((compressed[0]) & 6) == 2 && !check_inflate_code1 (compressed, 36))
    {
      abort=1;
    }
    if (((compressed[0]) & 6) == 4 && !check_inflate_code2 (compressed))
    {
      abort=1;
    }

    if (abort)
    {
      continue;
    }

    for (unsigned int i = 36; i < esalt_bufs[digests_offset].hash.data_length; i++)
    {
      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hash.data[i] ^ key3;

      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      compressed[i - 12] = plain;
    }

    unsigned char inflated[MAX_UNCOMPRESSED_LENGTH];
    mz_stream infstream;
    inflate_state pStream;
    infstream.zalloc    = Z_NULL;
    infstream.zfree     = Z_NULL;
    infstream.opaque    = Z_NULL;
    infstream.avail_in  = esalt_bufs[digests_offset].hash.data_length - 12; // size of input
    infstream.next_in   = (Bytef *)compressed; // input char array
    infstream.avail_out = 2048; // size of output
    infstream.next_out  = (Bytef *)inflated; // output char array

    // inflateinit2 is needed because otherwise it checks for headers by default
    mz_inflateInit2(&infstream, -MAX_WBITS, &pStream);
    int ret = mz_inflate(&infstream, Z_NO_FLUSH);
    if (ret < 0)
    {
      continue; // failed to inflate
    }

    // check CRC
    u32x crc = 0xffffffff;
    for (unsigned int k = 0; k < infstream.total_out; ++k)
    {
      crc = CRC32(crc, inflated[k]);
    }
    crc = ~crc;

    if (crc == esalt_bufs[digests_offset].hash.crc32)
    {
      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

__kernel void m17200_mxx (KERN_ATTR_VECTOR_ESALT (pkzip_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  __local u32 l_crc32tab[0x100];

  u32 remainder;
  u32 b = 0;
  u8 set = 0;
  for (u32 b = 0; b < 256; b++)
  {
    remainder = b;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    if (remainder & 1) remainder = (remainder >> 1) ^ POLYNOMIAL;
    else remainder >>= 1;

    l_crc32tab[b] = remainder;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x key0, key1, key2;
  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    const u32x w0 = w0l | w0r;
    w[0] = w0;

    key0 = 0x12345678;
    key1 = 0x23456789;
    key2 = 0x34567890;

    for(u8 i = 0; i < pw_len; i++)
    {
      key0 = CRC32( key0, (w[i >> 2] >> ((i & 3) << 3)) & 0xff );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );
    }

    u8 compressed[MAX_COMPRESSED_LENGTH];
    u8 abort = 0;
    u8 plain;
    u8 key3;
    u16 temp;

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[0] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[1] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[2] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[3] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[4] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[5] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[6] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[7] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[8] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[9] ^ key3;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[10] ^ key3;

    if (esalt_bufs[digests_offset].checksum_size == 2 && plain != (esalt_bufs[digests_offset].hash.checksum_from_crc & 0xff) && plain != (esalt_bufs[digests_offset].hash.checksum_from_timestamp & 0xff))
    {
      continue;
    }

    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[11] ^ key3;

    if (plain != (esalt_bufs[digests_offset].hash.checksum_from_crc >> 8) && plain != (esalt_bufs[digests_offset].hash.checksum_from_timestamp >> 8))
    {
      continue;
    }

    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    temp = (key2 & 0xffff) | 3;
    key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
    plain = esalt_bufs[digests_offset].hash.data[12] ^ key3;

    if ((plain & 6) == 0 || (plain & 6) == 6)
    {
      continue;
    }

    compressed[0] = plain;
    key0 = CRC32( key0, plain );
    key1 = (key1 + (key0 & 0xff)) * CONST + 1;
    key2 = CRC32( key2, MSB(key1) );

    for (unsigned int i = 13; i < 36; i++)
    {
      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hash.data[i] ^ key3;

      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      compressed[i-12] = plain;
    }

    if (((compressed[0]) & 6) == 2 && !check_inflate_code1 (compressed, 36))
    {
      abort=1;
    }
    if (((compressed[0]) & 6) == 4 && !check_inflate_code2 (compressed))
    {
      abort=1;
    }

    if (abort)
    {
      continue;
    }

    for (unsigned int i = 36; i < esalt_bufs[digests_offset].hash.data_length; i++)
    {
      temp = (key2 & 0xffff) | 3;
      key3 = ((temp * (temp ^ 1)) >> 8) & 0xff;
      plain = esalt_bufs[digests_offset].hash.data[i] ^ key3;

      key0 = CRC32( key0, plain );
      key1 = (key1 + (key0 & 0xff)) * CONST + 1;
      key2 = CRC32( key2, MSB(key1) );

      compressed[i - 12] = plain;
    }

    unsigned char inflated[MAX_UNCOMPRESSED_LENGTH];
    mz_stream infstream;
    inflate_state pStream;
    infstream.zalloc    = Z_NULL;
    infstream.zfree     = Z_NULL;
    infstream.opaque    = Z_NULL;
    infstream.avail_in  = esalt_bufs[digests_offset].hash.data_length - 12; // size of input
    infstream.next_in   = (Bytef *)compressed; // input char array
    infstream.avail_out = 2048; // size of output
    infstream.next_out  = (Bytef *)inflated; // output char array

    // inflateinit2 is needed because otherwise it checks for headers by default
    mz_inflateInit2(&infstream, -MAX_WBITS, &pStream);
    int ret = mz_inflate(&infstream, Z_NO_FLUSH);
    if (ret < 0)
    {
      continue; // failed to inflate
    }

    // check CRC
    u32x crc = 0xffffffff;
    for (unsigned int k = 0; k < infstream.total_out; ++k)
    {
      crc = CRC32(crc, inflated[k]);
    }
    crc = ~crc;

    if (crc == esalt_bufs[digests_offset].hash.crc32)
    {
      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
      }
    }
  }
}