/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

/**
 * Based on bitcoin/libbase58 implementation 
 * by Luke Dashjr
 * adapted by b0lek to run on GPUs as part of hashcat
 */


#include "inc_vendor.h"
#include "inc_common.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_hash_sha256.h"

#include "inc_hash_base58.h"

typedef u64 b58_maxint_t;
typedef u32 b58_almostmaxint_t;
#define b58_almostmaxint_bits (sizeof(b58_almostmaxint_t) * 8)
const b58_almostmaxint_t b58_almostmaxint_mask = ((((b58_maxint_t)1) << b58_almostmaxint_bits) - 1);

static const int b58digits_map[] = {
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
        -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
        22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
        -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
        47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
    };

DECLSPEC bool b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz)
{
	size_t binsz = *binszp;
	const u8 *b58u = (u8*)b58;
	u8 *binu = (u8*)bin;
	size_t outisz = (binsz + sizeof(b58_almostmaxint_t) - 1) / sizeof(b58_almostmaxint_t);
	b58_almostmaxint_t outi[200];
	b58_maxint_t t;
	b58_almostmaxint_t c;
	size_t i, j;
	u8 bytesleft = binsz % sizeof(b58_almostmaxint_t);
	b58_almostmaxint_t zeromask = bytesleft ? (b58_almostmaxint_mask << (bytesleft * 8)) : 0;
	unsigned zerocount = 0;
	
	for (i = 0; i < outisz; ++i) {
		outi[i] = 0;
	}
	
	// Leading zeros, just count
	for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
		++zerocount;
	
	for ( ; i < b58sz; ++i)
	{
		if (b58u[i] & 0x80)
			// High-bit set on invalid digit
			return false;
		if (b58digits_map[b58u[i]] == -1)
			// Invalid base58 digit
			return false;
		c = (unsigned)b58digits_map[b58u[i]];
		for (j = outisz; j--; )
		{
			t = ((b58_maxint_t)outi[j]) * 58 + c;
			c = t >> b58_almostmaxint_bits;
			outi[j] = t & b58_almostmaxint_mask;
		}
		if (c)
			// Output number too big (carry to the next int32)
			return false;
		if (outi[0] & zeromask)
			// Output number too big (last int32 filled too far)
			return false;
	}
	
	j = 0;
	if (bytesleft) {
		for (i = bytesleft; i > 0; --i) {
			*(binu++) = (outi[0] >> (8 * (i - 1))) & 0xff;
		}
		++j;
	}
	
	for (; j < outisz; ++j)
	{
		for (i = sizeof(*outi); i > 0; --i) {
			*(binu++) = (outi[j] >> (8 * (i - 1))) & 0xff;
		}
	}
	
	// Count canonical base58 byte count
	binu = (u8*)bin;
	for (i = 0; i < binsz; ++i)
	{
		if (binu[i])
			break;
		--*binszp;
	}
	*binszp += zerocount;
	
	return true;
}

DECLSPEC int b58check(const void *bin, size_t binsz)
{
	u32 data[128]={0};
	u8 * datac = (u8*)data;
	u8 *binc = (u8 *)bin;

	size_t i;
	if (binsz < 4)
		return -4;
	for (i=0;i<binsz-4;i++)
	{
		datac[i]=binc[i];
	}

    sha256_ctx_t ctx;
    sha256_ctx_t ctx1;

    sha256_init (&ctx);

    sha256_update_swap (&ctx, data, binsz-4);

    sha256_final (&ctx);

    u32 data1[128] = {0};

    for (i=0;i<0x20;i++)
    {
        ((u8*)data1)[i] = ((u8*)ctx.h)[i];
    }

    sha256_init (&ctx1);

    sha256_update (&ctx1, data1, 0x20);

    sha256_final (&ctx1);

    ctx1.h[0] = hc_swap32_S(ctx1.h[0]);

    u8 * ph4 = (u8*) ctx1.h;
    u8 * sum = (u8*) (binc+(binsz-4));
    if (ph4[0] != sum[0]) return -1;
    if (ph4[1] != sum[1]) return -1;
    if (ph4[2] != sum[2]) return -1;
    if (ph4[3] != sum[3]) return -1;
    return 0;
}

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

DECLSPEC bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz)
{
	const u8 *bin = (u8 *) data;
	int carry;
	size_t i, j, high, zcount = 0;
	size_t size;
	
	while (zcount < binsz && !bin[zcount])
		++zcount;

	size = (binsz - zcount) * 138 / 100 + 1;
	u8 buf[200]={0};
	
	for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
			if (!j) {
				break;
			}
		}
	}
	
	for (j = 0; j < size && !buf[j]; ++j)
	{
		;
	}
	
	if (*b58sz <= zcount + size - j)
	{
		*b58sz = zcount + size - j + 1;
		return false;
	}
	
    for (i=0; i<zcount; i++)
    {
	  b58[i] = '1';
	}
	for (i = zcount; j < size; ++i, ++j)
    {
		b58[i] = b58digits_ordered[buf[j]];
    }
	b58[i] = '\0';
	*b58sz = i + 1;
	
	return true;
}

DECLSPEC bool b58check_enc(char *b58c, size_t *b58c_sz, u8 ver, const void *data, size_t datasz)
{
	u8    buf[128] = {0};
    u32 * buf32 = (u32 *)buf;
	u8 *  hash = &buf[1 + datasz];
    u8 *  data8 = (u8*) data;
    size_t i;
	
	buf[0] = ver;
    for (i=0;i<datasz;i++)
    {
        buf[i+1]=data8[i];
    }

    sha256_ctx_t ctx;
    sha256_ctx_t ctx1;

    sha256_init (&ctx);

    sha256_update_swap (&ctx, buf32, datasz+1);

    sha256_final (&ctx);

    u32 data1[128] = {0};

    for (i=0;i<0x20;i++)
    {
        ((u8*)data1)[i] = ((u8*)ctx.h)[i];
    } 

    sha256_init (&ctx1);

    sha256_update (&ctx1, data1, 0x20);

    sha256_final (&ctx1);

    ctx1.h[0] = hc_swap32_S(ctx1.h[0]);

    for (i=0;i<4;i++)
      ((u8*)hash)[i]=((u8*)ctx1.h)[i];
	
	return b58enc(b58c, b58c_sz, buf, 1 + datasz + 4);
}


// special function to handle only WIF input of 51 or 52 characters

DECLSPEC bool b58dec_51 (u32 *out, const char *data)
{
	// data length must be 51 and must be checked before calling the function

  if (data[0] != '5') return false;

  /*
   * Base58 decode:
   */

  // we need 1 + 32 + 0 + 4 = 37 ~ 40 (divided by 4 because of u32) bytes:

  // test speed with (manual or automatic) #pragma unroll
	u32 i5 = 0;  // i/5
	u32 mod = 0; //
  for (u32 i = 0; i < 51; i++)
  {

    u32 c = b58digits_map[(u8)data[i]];

    // test speed with (manual or automatic) #pragma unroll

    for (u32 j = 0; j <= i5; j++)
    {
      const u32 pos = 10 - j;

      const u64 t = ((u64) out[pos]) * 58 + c;

      c = t >> 32; // upper u32

      out[pos] = t; // lower u32 (& 0xffffffff)
    }
		mod++;
		if (mod == 5){
			i5++;
			mod = 0;
		}
  }

  // fix byte alignment:
  // (test speed with (manual or automatic) #pragma unroll)

  for (u32 i = 0; i < 10; i++) // offset of: 3 bytes
  {
    out[i] = hc_swap32_S( 
			        (out[i + 1] << 24) |
              (out[i + 2] >>  8) ); 
  }

	return true;

}


DECLSPEC bool b58dec_52 (u32 *out, const char *data)
{
	// data length must be 51 and must be checked before calling the function

	if ((data[0] != 'K') &&
		(data[0] != 'L')) return false;
  // test speed with (manual or automatic) #pragma unroll
	u32 i5 = 0;  // i/5
	u32 mod = 0; //
  for (u32 i = 0; i < 52; i++)
  {

    u32 c = b58digits_map[(u8)data[i]];

    // test speed with (manual or automatic) #pragma unroll

    for (u32 j = 0; j <= i5; j++)
    {
      const u32 pos = 10 - j;

      const u64 t = ((u64) out[pos]) * 58 + c;

      c = t >> 32; // upper u32

      out[pos] = t; // lower u32 (& 0xffffffff)
    }
		mod++;
		if (mod == 5){
			i5++;
			mod = 0;
		}
  }

  // fix byte alignment:
  // (test speed with (manual or automatic) #pragma unroll)

  for (u32 i = 0; i < 10; i++) // offset of: 2 bytes
  {
    out[i] = hc_swap32_S(
			        (out[i + 1] << 16) |
              (out[i + 2] >> 16) );
  }

	return true;
}