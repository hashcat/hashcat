

#ifndef _OPENCL_CAST_H
#define _OPENCL_CAST_H

// #include "opencl_misc.h"
#define GET_UINT32BE(n, b, i)	  \
	{ \
		(n) = ((uint) (b)[(i)] << 24) \
			| ((uint) (b)[(i) + 1] << 16) \
			| ((uint) (b)[(i) + 2] <<  8) \
			| ((uint) (b)[(i) + 3]      ); \
	}
#define PUT_UINT32BE(n, b, i)	  \
	{ \
		(b)[(i)    ] = (u8) ((n) >> 24); \
		(b)[(i) + 1] = (u8) ((n) >> 16); \
		(b)[(i) + 2] = (u8) ((n) >>  8); \
		(b)[(i) + 3] = (u8) ((n)      ); \
	}

typedef struct {
	u32 K[32];
} CAST_KEY;

#define GETBYTE(x, y) (uint)(u8)((x)>>(8*(y)))

/* Macros to access 8-bit bytes out of a 32-bit word */
#define U8a(x) GETBYTE(x,3)
#define U8b(x) GETBYTE(x,2)
#define U8c(x) GETBYTE(x,1)
#define U8d(x) GETBYTE(x,0)

/* CAST uses three different round functions */
#define _CAST_f1(l, r, km, kr) \
	t = hc_rotl32_S(km + r, kr); \
	l ^= ((s_S[0][U8a(t)] ^ s_S[1][U8b(t)]) - \
	 s_S[2][U8c(t)]) + s_S[3][U8d(t)];
#define _CAST_f2(l, r, km, kr) \
	t = hc_rotl32_S(km ^ r, kr); \
	l ^= ((s_S[0][U8a(t)] - s_S[1][U8b(t)]) + \
	 s_S[2][U8c(t)]) ^ s_S[3][U8d(t)];
#define _CAST_f3(l, r, km, kr) \
	t = hc_rotl32_S(km - r, kr); \
	l ^= ((s_S[0][U8a(t)] + s_S[1][U8b(t)]) ^ \
	 s_S[2][U8c(t)]) - s_S[3][U8d(t)];

#define _CAST_F1(l, r, i, j) _CAST_f1(l, r, K[i], K[i+j])
#define _CAST_F2(l, r, i, j) _CAST_f2(l, r, K[i], K[i+j])
#define _CAST_F3(l, r, i, j) _CAST_f3(l, r, K[i], K[i+j])


/* OpenSSL API compatibility */
#define CAST_set_key(ckey, len, key)     Cast5SetKey(ckey, len, key)
#define CAST_ecb_encrypt(in, out, ckey)  Cast5Encrypt(in, out, ckey)
#define CAST_ecb_decrypt(in, out, ckey)  Cast5Decrypt(in, out, ckey)


#endif /* _OPENCL_CAST_H */
