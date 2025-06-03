/*-
 * Copyright 2009 Colin Percival
 * Copyright 2013-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 *
 * This is the reference implementation.  Its purpose is to provide a simple
 * human- and machine-readable specification that implementations intended
 * for actual use should be tested against.  It is deliberately mostly not
 * optimized, and it is not meant to be used in production.  Instead, use
 * yescrypt-opt.c.
 */

#ifdef __GNUC__
#warning "This reference implementation is deliberately mostly not optimized, nor does it make any attempt not to leave sensitive data in memory. Use yescrypt-opt.c instead unless you're testing (against) the reference implementation on purpose."
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "sysendian.h"

#define YESCRYPT_INTERNAL
#include "yescrypt.h"

static void blkcpy(uint32_t *dst, const uint32_t *src, size_t count)
{
	do {
		*dst++ = *src++;
	} while (--count);
}

static void blkxor(uint32_t *dst, const uint32_t *src, size_t count)
{
	do {
		*dst++ ^= *src++;
	} while (--count);
}

/**
 * salsa20(B):
 * Apply the Salsa20 core to the provided block.
 */
static void salsa20(uint32_t B[16], uint32_t rounds)
{
	uint32_t x[16];
	size_t i;

	/* SIMD unshuffle */
	for (i = 0; i < 16; i++)
		x[i * 5 % 16] = B[i];

	for (i = 0; i < rounds; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns */
		x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
		x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

		x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
		x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

		x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
		x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

		/* Operate on rows */
		x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
		x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);

		x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
		x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);

		x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
		x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);

		x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
	}

	/* SIMD shuffle */
	for (i = 0; i < 16; i++)
		B[i] += x[i * 5 % 16];
}

/**
 * blockmix_salsa8(B, Y, r):
 * Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
 */
static void blockmix_salsa8(uint32_t *B, uint32_t *Y, size_t r)
{
	uint32_t X[16];
	size_t i;

	/* 1: X <-- B_{2r - 1} */
	blkcpy(X, &B[(2 * r - 1) * 16], 16);

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < 2 * r; i++) {
		/* 3: X <-- H(X xor B_i) */
		blkxor(X, &B[i * 16], 16);
		salsa20(X, 8);

		/* 4: Y_i <-- X */
		blkcpy(&Y[i * 16], X, 16);
	}

	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	for (i = 0; i < r; i++)
		blkcpy(&B[i * 16], &Y[(i * 2) * 16], 16);
	for (i = 0; i < r; i++)
		blkcpy(&B[(i + r) * 16], &Y[(i * 2 + 1) * 16], 16);
}

/* These are tunable, but they must meet certain constraints */
#define PWXsimple 2
#define PWXgather 4
#define PWXrounds 6
#define Swidth 8

/* Derived values.  Not tunable on their own. */
#define PWXbytes (PWXgather * PWXsimple * 8)
#define PWXwords (PWXbytes / sizeof(uint32_t))
#define Sbytes (3 * (1 << Swidth) * PWXsimple * 8)
#define Swords (Sbytes / sizeof(uint32_t))
#define Smask (((1 << Swidth) - 1) * PWXsimple * 8)
#define rmin ((PWXbytes + 127) / 128)

typedef struct {
	uint32_t *S;
	uint32_t (*S0)[2], (*S1)[2], (*S2)[2];
	size_t w;
} pwxform_ctx_t;

/**
 * pwxform(B):
 * Transform the provided block using the provided S-boxes.
 */
static void pwxform(uint32_t *B, pwxform_ctx_t *ctx)
{
	uint32_t (*X)[PWXsimple][2] = (uint32_t (*)[PWXsimple][2])B;
	uint32_t (*S0)[2] = ctx->S0, (*S1)[2] = ctx->S1, (*S2)[2] = ctx->S2;
	size_t w = ctx->w;
	size_t i, j, k;

	/* 1: for i = 0 to PWXrounds - 1 do */
	for (i = 0; i < PWXrounds; i++) {
		/* 2: for j = 0 to PWXgather - 1 do */
		for (j = 0; j < PWXgather; j++) {
			uint32_t xl = X[j][0][0];
			uint32_t xh = X[j][0][1];
			uint32_t (*p0)[2], (*p1)[2];

			/* 3: p0 <-- (lo(B_{j,0}) & Smask) / (PWXsimple * 8) */
			p0 = S0 + (xl & Smask) / sizeof(*S0);
			/* 4: p1 <-- (hi(B_{j,0}) & Smask) / (PWXsimple * 8) */
			p1 = S1 + (xh & Smask) / sizeof(*S1);

			/* 5: for k = 0 to PWXsimple - 1 do */
			for (k = 0; k < PWXsimple; k++) {
				uint64_t x, s0, s1;

				/* 6: B_{j,k} <-- (hi(B_{j,k}) * lo(B_{j,k}) + S0_{p0,k}) xor S1_{p1,k} */
				s0 = ((uint64_t)p0[k][1] << 32) + p0[k][0];
				s1 = ((uint64_t)p1[k][1] << 32) + p1[k][0];

				xl = X[j][k][0];
				xh = X[j][k][1];

				x = (uint64_t)xh * xl;
				x += s0;
				x ^= s1;

				X[j][k][0] = x;
				X[j][k][1] = x >> 32;

				/* 8: if (i != 0) and (i != PWXrounds - 1) */
				if (i != 0 && i != PWXrounds - 1) {
					/* 9: S2_w <-- B_j */
					S2[w][0] = x;
					S2[w][1] = x >> 32;
					/* 10: w <-- w + 1 */
					w++;
				}
			}
		}
	}

	/* 14: (S0, S1, S2) <-- (S2, S0, S1) */
	ctx->S0 = S2;
	ctx->S1 = S0;
	ctx->S2 = S1;
	/* 15: w <-- w mod 2^Swidth */
	ctx->w = w & ((1 << Swidth) * PWXsimple - 1);
}

/**
 * blockmix_pwxform(B, ctx, r):
 * Compute B = BlockMix_pwxform{salsa20/2, ctx, r}(B).  The input B must be
 * 128r bytes in length.
 */
static void blockmix_pwxform(uint32_t *B, pwxform_ctx_t *ctx, size_t r)
{
	uint32_t X[PWXwords];
	size_t r1, i;

	/* Convert 128-byte blocks to PWXbytes blocks */
	/* 1: r_1 <-- 128r / PWXbytes */
	r1 = 128 * r / PWXbytes;

	/* 2: X <-- B'_{r_1 - 1} */
	blkcpy(X, &B[(r1 - 1) * PWXwords], PWXwords);

	/* 3: for i = 0 to r_1 - 1 do */
	for (i = 0; i < r1; i++) {
		/* 4: if r_1 > 1 */
		if (r1 > 1) {
			/* 5: X <-- X xor B'_i */
			blkxor(X, &B[i * PWXwords], PWXwords);
		}

		/* 7: X <-- pwxform(X) */
		pwxform(X, ctx);

		/* 8: B'_i <-- X */
		blkcpy(&B[i * PWXwords], X, PWXwords);
	}

	/* 10: i <-- floor((r_1 - 1) * PWXbytes / 64) */
	i = (r1 - 1) * PWXbytes / 64;

	/* 11: B_i <-- H(B_i) */
	salsa20(&B[i * 16], 2);

#if 1 /* No-op with our current pwxform settings, but do it to make sure */
	/* 12: for i = i + 1 to 2r - 1 do */
	for (i++; i < 2 * r; i++) {
		/* 13: B_i <-- H(B_i xor B_{i-1}) */
		blkxor(&B[i * 16], &B[(i - 1) * 16], 16);
		salsa20(&B[i * 16], 2);
	}
#endif
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static uint64_t integerify(const uint32_t *B, size_t r)
{
/*
 * Our 32-bit words are in host byte order, and word 13 is the second word of
 * B_{2r-1} due to SIMD shuffling.  The 64-bit value we return is also in host
 * byte order, as it should be.
 */
	const uint32_t *X = &B[(2 * r - 1) * 16];
	return ((uint64_t)X[13] << 32) + X[0];
}

/**
 * p2floor(x):
 * Largest power of 2 not greater than argument.
 */
static uint64_t p2floor(uint64_t x)
{
	uint64_t y;
	while ((y = x & (x - 1)))
		x = y;
	return x;
}

/**
 * wrap(x, i):
 * Wrap x to the range 0 to i-1.
 */
static uint64_t wrap(uint64_t x, uint64_t i)
{
	uint64_t n = p2floor(i);
	return (x & (n - 1)) + (i - n);
}

/**
 * smix1(B, r, N, flags, V, NROM, VROM, XY, ctx):
 * Compute first loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r bytes in length.
 */
static void smix1(uint32_t *B, size_t r, uint64_t N, yescrypt_flags_t flags,
    uint32_t *V, uint64_t NROM, const uint32_t *VROM,
    uint32_t *XY, pwxform_ctx_t *ctx)
{
	size_t s = 32 * r;
	uint32_t *X = XY;
	uint32_t *Y = &XY[s];
	uint64_t i, j;
	size_t k;

	/* 1: X <-- B */
	for (k = 0; k < 2 * r; k++)
		for (i = 0; i < 16; i++)
			X[k * 16 + i] = le32dec(&B[k * 16 + (i * 5 % 16)]);

	/* 2: for i = 0 to N - 1 do */
	for (i = 0; i < N; i++) {
		/* 3: V_i <-- X */
		blkcpy(&V[i * s], X, s);

		if (VROM && i == 0) {
			/* X <-- X xor VROM_{NROM-1} */
			blkxor(X, &VROM[(NROM - 1) * s], s);
		} else if (VROM && (i & 1)) {
			/* j <-- Integerify(X) mod NROM */
			j = integerify(X, r) & (NROM - 1);

			/* X <-- X xor VROM_j */
			blkxor(X, &VROM[j * s], s);
		} else if ((flags & YESCRYPT_RW) && i > 1) {
			/* j <-- Wrap(Integerify(X), i) */
			j = wrap(integerify(X, r), i);

			/* X <-- X xor V_j */
			blkxor(X, &V[j * s], s);
		}

		/* 4: X <-- H(X) */
		if (ctx)
			blockmix_pwxform(X, ctx, r);
		else
			blockmix_salsa8(X, Y, r);
	}

	/* B' <-- X */
	for (k = 0; k < 2 * r; k++)
		for (i = 0; i < 16; i++)
			le32enc(&B[k * 16 + (i * 5 % 16)], X[k * 16 + i]);
}

/**
 * smix2(B, r, N, Nloop, flags, V, NROM, VROM, XY, ctx):
 * Compute second loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r bytes in length.  The value N must be a power of 2
 * greater than 1.
 */
static void smix2(uint32_t *B, size_t r, uint64_t N, uint64_t Nloop,
    yescrypt_flags_t flags, uint32_t *V, uint64_t NROM,
    const uint32_t *VROM, uint32_t *XY, pwxform_ctx_t *ctx)
{
	size_t s = 32 * r;
	uint32_t *X = XY;
	uint32_t *Y = &XY[s];
	uint64_t i, j;
	size_t k;

	/* X <-- B */
	for (k = 0; k < 2 * r; k++)
		for (i = 0; i < 16; i++)
			X[k * 16 + i] = le32dec(&B[k * 16 + (i * 5 % 16)]);

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < Nloop; i++) {
		if (VROM && (i & 1)) {
			/* j <-- Integerify(X) mod NROM */
			j = integerify(X, r) & (NROM - 1);

			/* X <-- H(X xor VROM_j) */
			blkxor(X, &VROM[j * s], s);
		} else {
			/* 7: j <-- Integerify(X) mod N */
			j = integerify(X, r) & (N - 1);

			/* 8.1: X <-- X xor V_j */
			blkxor(X, &V[j * s], s);
			/* V_j <-- X */
			if (flags & YESCRYPT_RW)
				blkcpy(&V[j * s], X, s);
		}

		/* 8.2: X <-- H(X) */
		if (ctx)
			blockmix_pwxform(X, ctx, r);
		else
			blockmix_salsa8(X, Y, r);
	}

	/* 10: B' <-- X */
	for (k = 0; k < 2 * r; k++)
		for (i = 0; i < 16; i++)
			le32enc(&B[k * 16 + (i * 5 % 16)], X[k * 16 + i]);
}

/**
 * smix(B, r, N, p, t, flags, V, NROM, VROM, XY, ctx, passwd):
 * Compute B = SMix_r(B, N).  The input B must be 128rp bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  The value N must be a power of 2 greater
 * than 1.
 */
static void smix(uint32_t *B, size_t r, uint64_t N, uint32_t p, uint32_t t,
    yescrypt_flags_t flags,
    uint32_t *V, uint64_t NROM, const uint32_t *VROM,
    uint32_t *XY, pwxform_ctx_t *ctx, uint8_t *passwd)
{
	size_t s = 32 * r;
	uint64_t Nchunk, Nloop_all, Nloop_rw, Vchunk;
	uint32_t i;

	/* 1: n <-- N / p */
	Nchunk = N / p;

	/* 2: Nloop_all <-- fNloop(n, t, flags) */
	Nloop_all = Nchunk;
	if (flags & YESCRYPT_RW) {
		if (t <= 1) {
			if (t)
				Nloop_all *= 2; /* 2/3 */
			Nloop_all = (Nloop_all + 2) / 3; /* 1/3, round up */
		} else {
			Nloop_all *= t - 1;
		}
	} else if (t) {
		if (t == 1)
			Nloop_all += (Nloop_all + 1) / 2; /* 1.5, round up */
		Nloop_all *= t;
	}

	/* 6: Nloop_rw <-- 0 */
	Nloop_rw = 0;
	if (flags & YESCRYPT_INIT_SHARED) {
		Nloop_rw = Nloop_all;
	} else {
		/* 3: if YESCRYPT_RW flag is set */
		if (flags & YESCRYPT_RW) {
			/* 4: Nloop_rw <-- Nloop_all / p */
			Nloop_rw = Nloop_all / p;
		}
	}

	/* 8: n <-- n - (n mod 2) */
	Nchunk &= ~(uint64_t)1; /* round down to even */
	/* 9: Nloop_all <-- Nloop_all + (Nloop_all mod 2) */
	Nloop_all++; Nloop_all &= ~(uint64_t)1; /* round up to even */
	/* 10: Nloop_rw <-- Nloop_rw + (Nloop_rw mod 2) */
	Nloop_rw++; Nloop_rw &= ~(uint64_t)1; /* round up to even */

	/* 11: for i = 0 to p - 1 do */
	/* 12: u <-- in */
	for (i = 0, Vchunk = 0; i < p; i++, Vchunk += Nchunk) {
		/* 13: if i = p - 1 */
		/* 14:   n <-- N - u */
		/* 15: end if */
		/* 16: v <-- u + n - 1 */
		uint64_t Np = (i < p - 1) ? Nchunk : (N - Vchunk);
		uint32_t *Bp = &B[i * s];
		uint32_t *Vp = &V[Vchunk * s];
		pwxform_ctx_t *ctx_i = NULL;
		/* 17: if YESCRYPT_RW flag is set */
		if (flags & YESCRYPT_RW) {
			ctx_i = &ctx[i];
			/* 18: SMix1_1(B_i, Sbytes / 128, S_i, no flags) */
			smix1(Bp, 1, Sbytes / 128, 0 /* no flags */,
			    ctx_i->S, 0, NULL, XY, NULL);
			/* 19: S2_i <-- S_{i,0...2^Swidth-1} */
			ctx_i->S2 = (uint32_t (*)[2])ctx_i->S;
			/* 20: S1_i <-- S_{i,2^Swidth...2*2^Swidth-1} */
			ctx_i->S1 = ctx_i->S2 + (1 << Swidth) * PWXsimple;
			/* 21: S0_i <-- S_{i,2*2^Swidth...3*2^Swidth-1} */
			ctx_i->S0 = ctx_i->S1 + (1 << Swidth) * PWXsimple;
			/* 22: w_i <-- 0 */
			ctx_i->w = 0;
			/* 23: if i = 0 */
			if (i == 0) {
				/* 24: passwd <-- HMAC-SHA256(B_{0,2r-1}, passwd) */
				HMAC_SHA256_Buf(Bp + (s - 16), 64,
				    passwd, 32, passwd);
			}
		}
		/* 27: SMix1_r(B_i, n, V_{u..v}, flags) */
		smix1(Bp, r, Np, flags, Vp, NROM, VROM, XY, ctx_i);
		/* 28: SMix2_r(B_i, p2floor(n), Nloop_rw, V_{u..v}, flags) */
		smix2(Bp, r, p2floor(Np), Nloop_rw, flags, Vp,
		    NROM, VROM, XY, ctx_i);
	}

	/* 30: for i = 0 to p - 1 do */
	for (i = 0; i < p; i++) {
		uint32_t *Bp = &B[i * s];
		/* 31: SMix2_r(B_i, N, Nloop_all - Nloop_rw, V, flags excluding YESCRYPT_RW) */
		smix2(Bp, r, N, Nloop_all - Nloop_rw, flags & ~YESCRYPT_RW,
		    V, NROM, VROM, XY, (flags & YESCRYPT_RW) ? &ctx[i] : NULL);
	}
}

/**
 * yescrypt_kdf_body(shared, local, passwd, passwdlen, salt, saltlen,
 *     flags, N, r, p, t, NROM, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen), or a revision of scrypt as requested by flags and shared, and
 * write the result into buf.
 *
 * shared and flags may request special modes as described in yescrypt.h.
 *
 * local is the thread-local data structure, allowing optimized implementations
 * to preserve and reuse a memory allocation across calls, thereby reducing its
 * overhead (this reference implementation does not make that optimization).
 *
 * t controls computation time while not affecting peak memory usage.
 *
 * Return 0 on success; or -1 on error.
 */
static int yescrypt_kdf_body(const yescrypt_shared_t *shared,
    yescrypt_local_t *local,
    const uint8_t *passwd, size_t passwdlen,
    const uint8_t *salt, size_t saltlen,
    yescrypt_flags_t flags, uint64_t N, uint32_t r, uint32_t p, uint32_t t,
    uint64_t NROM,
    uint8_t *buf, size_t buflen)
{
	int retval = -1;
	const uint32_t *VROM;
	size_t B_size, V_size;
	uint32_t *B, *V, *XY, *S;
	pwxform_ctx_t *pwxform_ctx;
	uint32_t sha256[8];
	uint8_t dk[sizeof(sha256)], *dkp = buf;
	uint32_t i;

	/* Sanity-check parameters */
	switch (flags & YESCRYPT_MODE_MASK) {
	case 0: /* classic scrypt - can't have anything non-standard */
		if (flags || t || NROM)
			goto out_EINVAL;
		break;
	case YESCRYPT_WORM:
		if (flags != YESCRYPT_WORM || NROM)
			goto out_EINVAL;
		break;
	case YESCRYPT_RW:
		if (flags != (flags & YESCRYPT_KNOWN_FLAGS))
			goto out_EINVAL;
#if PWXsimple == 2 && PWXgather == 4 && PWXrounds == 6 && Sbytes == 12288
		if ((flags & YESCRYPT_RW_FLAVOR_MASK) ==
		    (YESCRYPT_ROUNDS_6 | YESCRYPT_GATHER_4 |
		    YESCRYPT_SIMPLE_2 | YESCRYPT_SBOX_12K))
			break;
#else
#error "Unsupported pwxform settings"
#endif
		/* FALLTHRU */
	default:
		goto out_EINVAL;
	}
#if SIZE_MAX > UINT32_MAX
	if (buflen > (((uint64_t)1 << 32) - 1) * 32)
		goto out_EINVAL;
#endif
	if ((uint64_t)r * (uint64_t)p >= 1 << 30)
		goto out_EINVAL;
	if ((N & (N - 1)) != 0 || N <= 1 || r < 1 || p < 1)
		goto out_EINVAL;
	if (r > SIZE_MAX / 128 / p ||
#if SIZE_MAX / 256 <= UINT32_MAX
	    r > SIZE_MAX / 256 ||
#endif
	    N > SIZE_MAX / 128 / r)
		goto out_EINVAL;
	if (N > UINT64_MAX / ((uint64_t)t + 1))
		goto out_EINVAL;
	if (flags & YESCRYPT_RW) {
		if (N / p <= 1 || r < rmin ||
		    p > SIZE_MAX / Sbytes ||
		    p > SIZE_MAX / sizeof(*pwxform_ctx))
			goto out_EINVAL;
	}

	VROM = NULL;
	if (shared) {
		uint64_t expected_size = (size_t)128 * r * NROM;
		if ((NROM & (NROM - 1)) != 0 || NROM <= 1 ||
		    shared->aligned_size < expected_size)
			goto out_EINVAL;
		if (!(flags & YESCRYPT_INIT_SHARED)) {
			uint32_t *tag = (uint32_t *)
			    ((uint8_t *)shared->aligned + expected_size - 48);
			uint64_t tag1 = ((uint64_t)tag[1] << 32) + tag[0];
			uint64_t tag2 = ((uint64_t)tag[3] << 32) + tag[2];
			if (tag1 != YESCRYPT_ROM_TAG1 || tag2 != YESCRYPT_ROM_TAG2)
				goto out_EINVAL;
		}
		VROM = shared->aligned;
	} else {
		if (NROM)
			goto out_EINVAL;
	}

	/* Allocate memory */
	V_size = (size_t)128 * r * N;
	if (flags & YESCRYPT_INIT_SHARED) {
		V = (uint32_t *)local->aligned;
		if (local->aligned_size < V_size) {
			if (local->base || local->aligned ||
			    local->base_size || local->aligned_size)
				goto out_EINVAL;
			if ((V = malloc(V_size)) == NULL)
				return -1;
			local->base = local->aligned = V;
			local->base_size = local->aligned_size = V_size;
		}
		if (flags & YESCRYPT_ALLOC_ONLY)
			return -2; /* expected "failure" */
	} else {
		if ((V = malloc(V_size)) == NULL)
			return -1;
	}
	B_size = (size_t)128 * r * p;
	if ((B = malloc(B_size)) == NULL)
		goto free_V;
	if ((XY = malloc((size_t)256 * r)) == NULL)
		goto free_B;
	S = NULL;
	pwxform_ctx = NULL;
	if (flags & YESCRYPT_RW) {
		if ((S = malloc((size_t)Sbytes * p)) == NULL)
			goto free_XY;
		if ((pwxform_ctx = malloc(sizeof(*pwxform_ctx) * p)) == NULL)
			goto free_S;
	}

	if (flags) {
		HMAC_SHA256_Buf("yescrypt-prehash",
		    (flags & YESCRYPT_PREHASH) ? 16 : 8,
		    passwd, passwdlen, (uint8_t *)sha256);
		passwd = (uint8_t *)sha256;
		passwdlen = sizeof(sha256);
	}

	/* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
	PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, 1,
	    (uint8_t *)B, B_size);

	if (flags)
		blkcpy(sha256, B, sizeof(sha256) / sizeof(sha256[0]));

	if (flags & YESCRYPT_RW) {
		for (i = 0; i < p; i++)
			pwxform_ctx[i].S = &S[i * Swords];
		smix(B, r, N, p, t, flags, V, NROM, VROM, XY, pwxform_ctx,
		    (uint8_t *)sha256);
	} else {
		/* 2: for i = 0 to p - 1 do */
		for (i = 0; i < p; i++) {
			/* 3: B_i <-- MF(B_i, N) */
			smix(&B[(size_t)32 * r * i], r, N, 1, t, flags, V,
			    NROM, VROM, XY, NULL, NULL);
		}
	}

	dkp = buf;
	if (flags && buflen < sizeof(dk)) {
		PBKDF2_SHA256(passwd, passwdlen, (uint8_t *)B, B_size, 1,
		    dk, sizeof(dk));
		dkp = dk;
	}

	/* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
	PBKDF2_SHA256(passwd, passwdlen, (uint8_t *)B, B_size, 1, buf, buflen);

	/*
	 * Except when computing classic scrypt, allow all computation so far
	 * to be performed on the client.  The final steps below match those of
	 * SCRAM (RFC 5802), so that an extension of SCRAM (with the steps so
	 * far in place of SCRAM's use of PBKDF2 and with SHA-256 in place of
	 * SCRAM's use of SHA-1) would be usable with yescrypt hashes.
	 */
	if (flags && !(flags & YESCRYPT_PREHASH)) {
		/* Compute ClientKey */
		HMAC_SHA256_Buf(dkp, sizeof(dk), "Client Key", 10,
		    (uint8_t *)sha256);
		/* Compute StoredKey */
		{
			size_t clen = buflen;
			if (clen > sizeof(dk))
				clen = sizeof(dk);
			SHA256_Buf((uint8_t *)sha256, sizeof(sha256), dk);
			memcpy(buf, dk, clen);
		}
	}

	/* Success! */
	retval = 0;

	/* Free memory */
	free(pwxform_ctx);
free_S:
	free(S);
free_XY:
	free(XY);
free_B:
	free(B);
free_V:
	if (!(flags & YESCRYPT_INIT_SHARED))
		free(V);

	return retval;

out_EINVAL:
	errno = EINVAL;
	return -1;
}

/**
 * yescrypt_kdf(shared, local, passwd, passwdlen, salt, saltlen, params,
 *     buf, buflen):
 * Compute scrypt or its revision as requested by the parameters.  The inputs
 * to this function are the same as those for yescrypt_kdf_body() above, with
 * the addition of g, which controls hash upgrades (0 for no upgrades so far).
 */
int yescrypt_kdf(const yescrypt_shared_t *shared, yescrypt_local_t *local,
    const uint8_t *passwd, size_t passwdlen,
    const uint8_t *salt, size_t saltlen,
    const yescrypt_params_t *params,
    uint8_t *buf, size_t buflen)
{
	yescrypt_flags_t flags = params->flags;
	uint64_t N = params->N;
	uint32_t r = params->r;
	uint32_t p = params->p;
	uint32_t t = params->t;
	uint32_t g = params->g;
	uint64_t NROM = params->NROM;
	uint8_t dk[32];

	/* Support for hash upgrades has been temporarily removed */
	if (g) {
		errno = EINVAL;
		return -1;
	}

	if ((flags & YESCRYPT_RW) &&
	    p >= 1 && N / p >= 0x100 && N / p * r >= 0x20000) {
		/*
		 * This reference implementation's yescrypt_kdf_body()
		 * (de)allocates memory on each call, which defeats the purpose
		 * of this pre-hashing.  The optimized implementations, which
		 * you should actually use, make the larger allocation first
		 * and then reuse it.  Thus, this implementation doing things
		 * differently serves as a test that the computation result is
		 * unaffected by such differences.
		 */
		int retval = yescrypt_kdf_body(shared, local,
		    passwd, passwdlen, salt, saltlen,
		    flags | YESCRYPT_PREHASH, N >> 6, r, p, 0, NROM,
		    dk, sizeof(dk));
		if (retval)
			return retval;
		passwd = dk;
		passwdlen = sizeof(dk);
	}

	return yescrypt_kdf_body(shared, local,
	    passwd, passwdlen, salt, saltlen,
	    flags, N, r, p, t, NROM, buf, buflen);
}

int yescrypt_init_shared(yescrypt_shared_t *shared,
    const uint8_t *seed, size_t seedlen,
    const yescrypt_params_t *params)
{
	yescrypt_flags_t flags = params->flags;
	uint64_t N = params->NROM;
	uint32_t r = params->r;
	uint32_t p = params->p;
	uint32_t t = params->t;
	yescrypt_shared_t half1, half2;
	uint8_t salt[32];
	uint32_t *tag;

	if (!(params->flags & YESCRYPT_RW) || params->N || params->g)
		return -1;

	if (flags & YESCRYPT_SHARED_PREALLOCATED) {
		if (!shared->aligned || !shared->aligned_size)
			return -1;

/* Overwrite a possible old ROM tag before we overwrite the rest */
		tag = (uint32_t *)
		    ((uint8_t *)shared->aligned + shared->aligned_size - 48);
		memset(tag, 0, 48);
	} else {
		shared->base = shared->aligned = NULL;
		shared->base_size = shared->aligned_size = 0;

		if (yescrypt_kdf_body(NULL, shared, NULL, 0, NULL, 0,
		    flags | YESCRYPT_INIT_SHARED | YESCRYPT_ALLOC_ONLY,
		    N, r, p, t, 0, NULL, 0) != -2 || !shared->aligned)
			goto fail;
	}

	half1 = half2 = *shared;
	half1.aligned_size /= 2;
	half2.aligned = (uint8_t *)half2.aligned + half1.aligned_size;
	half2.aligned_size = half1.aligned_size;
	N /= 2;

	if (yescrypt_kdf_body(NULL, &half1,
	    seed, seedlen, (const uint8_t *)"yescrypt-ROMhash", 16,
	    flags | YESCRYPT_INIT_SHARED, N, r, p, t, 0,
	    salt, sizeof(salt)))
		goto fail;

	if (yescrypt_kdf_body(&half1, &half2,
	    seed, seedlen, salt, sizeof(salt),
	    flags | YESCRYPT_INIT_SHARED, N, r, p, t, N,
	    salt, sizeof(salt)))
		goto fail;

	if (yescrypt_kdf_body(&half2, &half1,
	    seed, seedlen, salt, sizeof(salt),
	    flags | YESCRYPT_INIT_SHARED, N, r, p, t, N,
	    salt, sizeof(salt)))
		goto fail;

	tag = (uint32_t *)
	    ((uint8_t *)shared->aligned + shared->aligned_size - 48);
	tag[0] = YESCRYPT_ROM_TAG1 & 0xffffffffU;
	tag[1] = YESCRYPT_ROM_TAG1 >> 32;
	tag[2] = YESCRYPT_ROM_TAG2 & 0xffffffffU;
	tag[3] = YESCRYPT_ROM_TAG2 >> 32;
	tag[4] = le32dec(salt);
	tag[5] = le32dec(salt + 4);
	tag[6] = le32dec(salt + 8);
	tag[7] = le32dec(salt + 12);
	tag[8] = le32dec(salt + 16);
	tag[9] = le32dec(salt + 20);
	tag[10] = le32dec(salt + 24);
	tag[11] = le32dec(salt + 28);

	return 0;

fail:
	if (!(flags & YESCRYPT_SHARED_PREALLOCATED))
		free(shared->base);
	return -1;
}

yescrypt_binary_t *yescrypt_digest_shared(yescrypt_shared_t *shared)
{
	static yescrypt_binary_t digest;
	uint32_t *tag;
	uint64_t tag1, tag2;

	if (shared->aligned_size < 48)
		return NULL;

	tag = (uint32_t *)
	    ((uint8_t *)shared->aligned + shared->aligned_size - 48);

	tag1 = ((uint64_t)tag[1] << 32) + tag[0];
	tag2 = ((uint64_t)tag[3] << 32) + tag[2];
	if (tag1 != YESCRYPT_ROM_TAG1 || tag2 != YESCRYPT_ROM_TAG2)
		return NULL;

	le32enc(digest.uc, tag[4]);
	le32enc(digest.uc + 4, tag[5]);
	le32enc(digest.uc + 8, tag[6]);
	le32enc(digest.uc + 12, tag[7]);
	le32enc(digest.uc + 16, tag[8]);
	le32enc(digest.uc + 20, tag[9]);
	le32enc(digest.uc + 24, tag[10]);
	le32enc(digest.uc + 28, tag[11]);

	return &digest;
}

int yescrypt_free_shared(yescrypt_shared_t *shared)
{
	free(shared->base);
	shared->base = shared->aligned = NULL;
	shared->base_size = shared->aligned_size = 0;
	return 0;
}

int yescrypt_init_local(yescrypt_local_t *local)
{
/* The reference implementation doesn't use the local structure */
	local->base = local->aligned = NULL;
	local->base_size = local->aligned_size = 0;
	return 0;
}

int yescrypt_free_local(yescrypt_local_t *local)
{
/* The reference implementation frees its memory in yescrypt_kdf() */
	(void)local; /* unused */
	return 0;
}
