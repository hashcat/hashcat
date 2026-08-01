#if !defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_HAVE_ROMIX)

#if defined(SCRYPT_CHOOSE_COMPILETIME)
#undef SCRYPT_ROMIX_FN
#define SCRYPT_ROMIX_FN scrypt_ROMix
#endif

#undef SCRYPT_HAVE_ROMIX
#define SCRYPT_HAVE_ROMIX

#if !defined(SCRYPT_CHUNKMIX_FN)

#define SCRYPT_CHUNKMIX_FN scrypt_ChunkMix_basic

/*
	Bout = ChunkMix(Bin)

	2*r: number of blocks in the chunk
*/
static void asm_calling_convention
SCRYPT_CHUNKMIX_FN(scrypt_mix_word_t *Bout/*[chunkWords]*/, scrypt_mix_word_t *Bin/*[chunkWords]*/, scrypt_mix_word_t *Bxor/*[chunkWords]*/, uint32_t r) {
#if (defined(X86ASM_AVX2) || defined(X86_64ASM_AVX2) || defined(X86_INTRINSIC_AVX2))
	scrypt_mix_word_t JANE_ALIGN(32) X[SCRYPT_BLOCK_WORDS], *block;
#else
	scrypt_mix_word_t JANE_ALIGN(16) X[SCRYPT_BLOCK_WORDS], *block;
#endif
	uint32_t i, j, blocksPerChunk = r * 2, half = 0;

	/* 1: X = B_{2r - 1} */
	block = scrypt_block(Bin, blocksPerChunk - 1);
	for (i = 0; i < SCRYPT_BLOCK_WORDS; i++)
		X[i] = block[i];

	if (Bxor) {
		block = scrypt_block(Bxor, blocksPerChunk - 1);
		for (i = 0; i < SCRYPT_BLOCK_WORDS; i++)
			X[i] ^= block[i];
	}

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < blocksPerChunk; i++, half ^= r) {
		/* 3: X = H(X ^ B_i) */
		block = scrypt_block(Bin, i);
		for (j = 0; j < SCRYPT_BLOCK_WORDS; j++)
			X[j] ^= block[j];

		if (Bxor) {
			block = scrypt_block(Bxor, i);
			for (j = 0; j < SCRYPT_BLOCK_WORDS; j++)
				X[j] ^= block[j];
		}
		SCRYPT_MIX_FN(X);

		/* 4: Y_i = X */
		/* 6: B'[0..r-1] = Y_even */
		/* 6: B'[r..2r-1] = Y_odd */
		block = scrypt_block(Bout, (i / 2) + half);
		for (j = 0; j < SCRYPT_BLOCK_WORDS; j++)
			block[j] = X[j];
	}
}
#endif

/*
	X = ROMix(X)

	X: chunk to mix
	Y: scratch chunk
	N: number of rounds
	V[N]: array of chunks to randomly index in to
	2*r: number of blocks in a chunk
*/

static void NOINLINE FASTCALL
SCRYPT_ROMIX_FN(scrypt_mix_word_t *X/*[chunkWords]*/, scrypt_mix_word_t *Y/*[chunkWords]*/, scrypt_mix_word_t *V/*[N * chunkWords]*/, uint32_t N, uint32_t r) {
	uint32_t i, j, chunkWords = (uint32_t)(SCRYPT_BLOCK_WORDS * r * 2);
	scrypt_mix_word_t *block = V;

	SCRYPT_ROMIX_TANGLE_FN(X, r * 2);

	/* 1: X = B */
	/* implicit */

	/* 2: for i = 0 to N - 1 do */
	memcpy(block, X, chunkWords * sizeof(scrypt_mix_word_t));
	for (i = 0; i < N - 1; i++, block += chunkWords) {
		/* 3: V_i = X */
		/* 4: X = H(X) */
		SCRYPT_CHUNKMIX_FN(block + chunkWords, block, NULL, r);
	}
	SCRYPT_CHUNKMIX_FN(X, block, NULL, r);

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 7: j = Integerify(X) % N */
		j = X[chunkWords - SCRYPT_BLOCK_WORDS] & (N - 1);

		/* 8: X = H(Y ^ V_j) */
		SCRYPT_CHUNKMIX_FN(Y, X, scrypt_item(V, j, chunkWords), r);

		/* 7: j = Integerify(Y) % N */
		j = Y[chunkWords - SCRYPT_BLOCK_WORDS] & (N - 1);

		/* 8: X = H(Y ^ V_j) */
		SCRYPT_CHUNKMIX_FN(X, Y, scrypt_item(V, j, chunkWords), r);
	}

	/* 10: B' = X */
	/* implicit */

	SCRYPT_ROMIX_UNTANGLE_FN(X, r * 2);
}

#if defined(SCRYPT_CHOOSE_COMPILETIME)

/*
	scrypt_ROMix_range(X, Y, V, N, r, pos, cnt)

	Advance one ROMix by cnt steps, starting at step pos of the 2N steps it takes in
	total. Steps [0, N) are the V fill, steps [N, 2N) are the mix. Everything that has
	to survive between calls lives in X, Y and V, so a caller may split the 2N steps
	over as many calls as it likes, as long as it keeps those three buffers alive per
	candidate and walks pos forward without gaps or overlaps.

	Calling this once with pos 0 and cnt 2N computes exactly what SCRYPT_ROMIX_FN does.

	The mix works in pairs and hands the live chunk between X and Y, so stopping on an
	odd offset leaves it in Y. That is why Y is a caller buffer here rather than scratch:
	the parity of the offset says which of the two currently holds it, which is what
	lets the split happen at any step instead of only at even ones.
*/
static void NOINLINE FASTCALL
scrypt_ROMix_range(scrypt_mix_word_t *X/*[chunkWords]*/, scrypt_mix_word_t *Y/*[chunkWords]*/, scrypt_mix_word_t *V/*[N * chunkWords]*/, uint32_t N, uint32_t r, uint32_t pos, uint32_t cnt) {
	uint32_t i, j, chunkWords = (uint32_t)(SCRYPT_BLOCK_WORDS * r * 2);
	uint32_t end = pos + cnt;

	if (cnt == 0)
		return;

	/* B arrives untangled, so tangle it once, as the first step does */
	if (pos == 0) {
		SCRYPT_ROMIX_TANGLE_FN(X, r * 2);

		/* 3: V_0 = X */
		memcpy(V, X, chunkWords * sizeof(scrypt_mix_word_t));
	}

	/* 2: for i = 0 to N - 1 do. step i derives V_{i+1}, the last one derives X */
	for (i = pos; (i < N) && (i < end); i++) {
		scrypt_mix_word_t *block = scrypt_item(V, i, chunkWords);

		if (i < (N - 1))
			SCRYPT_CHUNKMIX_FN(block + chunkWords, block, NULL, r);
		else
			SCRYPT_CHUNKMIX_FN(X, block, NULL, r);
	}

	/* 6: for i = 0 to N - 1 do, one half step at a time so any offset can be resumed */
	for (i = (pos > N) ? pos : N; i < end; i++) {
		if (((i - N) & 1) == 0) {
			/* 7, 8: j = Integerify(X) % N, Y = H(X ^ V_j) */
			j = X[chunkWords - SCRYPT_BLOCK_WORDS] & (N - 1);

			SCRYPT_CHUNKMIX_FN(Y, X, scrypt_item(V, j, chunkWords), r);
		} else {
			/* 7, 8: j = Integerify(Y) % N, X = H(Y ^ V_j) */
			j = Y[chunkWords - SCRYPT_BLOCK_WORDS] & (N - 1);

			SCRYPT_CHUNKMIX_FN(X, Y, scrypt_item(V, j, chunkWords), r);
		}
	}

	/* 10: B' = X. the 2N steps are an even count, so the live chunk ends up in X */
	if (end == (N * 2))
		SCRYPT_ROMIX_UNTANGLE_FN(X, r * 2);
}

#endif /* defined(SCRYPT_CHOOSE_COMPILETIME) */

#endif /* !defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_HAVE_ROMIX) */


#undef SCRYPT_CHUNKMIX_FN
#undef SCRYPT_ROMIX_FN
#undef SCRYPT_MIX_FN
#undef SCRYPT_ROMIX_TANGLE_FN
#undef SCRYPT_ROMIX_UNTANGLE_FN

