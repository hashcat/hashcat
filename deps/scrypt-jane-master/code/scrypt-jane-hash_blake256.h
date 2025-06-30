#define SCRYPT_HASH "BLAKE-256"
#define SCRYPT_HASH_BLOCK_SIZE 64
#define SCRYPT_HASH_DIGEST_SIZE 32

typedef uint8_t scrypt_hash_digest[SCRYPT_HASH_DIGEST_SIZE];

const uint8_t blake256_sigma[] = {
	 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
	14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3,
	11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4,
	 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8,
	 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13,
	 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9,
	12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11,
	13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10,
	 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5,
	10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13 ,0,
};

const uint32_t blake256_constants[16] = {
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

typedef struct scrypt_hash_state_t {
	uint32_t H[8], T[2];
	uint32_t leftover;
	uint8_t buffer[SCRYPT_HASH_BLOCK_SIZE];
} scrypt_hash_state;

static void
blake256_blocks(scrypt_hash_state *S, const uint8_t *in, size_t blocks) {
	const uint8_t *sigma, *sigma_end = blake256_sigma + (10 * 16);
	uint32_t m[16], v[16], h[8], t[2];
	uint32_t i;

	for (i = 0; i < 8; i++) h[i] = S->H[i];
	for (i = 0; i < 2; i++) t[i] = S->T[i];

	while (blocks--) {
		t[0] += 512;
		t[1] += (t[0] < 512) ? 1 : 0;

		for (i = 0; i <  8; i++) v[i     ] = h[i];
		for (i = 0; i <  4; i++) v[i +  8] = blake256_constants[i];
		for (i = 0; i <  2; i++) v[i + 12] = blake256_constants[i+4] ^ t[0];
		for (i = 0; i <  2; i++) v[i + 14] = blake256_constants[i+6] ^ t[1];
		
		for (i = 0; i < 16; i++) m[i] = U8TO32_BE(&in[i * 4]);
		in += 64;

		#define G(a,b,c,d,e)                                                 \
			v[a] += (m[sigma[e+0]] ^ blake256_constants[sigma[e+1]]) + v[b]; \
			v[d] = ROTR32(v[d] ^ v[a],16);                                   \
			v[c] += v[d];                                                    \
			v[b] = ROTR32(v[b] ^ v[c],12);                                   \
			v[a] += (m[sigma[e+1]] ^ blake256_constants[sigma[e+0]]) + v[b]; \
			v[d] = ROTR32(v[d] ^ v[a], 8);                                   \
			v[c] += v[d];                                                    \
			v[b] = ROTR32(v[b] ^ v[c], 7);

		for (i = 0, sigma = blake256_sigma; i < 14; i++) {
			G(0, 4, 8,12, 0);
			G(1, 5, 9,13, 2);
			G(2, 6,10,14, 4);
			G(3, 7,11,15, 6);

			G(0, 5,10,15, 8);
			G(1, 6,11,12,10);
			G(2, 7, 8,13,12);
			G(3, 4, 9,14,14);

			sigma += 16;
			if (sigma == sigma_end)
				sigma = blake256_sigma;
		}

		#undef G

		for (i = 0; i < 8; i++) h[i] ^= (v[i] ^ v[i + 8]);
	}

	for (i = 0; i < 8; i++) S->H[i] = h[i];
	for (i = 0; i < 2; i++) S->T[i] = t[i];
}

static void
scrypt_hash_init(scrypt_hash_state *S) {
	S->H[0] = 0x6a09e667ULL;
	S->H[1] = 0xbb67ae85ULL;
	S->H[2] = 0x3c6ef372ULL;
	S->H[3] = 0xa54ff53aULL;
	S->H[4] = 0x510e527fULL;
	S->H[5] = 0x9b05688cULL;
	S->H[6] = 0x1f83d9abULL;
	S->H[7] = 0x5be0cd19ULL;
	S->T[0] = 0;
	S->T[1] = 0;
	S->leftover = 0;
}

static void
scrypt_hash_update(scrypt_hash_state *S, const uint8_t *in, size_t inlen) {
	size_t blocks, want;

	/* handle the previous data */
	if (S->leftover) {
		want = (SCRYPT_HASH_BLOCK_SIZE - S->leftover);
		want = (want < inlen) ? want : inlen;
		memcpy(S->buffer + S->leftover, in, want);
		S->leftover += (uint32_t)want;
		if (S->leftover < SCRYPT_HASH_BLOCK_SIZE)
			return;
		in += want;
		inlen -= want;
		blake256_blocks(S, S->buffer, 1);
	}

	/* handle the current data */
	blocks = (inlen & ~(SCRYPT_HASH_BLOCK_SIZE - 1));
	S->leftover = (uint32_t)(inlen - blocks);
	if (blocks) {
		blake256_blocks(S, in, blocks / SCRYPT_HASH_BLOCK_SIZE);
		in += blocks;
	}

	/* handle leftover data */
	if (S->leftover)
		memcpy(S->buffer, in, S->leftover);
}

static void
scrypt_hash_finish(scrypt_hash_state *S, uint8_t *hash) {
	uint32_t th, tl, bits;

	bits = (S->leftover << 3);
	tl = S->T[0] + bits;
	th = S->T[1];
	if (S->leftover == 0) {
		S->T[0] = (uint32_t)0 - (uint32_t)512;
		S->T[1] = (uint32_t)0 - (uint32_t)1;
	} else if (S->T[0] == 0) {
		S->T[0] = ((uint32_t)0 - (uint32_t)512) + bits;
		S->T[1] = S->T[1] - 1;
	} else {
		S->T[0] -= (512 - bits);
	}

	S->buffer[S->leftover] = 0x80;
	if (S->leftover <= 55) {
		memset(S->buffer + S->leftover + 1, 0, 55 - S->leftover);
	} else {
		memset(S->buffer + S->leftover + 1, 0, 63 - S->leftover);
		blake256_blocks(S, S->buffer, 1);
		S->T[0] = (uint32_t)0 - (uint32_t)512;
		S->T[1] = (uint32_t)0 - (uint32_t)1;
		memset(S->buffer, 0, 56);
	}
	S->buffer[55] |= 1;
	U32TO8_BE(S->buffer + 56, th);
	U32TO8_BE(S->buffer + 60, tl);
	blake256_blocks(S, S->buffer, 1);

	U32TO8_BE(&hash[ 0], S->H[0]);
	U32TO8_BE(&hash[ 4], S->H[1]);
	U32TO8_BE(&hash[ 8], S->H[2]);
	U32TO8_BE(&hash[12], S->H[3]);
	U32TO8_BE(&hash[16], S->H[4]);
	U32TO8_BE(&hash[20], S->H[5]);
	U32TO8_BE(&hash[24], S->H[6]);
	U32TO8_BE(&hash[28], S->H[7]);
}

static const uint8_t scrypt_test_hash_expected[SCRYPT_HASH_DIGEST_SIZE] = {
	0xcc,0xa9,0x1e,0xa9,0x20,0x97,0x37,0x40,0x17,0xc0,0xa0,0x52,0x87,0xfc,0x08,0x20,
	0x40,0xf5,0x81,0x86,0x62,0x75,0x78,0xb2,0x79,0xce,0xde,0x27,0x3c,0x7f,0x85,0xd8,
};
