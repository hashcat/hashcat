#define SCRYPT_HASH "BLAKE-512"
#define SCRYPT_HASH_BLOCK_SIZE 128
#define SCRYPT_HASH_DIGEST_SIZE 64

typedef uint8_t scrypt_hash_digest[SCRYPT_HASH_DIGEST_SIZE];

const uint8_t blake512_sigma[] = {
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

const uint64_t blake512_constants[16] = {
	0x243f6a8885a308d3ULL, 0x13198a2e03707344ULL, 0xa4093822299f31d0ULL, 0x082efa98ec4e6c89ULL,
	0x452821e638d01377ULL, 0xbe5466cf34e90c6cULL, 0xc0ac29b7c97c50ddULL, 0x3f84d5b5b5470917ULL,
	0x9216d5d98979fb1bULL, 0xd1310ba698dfb5acULL, 0x2ffd72dbd01adfb7ULL, 0xb8e1afed6a267e96ULL,
	0xba7c9045f12c7f99ULL, 0x24a19947b3916cf7ULL, 0x0801f2e2858efc16ULL, 0x636920d871574e69ULL
};

typedef struct scrypt_hash_state_t {
	uint64_t H[8], T[2];
	uint32_t leftover;
	uint8_t buffer[SCRYPT_HASH_BLOCK_SIZE];
} scrypt_hash_state;

static void
blake512_blocks(scrypt_hash_state *S, const uint8_t *in, size_t blocks) {
	const uint8_t *sigma, *sigma_end = blake512_sigma + (10 * 16);
	uint64_t m[16], v[16], h[8], t[2];
	uint32_t i;

	for (i = 0; i < 8; i++) h[i] = S->H[i];
	for (i = 0; i < 2; i++) t[i] = S->T[i];

	while (blocks--) {
		t[0] += 1024;
		t[1] += (t[0] < 1024) ? 1 : 0;

		for (i = 0; i <  8; i++) v[i     ] = h[i];
		for (i = 0; i <  4; i++) v[i +  8] = blake512_constants[i];
		for (i = 0; i <  2; i++) v[i + 12] = blake512_constants[i+4] ^ t[0];
		for (i = 0; i <  2; i++) v[i + 14] = blake512_constants[i+6] ^ t[1];

		for (i = 0; i < 16; i++) m[i] = U8TO64_BE(&in[i * 8]);
		in += 128;

		#define G(a,b,c,d,e)                                                 \
			v[a] += (m[sigma[e+0]] ^ blake512_constants[sigma[e+1]]) + v[b]; \
			v[d] = ROTR64(v[d] ^ v[a],32);                                   \
			v[c] += v[d];                                                    \
			v[b] = ROTR64(v[b] ^ v[c],25);                                   \
			v[a] += (m[sigma[e+1]] ^ blake512_constants[sigma[e+0]]) + v[b]; \
			v[d] = ROTR64(v[d] ^ v[a],16);                                   \
			v[c] += v[d];                                                    \
			v[b] = ROTR64(v[b] ^ v[c],11);

		for (i = 0, sigma = blake512_sigma; i < 16; i++) {
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
				sigma = blake512_sigma;
		}

		#undef G

		for (i = 0; i < 8; i++) h[i] ^= (v[i] ^ v[i + 8]);
	}

	for (i = 0; i < 8; i++) S->H[i] = h[i];
	for (i = 0; i < 2; i++) S->T[i] = t[i];
}

static void
scrypt_hash_init(scrypt_hash_state *S) {
	S->H[0] = 0x6a09e667f3bcc908ULL;
	S->H[1] = 0xbb67ae8584caa73bULL;
	S->H[2] = 0x3c6ef372fe94f82bULL;
	S->H[3] = 0xa54ff53a5f1d36f1ULL;
	S->H[4] = 0x510e527fade682d1ULL;
	S->H[5] = 0x9b05688c2b3e6c1fULL;
	S->H[6] = 0x1f83d9abfb41bd6bULL;
	S->H[7] = 0x5be0cd19137e2179ULL;
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
		blake512_blocks(S, S->buffer, 1);
	}

	/* handle the current data */
	blocks = (inlen & ~(SCRYPT_HASH_BLOCK_SIZE - 1));
	S->leftover = (uint32_t)(inlen - blocks);
	if (blocks) {
		blake512_blocks(S, in, blocks / SCRYPT_HASH_BLOCK_SIZE);
		in += blocks;
	}

	/* handle leftover data */
	if (S->leftover)
		memcpy(S->buffer, in, S->leftover);
}

static void
scrypt_hash_finish(scrypt_hash_state *S, uint8_t *hash) {
	uint64_t th, tl;
	size_t bits;

	bits = (S->leftover << 3);
	tl = S->T[0] + bits;
	th = S->T[1];
	if (S->leftover == 0) {
		S->T[0] = (uint64_t)0 - (uint64_t)1024;
		S->T[1] = (uint64_t)0 - (uint64_t)1;
	} else if (S->T[0] == 0) {
		S->T[0] = ((uint64_t)0 - (uint64_t)1024) + bits;
		S->T[1] = S->T[1] - 1;
	} else {
		S->T[0] -= (1024 - bits);
	}

	S->buffer[S->leftover] = 0x80;
	if (S->leftover <= 111) {
		memset(S->buffer + S->leftover + 1, 0, 111 - S->leftover);
	} else {
		memset(S->buffer + S->leftover + 1, 0, 127 - S->leftover);
		blake512_blocks(S, S->buffer, 1);
		S->T[0] = (uint64_t)0 - (uint64_t)1024;
		S->T[1] = (uint64_t)0 - (uint64_t)1;
		memset(S->buffer, 0, 112);
	}
	S->buffer[111] |= 1;
	U64TO8_BE(S->buffer + 112, th);
	U64TO8_BE(S->buffer + 120, tl);
	blake512_blocks(S, S->buffer, 1);

	U64TO8_BE(&hash[ 0], S->H[0]);
	U64TO8_BE(&hash[ 8], S->H[1]);
	U64TO8_BE(&hash[16], S->H[2]);
	U64TO8_BE(&hash[24], S->H[3]);
	U64TO8_BE(&hash[32], S->H[4]);
	U64TO8_BE(&hash[40], S->H[5]);
	U64TO8_BE(&hash[48], S->H[6]);
	U64TO8_BE(&hash[56], S->H[7]);
}

static const uint8_t scrypt_test_hash_expected[SCRYPT_HASH_DIGEST_SIZE] = {
	0x2f,0x9d,0x5b,0xbe,0x24,0x0d,0x63,0xd3,0xa0,0xac,0x4f,0xd3,0x01,0xc0,0x23,0x6f,
	0x6d,0xdf,0x6e,0xfb,0x60,0x6f,0xa0,0x74,0xdf,0x9f,0x25,0x65,0xb6,0x11,0x0a,0x83,
	0x23,0x96,0xba,0x91,0x68,0x4b,0x85,0x15,0x13,0x54,0xba,0x19,0xf3,0x2c,0x5a,0x4a,
	0x1f,0x78,0x31,0x02,0xc9,0x1e,0x56,0xc4,0x54,0xca,0xf9,0x8f,0x2c,0x7f,0x85,0xac
};
