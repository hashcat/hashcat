#define SCRYPT_HASH "Skein-512"
#define SCRYPT_HASH_BLOCK_SIZE 64
#define SCRYPT_HASH_DIGEST_SIZE 64

typedef uint8_t scrypt_hash_digest[SCRYPT_HASH_DIGEST_SIZE];

typedef struct scrypt_hash_state_t {
	uint64_t X[8], T[2];
	uint32_t leftover;
	uint8_t buffer[SCRYPT_HASH_BLOCK_SIZE];
} scrypt_hash_state;

#include <stdio.h>

static void
skein512_blocks(scrypt_hash_state *S, const uint8_t *in, size_t blocks, size_t add) {
	uint64_t X[8], key[8], Xt[9+18], T[3+1];
	size_t r;

	while (blocks--) {
		T[0] = S->T[0] + add;
		T[1] = S->T[1];
		T[2] = T[0] ^ T[1];
		key[0] = U8TO64_LE(in +  0); Xt[0] = S->X[0]; X[0] = key[0] + Xt[0];
		key[1] = U8TO64_LE(in +  8); Xt[1] = S->X[1]; X[1] = key[1] + Xt[1];
		key[2] = U8TO64_LE(in + 16); Xt[2] = S->X[2]; X[2] = key[2] + Xt[2];
		key[3] = U8TO64_LE(in + 24); Xt[3] = S->X[3]; X[3] = key[3] + Xt[3];
		key[4] = U8TO64_LE(in + 32); Xt[4] = S->X[4]; X[4] = key[4] + Xt[4];
		key[5] = U8TO64_LE(in + 40); Xt[5] = S->X[5]; X[5] = key[5] + Xt[5] + T[0];
		key[6] = U8TO64_LE(in + 48); Xt[6] = S->X[6]; X[6] = key[6] + Xt[6] + T[1];
		key[7] = U8TO64_LE(in + 56); Xt[7] = S->X[7]; X[7] = key[7] + Xt[7];
		Xt[8] = 0x1BD11BDAA9FC1A22ull ^ Xt[0] ^ Xt[1] ^ Xt[2] ^ Xt[3] ^ Xt[4] ^ Xt[5] ^ Xt[6] ^ Xt[7];
		in += SCRYPT_HASH_BLOCK_SIZE;

		for (r = 0; r < 18; r++)
			Xt[r + 9] = Xt[r + 0];

		for (r = 0; r < 18; r += 2) {
			X[0] += X[1]; X[1] = ROTL64(X[1], 46) ^ X[0];
			X[2] += X[3]; X[3] = ROTL64(X[3], 36) ^ X[2];
			X[4] += X[5]; X[5] = ROTL64(X[5], 19) ^ X[4];
			X[6] += X[7]; X[7] = ROTL64(X[7], 37) ^ X[6];
			X[2] += X[1]; X[1] = ROTL64(X[1], 33) ^ X[2];
			X[0] += X[3]; X[3] = ROTL64(X[3], 42) ^ X[0];
			X[6] += X[5]; X[5] = ROTL64(X[5], 14) ^ X[6];
			X[4] += X[7]; X[7] = ROTL64(X[7], 27) ^ X[4];
			X[4] += X[1]; X[1] = ROTL64(X[1], 17) ^ X[4];
			X[6] += X[3]; X[3] = ROTL64(X[3], 49) ^ X[6];
			X[0] += X[5]; X[5] = ROTL64(X[5], 36) ^ X[0];
			X[2] += X[7]; X[7] = ROTL64(X[7], 39) ^ X[2];
			X[6] += X[1]; X[1] = ROTL64(X[1], 44) ^ X[6];
			X[4] += X[3]; X[3] = ROTL64(X[3], 56) ^ X[4];
			X[2] += X[5]; X[5] = ROTL64(X[5], 54) ^ X[2];
			X[0] += X[7]; X[7] = ROTL64(X[7],  9) ^ X[0];

			X[0] += Xt[r + 1];
			X[1] += Xt[r + 2];
			X[2] += Xt[r + 3];
			X[3] += Xt[r + 4];
			X[4] += Xt[r + 5];
			X[5] += Xt[r + 6] + T[1];
			X[6] += Xt[r + 7] + T[2];
			X[7] += Xt[r + 8] + r + 1;

			T[3] = T[0];
			T[0] = T[1];
			T[1] = T[2];
			T[2] = T[3];

			X[0] += X[1]; X[1] = ROTL64(X[1], 39) ^ X[0];
			X[2] += X[3]; X[3] = ROTL64(X[3], 30) ^ X[2];
			X[4] += X[5]; X[5] = ROTL64(X[5], 34) ^ X[4];
			X[6] += X[7]; X[7] = ROTL64(X[7], 24) ^ X[6];
			X[2] += X[1]; X[1] = ROTL64(X[1], 13) ^ X[2];
			X[0] += X[3]; X[3] = ROTL64(X[3], 17) ^ X[0];
			X[6] += X[5]; X[5] = ROTL64(X[5], 10) ^ X[6];
			X[4] += X[7]; X[7] = ROTL64(X[7], 50) ^ X[4];
			X[4] += X[1]; X[1] = ROTL64(X[1], 25) ^ X[4];
			X[6] += X[3]; X[3] = ROTL64(X[3], 29) ^ X[6];
			X[0] += X[5]; X[5] = ROTL64(X[5], 39) ^ X[0];
			X[2] += X[7]; X[7] = ROTL64(X[7], 43) ^ X[2];
			X[6] += X[1]; X[1] = ROTL64(X[1],  8) ^ X[6];
			X[4] += X[3]; X[3] = ROTL64(X[3], 22) ^ X[4];
			X[2] += X[5]; X[5] = ROTL64(X[5], 56) ^ X[2];
			X[0] += X[7]; X[7] = ROTL64(X[7], 35) ^ X[0];

			X[0] += Xt[r + 2];
			X[1] += Xt[r + 3];
			X[2] += Xt[r + 4];
			X[3] += Xt[r + 5];
			X[4] += Xt[r + 6];
			X[5] += Xt[r + 7] + T[1];
			X[6] += Xt[r + 8] + T[2];
			X[7] += Xt[r + 9] + r + 2;

			T[3] = T[0];
			T[0] = T[1];
			T[1] = T[2];
			T[2] = T[3];
		}

		S->X[0] = key[0] ^ X[0];
		S->X[1] = key[1] ^ X[1];
		S->X[2] = key[2] ^ X[2];
		S->X[3] = key[3] ^ X[3];
		S->X[4] = key[4] ^ X[4];
		S->X[5] = key[5] ^ X[5];
		S->X[6] = key[6] ^ X[6];
		S->X[7] = key[7] ^ X[7];

		S->T[0] = T[0];
		S->T[1] = T[1] & ~0x4000000000000000ull;
	}
}

static void
scrypt_hash_init(scrypt_hash_state *S) {
	S->X[0] = 0x4903ADFF749C51CEull;
	S->X[1] = 0x0D95DE399746DF03ull;
	S->X[2] = 0x8FD1934127C79BCEull;
	S->X[3] = 0x9A255629FF352CB1ull;
	S->X[4] = 0x5DB62599DF6CA7B0ull;
	S->X[5] = 0xEABE394CA9D5C3F4ull;
	S->X[6] = 0x991112C71A75B523ull;
	S->X[7] = 0xAE18A40B660FCC33ull;
	S->T[0] = 0x0000000000000000ull;
	S->T[1] = 0x7000000000000000ull;
	S->leftover = 0;
}

static void
scrypt_hash_update(scrypt_hash_state *S, const uint8_t *in, size_t inlen) {
	size_t blocks, want;

	/* skein processes the final <=64 bytes raw, so we can only update if there are at least 64+1 bytes available */
	if ((S->leftover + inlen) > SCRYPT_HASH_BLOCK_SIZE) {
		/* handle the previous data, we know there is enough for at least one block */
		if (S->leftover) {
			want = (SCRYPT_HASH_BLOCK_SIZE - S->leftover);
			memcpy(S->buffer + S->leftover, in, want);
			in += want;
			inlen -= want;
			S->leftover = 0;
			skein512_blocks(S, S->buffer, 1, SCRYPT_HASH_BLOCK_SIZE);
		}

		/* handle the current data if there's more than one block */
		if (inlen > SCRYPT_HASH_BLOCK_SIZE) {
			blocks = ((inlen - 1) & ~(SCRYPT_HASH_BLOCK_SIZE - 1));
			skein512_blocks(S, in, blocks / SCRYPT_HASH_BLOCK_SIZE, SCRYPT_HASH_BLOCK_SIZE);
			inlen -= blocks;
			in += blocks;
		}
	}
	
	/* handle leftover data */
	memcpy(S->buffer + S->leftover, in, inlen);
	S->leftover += inlen;
}

static void
scrypt_hash_finish(scrypt_hash_state *S, uint8_t *hash) {
	memset(S->buffer + S->leftover, 0, SCRYPT_HASH_BLOCK_SIZE - S->leftover);
	S->T[1] |= 0x8000000000000000ull;
	skein512_blocks(S, S->buffer, 1, S->leftover);

	memset(S->buffer, 0, SCRYPT_HASH_BLOCK_SIZE);
	S->T[0] = 0;
	S->T[1] = 0xff00000000000000ull;
	skein512_blocks(S, S->buffer, 1, 8);

	U64TO8_LE(&hash[ 0], S->X[0]);
	U64TO8_LE(&hash[ 8], S->X[1]);
	U64TO8_LE(&hash[16], S->X[2]);
	U64TO8_LE(&hash[24], S->X[3]);
	U64TO8_LE(&hash[32], S->X[4]);
	U64TO8_LE(&hash[40], S->X[5]);
	U64TO8_LE(&hash[48], S->X[6]);
	U64TO8_LE(&hash[56], S->X[7]);
}


static const uint8_t scrypt_test_hash_expected[SCRYPT_HASH_DIGEST_SIZE] = {
	0x4d,0x52,0x29,0xff,0x10,0xbc,0xd2,0x62,0xd1,0x61,0x83,0xc8,0xe6,0xf0,0x83,0xc4,
	0x9f,0xf5,0x6a,0x42,0x75,0x2a,0x26,0x4e,0xf0,0x28,0x72,0x28,0x47,0xe8,0x23,0xdf,
	0x1e,0x64,0xf1,0x51,0x38,0x35,0x9d,0xc2,0x83,0xfc,0x35,0x4e,0xc0,0x52,0x5f,0x41,
	0x6a,0x0b,0x7d,0xf5,0xce,0x98,0xde,0x6f,0x36,0xd8,0x51,0x15,0x78,0x78,0x93,0x67,
};
