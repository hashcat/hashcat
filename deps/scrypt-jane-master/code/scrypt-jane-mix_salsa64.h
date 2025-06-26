#if !defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_SALSA64_INCLUDED)

#undef SCRYPT_MIX
#define SCRYPT_MIX "Salsa64/8 Ref"

#undef SCRYPT_SALSA64_INCLUDED
#define SCRYPT_SALSA64_INCLUDED
#define SCRYPT_SALSA64_BASIC

static void
salsa64_core_basic(uint64_t state[16]) {
	const size_t rounds = 8;
	uint64_t v[16], t;
	size_t i;

	for (i = 0; i < 16; i++) v[i] = state[i];

	#define G(a,b,c,d) \
		t = v[a]+v[d]; t = ROTL64(t, 32); v[b] ^= t; \
		t = v[b]+v[a]; t = ROTL64(t, 13); v[c] ^= t; \
		t = v[c]+v[b]; t = ROTL64(t, 39); v[d] ^= t; \
		t = v[d]+v[c]; t = ROTL64(t, 32); v[a] ^= t; \

	for (i = 0; i < rounds; i += 2) {
		G( 0, 4, 8,12);
		G( 5, 9,13, 1);
		G(10,14, 2, 6);
		G(15, 3, 7,11);
		G( 0, 1, 2, 3);
		G( 5, 6, 7, 4);
		G(10,11, 8, 9);
		G(15,12,13,14);
	}

	for (i = 0; i < 16; i++) state[i] += v[i];

	#undef G
}

#endif

