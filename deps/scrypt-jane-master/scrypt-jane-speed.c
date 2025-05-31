#define SCRYPT_TEST_SPEED
#include "scrypt-jane.c"

/* ticks - not tested on anything other than x86 */
static uint64_t
get_ticks(void) {
#if defined(CPU_X86) || defined(CPU_X86_64)
	#if defined(COMPILER_INTEL)
		return _rdtsc();
	#elif defined(COMPILER_MSVC)
		return __rdtsc();
	#elif defined(COMPILER_GCC)
		uint32_t lo, hi;
		__asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
		return ((uint64_t)lo | ((uint64_t)hi << 32));
	#else
		need rdtsc for this compiler
	#endif
#elif defined(OS_SOLARIS)
	return (uint64_t)gethrtime();
#elif defined(CPU_SPARC) && !defined(OS_OPENBSD)
	uint64_t t;
	__asm__ __volatile__("rd %%tick, %0" : "=r" (t));
	return t;
#elif defined(CPU_PPC)
	uint32_t lo = 0, hi = 0;
	__asm__ __volatile__("mftbu %0; mftb %1" : "=r" (hi), "=r" (lo));
	return ((uint64_t)lo | ((uint64_t)hi << 32));
#elif defined(CPU_IA64)
	uint64_t t;
	__asm__ __volatile__("mov %0=ar.itc" : "=r" (t));
	return t;
#elif defined(OS_NIX)
	timeval t2;
	gettimeofday(&t2, NULL);
	t = ((uint64_t)t2.tv_usec << 32) | (uint64_t)t2.tv_sec;
	return t;
#else
	need ticks for this platform
#endif
}

#define timeit(x,minvar) {       \
	ticks = get_ticks();         \
 	x;                           \
	ticks = get_ticks() - ticks; \
	if (ticks < minvar)          \
		minvar = ticks;          \
	}

#define maxticks 0xffffffffffffffffull

typedef struct scrypt_speed_settings_t {
	const char *desc;
	uint8_t Nfactor, rfactor, pfactor;
} scrypt_speed_settings;

/* scrypt_r_32kb is set to a 32kb chunk, so (1 << (scrypt_r_32kb - 5)) = 1kb chunk */
static const scrypt_speed_settings settings[] = {
	{"scrypt high volume     ( ~4mb)", 11, scrypt_r_32kb - 5, 0},
	{"scrypt interactive     (~16mb)", 13, scrypt_r_32kb - 5, 0},
	{"scrypt non-interactive (~ 1gb)", 19, scrypt_r_32kb - 5, 0},
	{0}
};

int main(void) {
	const scrypt_speed_settings *s;
	uint8_t password[64], salt[24], digest[64];
	uint64_t minticks, ticks;
	size_t i, passes;
	size_t cpuflags, topbit;

	for (i = 0; i < sizeof(password); i++)
		password[i] = (uint8_t)i;
	for (i = 0; i < sizeof(salt); i++)
		salt[i] = 255 - (uint8_t)i;

	/* warm up a little */
	scrypt(password, sizeof(password), salt, sizeof(salt), 15, 3, 4, digest, sizeof(digest));

	cpuflags = available_implementations();
	topbit = 0;
	for (i = cpuflags; i != 0; i >>= 1)
		topbit++;
	topbit = ((size_t)1 << topbit);

	while (1) {
	#if defined(SCRYPT_CHOOSE_COMPILETIME)
		printf("speed test for scrypt[%s,%s]\n", SCRYPT_HASH, SCRYPT_MIX);
	#else
		printf("speed test for scrypt[%s,%s,%s]\n", SCRYPT_HASH, SCRYPT_MIX, get_top_cpuflag_desc(cpuflags));
	#endif

		cpu_detect_mask = cpuflags;
		for (i = 0; settings[i].desc; i++) {
			s = &settings[i];
			minticks = maxticks;
			for (passes = 0; passes < 16; passes++)
				timeit(scrypt(password, sizeof(password), salt, sizeof(salt), s->Nfactor, s->rfactor, s->pfactor, digest, sizeof(digest)), minticks)

			printf("%s, %.0f ticks\n", s->desc, (double)minticks);
		}

	#if defined(SCRYPT_CHOOSE_COMPILETIME)
		break;
	#else
		while (topbit && ((cpuflags & topbit) == 0)) 
			topbit >>= 1;
		cpuflags &= ~topbit;

		/* (cpuflags == 0) is the basic/portable version, don't bother timing it */
		if (!cpuflags)
			break;
	#endif
	}

	printf("\n\n");

	return 0;
}

