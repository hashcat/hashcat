/*-
 * Copyright 2013-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
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
 */

#define YESCRYPT_FLAGS YESCRYPT_DEFAULTS
//#define YESCRYPT_FLAGS YESCRYPT_WORM
//#define YESCRYPT_FLAGS 0

#define ROM_SHM_KEY			0x7965730a

//#define DISABLE_ROM
//#define DUMP_LOCAL

#include <stdio.h>
#include <stdlib.h> /* for atoi() */
#include <string.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/times.h>
#include <sched.h>

#include "yescrypt.h"

#ifdef _OPENMP
#include <omp.h>

#define NSAVE				1000

static uint64_t time_us(void)
{
	struct timespec t;
#ifdef CLOCK_MONOTONIC_RAW
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &t))
		return 0;
#else
	if (clock_gettime(CLOCK_MONOTONIC, &t))
		return 0;
#endif
	return 1 + (uint64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
#endif

int main(int argc, const char * const *argv)
{
#if 0
	uint64_t rom_bytes = 112 * (1024ULL*1024*1024);
	uint64_t ram_bytes = 1 * (1024ULL*1024);
#else
	uint64_t rom_bytes = 3 * (1024ULL*1024*1024);
	uint64_t ram_bytes = 2 * (1024ULL*1024);
#endif
	uint32_t r, min_r;
	uint64_t NROM_log2, N_log2;
	yescrypt_shared_t shared_s;
	yescrypt_shared_t *shared = NULL;
#ifndef DISABLE_ROM
	int shmid;
#endif
	const char *rom_filename = NULL;
	int rom_fd;
	yescrypt_binary_t key = {.uc={
	    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
	    17,18,19,20,21,22,23,24,25,26,27,28,255,128,64,32}};

	if (argc > 1)
		rom_bytes = atoi(argv[1]) * (1024ULL*1024*1024);
	if (argc > 2)
		ram_bytes = atoi(argv[2]) * (1024ULL*1024);
	if (argc > 3 && rom_bytes)
		rom_filename = argv[3];

	r = 16;
	min_r = 9;
	if (rom_filename)
		min_r = 8 * 64;

	NROM_log2 = 0;
	if (rom_bytes) {
		while (((rom_bytes >> NROM_log2) & 0xff) == 0)
			NROM_log2++;
		r = rom_bytes >> (7 + NROM_log2);
		while (r < min_r && NROM_log2 > 0) {
			r <<= 1;
			NROM_log2--;
		}
		rom_bytes = (uint64_t)r << (7 + NROM_log2);
	}

	N_log2 = 0;
	while (((uint64_t)r << (7 + N_log2)) < ram_bytes)
		N_log2++;
	ram_bytes = (uint64_t)r << (7 + N_log2);

	printf("r=%u N=2^%u NROM=2^%u\n", r,
	    (unsigned int)N_log2, (unsigned int)NROM_log2);

#ifdef DISABLE_ROM
	rom_bytes = 0;
#endif

	printf("Will use %.2f KiB ROM\n", rom_bytes / 1024.0);
	printf("         %.2f KiB RAM\n", ram_bytes / 1024.0);

#ifndef DISABLE_ROM
	if (rom_filename) {
		rom_fd = open(rom_filename, O_RDONLY);
		if (rom_fd < 0) {
			perror("open");
			return 1;
		}

		int flags =
#ifdef MAP_NOCORE
		    MAP_NOCORE |
#endif
#ifdef MAP_HUGETLB
		    MAP_HUGETLB |
#endif
		    MAP_SHARED;
		void *p = mmap(NULL, rom_bytes, PROT_READ, flags, rom_fd, 0);
#ifdef MAP_HUGETLB
		if (p == MAP_FAILED)
			p = mmap(NULL, rom_bytes, PROT_READ,
			    flags & ~MAP_HUGETLB, rom_fd, 0);
#endif
		if (p == MAP_FAILED) {
			perror("mmap");
			close(rom_fd);
			return 1;
		}
		close(rom_fd);

		shared = &shared_s;
		shared->base = shared->aligned = p;
		shared->aligned_size = rom_bytes;
	} else if (rom_bytes) {
		shared = &shared_s;
		shared->aligned_size = rom_bytes;
		shmid = shmget(ROM_SHM_KEY, shared->aligned_size, 0);
		if (shmid == -1) {
			perror("shmget");
			return 1;
		}

		shared->base = shared->aligned = shmat(shmid, NULL, SHM_RDONLY);
		if (shared->base == (void *)-1) {
			perror("shmat");
			return 1;
		}
	}
#endif

	{
		yescrypt_local_t local;
		const uint8_t *setting;

		if (yescrypt_init_local(&local)) {
			puts("yescrypt_init_local() FAILED");
			return 1;
		}

		yescrypt_params_t params = {
		    .flags = YESCRYPT_FLAGS,
		    .N = (uint64_t)1 << N_log2,
		    .NROM = NROM_log2 ? ((uint64_t)1 << NROM_log2) : 0,
		    .r = r,
		    .p = 1 };
		setting = yescrypt_encode_params(&params,
		    (const uint8_t *)"WZaPV7LSUEKMo34.", 16);

		{
			uint8_t hash[128];
			if (!yescrypt_r(shared, &local,
			    (const uint8_t *)"pleaseletmein", 13, setting, NULL,
			    hash, sizeof(hash))) {
				puts("yescrypt_r() FAILED");
				return 1;
			}
			printf("Plaintext: '%s'\n", (char *)hash);
			if (!yescrypt_r(shared, &local,
			    (const uint8_t *)"pleaseletmein", 13, setting, &key,
			    hash, sizeof(hash))) {
				puts("yescrypt_r() FAILED");
				return 1;
			}
			printf("Encrypted: '%s'\n", (char *)hash);
		}

#ifdef DUMP_LOCAL
#if 0
		fwrite(local.aligned, local.aligned_size, 1, stderr);
#else
		/* Skip B, dump only V */
		if (local.aligned_size >= ram_bytes + 128 * r)
			fwrite((char *)local.aligned + 128 * r, ram_bytes,
			    1, stderr);
#endif
#endif

		puts("Benchmarking 1 thread ...");

		clock_t clk_tck = sysconf(_SC_CLK_TCK);
		struct tms start_tms, end_tms;
		clock_t start = times(&start_tms), end;
		unsigned int i, n;
		unsigned long long count;
#ifdef _OPENMP
		char save[NSAVE][128];
		unsigned int nsave = 0;
#endif
		unsigned int seed = start * 1812433253U;

		n = 1;
		count = 0;
		do {
			for (i = 0; i < n; i++) {
				unsigned int j = count + i;
				char p[32];
				uint8_t hash[128];
				snprintf(p, sizeof(p), "%u", seed + j);
#ifdef _OPENMP
				const uint8_t *h =
#endif
				yescrypt_r(shared, &local,
				    (const uint8_t *)p, strlen(p),
				    setting, &key, hash, sizeof(hash));
#ifdef _OPENMP
				if (j < NSAVE) {
					save[j][0] = 0;
					strncat(save[j], (char *)h,
					    sizeof(save[j]) - 1);
					nsave = j;
				}
#endif
			}
			count += n;

			end = times(&end_tms);
			n <<= 1;
		} while (end - start < clk_tck * 2);

		clock_t start_v = start_tms.tms_utime + start_tms.tms_stime +
		    start_tms.tms_cutime + start_tms.tms_cstime;
		clock_t end_v = end_tms.tms_utime + end_tms.tms_stime +
		    end_tms.tms_cutime + end_tms.tms_cstime;

		printf("%llu c/s real, %llu c/s virtual "
		    "(%llu hashes in %.2f seconds)\n",
		    count * clk_tck / (end - start),
		    count * clk_tck / (end_v - start_v),
		    count, (double)(end - start) / clk_tck);

#ifdef _OPENMP
		unsigned int nt = omp_get_max_threads();

		printf("Benchmarking %u thread%s ...\n",
		    nt, nt == 1 ? "" : "s");

		typedef struct {
			yescrypt_local_t local;
			uint64_t min, max, total;
		} thread_data_s;
		union {
			thread_data_s s;
			uint8_t cachelines[2][64]; /* avoid false sharing */
		} thread_data[nt]; /* tricky to align this when on stack */

		unsigned int t;
		for (t = 0; t < nt; t++) {
			thread_data_s *td = &thread_data[t].s;
			if (yescrypt_init_local(&td->local)) {
				puts("yescrypt_init_local() FAILED");
				return 1;
			}
			td->min = ~(uint64_t)0; td->max = 0; td->total = 0;
		}

		unsigned long long count1 = count, count_restart = 0;

		if (!geteuid()) {
			puts("Running as root, so trying to set SCHED_RR");
#pragma omp parallel
			{
				struct sched_param param = { .sched_priority = 1 };
				if (sched_setscheduler(getpid(), SCHED_RR, &param))
					perror("sched_setscheduler");
			}
		}

		start = times(&start_tms);

		n = count * omp_get_max_threads();
		count = 0;
		do {
#pragma omp parallel for default(none) private(i) shared(n, shared, thread_data, setting, seed, count, save, nsave, key)
			for (i = 0; i < n; i++) {
				unsigned int j = count + i;
				char p[32];
				uint8_t hash[128];
				snprintf(p, sizeof(p), "%u", seed + j);
				thread_data_s *td = &thread_data[omp_get_thread_num()].s;
				uint64_t start1 = time_us();
#if 1
				const char *h = (const char *)yescrypt_r(
				    shared, &td->local,
				    (const uint8_t *)p, strlen(p),
				    setting, &key, hash, sizeof(hash));
#else
				yescrypt_local_t local;
				yescrypt_init_local(&local);
				const char *h = (const char *)yescrypt_r(
				    shared, &local,
				    (const uint8_t *)p, strlen(p),
				    setting, &key, hash, sizeof(hash));
				yescrypt_free_local(&local);
#endif
				uint64_t end1 = time_us();
				if (end1 < start1)
					end1 = start1;
				uint64_t diff1 = end1 - start1;
				td->total += diff1;
				if (diff1 < td->min)
					td->min = diff1;
				if (diff1 > td->max)
					td->max = diff1;
				if (j < nsave && strcmp(save[j], h)) {
#pragma omp critical
					printf("Mismatch at %u, %s != %s\n",
					    j, save[j], h);
				}
			}

			count += n;
			if ((count - n) < count1 && count >= count1) {
/* Disregard our repeat of single thread's results (could be partially cached
 * by same core, but OTOH other cores not yet warmed up to full clock rate). */
				start = times(&start_tms);
				count_restart = count;
				for (t = 0; t < nt; t++) {
					thread_data_s *td = &thread_data[t].s;
					td->min = ~(uint64_t)0; td->max = 0; td->total = 0;
				}
			} else {
				n <<= 1;
			}

			end = times(&end_tms);
		} while (end - start < clk_tck);

		if (!count_restart)
			puts("Didn't reach single-thread's hash count");
		count -= count_restart;

		start_v = start_tms.tms_utime + start_tms.tms_stime +
		    start_tms.tms_cutime + start_tms.tms_cstime;
		end_v = end_tms.tms_utime + end_tms.tms_stime +
		    end_tms.tms_cutime + end_tms.tms_cstime;

		printf("%llu c/s real, %llu c/s virtual "
		    "(%llu hashes in %.2f seconds)\n",
		    count * clk_tck / (end - start),
		    count * clk_tck / (end_v - start_v),
		    count, (double)(end - start) / clk_tck);

		uint64_t min = ~(uint64_t)0, max = 0, total = 0;
		for (t = 0; t < nt; t++) {
			thread_data_s *td = &thread_data[t].s;
			total += td->total;
			if (td->min < min)
				min = td->min;
			if (td->max > max)
				max = td->max;
		}
		printf("min %.3f ms, avg %.3f ms, max %.3f ms\n",
			min / 1000.0, total / 1000.0 / count, max / 1000.0);
#endif
	}

	if (rom_filename && munmap(shared->base, rom_bytes)) {
		perror("munmap");
		return 1;
	}

	return 0;
}
