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

#define ROM_SHM_KEY			0x7965730a
#define ROM_LOCAL_PARAM			"change this before use"

/* Maximum parallelism factor during ROM initialization */
#define YESCRYPT_PROM_SHM		112
#define YESCRYPT_PROM_FILE		4

//#define USE_HUGEPAGE
//#define DUMP_SHARED

#include <errno.h>
#include <stdio.h>
#include <stdlib.h> /* for atoi() */
#include <string.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "yescrypt.h"

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
	int shmid;
	yescrypt_shared_t shared;
	yescrypt_binary_t *digest;
	const char *rom_filename = NULL;
	int rom_fd;

	if (argc > 1)
		rom_bytes = atoi(argv[1]) * (1024ULL*1024*1024);
	if (argc > 2)
		ram_bytes = atoi(argv[2]) * (1024ULL*1024);
	if (argc > 3)
		rom_filename = argv[3];

	if (!rom_bytes) {
		puts("Wrong ROM size requested");
		return 1;
	}

	min_r = 9;
	if (rom_filename)
		min_r = 8 * 256;

	NROM_log2 = 0;
	while (((rom_bytes >> NROM_log2) & 0xff) == 0)
		NROM_log2++;
	r = rom_bytes >> (7 + NROM_log2);
	while (r < min_r && NROM_log2 > 0) {
		r <<= 1;
		NROM_log2--;
	}
	rom_bytes = (uint64_t)r << (7 + NROM_log2);

	N_log2 = 3;
	while (((uint64_t)r << (7 + N_log2)) < ram_bytes)
		N_log2++;
	ram_bytes = (uint64_t)r << (7 + N_log2);

	printf("r=%u N=2^%u NROM=2^%u\n", r,
	    (unsigned int)N_log2, (unsigned int)NROM_log2);

	printf("Will use %.2f KiB ROM\n", rom_bytes / 1024.0);
	printf("         %.2f KiB RAM\n", ram_bytes / 1024.0);

	shared.aligned_size = rom_bytes;

	if (rom_filename) {
		rom_fd = open(rom_filename, O_CREAT|O_RDWR|O_EXCL,
		    S_IRUSR|S_IRGRP|S_IWUSR);
		if (rom_fd < 0) {
			perror("open");
			return 1;
		}
		if (ftruncate(rom_fd, rom_bytes)) {
			perror("ftruncate");
			close(rom_fd);
			unlink(rom_filename);
			return 1;
		}

		int flags =
#ifdef MAP_NOCORE
		    MAP_NOCORE |
#endif
#if defined(MAP_HUGETLB) && defined(USE_HUGEPAGE)
		    MAP_HUGETLB |
#endif
		    MAP_SHARED;
		void *p = mmap(NULL, rom_bytes, PROT_READ | PROT_WRITE,
		    flags, rom_fd, 0);
#if defined(MAP_HUGETLB) && defined(USE_HUGEPAGE)
		if (p == MAP_FAILED)
			p = mmap(NULL, rom_bytes, PROT_READ | PROT_WRITE,
			    flags & ~MAP_HUGETLB, rom_fd, 0);
#endif
		if (p == MAP_FAILED) {
			perror("mmap");
			close(rom_fd);
			unlink(rom_filename);
			return 1;
		}
		close(rom_fd);
		shared.base = shared.aligned = p;
	} else {
		shmid = shmget(ROM_SHM_KEY, shared.aligned_size,
#ifdef SHM_HUGETLB
		    SHM_HUGETLB |
#endif
		    IPC_CREAT|IPC_EXCL | S_IRUSR|S_IRGRP|S_IWUSR);
		if (shmid == -1) {
#ifdef SHM_HUGETLB
			perror("shmget");
			puts("Retrying without SHM_HUGETLB");
			shmid = shmget(ROM_SHM_KEY, shared.aligned_size,
			    IPC_CREAT|IPC_EXCL | S_IRUSR|S_IRGRP|S_IWUSR);
#endif
			if (shmid == -1) {
				perror("shmget");
				return 1;
			}
		}

		shared.base = shared.aligned = shmat(shmid, NULL, 0);
		if (shared.base == (void *)-1) {
			int save_errno = errno;
			shmctl(shmid, IPC_RMID, NULL);
			errno = save_errno;
			perror("shmat");
			return 1;
		}
	}

	printf("Initializing ROM ...");
	fflush(stdout);
	yescrypt_params_t rom_params = {
	    .flags = YESCRYPT_DEFAULTS | YESCRYPT_SHARED_PREALLOCATED,
	    .NROM = (uint64_t)1 << NROM_log2,
	    .r = r,
	    .p = rom_filename ? YESCRYPT_PROM_FILE : YESCRYPT_PROM_SHM };
	if (yescrypt_init_shared(&shared,
	    (uint8_t *)ROM_LOCAL_PARAM, strlen(ROM_LOCAL_PARAM),
	    &rom_params)) {
		puts(" FAILED");
		if (rom_filename)
			unlink(rom_filename);
		return 1;
	}
#ifdef DUMP_SHARED
	fwrite(shared.aligned, shared.aligned_size, 1, stderr);
#endif
	digest = yescrypt_digest_shared(&shared);
	printf(" DONE (%02x%02x%02x%02x)\n",
	    digest->uc[0], digest->uc[1], digest->uc[2], digest->uc[3]);

	{
		yescrypt_local_t local;
		const uint8_t *setting;
		uint8_t hash[128];

		if (yescrypt_init_local(&local)) {
			puts("yescrypt_init_local() FAILED");
			return 1;
		}

		yescrypt_params_t params = rom_params;
		params.flags = YESCRYPT_FLAGS;
		params.N = (uint64_t)1 << N_log2;
		params.p = 1;
		setting = yescrypt_encode_params(&params,
		    (const uint8_t *)"WZaPV7LSUEKMo34.", 16);

		printf("'%s'\n", (char *)yescrypt_r(&shared, &local,
		    (const uint8_t *)"pleaseletmein", 13, setting, NULL,
		    hash, sizeof(hash)));
	}

	if (rom_filename && munmap(shared.base, rom_bytes)) {
		perror("munmap");
		return 1;
	}

	return 0;
}
