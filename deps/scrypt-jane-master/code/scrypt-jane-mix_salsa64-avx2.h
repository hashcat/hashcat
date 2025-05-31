/* x64 */
#if defined(X86_64ASM_AVX2) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_SALSA64_INCLUDED)) && !defined(CPU_X86_FORCE_INTRINSICS)

#define SCRYPT_SALSA64_AVX2

asm_naked_fn_proto(void, scrypt_ChunkMix_avx2)(uint64_t *Bout/*[chunkBytes]*/, uint64_t *Bin/*[chunkBytes]*/, uint64_t *Bxor/*[chunkBytes]*/, uint32_t r)
asm_naked_fn(scrypt_ChunkMix_avx2)
	a2(lea rcx,[ecx*2]) /* zero extend uint32_t by using ecx, win64 can leave garbage in the top half */
	a2(shl rcx,7)
	a2(lea r9,[rcx-128])
	a2(lea rax,[rsi+r9])
	a2(lea r9,[rdx+r9])
	a2(and rdx, rdx)
	a2(vmovdqa ymm0,[rax+0])
	a2(vmovdqa ymm1,[rax+32])
	a2(vmovdqa ymm2,[rax+64])
	a2(vmovdqa ymm3,[rax+96])
	aj(jz scrypt_ChunkMix_avx2_no_xor1)
	a3(vpxor ymm0,ymm0,[r9+0])
	a3(vpxor ymm1,ymm1,[r9+32])
	a3(vpxor ymm2,ymm2,[r9+64])
	a3(vpxor ymm3,ymm3,[r9+96])
	a1(scrypt_ChunkMix_avx2_no_xor1:)
	a2(xor r9,r9)
	a2(xor r8,r8)
	a1(scrypt_ChunkMix_avx2_loop:)
		a2(and rdx, rdx)
		a3(vpxor ymm0,ymm0,[rsi+r9+0])
		a3(vpxor ymm1,ymm1,[rsi+r9+32])
		a3(vpxor ymm2,ymm2,[rsi+r9+64])
		a3(vpxor ymm3,ymm3,[rsi+r9+96])
		aj(jz scrypt_ChunkMix_avx2_no_xor2)
		a3(vpxor ymm0,ymm0,[rdx+r9+0])
		a3(vpxor ymm1,ymm1,[rdx+r9+32])
		a3(vpxor ymm2,ymm2,[rdx+r9+64])
		a3(vpxor ymm3,ymm3,[rdx+r9+96])
		a1(scrypt_ChunkMix_avx2_no_xor2:)
		a2(vmovdqa ymm6,ymm0)
		a2(vmovdqa ymm7,ymm1)
		a2(vmovdqa ymm8,ymm2)
		a2(vmovdqa ymm9,ymm3)
		a2(mov rax,4)
		a1(scrypt_salsa64_avx2_loop: )
			a3(vpaddq ymm4, ymm1, ymm0)
			a3(vpshufd ymm4, ymm4, 0xb1)
			a3(vpxor ymm3, ymm3, ymm4)
			a3(vpaddq ymm4, ymm0, ymm3)
			a3(vpsrlq ymm5, ymm4, 51)
			a3(vpxor ymm2, ymm2, ymm5)
			a3(vpsllq ymm4, ymm4, 13)
			a3(vpxor ymm2, ymm2, ymm4)
			a3(vpaddq ymm4, ymm3, ymm2)
			a3(vpsrlq ymm5, ymm4, 25)
			a3(vpxor ymm1, ymm1, ymm5)
			a3(vpsllq ymm4, ymm4, 39)
			a3(vpxor ymm1, ymm1, ymm4)
			a3(vpaddq ymm4, ymm2, ymm1)
			a3(vpshufd ymm4, ymm4, 0xb1)
			a3(vpermq ymm1, ymm1, 0x39)
			a3(vpermq ymm10, ymm2, 0x4e)
			a3(vpxor ymm0, ymm0, ymm4)
			a3(vpermq ymm3, ymm3, 0x93)
			a3(vpaddq ymm4, ymm3, ymm0)
			a3(vpshufd ymm4, ymm4, 0xb1)
			a3(vpxor ymm1, ymm1, ymm4)
			a3(vpaddq ymm4, ymm0, ymm1)
			a3(vpsrlq ymm5, ymm4, 51)
			a3(vpxor ymm10, ymm10, ymm5)
			a3(vpsllq ymm4, ymm4, 13)
			a3(vpxor ymm10, ymm10, ymm4)
			a3(vpaddq ymm4, ymm1, ymm10)
			a3(vpsrlq ymm5, ymm4, 25)
			a3(vpxor ymm3, ymm3, ymm5)
			a3(vpsllq ymm4, ymm4, 39)
			a3(vpermq ymm1, ymm1, 0x93)
			a3(vpxor ymm3, ymm3, ymm4)
			a3(vpermq ymm2, ymm10, 0x4e)
			a3(vpaddq ymm4, ymm10, ymm3)
			a3(vpshufd ymm4, ymm4, 0xb1)
			a3(vpermq ymm3, ymm3, 0x39)
			a3(vpxor ymm0, ymm0, ymm4)
			a1(dec rax)
			aj(jnz scrypt_salsa64_avx2_loop)
		a3(vpaddq ymm0,ymm0,ymm6)
		a3(vpaddq ymm1,ymm1,ymm7)
		a3(vpaddq ymm2,ymm2,ymm8)
		a3(vpaddq ymm3,ymm3,ymm9)
		a2(lea rax,[r8+r9])
		a2(xor r8,rcx)
		a2(and rax,~0xff)
		a2(add r9,128)
		a2(shr rax,1)
		a2(add rax, rdi)
		a2(cmp r9,rcx)
		a2(vmovdqa [rax+0],ymm0)
		a2(vmovdqa [rax+32],ymm1)
		a2(vmovdqa [rax+64],ymm2)
		a2(vmovdqa [rax+96],ymm3)
		aj(jne scrypt_ChunkMix_avx2_loop)
	a1(vzeroupper)
	a1(ret)
asm_naked_fn_end(scrypt_ChunkMix_avx2)

#endif


/* intrinsic */
#if defined(X86_INTRINSIC_AVX2) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_SALSA64_INCLUDED))

#define SCRYPT_SALSA64_AVX2

static void asm_calling_convention
scrypt_ChunkMix_avx2(uint64_t *Bout/*[chunkBytes]*/, uint64_t *Bin/*[chunkBytes]*/, uint64_t *Bxor/*[chunkBytes]*/, uint32_t r) {
	uint32_t i, blocksPerChunk = r * 2, half = 0;
	ymmi *ymmp,y0,y1,y2,y3,t0,t1,t2,t3,z0,z1;
	size_t rounds;

	/* 1: X = B_{2r - 1} */
	ymmp = (ymmi *)scrypt_block(Bin, blocksPerChunk - 1);
	y0 = ymmp[0];
	y1 = ymmp[1];
	y2 = ymmp[2];
	y3 = ymmp[3];

	if (Bxor) {
		ymmp = (ymmi *)scrypt_block(Bxor, blocksPerChunk - 1);
		y0 = _mm256_xor_si256(y0, ymmp[0]);
		y1 = _mm256_xor_si256(y1, ymmp[1]);
		y2 = _mm256_xor_si256(y2, ymmp[2]);
		y3 = _mm256_xor_si256(y3, ymmp[3]);
	}

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < blocksPerChunk; i++, half ^= r) {
		/* 3: X = H(X ^ B_i) */
		ymmp = (ymmi *)scrypt_block(Bin, i);
		y0 = _mm256_xor_si256(y0, ymmp[0]);
		y1 = _mm256_xor_si256(y1, ymmp[1]);
		y2 = _mm256_xor_si256(y2, ymmp[2]);
		y3 = _mm256_xor_si256(y3, ymmp[3]);

		if (Bxor) {
			ymmp = (ymmi *)scrypt_block(Bxor, i);
			y0 = _mm256_xor_si256(y0, ymmp[0]);
			y1 = _mm256_xor_si256(y1, ymmp[1]);
			y2 = _mm256_xor_si256(y2, ymmp[2]);
			y3 = _mm256_xor_si256(y3, ymmp[3]);
		}

		t0 = y0;
		t1 = y1;
		t2 = y2;
		t3 = y3;

		for (rounds = 8; rounds; rounds -= 2) {
			z0 = _mm256_add_epi64(y0, y1);
			z0 = _mm256_shuffle_epi32(z0, _MM_SHUFFLE(2,3,0,1));
			y3 = _mm256_xor_si256(y3, z0);
			z0 = _mm256_add_epi64(y3, y0);
			z1 = _mm256_srli_epi64(z0, 64-13);
			y2 = _mm256_xor_si256(y2, z1);
			z0 = _mm256_slli_epi64(z0, 13);
			y2 = _mm256_xor_si256(y2, z0);
			z0 = _mm256_add_epi64(y2, y3);
			z1 = _mm256_srli_epi64(z0, 64-39);
			y1 = _mm256_xor_si256(y1, z1);
			z0 = _mm256_slli_epi64(z0, 39);
			y1 = _mm256_xor_si256(y1, z0);
			y1 = _mm256_permute4x64_epi64(y1, _MM_SHUFFLE(0,3,2,1));
			y2 = _mm256_permute4x64_epi64(y2, _MM_SHUFFLE(1,0,3,2));
			y3 = _mm256_permute4x64_epi64(y3, _MM_SHUFFLE(2,1,0,3));
			z0 = _mm256_add_epi64(y1, y2);
			z0 = _mm256_shuffle_epi32(z0, _MM_SHUFFLE(2,3,0,1));
			y0 = _mm256_xor_si256(y0, z0);
			z0 = _mm256_add_epi64(y0, y3);
			z0 = _mm256_shuffle_epi32(z0, _MM_SHUFFLE(2,3,0,1));
			y1 = _mm256_xor_si256(y1, z0);
			z0 = _mm256_add_epi64(y1, y0);
			z1 = _mm256_srli_epi64(z0, 64-13);
			y2 = _mm256_xor_si256(y2, z1);
			z0 = _mm256_slli_epi64(z0, 13);
			y2 = _mm256_xor_si256(y2, z0);
			z0 = _mm256_add_epi64(y2, y1);
			z1 = _mm256_srli_epi64(z0, 64-39);
			y3 = _mm256_xor_si256(y3, z1);
			z0 = _mm256_slli_epi64(z0, 39);
			y3 = _mm256_xor_si256(y3, z0);
			z0 = _mm256_add_epi64(y3, y2);
			z0 = _mm256_shuffle_epi32(z0, _MM_SHUFFLE(2,3,0,1));
			y0 = _mm256_xor_si256(y0, z0);
			y1 = _mm256_permute4x64_epi64(y1, _MM_SHUFFLE(2,1,0,3));
			y2 = _mm256_permute4x64_epi64(y2, _MM_SHUFFLE(1,0,3,2));
			y3 = _mm256_permute4x64_epi64(y3, _MM_SHUFFLE(0,3,2,1));
		}

		y0 = _mm256_add_epi64(y0, t0);
		y1 = _mm256_add_epi64(y1, t1);
		y2 = _mm256_add_epi64(y2, t2);
		y3 = _mm256_add_epi64(y3, t3);

		/* 4: Y_i = X */
		/* 6: B'[0..r-1] = Y_even */
		/* 6: B'[r..2r-1] = Y_odd */
		ymmp = (ymmi *)scrypt_block(Bout, (i / 2) + half);
		ymmp[0] = y0;
		ymmp[1] = y1;
		ymmp[2] = y2;
		ymmp[3] = y3;
	}
}

#endif

#if defined(SCRYPT_SALSA64_AVX2)
	/* uses salsa64_core_tangle_sse2 */
	
	#undef SCRYPT_MIX
	#define SCRYPT_MIX "Salsa64/8-AVX2"
	#undef SCRYPT_SALSA64_INCLUDED
	#define SCRYPT_SALSA64_INCLUDED
#endif
