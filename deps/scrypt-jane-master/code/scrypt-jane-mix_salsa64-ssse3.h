/* x64 */
#if defined(X86_64ASM_SSSE3) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_SALSA64_INCLUDED)) && !defined(CPU_X86_FORCE_INTRINSICS)

#define SCRYPT_SALSA64_SSSE3

asm_naked_fn_proto(void, scrypt_ChunkMix_ssse3)(uint64_t *Bout/*[chunkBytes]*/, uint64_t *Bin/*[chunkBytes]*/, uint64_t *Bxor/*[chunkBytes]*/, uint32_t r)
asm_naked_fn(scrypt_ChunkMix_ssse3)
	a1(push rbp)
	a2(mov rbp, rsp)
	a2(and rsp, ~63)
	a2(sub rsp, 128)
	a2(lea rcx,[ecx*2]) /* zero extend uint32_t by using ecx, win64 can leave garbage in the top half */
	a2(shl rcx,7)
	a2(lea r9,[rcx-128])
	a2(lea rax,[rsi+r9])
	a2(lea r9,[rdx+r9])
	a2(and rdx, rdx)
	a2(movdqa xmm0,[rax+0])
	a2(movdqa xmm1,[rax+16])
	a2(movdqa xmm2,[rax+32])
	a2(movdqa xmm3,[rax+48])
	a2(movdqa xmm4,[rax+64])
	a2(movdqa xmm5,[rax+80])
	a2(movdqa xmm6,[rax+96])
	a2(movdqa xmm7,[rax+112])
	aj(jz scrypt_ChunkMix_ssse3_no_xor1)
	a2(pxor xmm0,[r9+0])
	a2(pxor xmm1,[r9+16])
	a2(pxor xmm2,[r9+32])
	a2(pxor xmm3,[r9+48])
	a2(pxor xmm4,[r9+64])
	a2(pxor xmm5,[r9+80])
	a2(pxor xmm6,[r9+96])
	a2(pxor xmm7,[r9+112])
	a1(scrypt_ChunkMix_ssse3_no_xor1:)
	a2(xor r9,r9)
	a2(xor r8,r8)
	a1(scrypt_ChunkMix_ssse3_loop:)
		a2(and rdx, rdx)
		a2(pxor xmm0,[rsi+r9+0])
		a2(pxor xmm1,[rsi+r9+16])
		a2(pxor xmm2,[rsi+r9+32])
		a2(pxor xmm3,[rsi+r9+48])
		a2(pxor xmm4,[rsi+r9+64])
		a2(pxor xmm5,[rsi+r9+80])
		a2(pxor xmm6,[rsi+r9+96])
		a2(pxor xmm7,[rsi+r9+112])
		aj(jz scrypt_ChunkMix_ssse3_no_xor2)
		a2(pxor xmm0,[rdx+r9+0])
		a2(pxor xmm1,[rdx+r9+16])
		a2(pxor xmm2,[rdx+r9+32])
		a2(pxor xmm3,[rdx+r9+48])
		a2(pxor xmm4,[rdx+r9+64])
		a2(pxor xmm5,[rdx+r9+80])
		a2(pxor xmm6,[rdx+r9+96])
		a2(pxor xmm7,[rdx+r9+112])
		a1(scrypt_ChunkMix_ssse3_no_xor2:)
		a2(movdqa [rsp+0],xmm0)
		a2(movdqa [rsp+16],xmm1)
		a2(movdqa [rsp+32],xmm2)
		a2(movdqa [rsp+48],xmm3)
		a2(movdqa [rsp+64],xmm4)
		a2(movdqa [rsp+80],xmm5)
		a2(movdqa [rsp+96],xmm6)
		a2(movdqa [rsp+112],xmm7)
		a2(mov rax,8)
		a1(scrypt_salsa64_ssse3_loop: )
			a2(movdqa xmm8, xmm0)
			a2(movdqa xmm9, xmm1)
			a2(paddq xmm8, xmm2)
			a2(paddq xmm9, xmm3)
			a3(pshufd xmm8, xmm8, 0xb1)
			a3(pshufd xmm9, xmm9, 0xb1)
			a2(pxor xmm6, xmm8)
			a2(pxor xmm7, xmm9)
			a2(movdqa xmm10, xmm0)
			a2(movdqa xmm11, xmm1)
			a2(paddq xmm10, xmm6)
			a2(paddq xmm11, xmm7)
			a2(movdqa xmm8, xmm10)
			a2(movdqa xmm9, xmm11)
			a2(psrlq xmm10, 51)
			a2(psrlq xmm11, 51)
			a2(psllq xmm8, 13)
			a2(psllq xmm9, 13)
			a2(pxor xmm4, xmm10)
			a2(pxor xmm5, xmm11)
			a2(pxor xmm4, xmm8)
			a2(pxor xmm5, xmm9)
			a2(movdqa xmm10, xmm6)
			a2(movdqa xmm11, xmm7)
			a2(paddq xmm10, xmm4)
			a2(paddq xmm11, xmm5)
			a2(movdqa xmm8, xmm10)
			a2(movdqa xmm9, xmm11)
			a2(psrlq xmm10, 25)
			a2(psrlq xmm11, 25)
			a2(psllq xmm8, 39)
			a2(psllq xmm9, 39)
			a2(pxor xmm2, xmm10)
			a2(pxor xmm3, xmm11)
			a2(pxor xmm2, xmm8)
			a2(pxor xmm3, xmm9)
			a2(movdqa xmm8, xmm4)
			a2(movdqa xmm9, xmm5)
			a2(paddq xmm8, xmm2)
			a2(paddq xmm9, xmm3)
			a3(pshufd xmm8, xmm8, 0xb1)
			a3(pshufd xmm9, xmm9, 0xb1)
			a2(pxor xmm0, xmm8)
			a2(pxor xmm1, xmm9)
			a2(movdqa xmm10, xmm2)
			a2(movdqa xmm11, xmm3)
			a2(movdqa xmm2, xmm6)
			a2(movdqa xmm3, xmm7)
			a3(palignr xmm2, xmm7, 8)
			a3(palignr xmm3, xmm6, 8)
			a2(movdqa xmm6, xmm11)
			a2(movdqa xmm7, xmm10)
			a3(palignr xmm6, xmm10, 8)
			a3(palignr xmm7, xmm11, 8)
			a2(sub rax, 2)
			a2(movdqa xmm8, xmm0)
			a2(movdqa xmm9, xmm1)
			a2(paddq xmm8, xmm2)
			a2(paddq xmm9, xmm3)
			a3(pshufd xmm8, xmm8, 0xb1)
			a3(pshufd xmm9, xmm9, 0xb1)
			a2(pxor xmm6, xmm8)
			a2(pxor xmm7, xmm9)
			a2(movdqa xmm10, xmm0)
			a2(movdqa xmm11, xmm1)
			a2(paddq xmm10, xmm6)
			a2(paddq xmm11, xmm7)
			a2(movdqa xmm8, xmm10)
			a2(movdqa xmm9, xmm11)
			a2(psrlq xmm10, 51)
			a2(psrlq xmm11, 51)
			a2(psllq xmm8, 13)
			a2(psllq xmm9, 13)
			a2(pxor xmm5, xmm10)
			a2(pxor xmm4, xmm11)
			a2(pxor xmm5, xmm8)
			a2(pxor xmm4, xmm9)
			a2(movdqa xmm10, xmm6)
			a2(movdqa xmm11, xmm7)
			a2(paddq xmm10, xmm5)
			a2(paddq xmm11, xmm4)
			a2(movdqa xmm8, xmm10)
			a2(movdqa xmm9, xmm11)
			a2(psrlq xmm10, 25)
			a2(psrlq xmm11, 25)
			a2(psllq xmm8, 39)
			a2(psllq xmm9, 39)
			a2(pxor xmm2, xmm10)
			a2(pxor xmm3, xmm11)
			a2(pxor xmm2, xmm8)
			a2(pxor xmm3, xmm9)
			a2(movdqa xmm8, xmm5)
			a2(movdqa xmm9, xmm4)
			a2(paddq xmm8, xmm2)
			a2(paddq xmm9, xmm3)
			a3(pshufd xmm8, xmm8, 0xb1)
			a3(pshufd xmm9, xmm9, 0xb1)
			a2(pxor xmm0, xmm8)
			a2(pxor xmm1, xmm9)
			a2(movdqa xmm10, xmm2)
			a2(movdqa xmm11, xmm3)
			a2(movdqa xmm2, xmm6)
			a2(movdqa xmm3, xmm7)
			a3(palignr xmm2, xmm7, 8)
			a3(palignr xmm3, xmm6, 8)
			a2(movdqa xmm6, xmm11)
			a2(movdqa xmm7, xmm10)
			a3(palignr xmm6, xmm10, 8)
			a3(palignr xmm7, xmm11, 8)
			aj(ja scrypt_salsa64_ssse3_loop)
		a2(paddq xmm0,[rsp+0])
		a2(paddq xmm1,[rsp+16])
		a2(paddq xmm2,[rsp+32])
		a2(paddq xmm3,[rsp+48])
		a2(paddq xmm4,[rsp+64])
		a2(paddq xmm5,[rsp+80])
		a2(paddq xmm6,[rsp+96])
		a2(paddq xmm7,[rsp+112])
		a2(lea rax,[r8+r9])
		a2(xor r8,rcx)
		a2(and rax,~0xff)
		a2(add r9,128)
		a2(shr rax,1)
		a2(add rax, rdi)
		a2(cmp r9,rcx)
		a2(movdqa [rax+0],xmm0)
		a2(movdqa [rax+16],xmm1)
		a2(movdqa [rax+32],xmm2)
		a2(movdqa [rax+48],xmm3)
		a2(movdqa [rax+64],xmm4)
		a2(movdqa [rax+80],xmm5)
		a2(movdqa [rax+96],xmm6)
		a2(movdqa [rax+112],xmm7)
		aj(jne scrypt_ChunkMix_ssse3_loop)
	a2(mov rsp, rbp)
	a1(pop rbp)
	a1(ret)
asm_naked_fn_end(scrypt_ChunkMix_ssse3)

#endif


/* intrinsic */
#if defined(X86_INTRINSIC_SSSE3) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_SALSA64_INCLUDED))

#define SCRYPT_SALSA64_SSSE3

static void asm_calling_convention
scrypt_ChunkMix_ssse3(uint64_t *Bout/*[chunkBytes]*/, uint64_t *Bin/*[chunkBytes]*/, uint64_t *Bxor/*[chunkBytes]*/, uint32_t r) {
	uint32_t i, blocksPerChunk = r * 2, half = 0;
	xmmi *xmmp,x0,x1,x2,x3,x4,x5,x6,x7,t0,t1,t2,t3,t4,t5,t6,t7,z0,z1,z2,z3;
	size_t rounds;

	/* 1: X = B_{2r - 1} */
	xmmp = (xmmi *)scrypt_block(Bin, blocksPerChunk - 1);
	x0 = xmmp[0];
	x1 = xmmp[1];
	x2 = xmmp[2];
	x3 = xmmp[3];
	x4 = xmmp[4];
	x5 = xmmp[5];
	x6 = xmmp[6];
	x7 = xmmp[7];

	if (Bxor) {
		xmmp = (xmmi *)scrypt_block(Bxor, blocksPerChunk - 1);
		x0 = _mm_xor_si128(x0, xmmp[0]);
		x1 = _mm_xor_si128(x1, xmmp[1]);
		x2 = _mm_xor_si128(x2, xmmp[2]);
		x3 = _mm_xor_si128(x3, xmmp[3]);
		x4 = _mm_xor_si128(x4, xmmp[4]);
		x5 = _mm_xor_si128(x5, xmmp[5]);
		x6 = _mm_xor_si128(x6, xmmp[6]);
		x7 = _mm_xor_si128(x7, xmmp[7]);
	}

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < blocksPerChunk; i++, half ^= r) {
		/* 3: X = H(X ^ B_i) */
		xmmp = (xmmi *)scrypt_block(Bin, i);
		x0 = _mm_xor_si128(x0, xmmp[0]);
		x1 = _mm_xor_si128(x1, xmmp[1]);
		x2 = _mm_xor_si128(x2, xmmp[2]);
		x3 = _mm_xor_si128(x3, xmmp[3]);
		x4 = _mm_xor_si128(x4, xmmp[4]);
		x5 = _mm_xor_si128(x5, xmmp[5]);
		x6 = _mm_xor_si128(x6, xmmp[6]);
		x7 = _mm_xor_si128(x7, xmmp[7]);

		if (Bxor) {
			xmmp = (xmmi *)scrypt_block(Bxor, i);
			x0 = _mm_xor_si128(x0, xmmp[0]);
			x1 = _mm_xor_si128(x1, xmmp[1]);
			x2 = _mm_xor_si128(x2, xmmp[2]);
			x3 = _mm_xor_si128(x3, xmmp[3]);
			x4 = _mm_xor_si128(x4, xmmp[4]);
			x5 = _mm_xor_si128(x5, xmmp[5]);
			x6 = _mm_xor_si128(x6, xmmp[6]);
			x7 = _mm_xor_si128(x7, xmmp[7]);
		}

		t0 = x0;
		t1 = x1;
		t2 = x2;
		t3 = x3;
		t4 = x4;
		t5 = x5;
		t6 = x6;
		t7 = x7;

		for (rounds = 8; rounds; rounds -= 2) {
			z0 = _mm_add_epi64(x0, x2);
			z1 = _mm_add_epi64(x1, x3);
			z0 = _mm_shuffle_epi32(z0, _MM_SHUFFLE(2,3,0,1));
			z1 = _mm_shuffle_epi32(z1, _MM_SHUFFLE(2,3,0,1));
			x6 = _mm_xor_si128(x6, z0);
			x7 = _mm_xor_si128(x7, z1);

			z0 = _mm_add_epi64(x6, x0);
			z1 = _mm_add_epi64(x7, x1);
			z2 = _mm_srli_epi64(z0, 64-13);
			z3 = _mm_srli_epi64(z1, 64-13);
			z0 = _mm_slli_epi64(z0, 13);
			z1 = _mm_slli_epi64(z1, 13);
			x4 = _mm_xor_si128(x4, z2);
			x5 = _mm_xor_si128(x5, z3);
			x4 = _mm_xor_si128(x4, z0);
			x5 = _mm_xor_si128(x5, z1);

			z0 = _mm_add_epi64(x4, x6);
			z1 = _mm_add_epi64(x5, x7);
			z2 = _mm_srli_epi64(z0, 64-39);
			z3 = _mm_srli_epi64(z1, 64-39);
			z0 = _mm_slli_epi64(z0, 39);
			z1 = _mm_slli_epi64(z1, 39);
			x2 = _mm_xor_si128(x2, z2);
			x3 = _mm_xor_si128(x3, z3);
			x2 = _mm_xor_si128(x2, z0);
			x3 = _mm_xor_si128(x3, z1);

			z0 = _mm_add_epi64(x2, x4);
			z1 = _mm_add_epi64(x3, x5);
			z0 = _mm_shuffle_epi32(z0, _MM_SHUFFLE(2,3,0,1));
			z1 = _mm_shuffle_epi32(z1, _MM_SHUFFLE(2,3,0,1));
			x0 = _mm_xor_si128(x0, z0);
			x1 = _mm_xor_si128(x1, z1);

			z0 = x2;
			z1 = x3;
			x2 = _mm_alignr_epi8(x6, x7, 8);
			x3 = _mm_alignr_epi8(x7, x6, 8);
			x6 = _mm_alignr_epi8(z1, z0, 8);
			x7 = _mm_alignr_epi8(z0, z1, 8);

			z0 = _mm_add_epi64(x0, x2);
			z1 = _mm_add_epi64(x1, x3);
			z0 = _mm_shuffle_epi32(z0, _MM_SHUFFLE(2,3,0,1));
			z1 = _mm_shuffle_epi32(z1, _MM_SHUFFLE(2,3,0,1));
			x6 = _mm_xor_si128(x6, z0);
			x7 = _mm_xor_si128(x7, z1);

			z0 = _mm_add_epi64(x6, x0);
			z1 = _mm_add_epi64(x7, x1);
			z2 = _mm_srli_epi64(z0, 64-13);
			z3 = _mm_srli_epi64(z1, 64-13);
			z0 = _mm_slli_epi64(z0, 13);
			z1 = _mm_slli_epi64(z1, 13);
			x5 = _mm_xor_si128(x5, z2);
			x4 = _mm_xor_si128(x4, z3);
			x5 = _mm_xor_si128(x5, z0);
			x4 = _mm_xor_si128(x4, z1);

			z0 = _mm_add_epi64(x5, x6);
			z1 = _mm_add_epi64(x4, x7);
			z2 = _mm_srli_epi64(z0, 64-39);
			z3 = _mm_srli_epi64(z1, 64-39);
			z0 = _mm_slli_epi64(z0, 39);
			z1 = _mm_slli_epi64(z1, 39);
			x2 = _mm_xor_si128(x2, z2);
			x3 = _mm_xor_si128(x3, z3);
			x2 = _mm_xor_si128(x2, z0);
			x3 = _mm_xor_si128(x3, z1);

			z0 = _mm_add_epi64(x2, x5);
			z1 = _mm_add_epi64(x3, x4);
			z0 = _mm_shuffle_epi32(z0, _MM_SHUFFLE(2,3,0,1));
			z1 = _mm_shuffle_epi32(z1, _MM_SHUFFLE(2,3,0,1));
			x0 = _mm_xor_si128(x0, z0);
			x1 = _mm_xor_si128(x1, z1);

			z0 = x2;
			z1 = x3;
			x2 = _mm_alignr_epi8(x6, x7, 8);
			x3 = _mm_alignr_epi8(x7, x6, 8);
			x6 = _mm_alignr_epi8(z1, z0, 8);
			x7 = _mm_alignr_epi8(z0, z1, 8);
		}

		x0 = _mm_add_epi64(x0, t0);
		x1 = _mm_add_epi64(x1, t1);
		x2 = _mm_add_epi64(x2, t2);
		x3 = _mm_add_epi64(x3, t3);
		x4 = _mm_add_epi64(x4, t4);
		x5 = _mm_add_epi64(x5, t5);
		x6 = _mm_add_epi64(x6, t6);
		x7 = _mm_add_epi64(x7, t7);

		/* 4: Y_i = X */
		/* 6: B'[0..r-1] = Y_even */
		/* 6: B'[r..2r-1] = Y_odd */
		xmmp = (xmmi *)scrypt_block(Bout, (i / 2) + half);
		xmmp[0] = x0;
		xmmp[1] = x1;
		xmmp[2] = x2;
		xmmp[3] = x3;
		xmmp[4] = x4;
		xmmp[5] = x5;
		xmmp[6] = x6;
		xmmp[7] = x7;
	}
}

#endif

#if defined(SCRYPT_SALSA64_SSSE3)
	/* uses salsa64_core_tangle_sse2 */
	
	#undef SCRYPT_MIX
	#define SCRYPT_MIX "Salsa64/8-SSSE3"
	#undef SCRYPT_SALSA64_INCLUDED
	#define SCRYPT_SALSA64_INCLUDED
#endif
