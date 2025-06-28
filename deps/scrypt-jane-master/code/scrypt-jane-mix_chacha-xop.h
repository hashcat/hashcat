/* x86 */
#if defined(X86ASM_XOP) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_CHACHA_INCLUDED)) && !defined(CPU_X86_FORCE_INTRINSICS)

#define SCRYPT_CHACHA_XOP

asm_naked_fn_proto(void, scrypt_ChunkMix_xop)(uint32_t *Bout/*[chunkBytes]*/, uint32_t *Bin/*[chunkBytes]*/, uint32_t *Bxor/*[chunkBytes]*/, uint32_t r)
asm_naked_fn(scrypt_ChunkMix_xop)
	a1(push ebx)
	a1(push edi)
	a1(push esi)
	a1(push ebp)
	a2(mov ebp,esp)
	a2(mov edi,[ebp+20])
	a2(mov esi,[ebp+24])
	a2(mov eax,[ebp+28])
	a2(mov ebx,[ebp+32])
	a2(sub esp,64)
	a2(and esp,~63)
	a2(lea edx,[ebx*2])
	a2(shl edx,6)
	a2(lea ecx,[edx-64])
	a2(and eax, eax)
	a2(vmovdqa xmm0,[ecx+esi+0])
	a2(vmovdqa xmm1,[ecx+esi+16])
	a2(vmovdqa xmm2,[ecx+esi+32])
	a2(vmovdqa xmm3,[ecx+esi+48])
	aj(jz scrypt_ChunkMix_xop_no_xor1)
	a3(vpxor xmm0,xmm0,[ecx+eax+0])
	a3(vpxor xmm1,xmm1,[ecx+eax+16])
	a3(vpxor xmm2,xmm2,[ecx+eax+32])
	a3(vpxor xmm3,xmm3,[ecx+eax+48])
	a1(scrypt_ChunkMix_xop_no_xor1:)
	a2(xor ecx,ecx)
	a2(xor ebx,ebx)
	a1(scrypt_ChunkMix_xop_loop:)
		a2(and eax, eax)
		a3(vpxor xmm0,xmm0,[esi+ecx+0])
		a3(vpxor xmm1,xmm1,[esi+ecx+16])
		a3(vpxor xmm2,xmm2,[esi+ecx+32])
		a3(vpxor xmm3,xmm3,[esi+ecx+48])
		aj(jz scrypt_ChunkMix_xop_no_xor2)
		a3(vpxor xmm0,xmm0,[eax+ecx+0])
		a3(vpxor xmm1,xmm1,[eax+ecx+16])
		a3(vpxor xmm2,xmm2,[eax+ecx+32])
		a3(vpxor xmm3,xmm3,[eax+ecx+48])
		a1(scrypt_ChunkMix_xop_no_xor2:)
		a2(vmovdqa xmm4,xmm0)
		a2(vmovdqa xmm5,xmm1)
		a2(vmovdqa xmm6,xmm2)
		a2(vmovdqa xmm7,xmm3)
		a2(mov eax,8)
		a1(scrypt_chacha_xop_loop: )
			a3(vpaddd xmm0,xmm0,xmm1)
			a3(vpxor  xmm3,xmm3,xmm0)
			a3(vprotd xmm3,xmm3,16)
			a3(vpaddd xmm2,xmm2,xmm3)
			a3(vpxor  xmm1,xmm1,xmm2)
			a3(vprotd xmm1,xmm1,12)
			a3(vpaddd xmm0,xmm0,xmm1)
			a3(vpxor  xmm3,xmm3,xmm0)
			a3(vprotd xmm3,xmm3,8)
			a3(vpaddd xmm2,xmm2,xmm3)
			a3(vpshufd xmm0,xmm0,0x93)
			a3(vpxor xmm1,xmm1,xmm2)
			a3(vprotd xmm1,xmm1,7)
			a3(vpshufd xmm3,xmm3,0x4e)
			a3(vpaddd xmm0,xmm0,xmm1)
			a3(vpshufd xmm2,xmm2,0x39)
			a3(vpxor  xmm3,xmm3,xmm0)
			a3(vprotd xmm3,xmm3,16)
			a3(vpaddd xmm2,xmm2,xmm3)
			a3(vpxor  xmm1,xmm1,xmm2)
			a3(vprotd xmm1,xmm1,12)
			a3(vpaddd xmm0,xmm0,xmm1)
			a3(vpxor  xmm3,xmm3,xmm0)
			a3(vprotd xmm3,xmm3,8)
			a3(vpaddd xmm2,xmm2,xmm3)
			a3(vpxor  xmm1,xmm1,xmm2)
			a3(vpshufd xmm0,xmm0,0x39)
			a3(vprotd xmm1,xmm1,7)
			a3(pshufd xmm3,xmm3,0x4e)
			a3(pshufd xmm2,xmm2,0x93)
			a2(sub eax,2)
			aj(ja scrypt_chacha_xop_loop)
		a3(vpaddd xmm0,xmm0,xmm4)
		a3(vpaddd xmm1,xmm1,xmm5)
		a3(vpaddd xmm2,xmm2,xmm6)
		a3(vpaddd xmm3,xmm3,xmm7)
		a2(lea eax,[ebx+ecx])
		a2(xor ebx,edx)
		a2(and eax,~0x7f)
		a2(add ecx,64)
		a2(shr eax,1)
		a2(add eax, edi)
		a2(cmp ecx,edx)
		a2(vmovdqa [eax+0],xmm0)
		a2(vmovdqa [eax+16],xmm1)
		a2(vmovdqa [eax+32],xmm2)
		a2(vmovdqa [eax+48],xmm3)
		a2(mov eax,[ebp+28])
		aj(jne scrypt_ChunkMix_xop_loop)
	a2(mov esp,ebp)
	a1(pop ebp)
	a1(pop esi)
	a1(pop edi)
	a1(pop ebx)
	aret(16)
asm_naked_fn_end(scrypt_ChunkMix_xop)

#endif



/* x64 */
#if defined(X86_64ASM_XOP) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_CHACHA_INCLUDED)) && !defined(CPU_X86_FORCE_INTRINSICS)

#define SCRYPT_CHACHA_XOP

asm_naked_fn_proto(void, scrypt_ChunkMix_xop)(uint32_t *Bout/*[chunkBytes]*/, uint32_t *Bin/*[chunkBytes]*/, uint32_t *Bxor/*[chunkBytes]*/, uint32_t r)
asm_naked_fn(scrypt_ChunkMix_xop)
	a2(lea rcx,[ecx*2]) /* zero extend uint32_t by using ecx, win64 can leave garbage in the top half */
	a2(shl rcx,6)
	a2(lea r9,[rcx-64])
	a2(lea rax,[rsi+r9])
	a2(lea r9,[rdx+r9])
	a2(and rdx, rdx)
	a2(vmovdqa xmm0,[rax+0])
	a2(vmovdqa xmm1,[rax+16])
	a2(vmovdqa xmm2,[rax+32])
	a2(vmovdqa xmm3,[rax+48])
	aj(jz scrypt_ChunkMix_xop_no_xor1)
	a3(vpxor xmm0,xmm0,[r9+0])
	a3(vpxor xmm1,xmm1,[r9+16])
	a3(vpxor xmm2,xmm2,[r9+32])
	a3(vpxor xmm3,xmm3,[r9+48])
	a1(scrypt_ChunkMix_xop_no_xor1:)
	a2(xor r8,r8)
	a2(xor r9,r9)
	a1(scrypt_ChunkMix_xop_loop:)
		a2(and rdx, rdx)
		a3(vpxor xmm0,xmm0,[rsi+r9+0])
		a3(vpxor xmm1,xmm1,[rsi+r9+16])
		a3(vpxor xmm2,xmm2,[rsi+r9+32])
		a3(vpxor xmm3,xmm3,[rsi+r9+48])
		aj(jz scrypt_ChunkMix_xop_no_xor2)
		a3(vpxor xmm0,xmm0,[rdx+r9+0])
		a3(vpxor xmm1,xmm1,[rdx+r9+16])
		a3(vpxor xmm2,xmm2,[rdx+r9+32])
		a3(vpxor xmm3,xmm3,[rdx+r9+48])
		a1(scrypt_ChunkMix_xop_no_xor2:)
		a2(vmovdqa xmm4,xmm0)
		a2(vmovdqa xmm5,xmm1)
		a2(vmovdqa xmm6,xmm2)
		a2(vmovdqa xmm7,xmm3)
		a2(mov rax,8)
		a1(scrypt_chacha_xop_loop: )
			a3(vpaddd xmm0,xmm0,xmm1)
			a3(vpxor  xmm3,xmm3,xmm0)
			a3(vprotd xmm3,xmm3,16)
			a3(vpaddd xmm2,xmm2,xmm3)
			a3(vpxor  xmm1,xmm1,xmm2)
			a3(vprotd xmm1,xmm1,12)
			a3(vpaddd xmm0,xmm0,xmm1)
			a3(vpxor  xmm3,xmm3,xmm0)
			a3(vprotd xmm3,xmm3,8)
			a3(vpaddd xmm2,xmm2,xmm3)
			a3(vpshufd xmm0,xmm0,0x93)
			a3(vpxor xmm1,xmm1,xmm2)
			a3(vprotd xmm1,xmm1,7)
			a3(vpshufd xmm3,xmm3,0x4e)
			a3(vpaddd xmm0,xmm0,xmm1)
			a3(vpshufd xmm2,xmm2,0x39)
			a3(vpxor  xmm3,xmm3,xmm0)
			a3(vprotd xmm3,xmm3,16)
			a3(vpaddd xmm2,xmm2,xmm3)
			a3(vpxor  xmm1,xmm1,xmm2)
			a3(vprotd xmm1,xmm1,12)
			a3(vpaddd xmm0,xmm0,xmm1)
			a3(vpxor  xmm3,xmm3,xmm0)
			a3(vprotd xmm3,xmm3,8)
			a3(vpaddd xmm2,xmm2,xmm3)
			a3(vpxor  xmm1,xmm1,xmm2)
			a3(vpshufd xmm0,xmm0,0x39)
			a3(vprotd xmm1,xmm1,7)
			a3(pshufd xmm3,xmm3,0x4e)
			a3(pshufd xmm2,xmm2,0x93)
			a2(sub rax,2)
			aj(ja scrypt_chacha_xop_loop)
		a3(vpaddd xmm0,xmm0,xmm4)
		a3(vpaddd xmm1,xmm1,xmm5)
		a3(vpaddd xmm2,xmm2,xmm6)
		a3(vpaddd xmm3,xmm3,xmm7)
		a2(lea rax,[r8+r9])
		a2(xor r8,rcx)
		a2(and rax,~0x7f)
		a2(add r9,64)
		a2(shr rax,1)
		a2(add rax, rdi)
		a2(cmp r9,rcx)
		a2(vmovdqa [rax+0],xmm0)
		a2(vmovdqa [rax+16],xmm1)
		a2(vmovdqa [rax+32],xmm2)
		a2(vmovdqa [rax+48],xmm3)
		aj(jne scrypt_ChunkMix_xop_loop)
	a1(ret)
asm_naked_fn_end(scrypt_ChunkMix_xop)

#endif


/* intrinsic */
#if defined(X86_INTRINSIC_XOP) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_CHACHA_INCLUDED))

#define SCRYPT_CHACHA_XOP

static void asm_calling_convention NOINLINE
scrypt_ChunkMix_xop(uint32_t *Bout/*[chunkBytes]*/, uint32_t *Bin/*[chunkBytes]*/, uint32_t *Bxor/*[chunkBytes]*/, uint32_t r) {
	uint32_t i, blocksPerChunk = r * 2, half = 0;
	xmmi *xmmp,x0,x1,x2,x3,x6,t0,t1,t2,t3;
	size_t rounds;

	/* 1: X = B_{2r - 1} */
	xmmp = (xmmi *)scrypt_block(Bin, blocksPerChunk - 1);
	x0 = xmmp[0];
	x1 = xmmp[1];
	x2 = xmmp[2];
	x3 = xmmp[3];

	if (Bxor) {
		xmmp = (xmmi *)scrypt_block(Bxor, blocksPerChunk - 1);
		x0 = _mm_xor_si128(x0, xmmp[0]);
		x1 = _mm_xor_si128(x1, xmmp[1]);
		x2 = _mm_xor_si128(x2, xmmp[2]);
		x3 = _mm_xor_si128(x3, xmmp[3]);
	}

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < blocksPerChunk; i++, half ^= r) {
		/* 3: X = H(X ^ B_i) */
		xmmp = (xmmi *)scrypt_block(Bin, i);
		x0 = _mm_xor_si128(x0, xmmp[0]);
		x1 = _mm_xor_si128(x1, xmmp[1]);
		x2 = _mm_xor_si128(x2, xmmp[2]);
		x3 = _mm_xor_si128(x3, xmmp[3]);

		if (Bxor) {
			xmmp = (xmmi *)scrypt_block(Bxor, i);
			x0 = _mm_xor_si128(x0, xmmp[0]);
			x1 = _mm_xor_si128(x1, xmmp[1]);
			x2 = _mm_xor_si128(x2, xmmp[2]);
			x3 = _mm_xor_si128(x3, xmmp[3]);
		}

		t0 = x0;
		t1 = x1;
		t2 = x2;
		t3 = x3;

		for (rounds = 8; rounds; rounds -= 2) {
			x0 = _mm_add_epi32(x0, x1);
			x3 = _mm_xor_si128(x3, x0);
			x3 = _mm_roti_epi32(x3, 16);
			x2 = _mm_add_epi32(x2, x3);
			x1 = _mm_xor_si128(x1, x2);
			x1 = _mm_roti_epi32(x1, 12);
			x0 = _mm_add_epi32(x0, x1);
			x3 = _mm_xor_si128(x3, x0);
			x3 = _mm_roti_epi32(x3, 8);
			x2 = _mm_add_epi32(x2, x3);
			x0 = _mm_shuffle_epi32(x0, 0x93);
			x1 = _mm_xor_si128(x1, x2);
			x1 = _mm_roti_epi32(x1, 7);
			x3 = _mm_shuffle_epi32(x3, 0x4e);
			x0 = _mm_add_epi32(x0, x1);
			x2 = _mm_shuffle_epi32(x2, 0x39);
			x3 = _mm_xor_si128(x3, x0);
			x3 = _mm_roti_epi32(x3, 16);
			x2 = _mm_add_epi32(x2, x3);
			x1 = _mm_xor_si128(x1, x2);
			x1 = _mm_roti_epi32(x1, 12);
			x0 = _mm_add_epi32(x0, x1);
			x3 = _mm_xor_si128(x3, x0);
			x3 = _mm_roti_epi32(x3, 8);
			x2 = _mm_add_epi32(x2, x3);
			x1 = _mm_xor_si128(x1, x2);
			x0 = _mm_shuffle_epi32(x0, 0x39);
			x1 = _mm_roti_epi32(x1, 7);
			x3 = _mm_shuffle_epi32(x3, 0x4e);
			x2 = _mm_shuffle_epi32(x2, 0x93);
		}

		x0 = _mm_add_epi32(x0, t0);
		x1 = _mm_add_epi32(x1, t1);
		x2 = _mm_add_epi32(x2, t2);
		x3 = _mm_add_epi32(x3, t3);

		/* 4: Y_i = X */
		/* 6: B'[0..r-1] = Y_even */
		/* 6: B'[r..2r-1] = Y_odd */
		xmmp = (xmmi *)scrypt_block(Bout, (i / 2) + half);
		xmmp[0] = x0;
		xmmp[1] = x1;
		xmmp[2] = x2;
		xmmp[3] = x3;
	}
}

#endif

#if defined(SCRYPT_CHACHA_XOP)
	#undef SCRYPT_MIX
	#define SCRYPT_MIX "ChaCha/8-XOP"
	#undef SCRYPT_CHACHA_INCLUDED
	#define SCRYPT_CHACHA_INCLUDED
#endif
