
SCRYPT_JANE := deps/scrypt-jane-master

BRIDGE_SRC_bridge_scrypt_jane           := src/bridges/bridge_scrypt_jane.c src/cpu_features.c

BRIDGE_CFLAGS_bridge_scrypt_jane        := -I$(SCRYPT_JANE)/ -DSCRYPT_SHA256 -DSCRYPT_SALSA -DSCRYPT_CHOOSE_COMPILETIME -Wno-unused-function -Wno-unused-but-set-variable -Wno-unused-variable

BRIDGE_CFLAGS_bridge_scrypt_jane_NATIVE := $(SIMD_NATIVE)
BRIDGE_CFLAGS_bridge_scrypt_jane_LINUX  := $(SIMD_LINUX)
BRIDGE_CFLAGS_bridge_scrypt_jane_WIN    := $(SIMD_WIN)

# scrypt-jane picks its mix implementation at compile time. On ARM the x86 intrinsic path is the one
# to take, mapped to NEON by sse2neon, rather than the portable scalar fallback. The sse2neon include
# and its warning suppression are already on CFLAGS_NATIVE and CFLAGS_LINUX for ARM, so only the two
# defines that select the path belong here. The cross build to Windows is x86 and keeps the x86 path.

ifeq ($(IS_ARM),1)
BRIDGE_CFLAGS_bridge_scrypt_jane_NATIVE += -DCPU_X86_FORCE_INTRINSICS -DX86_INTRINSIC_SSE2
BRIDGE_CFLAGS_bridge_scrypt_jane_LINUX  += -DCPU_X86_FORCE_INTRINSICS -DX86_INTRINSIC_SSE2
endif

# scrypt-jane writes its mix functions as naked inline asm, and LTO cannot see through them.
# The reference from one partition to scrypt_ChunkMix_avx in another is then left undefined and
# the link fails. This used to be guarded on clang, but the problem is not clang specific, gcc
# fails the same way, so the exclusion applies to the Windows build whoever compiles it

ifeq ($(ENABLE_LTO),1)
BRIDGE_CFLAGS_bridge_scrypt_jane_WIN    += -fno-lto
endif
