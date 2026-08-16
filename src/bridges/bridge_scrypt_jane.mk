
SCRYPT_JANE := deps/scrypt-jane-master

BRIDGE_SRC_bridge_scrypt_jane           := src/bridges/bridge_scrypt_jane.c src/cpu_features.c

BRIDGE_CFLAGS_bridge_scrypt_jane        := -I$(SCRYPT_JANE)/ -DSCRYPT_SHA256 -DSCRYPT_SALSA -DSCRYPT_CHOOSE_COMPILETIME -Wno-unused-function -Wno-unused-but-set-variable -Wno-unused-variable

BRIDGE_CFLAGS_bridge_scrypt_jane_NATIVE := $(SIMD_NATIVE)
BRIDGE_CFLAGS_bridge_scrypt_jane_LINUX  := $(SIMD_LINUX)
BRIDGE_CFLAGS_bridge_scrypt_jane_WIN    := $(SIMD_WIN)

# scrypt-jane writes its mix functions as naked inline asm, and LTO cannot see through them.
# The reference from one partition to scrypt_ChunkMix_avx in another is then left undefined and
# the link fails. This used to be guarded on clang, but the problem is not clang specific, gcc
# fails the same way, so the exclusion applies to the Windows build whoever compiles it

ifeq ($(ENABLE_LTO),1)
BRIDGE_CFLAGS_bridge_scrypt_jane_WIN    += -fno-lto
endif
