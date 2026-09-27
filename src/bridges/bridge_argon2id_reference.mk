
ARGON2_REFERENCE := deps/phc-winner-argon2-20190702

BRIDGE_SRC_bridge_argon2id_reference           := src/bridges/bridge_argon2id_reference.c src/cpu_features.c

BRIDGE_CFLAGS_bridge_argon2id_reference        := -I$(ARGON2_REFERENCE)/_hashcat/

BRIDGE_CFLAGS_bridge_argon2id_reference_NATIVE := $(SIMD_NATIVE)
BRIDGE_CFLAGS_bridge_argon2id_reference_LINUX  := $(SIMD_LINUX)
BRIDGE_CFLAGS_bridge_argon2id_reference_WIN    := $(SIMD_WIN)
