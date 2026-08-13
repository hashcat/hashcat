
SCRYPT_YESCRYPT := deps/yescrypt-master

BRIDGE_SRC_bridge_scrypt_yescrypt           := src/bridges/bridge_scrypt_yescrypt.c src/cpu_features.c
BRIDGE_SRC_bridge_scrypt_yescrypt           += $(SCRYPT_YESCRYPT)/yescrypt-opt.c $(SCRYPT_YESCRYPT)/sha256.c

BRIDGE_CFLAGS_bridge_scrypt_yescrypt        := -I$(SCRYPT_YESCRYPT)/ -DSKIP_MEMZERO -Wno-cpp -Wno-type-limits

BRIDGE_CFLAGS_bridge_scrypt_yescrypt_NATIVE := $(SIMD_NATIVE)
BRIDGE_CFLAGS_bridge_scrypt_yescrypt_LINUX  := $(SIMD_LINUX)
BRIDGE_CFLAGS_bridge_scrypt_yescrypt_WIN    := $(SIMD_WIN)
