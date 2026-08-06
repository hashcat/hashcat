
SCRYPT_JANE := deps/scrypt-jane-master
SCRYPT_JANE_CFLAGS := -I$(SCRYPT_JANE)/ -DSCRYPT_SHA256 -DSCRYPT_SALSA -DSCRYPT_CHOOSE_COMPILETIME -Wno-unused-function -Wno-unused-but-set-variable

ifeq ($(MAINTAINER_MODE),0)
ifeq ($(BUILD_MODE),cross)
SCRYPT_JANE_CFLAGS += -mavx2
else
ifeq ($(UNAME),Darwin)
ifeq ($(IS_APPLE_SILICON),0)
SCRYPT_JANE_CFLAGS += -mavx2
endif
else
ifeq ($(IS_PPC),1)
SCRYPT_JANE_CFLAGS += $(MCPU_NATIVE)
else
SCRYPT_JANE_CFLAGS += $(MARCH_NATIVE)
endif
endif
endif
endif

# scrypt-jane writes its mix functions as naked inline asm, and LTO cannot see through them.
# The reference from one partition to scrypt_ChunkMix_avx in another is then left undefined and
# the link fails. This used to be guarded on clang, but the problem is not clang specific, gcc
# fails the same way, so the exclusion applies to any cross compiler

ifeq ($(ENABLE_LTO),1)
ifeq ($(BUILD_MODE),cross)
bridges/bridge_scrypt_jane.dll: SCRYPT_JANE_CFLAGS += -fno-lto
endif
endif

ifeq ($(BUILD_MODE),cross)
bridges/bridge_scrypt_jane.so:  src/bridges/bridge_scrypt_jane.c src/cpu_features.c obj/combined.LINUX.a
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX)  $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_JANE_CFLAGS)
bridges/bridge_scrypt_jane.dll: src/bridges/bridge_scrypt_jane.c src/cpu_features.c obj/combined.WIN.a
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)    $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_JANE_CFLAGS)
else
ifeq ($(SHARED),1)
bridges/bridge_scrypt_jane.$(BRIDGE_SUFFIX): src/bridges/bridge_scrypt_jane.c src/cpu_features.c $(HASHCAT_LIBRARY)
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_JANE_CFLAGS)
else
bridges/bridge_scrypt_jane.$(BRIDGE_SUFFIX): src/bridges/bridge_scrypt_jane.c src/cpu_features.c obj/combined.NATIVE.a
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_JANE_CFLAGS)
endif
endif
