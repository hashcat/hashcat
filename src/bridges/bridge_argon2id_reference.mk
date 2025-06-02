
ARGON2_REFERENCE := deps/phc-winner-argon2-20190702
ARGON2_REFERENCE_CFLAGS := -I$(ARGON2_REFERENCE)/_hashcat/

ifeq ($(BUILD_MODE),cross)
ARGON2_REFERENCE_CFLAGS += -mavx2
else
ifeq ($(UNAME),Darwin)
ifeq ($(IS_APPLE_SILICON),0)
ARGON2_REFERENCE_CFLAGS += -mavx2
endif
else
ARGON2_REFERENCE_CFLAGS += -march=native
endif
endif

ifeq ($(BUILD_MODE),cross)
bridges/bridge_argon2id_reference.so:  src/bridges/bridge_argon2id_reference.c obj/combined.LINUX.a
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX)  $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(ARGON2_REFERENCE_CFLAGS)
bridges/bridge_argon2id_reference.dll: src/bridges/bridge_argon2id_reference.c obj/combined.WIN.a
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)    $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(ARGON2_REFERENCE_CFLAGS)
else
ifeq ($(SHARED),1)
bridges/bridge_argon2id_reference.$(BRIDGE_SUFFIX): src/bridges/bridge_argon2id_reference.c $(HASHCAT_LIBRARY)
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(ARGON2_REFERENCE_CFLAGS)
else
bridges/bridge_argon2id_reference.$(BRIDGE_SUFFIX): src/bridges/bridge_argon2id_reference.c obj/combined.NATIVE.a
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(ARGON2_REFERENCE_CFLAGS)
endif
endif
